"""Helpers for loading Hermes .env files consistently across entrypoints."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import io
import json
import ntpath
import os
import re
import stat
import subprocess
import sys
import threading
from collections.abc import Mapping
from pathlib import Path

from dotenv import dotenv_values, load_dotenv
from utils import atomic_replace, fast_safe_load


# Env var name suffixes that indicate credential values.  These are the
# only env vars whose values we sanitize on load — we must not silently
# alter arbitrary user env vars, but credentials are known to require
# pure ASCII (they become HTTP header values).
_CREDENTIAL_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET", "_KEY")

# Names we've already warned about during this process, so repeated
# load_hermes_dotenv() calls (user env + project env, gateway hot-reload,
# tests) don't spam the same warning multiple times.
_WARNED_KEYS: set[str] = set()

# Paths we've already emitted a UTF-32 refuse-to-mangle warning for.
# load_hermes_dotenv can call _sanitize_env_file_if_needed multiple times
# for the same file (user env + project env + hot-reload); once per path
# is enough.
_WARNED_UTF32_PATHS: set[str] = set()

# Map of env-var name → source label ("bitwarden", etc.) for credentials
# that were injected by an external secret source during load_hermes_dotenv().
# Used by setup / `hermes model` flows to label detected credentials so
# users understand WHERE a key came from when their .env doesn't contain it
# directly (otherwise the "credentials detected ✓" line looks identical to
# the .env case and they don't know Bitwarden is wired up).
_SECRET_SOURCES: dict[str, str] = {}
# Applied values are immutable per-home snapshots.  ``os.environ`` is shared
# across profiles and may be overwritten by a later home's source apply.
_SECRET_SOURCE_VALUES_BY_HOME: dict[str, dict[str, str]] = {}

# HERMES_HOME paths we've already pulled external secrets for during this
# process.  ``load_hermes_dotenv()`` is called at module-import time from
# several hot modules (cli.py, hermes_cli/main.py, run_agent.py,
# trajectory_compressor.py, gateway/run.py, ...), so without this guard the
# Bitwarden status line gets printed 3-5x per startup.  Bitwarden's own
# in-process cache prevents redundant network calls, but the print, the
# config re-parse, and the ASCII sanitization sweep still ran every time.
_APPLIED_HOMES: set[str] = set()
_SECRET_SOURCE_CACHE_LOCK = threading.RLock()

# Detached gateway launchers can pin their runtime provenance before Python
# starts.  The private marker carries a versioned snapshot because
# ``hermes_cli.main`` applies profile selection before its first dotenv load;
# reading the public variables only at dotenv time would therefore be too late.
# The snapshot is captured exactly once, removed from ``os.environ`` so child
# processes cannot inherit it, and re-applied after every source that may use
# ``override=True``.  Normal interactive/foreground invocations never set the
# marker and retain the usual dotenv semantics.
_GATEWAY_LAUNCH_ENV_LOCK_VAR = "_HERMES_GATEWAY_LAUNCH_ENV_LOCK"
_GATEWAY_LAUNCH_ENV_KEYS: tuple[str, ...] = (
    "HERMES_HOME",
    "HERMES_RUNTIME_HOME",
    "GLADLY_HERMES_CODE_ROOT",
    "PYTHONPATH",
    "VIRTUAL_ENV",
)
_GATEWAY_RUNTIME_PATH_ENV_KEYS: tuple[str, ...] = (
    "HERMES_GATEWAY_RUNTIME_PATH",
    "PATH",
)
_GATEWAY_MANAGED_PROVENANCE_ENV_KEYS: tuple[str, ...] = (
    "HERMES_GATEWAY_START_VALIDATOR",
    "HERMES_GATEWAY_START_VALIDATOR_ARGS",
)
_GATEWAY_MANAGED_LAUNCH_ENV_KEYS: tuple[str, ...] = (
    *_GATEWAY_RUNTIME_PATH_ENV_KEYS,
    *_GATEWAY_MANAGED_PROVENANCE_ENV_KEYS,
)
_SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX = threading.Lock()
_GATEWAY_LAUNCH_ENV_CAPTURE_ATTEMPTED = False
_GATEWAY_LAUNCH_ENV_STATE: tuple[dict[str, str], str] | None = None
_GATEWAY_LAUNCH_ENV_ERROR: str | None = None
_GATEWAY_START_VALIDATOR_MUTEX = threading.Lock()
_GATEWAY_START_VALIDATOR_ATTEMPTED = False
_GATEWAY_START_VALIDATOR_ERROR: str | None = None
_GATEWAY_START_PROVENANCE: dict[str, str | int] | None = None
_GLADLY_RUNTIME_INSTALL_RECEIPT = ".gladly-runtime-install.json"
_GLADLY_RUNTIME_INSTALL_SCHEMA = "gladly.runtime_install.v3"
_GLADLY_RUNTIME_MANIFEST_SCHEMA = "hermes.runtime_bundle_manifest.v1"
_GLADLY_GATEWAY_VALIDATOR_IMPORT_CLOSURE = (
    "runtime-gateway-enable-cli.ts",
    "runtime-manifest-cli.ts",
    "runtime-manifest.ts",
    "codex-sandbox-executable.ts",
    "runtime-cron-policy.ts",
    "runtime-env-contract.ts",
    "stable-file-evidence.ts",
    "windows-known-paths.ts",
    "runtime-install-evidence.ts",
    "runtime-release-gate.ts",
    "runtime-authority-state.ts",
    "runtime-claim-authority.ts",
)


def _canonical_json(value: object) -> str:
    """Match the Gladly runtime canonical-JSON digest contract."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _normalized_evidence_path(value: str | os.PathLike) -> str:
    resolved = Path(value).resolve(strict=True).as_posix()
    return resolved.casefold() if sys.platform == "win32" else resolved


def _same_evidence_path(
    left: str | os.PathLike,
    right: str | os.PathLike,
) -> bool:
    try:
        return _normalized_evidence_path(left) == _normalized_evidence_path(right)
    except OSError:
        return False


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        getattr(value, "st_file_attributes", 0),
    )


def _assert_closed_path(path: Path, label: str) -> Path:
    """Reject every link/reparse component and return the lexical target."""
    candidate = Path(os.path.abspath(os.fspath(path)))
    anchor = Path(candidate.anchor)
    current = anchor
    for part in candidate.parts[1:]:
        current = current / part
        status = current.lstat()
        if stat.S_ISLNK(status.st_mode) or bool(
            getattr(status, "st_file_attributes", 0) & 0x400
        ):
            raise OSError(f"{label} traverses a link or reparse point")
    if _normalized_launch_cwd(candidate) != _normalized_launch_cwd(
        candidate.resolve(strict=True)
    ):
        raise OSError(f"{label} resolves through a redirected path")
    return candidate


def _stable_regular_file(path: Path, label: str) -> dict[str, object]:
    """Read exact bytes through one no-follow handle with ancestor rechecks."""
    candidate = _assert_closed_path(path, label)
    before = candidate.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OSError(f"{label} is not a regular file")
    expected = _file_identity(before)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened_before = os.fstat(descriptor)
        if _file_identity(opened_before) != expected:
            raise OSError(f"{label} changed before its handle opened")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        opened_after = os.fstat(descriptor)
        if _file_identity(opened_after) != expected:
            raise OSError(f"{label} changed while its handle was open")
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    after_path = candidate.lstat()
    if _file_identity(after_path) != expected:
        raise OSError(f"{label} path changed while it was read")
    _assert_closed_path(candidate, label)
    final = candidate.lstat()
    if _file_identity(final) != expected:
        raise OSError(f"{label} changed after its handle closed")
    return {
        "path": _normalized_evidence_path(candidate),
        "content": content,
        "fileDigest": _sha256_digest(content),
        "identity": expected,
    }


def _strict_json_bytes(content: bytes, label: str) -> dict[str, object]:
    try:
        parsed = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_json_object_without_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON data") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} is not a JSON object")
    return parsed


def _managed_install_root() -> Path | None:
    """Detect the Gladly embedding from the imported tree, never public env."""
    lexical_module = Path(os.path.abspath(__file__))
    candidates: list[Path] = []
    source_agent_root = lexical_module.parent.parent
    if source_agent_root.name.casefold() == "hermes-agent":
        candidates.append(source_agent_root)
    interpreter = Path(os.path.abspath(sys.executable))
    if interpreter.parent.name.casefold() in {"scripts", "bin"}:
        venv_root = interpreter.parent.parent
        interpreter_agent_root = venv_root.parent
        if (
            venv_root.name.casefold() == "venv"
            and interpreter_agent_root.name.casefold() == "hermes-agent"
        ):
            try:
                module_key = _normalized_launch_cwd(lexical_module)
                agent_key = _normalized_launch_cwd(interpreter_agent_root)
                if os.path.commonpath([module_key, agent_key]) == agent_key:
                    candidates.append(interpreter_agent_root)
            except (OSError, ValueError):
                pass
    if not candidates:
        return None
    agent_root = candidates[0]
    root = agent_root.parent
    receipt = agent_root / "venv" / _GLADLY_RUNTIME_INSTALL_RECEIPT
    validator = root / "bridge" / "src" / "runtime-gateway-start-validator-cli.ts"
    home = root / "home"
    # Receipt deletion or public HERMES_HOME redirection must not turn a
    # managed checkout into a standalone one.  The embedding layout itself is
    # the marker; missing evidence is handled as a fail-closed contract error.
    if not (receipt.exists() or validator.exists() or home.is_dir()):
        return None
    _assert_closed_path(lexical_module, "Imported Hermes environment loader")
    _assert_closed_path(root, "Managed Gladly checkout")
    return root


def _receipt_tool(
    receipt: Mapping[str, object],
    name: str,
) -> tuple[str, str]:
    tools = receipt.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("managed receipt tools are missing")
    tool = tools.get(name)
    if not isinstance(tool, dict):
        raise ValueError(f"managed receipt {name} tool is missing")
    path = tool.get("path")
    identity_digest = tool.get("identityDigest")
    if (
        not isinstance(path, str)
        or not path
        or not (os.path.isabs(path) or ntpath.isabs(path))
        or not isinstance(identity_digest, str)
        or _SHA256_DIGEST_RE.fullmatch(identity_digest) is None
    ):
        raise ValueError(f"managed receipt {name} tool is invalid")
    return path, identity_digest


def _executable_identity_digest(path: str, label: str) -> tuple[str, dict[str, object]]:
    measured = _stable_regular_file(Path(path), label)
    payload = {
        "path": measured["path"],
        "fileDigest": measured["fileDigest"],
    }
    return _sha256_digest(_canonical_json(payload).encode("utf-8")), measured


def _managed_install_contract() -> dict[str, object] | None:
    """Derive the only valid managed validator contract from fixed evidence."""
    root = _managed_install_root()
    if root is None:
        return None
    agent_root = root / "hermes-agent"
    home = root / "home"
    receipt_path = agent_root / "venv" / _GLADLY_RUNTIME_INSTALL_RECEIPT
    receipt_file = _stable_regular_file(receipt_path, "Managed runtime install receipt")
    receipt = _strict_json_bytes(
        receipt_file["content"],  # type: ignore[arg-type]
        "Managed runtime install receipt",
    )
    if receipt.get("schemaVersion") != _GLADLY_RUNTIME_INSTALL_SCHEMA:
        raise ValueError("managed runtime install receipt schema is unsupported")
    bun_path, bun_identity = _receipt_tool(receipt, "bun")
    actual_bun_identity, bun_file = _executable_identity_digest(
        bun_path,
        "Managed receipt-bound Bun executable",
    )
    if actual_bun_identity != bun_identity:
        raise ValueError("managed receipt-bound Bun executable identity changed")
    runtime_path = receipt.get("runtimePathPolicy")
    if not isinstance(runtime_path, dict):
        raise ValueError("managed receipt PATH policy is missing")
    path_value = runtime_path.get("value")
    if not isinstance(path_value, str) or not path_value:
        raise ValueError("managed receipt PATH policy is invalid")
    validator_script = root / "bridge" / "src" / "runtime-gateway-start-validator-cli.ts"
    validator_file = _stable_regular_file(
        validator_script,
        "Managed gateway start validator entrypoint",
    )
    manifest_path = home / "state" / "runtime-bundle-manifest.json"
    validator_argv = (
        str(validator_script),
        "--root",
        str(root),
        "--manifest",
        str(manifest_path),
    )
    managed_values = {
        "HERMES_GATEWAY_RUNTIME_PATH": path_value,
        "PATH": path_value,
        "HERMES_GATEWAY_START_VALIDATOR": bun_path,
        "HERMES_GATEWAY_START_VALIDATOR_ARGS": _encode_gateway_start_validator_args(
            validator_argv
        ),
    }
    _validate_gateway_managed_launch_values(managed_values)
    return {
        "root": root,
        "agentRoot": agent_root,
        "home": home,
        "receiptPath": receipt_path,
        "receipt": receipt,
        "receiptFile": receipt_file,
        "receiptDigest": _sha256_digest(_canonical_json(receipt).encode("utf-8")),
        "bunPath": bun_path,
        "bunIdentityDigest": bun_identity,
        "bunFile": bun_file,
        "validatorScript": validator_script,
        "validatorFile": validator_file,
        "manifestPath": manifest_path,
        "validatorArgv": validator_argv,
        "managedValues": managed_values,
    }


def _manifest_inventory_digest(manifest: Mapping[str, object], item_id: str) -> str:
    tools = manifest.get("tools")
    if not isinstance(tools, list):
        raise ValueError("managed runtime manifest inventory is missing")
    matches = [
        item for item in tools
        if isinstance(item, dict) and item.get("id") == item_id
    ]
    if len(matches) != 1:
        raise ValueError(f"managed runtime manifest must bind exactly one {item_id}")
    digest = matches[0].get("digest")
    if not isinstance(digest, str) or _SHA256_DIGEST_RE.fullmatch(digest) is None:
        raise ValueError(f"managed runtime manifest {item_id} digest is invalid")
    return digest


def _managed_start_expectations(contract: Mapping[str, object]) -> dict[str, object]:
    """Bind the executable/entrypoint/output to the current stored manifest."""
    manifest_path = contract["manifestPath"]
    if not isinstance(manifest_path, Path):
        raise ValueError("managed runtime manifest path is invalid")
    manifest_file = _stable_regular_file(manifest_path, "Managed stored runtime manifest")
    manifest = _strict_json_bytes(
        manifest_file["content"],  # type: ignore[arg-type]
        "Managed stored runtime manifest",
    )
    if manifest.get("schemaVersion") != _GLADLY_RUNTIME_MANIFEST_SCHEMA:
        raise ValueError("managed stored runtime manifest schema is unsupported")
    receipt_digest = contract["receiptDigest"]
    bun_identity = contract["bunIdentityDigest"]
    validator_file = contract["validatorFile"]
    if (
        _manifest_inventory_digest(manifest, "runtime/install-receipt")
        != receipt_digest
        or _manifest_inventory_digest(manifest, "runtime/bun-executable")
        != bun_identity
        or not isinstance(validator_file, dict)
        or _manifest_inventory_digest(manifest, "runtime/gateway-start-validator")
        != validator_file.get("fileDigest")
    ):
        raise ValueError(
            "managed validator executable or entrypoint is not receipt/manifest-bound"
        )
    root = contract.get("root")
    if not isinstance(root, Path):
        raise ValueError("managed runtime root is invalid")
    closure_files: dict[str, dict[str, object]] = {}
    for dependency in _GLADLY_GATEWAY_VALIDATOR_IMPORT_CLOSURE:
        item_id = f"runtime/windows-gateway-disable-import/{dependency}"
        measured = _stable_regular_file(
            root / "bridge" / "src" / dependency,
            f"Managed gateway validator import {dependency}",
        )
        if _manifest_inventory_digest(manifest, item_id) != measured["fileDigest"]:
            raise ValueError(
                f"managed gateway validator import {dependency} is not manifest-bound"
            )
        closure_files[dependency] = measured
    current_loader = _stable_regular_file(
        Path(__file__),
        "Managed gateway environment loader",
    )
    if (
        _manifest_inventory_digest(manifest, "runtime/windows-gateway-env-loader")
        != current_loader["fileDigest"]
    ):
        raise ValueError("managed gateway environment loader is not manifest-bound")
    manifest_digest = manifest.get("digest")
    if not isinstance(manifest_digest, str) or _SHA256_DIGEST_RE.fullmatch(manifest_digest) is None:
        raise ValueError("managed stored runtime manifest digest is invalid")
    expected_provenance = {
        "version": 1,
        "receiptDigest": receipt_digest,
        "manifestDigest": manifest_digest,
        "taskEvidenceDigest": _manifest_inventory_digest(
            manifest,
            "runtime/windows-gateway-evidence",
        ),
    }
    return {
        "manifest": manifest,
        "manifestFile": manifest_file,
        "loaderFile": current_loader,
        "closureFiles": closure_files,
        "provenance": expected_provenance,
    }


def _measured_file_snapshot(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("managed measured-file evidence is invalid")
    return {
        "path": value.get("path"),
        "fileDigest": value.get("fileDigest"),
        "identity": value.get("identity"),
    }


def _managed_contract_snapshot(contract: Mapping[str, object]) -> dict[str, object]:
    return {
        "root": str(contract.get("root")),
        "agentRoot": str(contract.get("agentRoot")),
        "home": str(contract.get("home")),
        "receiptPath": str(contract.get("receiptPath")),
        "receiptDigest": contract.get("receiptDigest"),
        "bunPath": contract.get("bunPath"),
        "bunIdentityDigest": contract.get("bunIdentityDigest"),
        "validatorScript": str(contract.get("validatorScript")),
        "manifestPath": str(contract.get("manifestPath")),
        "validatorArgv": contract.get("validatorArgv"),
        "managedValues": contract.get("managedValues"),
        "receiptFile": _measured_file_snapshot(contract.get("receiptFile")),
        "bunFile": _measured_file_snapshot(contract.get("bunFile")),
        "validatorFile": _measured_file_snapshot(contract.get("validatorFile")),
    }


def _managed_expectations_snapshot(expected: Mapping[str, object]) -> dict[str, object]:
    closure = expected.get("closureFiles")
    if not isinstance(closure, dict):
        raise ValueError("managed validator import-closure evidence is invalid")
    return {
        "provenance": expected.get("provenance"),
        "manifestFile": _measured_file_snapshot(expected.get("manifestFile")),
        "loaderFile": _measured_file_snapshot(expected.get("loaderFile")),
        "closureFiles": {
            name: _measured_file_snapshot(value)
            for name, value in sorted(closure.items())
        },
    }


def _encode_gateway_start_validator_args(args: list[str] | tuple[str, ...]) -> str:
    """Encode the exact validator argv suffix as canonical unpadded base64url."""
    _validate_gateway_start_validator_argv(args)
    raw = json.dumps(
        list(args), ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _validate_gateway_start_validator_argv(
    value: object,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value or len(value) > 64:
        raise ValueError("gateway start validator argv has an invalid shape")
    result: list[str] = []
    total = 0
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 8192
            or any(char in item for char in ("\x00", "\r", "\n"))
        ):
            raise ValueError("gateway start validator argv has an invalid item")
        total += len(item)
        result.append(item)
    if total > 32768:
        raise ValueError("gateway start validator argv is too large")
    return tuple(result)


def _decode_gateway_start_validator_args(raw: str) -> tuple[str, ...]:
    """Decode only canonical unpadded base64url JSON arrays of argv strings."""
    if (
        not isinstance(raw, str)
        or not raw
        or len(raw) > 65536
        or re.fullmatch(r"[A-Za-z0-9_-]+", raw) is None
    ):
        raise ValueError("gateway start validator args are malformed")
    try:
        padding = "=" * (-len(raw) % 4)
        decoded = base64.b64decode(
            (raw + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != raw:
            raise ValueError("non-canonical base64url")
        parsed = json.loads(decoded.decode("utf-8"))
    except (
        binascii.Error,
        UnicodeDecodeError,
        UnicodeEncodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise ValueError("gateway start validator args are malformed") from exc
    argv = _validate_gateway_start_validator_argv(parsed)
    canonical = json.dumps(
        list(argv), ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    if decoded != canonical:
        raise ValueError("gateway start validator args are not canonical JSON")
    return argv


def _validate_gateway_managed_launch_values(
    env: Mapping[str, str],
) -> dict[str, str]:
    """Validate and return the complete managed launch/provenance contract."""
    values: dict[str, str] = {}
    for key in _GATEWAY_MANAGED_LAUNCH_ENV_KEYS:
        value = env.get(key)
        if (
            not isinstance(value, str)
            or not value
            or any(char in value for char in ("\x00", "\r", "\n"))
        ):
            raise ValueError(f"gateway managed launch environment is missing {key}")
        values[key] = value

    if values["PATH"] != values["HERMES_GATEWAY_RUNTIME_PATH"]:
        raise ValueError("gateway PATH must match HERMES_GATEWAY_RUNTIME_PATH")
    runtime_path = values["HERMES_GATEWAY_RUNTIME_PATH"]
    if any(char in runtime_path for char in ('"', "%", "!")):
        raise ValueError("gateway runtime PATH contains unsafe launcher syntax")
    entries = runtime_path.split(";")
    if any(not entry or entry != entry.strip() for entry in entries):
        raise ValueError("gateway runtime PATH contains an empty or padded entry")
    normalized: set[str] = set()
    for entry in entries:
        if not ntpath.isabs(entry):
            raise ValueError("gateway runtime PATH contains a non-absolute entry")
        if any(part in {".", ".."} for part in entry.replace("/", "\\").split("\\")):
            raise ValueError("gateway runtime PATH contains a relative segment")
        key = ntpath.normcase(ntpath.normpath(entry))
        if key in normalized:
            raise ValueError("gateway runtime PATH contains a duplicate entry")
        normalized.add(key)
    validator = values["HERMES_GATEWAY_START_VALIDATOR"]
    if not (os.path.isabs(validator) or ntpath.isabs(validator)):
        raise ValueError("gateway start validator must be an absolute path")
    _decode_gateway_start_validator_args(
        values["HERMES_GATEWAY_START_VALIDATOR_ARGS"]
    )
    return values


def _encode_gateway_launch_env_lock(
    env: Mapping[str, str],
    cwd: str | os.PathLike,
) -> str:
    """Encode the immutable environment snapshot used by gateway launchers.

    This is deliberately a private launcher contract, not a user-facing config
    option.  A launcher must provide every protected value; accepting a partial
    snapshot would make a staged service appear pinned while leaving one path
    open to a later ``.env`` override.
    """
    protected: dict[str, str] = {}
    for key in _GATEWAY_LAUNCH_ENV_KEYS:
        value = env.get(key)
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError(f"gateway launch environment is missing a valid {key}")
        protected[key] = value

    managed_values = [env.get(key) for key in _GATEWAY_MANAGED_LAUNCH_ENV_KEYS]
    if any(value is not None for value in managed_values):
        protected.update(_validate_gateway_managed_launch_values(env))

    cwd_value = os.fspath(cwd)
    if not cwd_value or "\x00" in cwd_value:
        raise ValueError("gateway launch environment is missing a valid cwd")
    if _normalized_launch_cwd(protected["HERMES_HOME"]) != _normalized_launch_cwd(
        protected["HERMES_RUNTIME_HOME"]
    ):
        raise ValueError("gateway runtime home must match its locked Hermes home")
    if _normalized_launch_cwd(cwd_value) != _normalized_launch_cwd(
        protected["GLADLY_HERMES_CODE_ROOT"]
    ):
        raise ValueError("gateway cwd must match its locked reviewed code root")

    payload = {
        "version": 3 if "PATH" in protected else 1,
        "cwd": cwd_value,
        "env": protected,
    }
    raw = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_gateway_launch_env_lock(raw: str) -> tuple[dict[str, str], str]:
    """Decode and strictly validate a gateway launcher snapshot."""
    if not raw or len(raw) > 32768:
        raise ValueError("gateway launch environment lock is empty or too large")
    try:
        decoded = base64.b64decode(
            raw.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        payload = json.loads(decoded.decode("utf-8"))
    except (
        binascii.Error,
        UnicodeDecodeError,
        UnicodeEncodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise ValueError("gateway launch environment lock is malformed") from exc

    if not isinstance(payload, dict) or set(payload) != {"version", "cwd", "env"}:
        raise ValueError("gateway launch environment lock has an invalid shape")
    version = payload.get("version")
    if version not in {1, 3}:
        raise ValueError("gateway launch environment lock has an unsupported version")

    cwd = payload.get("cwd")
    values = payload.get("env")
    if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
        raise ValueError("gateway launch environment lock has an invalid cwd")
    expected_keys = set(_GATEWAY_LAUNCH_ENV_KEYS)
    if version == 3:
        expected_keys.update(_GATEWAY_MANAGED_LAUNCH_ENV_KEYS)
    if not isinstance(values, dict) or set(values) != expected_keys:
        raise ValueError("gateway launch environment lock has incomplete variables")
    for key in expected_keys:
        value = values.get(key)
        if (
            not isinstance(value, str)
            or not value
            or any(char in value for char in ("\x00", "\r", "\n"))
        ):
            raise ValueError(f"gateway launch environment lock has an invalid {key}")
    if version == 3:
        _validate_gateway_managed_launch_values(values)
    if _normalized_launch_cwd(values["HERMES_HOME"]) != _normalized_launch_cwd(
        values["HERMES_RUNTIME_HOME"]
    ):
        raise ValueError("gateway launch environment lock has mismatched homes")
    if _normalized_launch_cwd(cwd) != _normalized_launch_cwd(
        values["GLADLY_HERMES_CODE_ROOT"]
    ):
        raise ValueError("gateway launch environment lock has mismatched cwd")
    return dict(values), cwd


def _normalized_launch_cwd(value: str | os.PathLike) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(os.fspath(value))))


def _capture_gateway_launch_env_lock() -> None:
    """Capture a launcher snapshot once, before dotenv can replace it."""
    global _GATEWAY_LAUNCH_ENV_CAPTURE_ATTEMPTED
    global _GATEWAY_LAUNCH_ENV_STATE
    global _GATEWAY_LAUNCH_ENV_ERROR

    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        if _GATEWAY_LAUNCH_ENV_CAPTURE_ATTEMPTED:
            if _GATEWAY_LAUNCH_ENV_ERROR:
                raise RuntimeError(_GATEWAY_LAUNCH_ENV_ERROR)
            return

        raw = os.environ.pop(_GATEWAY_LAUNCH_ENV_LOCK_VAR, None)
        _GATEWAY_LAUNCH_ENV_CAPTURE_ATTEMPTED = True
        if raw is None:
            return

        try:
            values, expected_cwd = _decode_gateway_launch_env_lock(raw)
            actual_cwd = os.getcwd()
            if _normalized_launch_cwd(actual_cwd) != _normalized_launch_cwd(expected_cwd):
                raise ValueError("gateway launcher cwd does not match its locked cwd")
            if any(os.environ.get(key) != value for key, value in values.items()):
                raise ValueError(
                    "gateway launcher variables do not match their locked values"
                )
            imported_root = _normalized_launch_cwd(Path(__file__).resolve().parent.parent)
            pythonpath_entries = values["PYTHONPATH"].split(os.pathsep)
            if not any(
                entry and _normalized_launch_cwd(entry) == imported_root
                for entry in pythonpath_entries
            ):
                raise ValueError(
                    "gateway launcher PYTHONPATH does not contain the imported tree"
                )
        except (OSError, ValueError) as exc:
            _GATEWAY_LAUNCH_ENV_ERROR = (
                "Refusing detached gateway startup because its launch environment "
                "lock is invalid. Reinstall the gateway service."
            )
            raise RuntimeError(_GATEWAY_LAUNCH_ENV_ERROR) from exc

        _GATEWAY_LAUNCH_ENV_STATE = (values, expected_cwd)


def _reapply_gateway_launch_env_lock() -> None:
    """Restore process-local gateway provenance after an overriding source."""
    # Always discard a marker injected by a dotenv/managed source.  Only the
    # process-launch value captured before the first load is authoritative.
    os.environ.pop(_GATEWAY_LAUNCH_ENV_LOCK_VAR, None)
    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        if _GATEWAY_LAUNCH_ENV_ERROR:
            raise RuntimeError(_GATEWAY_LAUNCH_ENV_ERROR)
        state = _GATEWAY_LAUNCH_ENV_STATE
        if state is None:
            return
        values, _expected_cwd = state
        for key, value in values.items():
            os.environ[key] = value


def _gateway_launch_env_locked_values() -> dict[str, str] | None:
    """Return a copy of the active process-local launcher snapshot."""
    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        if _GATEWAY_LAUNCH_ENV_STATE is None:
            return None
        values, _expected_cwd = _GATEWAY_LAUNCH_ENV_STATE
        return dict(values)


def _json_object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_gateway_start_provenance(raw: str) -> dict[str, str | int]:
    """Decode the validator's exact, duplicate-free provenance response."""
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 16384:
        raise ValueError("gateway start provenance has invalid output")
    parsed = json.loads(
        raw,
        object_pairs_hook=_json_object_without_duplicate_keys,
    )
    expected_keys = {
        "version",
        "receiptDigest",
        "manifestDigest",
        "taskEvidenceDigest",
    }
    if (
        not isinstance(parsed, dict)
        or set(parsed) != expected_keys
        or type(parsed.get("version")) is not int
        or parsed.get("version") != 1
        or any(
            not isinstance(parsed.get(key), str)
            or _SHA256_DIGEST_RE.fullmatch(parsed[key]) is None
            for key in (
                "receiptDigest",
                "manifestDigest",
                "taskEvidenceDigest",
            )
        )
    ):
        raise ValueError("gateway start provenance has an invalid shape")
    return {
        "version": 1,
        "receiptDigest": parsed["receiptDigest"],
        "manifestDigest": parsed["manifestDigest"],
        "taskEvidenceDigest": parsed["taskEvidenceDigest"],
    }


def _gateway_start_provenance() -> dict[str, str | int] | None:
    """Return the immutable, validator-confirmed launch provenance."""
    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        if _GATEWAY_START_PROVENANCE is None:
            return None
        return dict(_GATEWAY_START_PROVENANCE)


def _assert_managed_launch_matches_install(
    values: Mapping[str, str],
    expected_cwd: str,
    contract: Mapping[str, object],
) -> None:
    root = contract.get("root")
    home = contract.get("home")
    agent_root = contract.get("agentRoot")
    managed_values = contract.get("managedValues")
    validator_argv = contract.get("validatorArgv")
    if (
        not isinstance(root, Path)
        or not isinstance(home, Path)
        or not isinstance(agent_root, Path)
        or not isinstance(managed_values, dict)
        or not isinstance(validator_argv, tuple)
    ):
        raise ValueError("managed install contract is incomplete")
    for name, expected in (
        ("HERMES_HOME", home),
        ("HERMES_RUNTIME_HOME", home),
        ("GLADLY_HERMES_CODE_ROOT", root),
        ("VIRTUAL_ENV", agent_root / "venv"),
    ):
        actual = values.get(name)
        if not isinstance(actual, str) or not _same_evidence_path(actual, expected):
            raise ValueError(f"managed launch {name} redirects outside the reviewed install")
    if not _same_evidence_path(expected_cwd, root):
        raise ValueError("managed launch cwd redirects outside the reviewed install")
    pythonpath = values.get("PYTHONPATH", "").split(os.pathsep)
    if len(pythonpath) != 1 or not _same_evidence_path(pythonpath[0], agent_root):
        raise ValueError("managed launch PYTHONPATH is not the exact imported agent root")
    for key in ("HERMES_GATEWAY_RUNTIME_PATH", "PATH"):
        if values.get(key) != managed_values.get(key):
            raise ValueError(f"managed launch {key} differs from the receipt PATH policy")
    if not _same_evidence_path(
        values.get("HERMES_GATEWAY_START_VALIDATOR", ""),
        str(managed_values.get("HERMES_GATEWAY_START_VALIDATOR", "")),
    ):
        raise ValueError("managed launch validator is not the receipt-bound Bun executable")
    actual_argv = _decode_gateway_start_validator_args(
        values.get("HERMES_GATEWAY_START_VALIDATOR_ARGS", "")
    )
    if len(actual_argv) != len(validator_argv):
        raise ValueError("managed launch validator argv has the wrong shape")
    for index, (actual, expected) in enumerate(zip(actual_argv, validator_argv)):
        if index in {0, 2, 4}:
            if not _same_evidence_path(actual, expected):
                raise ValueError("managed launch validator argv redirects this runtime")
        elif actual != expected:
            raise ValueError("managed launch validator argv changes a fixed option")


def _assert_gateway_start_provenance_if_managed() -> None:
    """Reject a managed gateway runtime that did not enter via its v3 lock.

    Parent install/inspection commands need the public managed variables in
    order to render and compare launch evidence, so this assertion belongs at
    the gateway runtime entrypoints rather than at module import. It closes the
    raw ``gateway run`` path without breaking disabled staging operations.
    """
    opt_in_keys = (
        "HERMES_GATEWAY_RUNTIME_PATH",
        *_GATEWAY_MANAGED_PROVENANCE_ENV_KEYS,
    )
    managed_requested = any(key in os.environ for key in opt_in_keys)
    managed_layout = _managed_install_root() is not None
    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        state = _GATEWAY_LAUNCH_ENV_STATE
        state_is_managed = bool(
            state is not None and "HERMES_GATEWAY_RUNTIME_PATH" in state[0]
        )
        provenance = _GATEWAY_START_PROVENANCE
        error = _GATEWAY_START_VALIDATOR_ERROR
    if not managed_requested and not state_is_managed and not managed_layout:
        return
    if error:
        raise RuntimeError(error)
    if not state_is_managed or provenance is None:
        raise RuntimeError(
            "Refusing managed gateway runtime without validator-confirmed "
            "launch provenance. Start the reviewed Scheduled Task with "
            "`hermes gateway start`."
        )
    if managed_layout:
        # The first validation occurs before external secret providers.  Run
        # the exact receipt/manifest-bound validator again here so task state,
        # runtime authority, hold and canary freshness are checked at the last
        # boundary immediately before the serving/ticker path.
        _run_gateway_start_validator_fresh()


def _validator_file_identity(path: str) -> tuple[int, int, int, int, int, int, int]:
    """Capture a no-follow identity for the exact managed validator executable."""
    candidate = Path(path)
    before = candidate.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OSError("validator is not a regular file")
    if bool(getattr(before, "st_file_attributes", 0) & 0x400):
        raise OSError("validator is a reparse point")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = candidate.lstat()

    def identity(
        value: os.stat_result,
    ) -> tuple[int, int, int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            stat.S_IFMT(value.st_mode),
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
            getattr(value, "st_file_attributes", 0),
        )

    identities = {identity(before), identity(opened), identity(after)}
    if len(identities) != 1:
        raise OSError("validator changed during identity capture")
    return identity(after)


def _run_gateway_start_validator_if_needed() -> None:
    """Serialize the process-once validator so no concurrent loader bypasses it."""
    with _GATEWAY_START_VALIDATOR_MUTEX:
        _run_gateway_start_validator_once_if_needed()


def _execute_gateway_start_validator(
    values: Mapping[str, str],
    expected_cwd: str,
    contract: Mapping[str, object] | None,
) -> dict[str, str | int]:
    managed = _validate_gateway_managed_launch_values(values)
    if contract is not None:
        _assert_managed_launch_matches_install(values, expected_cwd, contract)
        expected = _managed_start_expectations(contract)
    else:
        expected = None
    validator = managed["HERMES_GATEWAY_START_VALIDATOR"]
    argv_suffix = _decode_gateway_start_validator_args(
        managed["HERMES_GATEWAY_START_VALIDATOR_ARGS"]
    )
    from hermes_cli.gateway_windows import _managed_gateway_child_environment

    child_env = _managed_gateway_child_environment(values)
    before_identity = _validator_file_identity(validator)
    run_kwargs: dict[str, object] = {
        "cwd": expected_cwd,
        "env": child_env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "strict",
        "timeout": 60,
        "check": False,
        "close_fds": True,
    }
    if sys.platform == "win32":
        run_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    completed = subprocess.run([validator, *argv_suffix], **run_kwargs)
    after_identity = _validator_file_identity(validator)
    if before_identity != after_identity:
        raise RuntimeError("validator executable changed while it ran")
    if completed.returncode != 0:
        raise RuntimeError("validator returned a non-zero status")
    parsed = _decode_gateway_start_provenance(completed.stdout)
    if expected is not None:
        final_contract = _managed_install_contract()
        if final_contract is None:
            raise RuntimeError("managed install disappeared during validation")
        final_expected = _managed_start_expectations(final_contract)
        if (
            _managed_contract_snapshot(contract)
            != _managed_contract_snapshot(final_contract)
            or _managed_expectations_snapshot(expected)
            != _managed_expectations_snapshot(final_expected)
            or parsed != expected["provenance"]
        ):
            raise RuntimeError(
                "validator evidence changed or its output does not match trusted provenance"
            )
    return parsed


def _run_gateway_start_validator_fresh() -> None:
    """Revalidate current managed evidence at the final serving boundary."""
    global _GATEWAY_START_VALIDATOR_ERROR
    global _GATEWAY_START_PROVENANCE

    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        state = _GATEWAY_LAUNCH_ENV_STATE
    if state is None or "HERMES_GATEWAY_RUNTIME_PATH" not in state[0]:
        raise RuntimeError(
            "Refusing managed gateway runtime without a v3 launch environment lock."
        )
    values, expected_cwd = state
    try:
        parsed = _execute_gateway_start_validator(
            values,
            expected_cwd,
            _managed_install_contract(),
        )
    except Exception as exc:
        message = (
            "Refusing managed gateway startup because final runtime evidence "
            "could not be validated. Re-run the Gladly runtime preparation flow."
        )
        with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
            _GATEWAY_START_VALIDATOR_ERROR = message
        raise RuntimeError(message) from exc
    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        _GATEWAY_START_PROVENANCE = dict(parsed)


def _run_gateway_start_validator_once_if_needed() -> None:
    """Run the exact managed start validator once, before any network source.

    The private v3 launch lock binds the validator executable and canonical
    argv. The validator derives the current receipt, complete stored manifest,
    and Scheduled Task evidence digests at each start, receives only the
    reviewed Windows child allowlist, and returns those identities in one
    strict JSON provenance object. Generic/v1 launchers remain unchanged.
    """
    global _GATEWAY_START_VALIDATOR_ATTEMPTED
    global _GATEWAY_START_VALIDATOR_ERROR
    global _GATEWAY_START_PROVENANCE

    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        if _GATEWAY_START_VALIDATOR_ATTEMPTED:
            if _GATEWAY_START_VALIDATOR_ERROR:
                raise RuntimeError(_GATEWAY_START_VALIDATOR_ERROR)
            return
        state = _GATEWAY_LAUNCH_ENV_STATE
        if state is None or "HERMES_GATEWAY_RUNTIME_PATH" not in state[0]:
            return
        _GATEWAY_START_VALIDATOR_ATTEMPTED = True
        values, expected_cwd = state
        _validate_gateway_managed_launch_values(values)

    try:
        parsed = _execute_gateway_start_validator(
            values,
            expected_cwd,
            _managed_install_contract(),
        )
    except Exception as exc:
        message = (
            "Refusing managed gateway startup because runtime evidence could "
            "not be validated. Re-run the Gladly runtime preparation flow."
        )
        with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
            _GATEWAY_START_VALIDATOR_ERROR = message
        raise RuntimeError(message) from exc

    with _GATEWAY_LAUNCH_ENV_CAPTURE_MUTEX:
        _GATEWAY_START_PROVENANCE = dict(parsed)


def _known_hermes_env_keys() -> set[str]:
    """Return the combined set of known Hermes env-var keys.

    Includes both ``OPTIONAL_ENV_VARS`` (setup-flow vars with metadata) and
    ``_EXTRA_ENV_KEYS`` (provider/platform keys managed outside the setup
    wizard).  Lazy-imported to avoid circular-dependency during early-bootstrap
    ``load_hermes_dotenv()`` calls.
    """
    from hermes_cli.config import _EXTRA_ENV_KEYS
    from hermes_cli.config_defaults import OPTIONAL_ENV_VARS

    return set(OPTIONAL_ENV_VARS.keys()) | set(_EXTRA_ENV_KEYS)


# Behavioral routing keys a parent Hermes process injects into child env and
# that silently redirect a profile onto the wrong provider path (ACP auth
# method, copilot-ACP endpoints). These — and ONLY these — are scrubbed from
# os.environ at startup when absent from the profile's .env. Credential keys
# (API keys/tokens) are excluded: shell exports are a legitimate,
# documented way to supply them, and read-time secret-scope checks
# (agent/secret_scope.py) own cross-profile credential isolation.
_PROFILE_MANAGED_ENV_KEYS: frozenset[str] = frozenset({
    "HERMES_ACP_AUTH_METHOD",
    "HERMES_ACP_AUTO_APPROVE",
    "HERMES_COPILOT_ACP_COMMAND",
    "HERMES_COPILOT_ACP_ARGS",
    "COPILOT_CLI_PATH",
    "COPILOT_ACP_BASE_URL",
})


def _env_keys_defined_in_dotenv(path: Path) -> set[str]:
    """Return KEY names assigned in a dotenv file (including empty ``KEY=``).

    Uses a fast line scanner rather than full dotenv parsing so it works
    during early bootstrap without importing python-dotenv.  Ignores comment
    and blank lines.  Non-ASCII encoding errors fall back to ``latin-1``,
    matching ``_load_dotenv_with_fallback``.
    """
    keys: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        try:
            text = path.read_text(encoding="latin-1", errors="replace")
        except Exception:
            return keys
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        key = line.split("=", 1)[0].strip()
        if key:
            keys.add(key)
    return keys


def _clear_known_keys_missing_from_dotenv(path: Path) -> None:
    """Remove inherited profile-managed Hermes keys absent from ``.env``.

    After the profile's ``.env`` has been loaded with ``override=True``,
    scan the file for which profile-managed keys it explicitly defines and
    delete any such key that exists in ``os.environ`` but is *not* present
    in the file.

    Scope is deliberately NARROW: only ``_PROFILE_MANAGED_ENV_KEYS`` —
    behavioral routing keys (ACP auth method, copilot-ACP endpoints) that a
    parent Hermes process injects and that silently change *which provider
    path* a profile uses. Provider API keys (OPENAI_API_KEY, …) are
    intentionally excluded: users legitimately export those in their shell
    (``export OPENAI_API_KEY=…`` is a documented flow — see
    ``tests/hermes_cli/test_dump_env_visibility.py``), and a startup scrub
    cannot distinguish a shell export from parent-process leakage. Clearing
    the full known-key set would delete user-exported credentials on every
    ``hermes`` invocation.

    Cross-profile *credential* isolation is handled at read time by
    ``agent.secret_scope.get_secret`` (scope authoritative under
    multiplexing), not by mutating ``os.environ`` here.

    Does **not** run when the ``.env`` file does not exist (bare-profile
    case, which follows ``#66930`` / ``#67027`` semantics).
    """
    if not path.exists():
        return
    defined = _env_keys_defined_in_dotenv(path)
    for key in _PROFILE_MANAGED_ENV_KEYS:
        if key not in defined and key in os.environ:
            del os.environ[key]


def get_secret_source(env_var: str) -> str | None:
    """Return the label of the secret source that supplied ``env_var``, if any.

    Returns ``"bitwarden"`` for keys pulled from Bitwarden Secrets Manager
    during the current process's ``load_hermes_dotenv()`` call.  Returns
    ``None`` for keys that came from ``.env``, the shell environment, or
    aren't tracked.  The returned label is metadata only: credential-pool
    persistence may store it to explain the origin of a borrowed secret, but
    must never treat it as authorization to persist the raw value.
    """
    return _SECRET_SOURCES.get(env_var)


def get_secret_source_values(
    hermes_home: str | os.PathLike,
) -> dict[str, str]:
    """Return the external-secret value snapshot for ``hermes_home``."""
    home_key = str(Path(hermes_home).resolve())
    return dict(_SECRET_SOURCE_VALUES_BY_HOME.get(home_key, {}))


def hydrate_profile_secret_sources(
    hermes_home: str | os.PathLike,
) -> dict[str, str]:
    """Resolve one profile's configured sources without mutating ``os.environ``.

    Multiplex gateways can route a first turn to a secondary profile that has
    never run the process-global dotenv startup path.  Resolve that profile's
    sources against a private mapping seeded from its own ``.env`` and record
    the usual per-home snapshot for ``build_profile_secret_scope()``.

    Fail-open and once-per-home semantics intentionally mirror
    ``_apply_external_secret_sources``.  The returned mapping contains only
    values actually contributed by external sources, never the profile's
    plaintext ``.env`` entries.
    """
    with _SECRET_SOURCE_CACHE_LOCK:
        return _hydrate_profile_secret_sources(Path(hermes_home))


def _hydrate_profile_secret_sources(home: Path) -> dict[str, str]:
    """Locked implementation for :func:`hydrate_profile_secret_sources`."""
    home_key = str(home.resolve())
    if home_key in _APPLIED_HOMES:
        return get_secret_source_values(home)

    try:
        cfg = _load_secrets_config(home)
    except Exception:  # noqa: BLE001 — external sources must not block routing
        return {}
    if not cfg:
        return {}

    try:
        from agent.secret_scope import _is_global_env, load_env_file
        from agent.secret_sources.registry import apply_all

        local_env = {
            name: value
            for name, value in os.environ.items()
            if _is_global_env(name)
        }
        local_env.update(load_env_file(home / ".env"))
        # Mirror load_hermes_dotenv()'s .op.env bootstrap: the 1Password
        # service-account token lives in <home>/.op.env (gitignored), not
        # .env. Without seeding it here a cold profile configured for the
        # supported .op.env flow fails 1Password hydration (sweeper review
        # on #74549). .env values win — never override an existing key.
        op_env = home / ".op.env"
        if op_env.exists():
            for _name, _value in load_env_file(op_env).items():
                local_env.setdefault(_name, _value)
        local_env["HERMES_HOME"] = str(home)
        report = apply_all(cfg, home, environ=local_env)
    except Exception:  # noqa: BLE001 — preserve fail-open startup behavior
        return {}

    if not report.sources:
        return {}

    _APPLIED_HOMES.add(home_key)
    values: dict[str, str] = {}
    for name, applied in report.provenance.items():
        value = local_env.get(name)
        if value is None:
            continue
        _SECRET_SOURCES[name] = applied.source
        values[name] = value
    if values:
        _SECRET_SOURCE_VALUES_BY_HOME[home_key] = values
    return dict(values)


def reset_secret_source_cache() -> None:
    """Forget which HERMES_HOME paths have already had external secrets applied.

    The first call to ``_apply_external_secret_sources(home_path)`` in a
    process pulls from Bitwarden (or other configured backend), records the
    applied keys in ``_SECRET_SOURCES``, and remembers ``home_path`` so
    subsequent calls in the same process are no-ops.  Call this to force the
    next call to re-pull — useful for tests, and for long-running processes
    that want to refresh after a config change.
    """
    _APPLIED_HOMES.clear()
    _SECRET_SOURCES.clear()
    _SECRET_SOURCE_VALUES_BY_HOME.clear()


def format_secret_source_suffix(env_var: str) -> str:
    """Return a human-readable suffix like ``" (from Bitwarden)"`` or ``""``.

    Use this when printing a detected credential so the user can see where
    it came from.  Empty string when the credential came from ``.env`` or
    the shell — those are the implicit / "default" cases users already
    understand.
    """
    source = get_secret_source(env_var)
    if not source:
        return ""
    if source == "bitwarden":
        return " (from Bitwarden)"
    # Ask the registry for the source's human label (e.g. "1Password").
    # Fall back to the raw source name for labels the registry doesn't
    # know (stale provenance from an uninstalled plugin, tests).
    try:
        from agent.secret_sources.registry import get_source

        registered = get_source(source)
        if registered is not None and registered.label:
            return f" (from {registered.label})"
    except Exception:  # noqa: BLE001 — label lookup must never raise
        pass
    return f" (from {source})"


def _format_offending_chars(value: str, limit: int = 3) -> str:
    """Return a compact 'U+XXXX ('c'), ...' summary of non-ASCII codepoints."""
    seen: list[str] = []
    for ch in value:
        if ord(ch) > 127:
            label = f"U+{ord(ch):04X}"
            if ch.isprintable():
                label += f" ({ch!r})"
            if label not in seen:
                seen.append(label)
            if len(seen) >= limit:
                break
    return ", ".join(seen)


def _sanitize_loaded_credentials() -> None:
    """Strip non-ASCII characters from credential env vars in os.environ.

    Called after dotenv loads so the rest of the codebase never sees
    non-ASCII API keys.  Only touches env vars whose names end with
    known credential suffixes (``_API_KEY``, ``_TOKEN``, etc.).

    Emits a one-line warning to stderr when characters are stripped.
    Silent stripping would mask copy-paste corruption (Unicode lookalike
    glyphs from PDFs / rich-text editors, ZWSP from web pages) as opaque
    provider-side "invalid API key" errors (see #6843).
    """
    for key, value in list(os.environ.items()):
        if not any(key.endswith(suffix) for suffix in _CREDENTIAL_SUFFIXES):
            continue
        try:
            value.encode("ascii")
            continue
        except UnicodeEncodeError:
            pass
        cleaned = value.encode("ascii", errors="ignore").decode("ascii")
        os.environ[key] = cleaned
        if key in _WARNED_KEYS:
            continue
        _WARNED_KEYS.add(key)
        stripped = len(value) - len(cleaned)
        detail = _format_offending_chars(value) or "non-printable"
        print(
            f"  Warning: {key} contained {stripped} non-ASCII character"
            f"{'s' if stripped != 1 else ''} ({detail}) — stripped so the "
            f"key can be sent as an HTTP header.",
            file=sys.stderr,
        )
        print(
            "  This usually means the key was copy-pasted from a PDF, "
            "rich-text editor, or web page that substituted lookalike\n"
            "  Unicode glyphs for ASCII letters. If authentication fails "
            "(e.g. \"API key not valid\"), re-copy the key from the\n"
            "  provider's dashboard and run `hermes setup` (or edit the "
            ".env file in a plain-text editor).",
            file=sys.stderr,
        )


def _load_dotenv_with_fallback(path: Path, *, override: bool) -> None:
    locked_values = _gateway_launch_env_locked_values()
    if locked_values is not None:
        # Parse into a private mapping and apply only unlocked names. Calling
        # python-dotenv's load_dotenv() and restoring afterwards leaves a
        # process-global TOCTOU window where another gateway thread can spawn
        # a child with stale runtime roots. Filtering at ingestion keeps the
        # protected names immutable for the whole reload.
        try:
            parsed = dotenv_values(dotenv_path=path, encoding="utf-8-sig")
        except UnicodeDecodeError:
            raw = path.read_bytes()
            if raw.startswith(codecs.BOM_UTF8):
                raw = raw[len(codecs.BOM_UTF8) :]
            parsed = dotenv_values(stream=io.StringIO(raw.decode("latin-1")))
        for key, value in parsed.items():
            if key in locked_values or key == _GATEWAY_LAUNCH_ENV_LOCK_VAR:
                continue
            if value is not None and (override or key not in os.environ):
                os.environ[key] = value
        _sanitize_loaded_credentials()
        _latch_cron_dispatch_pause_if_engaged()
        return

    try:
        # utf-8-sig strips a leading UTF-8 BOM if present (PowerShell 5.1
        # Set-Content -Encoding UTF8 / Notepad) and is a no-op for BOM-less
        # UTF-8. Plain "utf-8" would keep U+FEFF on the first key name and
        # silently drop it from os.environ under its canonical name.
        load_dotenv(dotenv_path=path, override=override, encoding="utf-8-sig")
    except UnicodeDecodeError:
        # utf-8-sig can't strip a BOM once we fall back to latin-1 decode.
        raw = path.read_bytes()
        if raw.startswith(codecs.BOM_UTF8):
            raw = raw[len(codecs.BOM_UTF8) :]
        load_dotenv(stream=io.StringIO(raw.decode("latin-1")), override=override)
    # Strip non-ASCII characters from credential env vars that were just
    # loaded.  API keys must be pure ASCII since they're sent as HTTP
    # header values (httpx encodes headers as ASCII).  Non-ASCII chars
    # typically come from copy-pasting keys from PDFs or rich-text editors
    # that substitute Unicode lookalike glyphs (e.g. ʋ U+028B for v).
    _sanitize_loaded_credentials()
    _latch_cron_dispatch_pause_if_engaged()


def _latch_cron_dispatch_pause_if_engaged() -> None:
    """Make a true migration quarantine monotonic across later env reloads."""
    value = os.getenv("HERMES_CRON_PAUSED", "")
    if value.strip().casefold() in {"", "0", "false", "no", "off"}:
        return
    try:
        # Lazy import avoids pulling the scheduler store into ordinary CLI
        # bootstrap unless the emergency switch is actually engaged.
        from cron.jobs import is_cron_dispatch_paused

        is_cron_dispatch_paused()
    except ImportError:
        # An unusually early import cycle will still be caught at the first
        # dispatch boundary, which calls the same predicate directly.
        return


def _sanitize_env_file_if_needed(path: Path) -> None:
    """Pre-sanitize a .env file before python-dotenv reads it.

    Strips embedded null bytes which crash ``os.environ[k] = v``
    with ``ValueError: embedded null byte`` — typically introduced by
    copy-pasting API keys from terminals or rich-text editors.

    Encoding: sniffs a leading BOM *before* any text decode. UTF-16
    (Notepad "Unicode") is decoded correctly and rewritten as clean
    UTF-8. UTF-32 is refused (left untouched) so we never fall through
    to the errors=replace corruption path. Order of BOM checks matters:
    UTF-32-LE's BOM starts with UTF-16-LE's FF FE.

    ``hermes_cli.config._sanitize_env_lines`` normalizes line endings while
    treating content after the first ``=`` as opaque for boundary discovery.
    """
    if not path.exists():
        return
    try:
        from hermes_cli.config import _sanitize_env_lines
    except ImportError:
        return  # early bootstrap — config module not available yet

    try:
        raw = path.read_bytes()
    except Exception:
        return

    # Sniff leading BOM bytes BEFORE decoding. ORDER MATTERS:
    # codecs.BOM_UTF32_LE is FF FE 00 00, which startswith
    # codecs.BOM_UTF16_LE (FF FE). Checking UTF-16 first would
    # misdetect UTF-32-LE as UTF-16-LE and mangle the file.
    force_utf8_rewrite = False
    if raw.startswith(codecs.BOM_UTF32_LE) or raw.startswith(codecs.BOM_UTF32_BE):
        # Lazy import keeps the module import block identical to #65124's
        # codecs/io additions so the two PRs auto-merge either order.
        path_key = str(path.resolve())
        if path_key not in _WARNED_UTF32_PATHS:
            _WARNED_UTF32_PATHS.add(path_key)
            import logging

            logging.getLogger(__name__).warning(
                "Skipping .env sanitize for %s: UTF-32 BOM detected; "
                "leaving file untouched to avoid corruption",
                path,
            )
        return
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        # "utf-16" uses the BOM to select endianness and strips it.
        # TextIOWrapper + newline=None matches open()'s universal-newlines
        # line splitting (\\n/\\r\\n/\\r only — not splitlines()'s extra
        # Unicode boundaries like U+2028), so sanitize sees the same lines
        # as the UTF-8 path.
        try:
            with io.TextIOWrapper(
                io.BytesIO(raw), encoding="utf-16", newline=None
            ) as f:
                original = f.readlines()
        except UnicodeDecodeError:
            return
        # Source is UTF-16 on disk; always rewrite as clean UTF-8 so
        # the subsequent utf-8 dotenv load sees a canonical file.
        force_utf8_rewrite = True
    else:
        # Default path: utf-8-sig (strips UTF-8 BOM if present) with
        # errors=replace so embedded NULs can be stripped below.
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as f:
                original = f.readlines()
        except Exception:
            return
        # Defense-in-depth: errors=replace turns undecodable leading
        # bytes into U+FFFD. Persisting that glues replacement chars
        # onto the first key name and rewrites the file permanently
        # (the UTF-16-with-BOM corruption path before BOM sniffing).
        # Leave the file untouched rather than write the mangling.
        if original and original[0].startswith("\ufffd"):
            return

    try:
        # Strip null bytes before _sanitize_env_lines so they never
        # reach python-dotenv (which passes them to os.environ and
        # crashes with ValueError). Also intentionally repairs
        # BOM-less UTF-16 (NUL-padded ASCII) into clean UTF-8.
        stripped = [line.replace("\x00", "") for line in original]
        sanitized = _sanitize_env_lines(stripped)
        if sanitized != original or force_utf8_rewrite:
            import tempfile
            fd, tmp = tempfile.mkstemp(
                dir=str(path.parent), suffix=".tmp", prefix=".env_"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.writelines(sanitized)
                    f.flush()
                    os.fsync(f.fileno())
                atomic_replace(tmp, path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
    except Exception:
        pass  # best-effort — don't block gateway startup


def load_hermes_dotenv(
    *,
    hermes_home: str | os.PathLike | None = None,
    project_env: str | os.PathLike | None = None,
    load_external_secrets: bool = True,
) -> list[Path]:
    """Load Hermes environment files with user config taking precedence.

    Behavior:
    - `~/.hermes/.env` overrides stale shell-exported values when present.
    - project `.env` acts as a dev fallback and only fills missing values when
      the user env exists.
    - if no user env exists, the project `.env` also overrides stale shell vars.
    - callers that only maintain the installation can set
      ``load_external_secrets=False`` to avoid loading optional secret-manager
      dependencies into the process that replaces that same environment.
    """
    # Observe an OS/launcher-injected quarantine before the first
    # override=True dotenv source gets any opportunity to replace it.
    _latch_cron_dispatch_pause_if_engaged()
    _capture_gateway_launch_env_lock()
    _reapply_gateway_launch_env_lock()
    loaded: list[Path] = []

    home_path = Path(hermes_home or os.getenv("HERMES_HOME", Path.home() / ".hermes"))
    user_env = home_path / ".env"
    project_env_path = Path(project_env) if project_env else None

    # Normalize safe formatting and remove invalid NUL bytes before parsing.
    if user_env.exists():
        _sanitize_env_file_if_needed(user_env)
    if project_env_path and project_env_path.exists():
        _sanitize_env_file_if_needed(project_env_path)

    if user_env.exists():
        try:
            _load_dotenv_with_fallback(user_env, override=True)
        finally:
            _reapply_gateway_launch_env_lock()
        loaded.append(user_env)
        # Mirror reload_env() known-key cleanup so inherited Hermes keys
        # absent from this profile's .env do not leak into the runtime.
        _clear_known_keys_missing_from_dotenv(user_env)

    # Load .op.env AFTER .env so that .env values win, but the bootstrap
    # token (OP_SERVICE_ACCOUNT_TOKEN) becomes available for
    # apply_onepassword_secrets() even in cron / subprocess environments
    # that inherit no shell state (no systemd EnvironmentFile, no op run).
    # .op.env is gitignored — the service-account token never enters the
    # committed .env file.
    # Users on systemd can alternatively use:
    #   EnvironmentFile=-/path/to/.hermes/.op.env
    # in their gateway unit, which takes precedence (override=False below
    # ensures .op.env never clobbers a token already in the environment).
    op_env = home_path / ".op.env"
    if op_env.exists() and not os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
        try:
            _load_dotenv_with_fallback(op_env, override=False)
        finally:
            _reapply_gateway_launch_env_lock()

    if project_env_path and project_env_path.exists():
        try:
            _load_dotenv_with_fallback(project_env_path, override=not loaded)
        finally:
            _reapply_gateway_launch_env_lock()
        loaded.append(project_env_path)

    # A managed gateway must prove its exact receipt + complete manifest +
    # Scheduled Task evidence after all local dotenv inputs have been applied,
    # but before external secret providers (which may perform network I/O) or
    # any gateway ticker can start. The validator is process-once; later
    # per-turn dotenv reloads only re-apply the already-proven launch lock.
    _run_gateway_start_validator_if_needed()

    # External secret sources are skipped in two updater situations:
    # 1. ``load_external_secrets=False`` — the caller is an ``update``
    #    invocation that must not import optional secret-manager libraries
    #    (Bitwarden → cryptography → ``_rust.pyd``) into the process that
    #    replaces that same environment on Windows (#73381, #86735).
    # 2. A fresh ``hermes update`` retry just completed a deferred dependency
    #    install before importing this module.  Do not remap native
    #    secret-source dependencies in that same updater process or the
    #    self-lock preflight will recreate the marker and exit 2 again.
    # Dotenv and managed env still load in both cases; only external source
    # resolution is unnecessary for the updater.
    from hermes_cli import _early_recovery

    if load_external_secrets and not _early_recovery._should_skip_external_secret_sources():
        try:
            _apply_external_secret_sources(home_path)
        finally:
            _latch_cron_dispatch_pause_if_engaged()
            _reapply_gateway_launch_env_lock()
    try:
        _apply_managed_env()
    finally:
        _latch_cron_dispatch_pause_if_engaged()
        _reapply_gateway_launch_env_lock()

    # config.yaml is the documented source of truth for terminal.* settings,
    # but the dotenv loads above run with override=True — so a stale
    # TERMINAL_ENV=docker left in ~/.hermes/.env (e.g. written by an older
    # `hermes setup` before the user switched terminal.backend in config.yaml)
    # silently wins again on every reload. Startup launchers bridge
    # config→env once, but long-lived processes (gateway per-turn reload,
    # cron standalone runs) call load_hermes_dotenv() repeatedly and used to
    # flip the effective backend back to the stale .env value mid-session
    # (#29186, #67323). Re-apply config.yaml's explicit terminal keys last so
    # the documented config path always wins. Runs after _apply_managed_env()
    # so the merged config (which already carries the managed overlay) is
    # what lands in the env.
    try:
        _reapply_terminal_config_bridge(home_path)
    finally:
        _reapply_gateway_launch_env_lock()

    return loaded


def _reapply_terminal_config_bridge(home_path: Path) -> None:
    """Re-assert config.yaml's explicit ``terminal.*`` keys over reloaded .env.

    Delegates to ``hermes_cli.config.apply_terminal_config_to_env`` — the
    single shared bridge (same one terminal_tool's fallback and the TUI/
    dashboard launchers use) — so key coverage, explicit-keys-only override
    semantics, cwd placeholder handling, and the managed-scope overlay can't
    drift from the other bridge sites. Only keys the user actually wrote in
    config.yaml's ``terminal`` section override env values; a config.yaml
    without a terminal section leaves .env/shell selections untouched.

    Scoped to the process HERMES_HOME: the shared bridge reads the
    process-global config, so re-applying it for a *different* profile's
    ``load_hermes_dotenv(hermes_home=...)`` call would bridge the wrong
    profile's config. Fail-open — a config problem must never break dotenv
    loading (the historical env-driven behavior still applies).
    """
    try:
        if Path(home_path).resolve() != _process_hermes_home().resolve():
            return
        from hermes_cli.config import apply_terminal_config_to_env

        apply_terminal_config_to_env(env=None)
    except Exception:  # noqa: BLE001 — early bootstrap / malformed config
        pass


def _apply_managed_env() -> None:
    """Apply the managed-scope .env last, with override, so it beats user/shell.

    Managed scope is machine-global (independent of HERMES_HOME / profile). v1
    enforcement is "applied last with override=True" — at the end of startup load
    ``os.environ`` holds the managed value for every managed key, beating both the
    user ``.env`` and any pre-existing shell export. This deliberately inverts the
    usual env-over-config precedence for the pinned keys (see
    ``docs/design/managed-scope.md`` §4.1).

    This does NOT prevent the agent from later mutating ``os.environ`` in-process
    or ``export``-ing in a subprocess shell; that hard boundary is a documented
    v2 item (design §8.1). v1 relies on filesystem permissions only.

    Fail-open: a missing managed dir or .env is the common case and a no-op; any
    error here is swallowed so managed scope can never block startup.
    """
    try:
        from hermes_cli import managed_scope

        managed_dir = managed_scope.get_managed_dir()
    except Exception:  # noqa: BLE001 — managed scope must never block startup
        return
    if managed_dir is None:
        return
    managed_env = managed_dir / ".env"
    if not managed_env.exists():
        return
    _sanitize_env_file_if_needed(managed_env)
    _load_dotenv_with_fallback(managed_env, override=True)


def _apply_external_secret_sources(home_path: Path) -> None:
    """Pull secrets from every enabled external source into env.

    Runs AFTER dotenv loads so .env values are visible (sources use them
    to locate bootstrap tokens) but BEFORE the rest of Hermes reads
    ``os.environ`` for credentials.  Any failure here is logged and
    swallowed — external secret sources must never block startup.

    The heavy lifting (source ordering, mapped-beats-bulk precedence,
    first-claim-wins conflict handling, override semantics, provenance)
    lives in ``agent.secret_sources.registry.apply_all``; this wrapper
    owns the once-per-HERMES_HOME guard, the post-apply ASCII
    sanitization sweep, the ``_SECRET_SOURCES`` provenance map that
    UI surfaces read, and the startup status lines.

    Idempotent within a process: subsequent calls for the same
    ``home_path`` are no-ops.  ``load_hermes_dotenv()`` runs at import
    time from several hot modules (cli.py, hermes_cli/main.py,
    run_agent.py, trajectory_compressor.py, ...), so without this guard
    the status lines would print 3-5x per CLI startup.  Use
    ``reset_secret_source_cache()`` if you need to force a re-pull
    (tests, long-running processes after a config change).
    """
    home_key = str(Path(home_path).resolve())
    if home_key in _APPLIED_HOMES:
        return

    try:
        cfg = _load_secrets_config(home_path)
    except Exception:  # noqa: BLE001 — config errors must not block startup
        # Deliberately NOT marked applied: a malformed config.yaml would
        # otherwise permanently disable secret loading for this process
        # even after the user fixes the file (#40597).
        return
    if not cfg:
        # No secrets section (or everything disabled at parse level).  Not
        # marked applied either — the re-parse is a cheap fast_safe_load and
        # leaving the home unmarked lets a process pick up a config change
        # on its next load_hermes_dotenv() call instead of never.
        return

    # Defer the registry import until we know a secrets source is enabled —
    # agent.secret_sources.bitwarden eagerly loads cryptography._rust.pyd,
    # which causes the Windows updater to self-lock before its preflight
    # (the updater itself maps the .pyd before the dependency sync runs).
    # A config with no enabled sources costs one dict scan; a config with
    # enabled sources pays the crypto load exactly once, on demand.
    # NOTE: only keys that smell like a real secret source trigger the import —
    # a generic dict entry must not force crypto load on every hermes launch.
    # We whitelist by *shape* (source dict with enabled flag) rather than
    # hardcoding names, so plugin/test sources pass through unknown keys.
    any_enabled = any(
        isinstance(v, dict) and v.get("enabled") is True
        for v in cfg.values()
    )
    if not any_enabled:
        return

    try:
        from agent.secret_sources.registry import apply_all
    except ImportError:
        return

    locked_values = _gateway_launch_env_locked_values()
    source_environ: dict[str, str] | None = None
    source_baseline: dict[str, str] | None = None
    if locked_values is not None:
        # Secret-source plugins can target arbitrary env names. Apply them to
        # a private copy, then merge only unlocked keys so a misconfigured
        # mapping cannot transiently replace launcher provenance in another
        # gateway thread.
        source_baseline = dict(os.environ)
        source_environ = dict(source_baseline)

    try:
        report = apply_all(cfg, home_path, environ=source_environ)
    except Exception:  # noqa: BLE001 — belt-and-braces; apply_all shouldn't raise
        _latch_cron_dispatch_pause_if_engaged()
        return

    if source_environ is not None:
        for key, value in source_environ.items():
            if key in locked_values or key == _GATEWAY_LAUNCH_ENV_LOCK_VAR:
                continue
            if source_baseline is not None and source_baseline.get(key) == value:
                continue
            os.environ[key] = value
    _latch_cron_dispatch_pause_if_engaged()

    if not report.sources:
        # Config parsed but no source is enabled: keep retrying cheaply
        # (no fetch happens for disabled sources) so flipping a source on
        # mid-process takes effect on the next call.
        return

    # A real fetch attempt happened (success OR error).  Mark the home now
    # so the 3-5 import-time load_hermes_dotenv() calls per startup don't
    # re-fetch / re-print — error retries within one process are opt-in via
    # reset_secret_source_cache().  Marking AFTER the attempt (not before,
    # see #40597) is what lets the earlier failure paths stay retryable.
    _APPLIED_HOMES.add(home_key)

    if report.applied_any:
        # Re-run the ASCII sanitization pass: vault values are
        # user-supplied and might have the same copy-paste corruption as
        # a manually edited .env (see #6843).
        _sanitize_loaded_credentials()
        # Remember where each var came from so setup / `hermes model`
        # flows can label detected credentials with "(from Bitwarden)" /
        # "(from 1Password)" — otherwise users see "credentials ✓" with
        # no hint the value came from a vault rather than .env.
        values: dict[str, str] = {}
        for name, applied in report.provenance.items():
            _SECRET_SOURCES[name] = applied.source
            effective_environ = source_environ or os.environ
            if name in effective_environ and name not in (locked_values or {}):
                values[name] = effective_environ[name]
        _SECRET_SOURCE_VALUES_BY_HOME[home_key] = values

    for src in report.sources:
        if src.applied:
            print(
                f"  {src.label}: applied {len(src.applied)} "
                f"secret{'s' if len(src.applied) != 1 else ''}",
                file=sys.stderr,
            )
        if src.result.error:
            print(f"  {src.label}: {src.result.error}", file=sys.stderr)
            hint = _remediation_hint(
                src.name, src.result.error_kind, cfg, scope=home_key
            )
            if hint:
                print(f"  {src.label}: → {hint}", file=sys.stderr)
        for warn in src.result.warnings:
            print(f"  {src.label}: {warn}", file=sys.stderr)
    for conflict in report.conflicts:
        print(f"  Secret sources: {conflict}", file=sys.stderr)


def _remediation_hint(
    source_name: str,
    error_kind,
    secrets_cfg: dict,
    *,
    scope: str | None = None,
) -> str:
    """Ask the failed source for its one-line fix-it hint.

    Defensive wrapper: remediation() is a pure mapping and shouldn't
    raise, but a plugin source could — and startup must never break on
    a status line.
    """
    try:
        from agent.secret_sources.registry import get_source

        source = get_source(source_name, scope=scope)
        if source is None:
            return ""
        src_cfg = secrets_cfg.get(source_name)
        src_cfg = src_cfg if isinstance(src_cfg, dict) else {}
        return str(source.remediation(error_kind, src_cfg) or "").strip()
    except Exception:  # noqa: BLE001 — hints must never block startup
        return ""


def _load_secrets_config(home_path: Path) -> dict:
    """Read just the ``secrets:`` section out of config.yaml.

    Imported lazily and isolated from the main config loader so a
    malformed config can't take down dotenv loading entirely.
    """
    config_path = home_path / "config.yaml"
    if not config_path.exists():
        return {}
    # Prefer the shared (mtime, size)-keyed raw-config cache — this is the
    # first config.yaml read in a normal `hermes` startup, so populating the
    # shared cache here lets main.py's early bridge and hermes_logging reuse
    # the same parse (one parse per process instead of 3-4). Falls back to a
    # direct isolated parse if the shared reader is unavailable, preserving
    # the "malformed config can't take down dotenv loading" property (the
    # shared reader also swallows parse errors and returns {}).
    if home_path == _process_hermes_home():
        try:
            from hermes_cli.config import read_raw_config

            data = read_raw_config() or {}
            return data.get("secrets") or {}
        except Exception:
            pass
    try:
        import yaml  # type: ignore
    except ImportError:
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = fast_safe_load(f) or {}
    except Exception:  # noqa: BLE001
        return {}
    return data.get("secrets") or {}


def _process_hermes_home() -> Path:
    """The HERMES_HOME the shared config cache is keyed to."""
    try:
        from hermes_constants import get_hermes_home

        return get_hermes_home()
    except Exception:
        return Path.home() / ".hermes"
