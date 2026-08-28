import base64
import codecs
import importlib
import json
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli.env_loader import load_hermes_dotenv


@pytest.fixture(autouse=True)
def reset_cron_pause_latch():
    import cron.jobs as jobs

    jobs._reset_cron_dispatch_pause_latch_for_tests()
    yield
    jobs._reset_cron_dispatch_pause_latch_for_tests()


def test_recovered_update_retry_skips_external_secret_sources(tmp_path, monkeypatch):
    """The post-recovery updater must not remap native vault dependencies."""
    import hermes_cli.env_loader as env_loader
    from hermes_cli import _early_recovery

    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    env_file.write_text("UPDATE_RETRY_DOTENV=loaded\n", encoding="utf-8")
    monkeypatch.delenv("UPDATE_RETRY_DOTENV", raising=False)
    monkeypatch.setattr(_early_recovery, "_UPDATE_RETRY_RECOVERED", True)
    external_calls = []
    monkeypatch.setattr(
        env_loader,
        "_apply_external_secret_sources",
        lambda path: external_calls.append(path),
    )

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.environ["UPDATE_RETRY_DOTENV"] == "loaded"
    assert external_calls == []


def test_utf8_bom_does_not_mangle_first_key(tmp_path, monkeypatch):
    """A leading UTF-8 BOM must not prefix the first key name in os.environ.

    PowerShell 5.1 ``Set-Content -Encoding UTF8`` and Windows Notepad write
    a BOM (EF BB BF). With encoding=utf-8, python-dotenv keeps U+FEFF on the
    first key so the canonical name is absent and callers see "not configured".
    """
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    env_file.write_bytes(
        b"\xef\xbb\xbfFIRST_KEY=first-value\nSECOND_KEY=second-value\n"
    )

    monkeypatch.delenv("FIRST_KEY", raising=False)
    monkeypatch.delenv("SECOND_KEY", raising=False)
    monkeypatch.delenv("\ufeffFIRST_KEY", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("FIRST_KEY") == "first-value"
    assert os.getenv("SECOND_KEY") == "second-value"
    assert os.environ.get("\ufeffFIRST_KEY") is None


def test_bomless_utf8_env_still_loads(tmp_path, monkeypatch):
    """BOM-less UTF-8 .env files must keep loading after utf-8-sig."""
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    env_file.write_text("OPENAI_API_KEY=sk-plain\nSECOND_KEY=ok\n", encoding="utf-8")

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SECOND_KEY", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("OPENAI_API_KEY") == "sk-plain"
    assert os.getenv("SECOND_KEY") == "ok"


def test_latin1_env_falls_back(tmp_path, monkeypatch):
    """Invalid UTF-8 bytes must still load via the latin-1 fallback."""
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    # 0xE9 is "é" in latin-1 and not a valid UTF-8 lead sequence alone.
    env_file.write_bytes(b"LATIN1_VALUE=caf\xe9\n")

    monkeypatch.delenv("LATIN1_VALUE", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("LATIN1_VALUE") == "café"


def test_utf8_bom_preserves_first_api_key_name(tmp_path, monkeypatch):
    """Real-world case: BOM + first line is a provider API key name."""
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    env_file.write_bytes(
        b"\xef\xbb\xbfANTHROPIC_API_KEY=sk-test-123\nSECOND_KEY=ok\n"
    )

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SECOND_KEY", raising=False)
    monkeypatch.delenv("\ufeffANTHROPIC_API_KEY", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("ANTHROPIC_API_KEY") == "sk-test-123"
    assert os.getenv("SECOND_KEY") == "ok"
    assert os.environ.get("\ufeffANTHROPIC_API_KEY") is None


def test_utf8_bom_plus_invalid_utf8_preserves_first_key(tmp_path, monkeypatch):
    """BOM + non-UTF-8 body must load via latin-1 without mangling the first key.

    utf-8-sig only applies on the primary path. When invalid UTF-8 forces the
    latin-1 fallback, a leading EF BB BF would otherwise become part of the
    first key name under latin-1 and drop the canonical name.
    """
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    # BOM + valid first key + latin-1 é (0xE9) in a later value.
    env_file.write_bytes(
        b"\xef\xbb\xbfANTHROPIC_API_KEY=sk-test-123\nBAD=caf\xe9\n"
    )

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("BAD", raising=False)
    monkeypatch.delenv("\ufeffANTHROPIC_API_KEY", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("ANTHROPIC_API_KEY") == "sk-test-123"
    assert os.getenv("BAD") == "café"
    assert os.environ.get("\ufeffANTHROPIC_API_KEY") is None

def test_bomless_latin1_env_still_loads(tmp_path, monkeypatch):
    """BOM-less cp1252/latin-1 .env files must keep loading after the BOM strip."""
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    env_file.write_bytes(b"LATIN1_VALUE=caf\xe9\nOTHER=ok\n")

    monkeypatch.delenv("LATIN1_VALUE", raising=False)
    monkeypatch.delenv("OTHER", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("LATIN1_VALUE") == "café"
    assert os.getenv("OTHER") == "ok"

def test_latin1_fallback_stream_honors_override(tmp_path, monkeypatch):
    """Stream-based latin-1 fallback must honor override= identically to dotenv_path."""
    from hermes_cli.env_loader import _load_dotenv_with_fallback

    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    # Invalid UTF-8 forces the stream/latin-1 path.
    env_file.write_bytes(b"OVERRIDE_PROBE=from-file\nLATIN1_VALUE=caf\xe9\n")

    monkeypatch.setenv("OVERRIDE_PROBE", "from-shell")
    monkeypatch.delenv("LATIN1_VALUE", raising=False)

    # override=False: shell value must win (same as dotenv_path form).
    _load_dotenv_with_fallback(env_file, override=False)
    assert os.getenv("OVERRIDE_PROBE") == "from-shell"
    assert os.getenv("LATIN1_VALUE") == "café"

    # override=True: file value must win (user-env path).
    _load_dotenv_with_fallback(env_file, override=True)
    assert os.getenv("OVERRIDE_PROBE") == "from-file"
    assert os.getenv("LATIN1_VALUE") == "café"

def test_latin1_fallback_stream_preserves_interpolation(tmp_path, monkeypatch):
    """Stream/latin-1 path must still expand ${VAR} like the dotenv_path form."""
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    # 0xE9 forces latin-1 fallback; ${FOO} must still expand.
    env_file.write_bytes(b"FOO=bar\nBAR=${FOO}\nLATIN1_VALUE=caf\xe9\n")

    monkeypatch.delenv("FOO", raising=False)
    monkeypatch.delenv("BAR", raising=False)
    monkeypatch.delenv("LATIN1_VALUE", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("FOO") == "bar"
    assert os.getenv("BAR") == "bar"
    assert os.getenv("LATIN1_VALUE") == "café"

# ---------------------------------------------------------------------------
# UTF-16 / UTF-32 .env sanitizer coverage
#
# UTF-8 BOM handling for _load_dotenv_with_fallback is covered above (#65124).
# This section covers the sanitizer rewrite path for UTF-16/32 (and UTF-8 /
# cp1252 regression guards for that path).
# ---------------------------------------------------------------------------


def _assert_clean_utf8_env_on_disk(env_file, *, first_key: str) -> None:
    """On-disk file must be clean UTF-8: no BOM, no U+FFFD, canonical key."""
    after = env_file.read_bytes()
    assert not after.startswith(codecs.BOM_UTF8)
    assert not after.startswith(codecs.BOM_UTF16_LE)
    assert not after.startswith(codecs.BOM_UTF16_BE)
    text = after.decode("utf-8")  # strict — raises if not clean UTF-8
    assert "\ufffd" not in text
    assert text.startswith(f"{first_key}=") or f"\n{first_key}=" in text
    assert first_key.encode("ascii") in after




def test_utf16_le_bom_preserves_non_ascii_values(tmp_path, monkeypatch):
    """UTF-16-LE+BOM rewrite must preserve non-ASCII values (not just ASCII keys).

    Uses non-credential var names so _sanitize_loaded_credentials does not
    strip non-ASCII from values (that path only targets *_KEY/*_TOKEN/etc.).
    """
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    content = "GREETING=café\nCJK_LABEL=日本語\n"
    env_file.write_bytes(codecs.BOM_UTF16_LE + content.encode("utf-16-le"))

    monkeypatch.delenv("GREETING", raising=False)
    monkeypatch.delenv("CJK_LABEL", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("GREETING") == "café"
    assert os.getenv("CJK_LABEL") == "日本語"
    after = env_file.read_bytes()
    assert after.decode("utf-8")  # strict
    assert "café".encode("utf-8") in after
    assert "日本語".encode("utf-8") in after
    assert b"\xef\xbf\xbd" not in after


def test_utf32_le_bom_leaves_file_untouched(tmp_path, caplog):
    """UTF-32-LE BOM: refuse-to-mangle (leave bytes untouched + warning).

    UTF-32-LE's BOM starts with UTF-16-LE's FF FE; sniff order must check
    UTF-32 first so we never misdetect and corrupt.

    Exercises ``_sanitize_env_file_if_needed`` only: the dotenv load path
    is out of scope here (#65124's surface) and still cannot ingest UTF-32.
    """
    import logging

    from hermes_cli.env_loader import _sanitize_env_file_if_needed

    env_file = tmp_path / ".env"
    content = "HERMES_TEST_KEY=hello_utf32\nSECOND_KEY=world\n"
    raw = codecs.BOM_UTF32_LE + content.encode("utf-32-le")
    env_file.write_bytes(raw)

    with caplog.at_level(logging.WARNING, logger="hermes_cli.env_loader"):
        _sanitize_env_file_if_needed(env_file)

    assert env_file.read_bytes() == raw  # untouched
    assert any("UTF-32" in r.message for r in caplog.records)




def test_utf32_warning_fires_once_per_path(tmp_path, caplog, monkeypatch):
    """Three sanitize calls on the same UTF-32 file → exactly one warning.

    Matches house style for warn-once (module-level seen-set, same class as
    ``_WARNED_KEYS``): hot-reload / multi-entry load must not spam logs.
    """
    import logging

    import hermes_cli.env_loader as env_loader
    from hermes_cli.env_loader import _sanitize_env_file_if_needed

    # Isolate process-level seen-set so other tests' paths don't leak in.
    monkeypatch.setattr(env_loader, "_WARNED_UTF32_PATHS", set())

    env_file = tmp_path / ".env"
    content = "HERMES_TEST_KEY=hello_utf32\nSECOND_KEY=world\n"
    raw = codecs.BOM_UTF32_LE + content.encode("utf-32-le")
    env_file.write_bytes(raw)

    with caplog.at_level(logging.WARNING, logger="hermes_cli.env_loader"):
        _sanitize_env_file_if_needed(env_file)
        _sanitize_env_file_if_needed(env_file)
        _sanitize_env_file_if_needed(env_file)

    utf32_warnings = [r for r in caplog.records if "UTF-32" in r.message]
    assert len(utf32_warnings) == 1
    assert env_file.read_bytes() == raw




def test_plain_utf8_env_regression(tmp_path, monkeypatch):
    """Plain UTF-8 .env must keep loading after the UTF-16 sanitize changes."""
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    before = b"OPENAI_API_KEY=sk-plain\nSECOND_KEY=ok\n"
    env_file.write_bytes(before)

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SECOND_KEY", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("OPENAI_API_KEY") == "sk-plain"
    assert os.getenv("SECOND_KEY") == "ok"
    # No spurious rewrite of an already-clean file.
    assert env_file.read_bytes() == before


def test_cp1252_env_regression_does_not_crash(tmp_path, monkeypatch):
    """cp1252/latin-1 body must not crash sanitize; ASCII keys still usable.

    0xE9 is 'é' in cp1252 and incomplete as UTF-8. First line does not begin
    with U+FFFD, so the FFFD guard must not refuse the whole file.

    Sanitize leaves the file bytes alone when the only "change" is
    errors=replace on values (original already replace-decoded equals
    sanitized), so _load_dotenv_with_fallback's latin-1 path recovers café.
    """
    home = tmp_path / "hermes"
    home.mkdir()
    env_file = home / ".env"
    before = b"ASCII_KEY=ok\nLATIN1_VALUE=caf\xe9\n"
    env_file.write_bytes(before)

    monkeypatch.delenv("ASCII_KEY", raising=False)
    monkeypatch.delenv("LATIN1_VALUE", raising=False)

    loaded = load_hermes_dotenv(hermes_home=home)

    assert loaded == [env_file]
    assert os.getenv("ASCII_KEY") == "ok"
    assert os.getenv("LATIN1_VALUE") == "café"
    # Sanitize must not have rewritten (would have persisted U+FFFD).
    assert env_file.read_bytes() == before


# ---------------------------------------------------------------------------
# Detached gateway launch provenance lock
# ---------------------------------------------------------------------------


def _reset_gateway_launch_env_lock(monkeypatch):
    import hermes_cli.env_loader as env_loader

    monkeypatch.setattr(
        env_loader, "_GATEWAY_LAUNCH_ENV_CAPTURE_ATTEMPTED", False
    )
    monkeypatch.setattr(env_loader, "_GATEWAY_LAUNCH_ENV_STATE", None)
    monkeypatch.setattr(env_loader, "_GATEWAY_LAUNCH_ENV_ERROR", None)
    monkeypatch.setattr(
        env_loader, "_GATEWAY_START_VALIDATOR_ATTEMPTED", False
    )
    monkeypatch.setattr(env_loader, "_GATEWAY_START_VALIDATOR_ERROR", None)
    monkeypatch.setattr(env_loader, "_GATEWAY_START_PROVENANCE", None)
    monkeypatch.delenv(env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR, raising=False)
    return env_loader


def _managed_gateway_lock_values(env_loader, home: Path, cwd: Path) -> dict[str, str]:
    runtime_path = r"C:\Reviewed\venv\Scripts;C:\Windows\System32"
    return {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(cwd),
        "PYTHONPATH": str(Path(env_loader.__file__).resolve().parent.parent),
        "VIRTUAL_ENV": str(home / "venv"),
        "HERMES_GATEWAY_RUNTIME_PATH": runtime_path,
        "PATH": runtime_path,
        "HERMES_GATEWAY_START_VALIDATOR": str(Path(sys.executable).resolve()),
        "HERMES_GATEWAY_START_VALIDATOR_ARGS": (
            env_loader._encode_gateway_start_validator_args(["validate-start"])
        ),
    }


def test_managed_gateway_lock_requires_complete_v3_validator_provenance(tmp_path):
    import hermes_cli.env_loader as env_loader

    home = tmp_path / "home"
    cwd = tmp_path / "reviewed"
    values = _managed_gateway_lock_values(env_loader, home, cwd)
    for missing in env_loader._GATEWAY_MANAGED_PROVENANCE_ENV_KEYS:
        incomplete = dict(values)
        incomplete.pop(missing)
        with pytest.raises(ValueError, match=missing):
            env_loader._encode_gateway_launch_env_lock(incomplete, cwd)

    encoded = env_loader._encode_gateway_launch_env_lock(values, cwd)
    decoded, decoded_cwd = env_loader._decode_gateway_launch_env_lock(encoded)
    assert decoded == values
    assert decoded_cwd == str(cwd)


def test_managed_gateway_runtime_requires_validator_confirmed_v3_state(
    tmp_path, monkeypatch
):
    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    home = tmp_path / "home"
    cwd = tmp_path / "reviewed"
    values = _managed_gateway_lock_values(env_loader, home, cwd)
    for key, value in values.items():
        monkeypatch.setenv(key, value)

    with pytest.raises(RuntimeError, match="without validator-confirmed"):
        env_loader._assert_gateway_start_provenance_if_managed()

    monkeypatch.setattr(
        env_loader,
        "_GATEWAY_LAUNCH_ENV_STATE",
        (values, str(cwd)),
    )
    with pytest.raises(RuntimeError, match="without validator-confirmed"):
        env_loader._assert_gateway_start_provenance_if_managed()

    provenance = {
        "version": 1,
        "receiptDigest": f"sha256:{'1' * 64}",
        "manifestDigest": f"sha256:{'2' * 64}",
        "taskEvidenceDigest": f"sha256:{'3' * 64}",
    }
    monkeypatch.setattr(env_loader, "_GATEWAY_START_PROVENANCE", provenance)
    monkeypatch.setattr(env_loader, "_run_gateway_start_validator_fresh", lambda: None)
    env_loader._assert_gateway_start_provenance_if_managed()


def test_checkout_detected_managed_gateway_cannot_downgrade_by_unsetting_public_vars(
    tmp_path, monkeypatch
):
    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    for key in (
        "HERMES_GATEWAY_RUNTIME_PATH",
        "HERMES_GATEWAY_START_VALIDATOR",
        "HERMES_GATEWAY_START_VALIDATOR_ARGS",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(env_loader, "_managed_install_root", lambda: tmp_path)

    with pytest.raises(RuntimeError, match="without validator-confirmed"):
        env_loader._assert_gateway_start_provenance_if_managed()


def test_managed_launch_rejects_caller_selected_validator_and_decoy_home(
    tmp_path,
):
    import hermes_cli.env_loader as env_loader

    root = tmp_path / "reviewed"
    agent_root = root / "hermes-agent"
    home = root / "home"
    bun = root / "tools" / "bun.exe"
    validator = root / "bridge" / "src" / "runtime-gateway-start-validator-cli.ts"
    manifest = home / "state" / "runtime-bundle-manifest.json"
    for directory in (
        agent_root,
        agent_root / "venv",
        home,
        bun.parent,
        validator.parent,
        manifest.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    bun.write_bytes(b"reviewed bun")
    validator.write_text("export {};\n", encoding="utf-8")
    manifest.write_text("{}\n", encoding="utf-8")
    runtime_path = r"C:\Reviewed\tools;C:\Windows\System32"
    argv = (str(validator), "--root", str(root), "--manifest", str(manifest))
    expected_managed = {
        "HERMES_GATEWAY_RUNTIME_PATH": runtime_path,
        "PATH": runtime_path,
        "HERMES_GATEWAY_START_VALIDATOR": str(bun),
        "HERMES_GATEWAY_START_VALIDATOR_ARGS": (
            env_loader._encode_gateway_start_validator_args(argv)
        ),
    }
    values = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(root),
        "PYTHONPATH": str(agent_root),
        "VIRTUAL_ENV": str(agent_root / "venv"),
        **expected_managed,
    }
    contract = {
        "root": root,
        "agentRoot": agent_root,
        "home": home,
        "managedValues": expected_managed,
        "validatorArgv": argv,
    }
    poisoned = dict(values)
    poisoned["HERMES_GATEWAY_START_VALIDATOR"] = str(tmp_path / "fake.exe")
    with pytest.raises(ValueError, match="receipt-bound Bun"):
        env_loader._assert_managed_launch_matches_install(
            poisoned,
            str(root),
            contract,
        )
    decoy = dict(values)
    decoy["HERMES_HOME"] = str(tmp_path / "clean-decoy-home")
    with pytest.raises(ValueError, match="redirects outside"):
        env_loader._assert_managed_launch_matches_install(
            decoy,
            str(root),
            contract,
        )


def test_receipt_bound_validator_rejects_forged_but_well_shaped_output(
    tmp_path, monkeypatch
):
    import hermes_cli.env_loader as env_loader
    import hermes_cli.gateway_windows as gateway_windows

    root = tmp_path / "reviewed"
    agent_root = root / "hermes-agent"
    home = root / "home"
    bun = root / "tools" / "bun.exe"
    validator = root / "bridge" / "src" / "runtime-gateway-start-validator-cli.ts"
    manifest = home / "state" / "runtime-bundle-manifest.json"
    for directory in (agent_root / "venv", bun.parent, validator.parent, manifest.parent):
        directory.mkdir(parents=True, exist_ok=True)
    bun.write_bytes(b"reviewed bun")
    validator.write_text("export {};\n", encoding="utf-8")
    manifest.write_text("{}\n", encoding="utf-8")
    runtime_path = r"C:\Reviewed\tools;C:\Windows\System32"
    argv = (str(validator), "--root", str(root), "--manifest", str(manifest))
    managed = {
        "HERMES_GATEWAY_RUNTIME_PATH": runtime_path,
        "PATH": runtime_path,
        "HERMES_GATEWAY_START_VALIDATOR": str(bun),
        "HERMES_GATEWAY_START_VALIDATOR_ARGS": (
            env_loader._encode_gateway_start_validator_args(argv)
        ),
    }
    values = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(root),
        "PYTHONPATH": str(agent_root),
        "VIRTUAL_ENV": str(agent_root / "venv"),
        **managed,
    }
    measured = {"path": str(bun), "fileDigest": f"sha256:{'a' * 64}", "identity": (1,) * 7}
    contract = {
        "root": root,
        "agentRoot": agent_root,
        "home": home,
        "receiptPath": agent_root / "venv" / ".gladly-runtime-install.json",
        "receiptDigest": f"sha256:{'1' * 64}",
        "bunPath": str(bun),
        "bunIdentityDigest": f"sha256:{'2' * 64}",
        "validatorScript": validator,
        "manifestPath": manifest,
        "validatorArgv": argv,
        "managedValues": managed,
        "receiptFile": measured,
        "bunFile": measured,
        "validatorFile": measured,
    }
    expected = {
        "provenance": {
            "version": 1,
            "receiptDigest": f"sha256:{'1' * 64}",
            "manifestDigest": f"sha256:{'2' * 64}",
            "taskEvidenceDigest": f"sha256:{'3' * 64}",
        },
        "manifestFile": measured,
        "loaderFile": measured,
        "closureFiles": {},
    }
    monkeypatch.setattr(env_loader, "_managed_start_expectations", lambda _value: expected)
    monkeypatch.setattr(env_loader, "_managed_install_contract", lambda: contract)
    monkeypatch.setattr(env_loader, "_validator_file_identity", lambda _path: (1,) * 7)
    monkeypatch.setattr(
        gateway_windows,
        "_managed_gateway_child_environment",
        lambda _values: {"PATH": runtime_path},
    )
    monkeypatch.setattr(
        env_loader.subprocess,
        "run",
        lambda _argv, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                '{"version":1,'
                f'"receiptDigest":"sha256:{"9" * 64}",'
                f'"manifestDigest":"sha256:{"2" * 64}",'
                f'"taskEvidenceDigest":"sha256:{"3" * 64}"}}'
            ),
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match="does not match trusted provenance"):
        env_loader._execute_gateway_start_validator(values, str(root), contract)


def test_managed_start_pre_attests_entire_bun_validator_import_closure(tmp_path):
    import hermes_cli.env_loader as env_loader

    root = tmp_path / "reviewed"
    source = root / "bridge" / "src"
    manifest_path = root / "home" / "state" / "runtime-bundle-manifest.json"
    source.mkdir(parents=True)
    manifest_path.parent.mkdir(parents=True)
    validator = source / "runtime-gateway-start-validator-cli.ts"
    validator.write_text("export {};\n", encoding="utf-8")
    closure_files = {}
    for dependency in env_loader._GLADLY_GATEWAY_VALIDATOR_IMPORT_CLOSURE:
        path = source / dependency
        path.write_text(f"// reviewed {dependency}\n", encoding="utf-8")
        closure_files[dependency] = env_loader._stable_regular_file(
            path,
            f"fixture {dependency}",
        )
    loader_file = env_loader._stable_regular_file(
        Path(env_loader.__file__),
        "fixture environment loader",
    )
    validator_file = env_loader._stable_regular_file(
        validator,
        "fixture validator",
    )
    receipt_digest = f"sha256:{'1' * 64}"
    bun_identity = f"sha256:{'2' * 64}"
    task_digest = f"sha256:{'3' * 64}"
    tools = [
        {"id": "runtime/install-receipt", "digest": receipt_digest},
        {"id": "runtime/bun-executable", "digest": bun_identity},
        {
            "id": "runtime/gateway-start-validator",
            "digest": validator_file["fileDigest"],
        },
        {
            "id": "runtime/windows-gateway-env-loader",
            "digest": loader_file["fileDigest"],
        },
        {"id": "runtime/windows-gateway-evidence", "digest": task_digest},
        *(
            {
                "id": f"runtime/windows-gateway-disable-import/{dependency}",
                "digest": measured["fileDigest"],
            }
            for dependency, measured in closure_files.items()
        ),
    ]
    manifest_path.write_text(
        json.dumps(
            {
                "schemaVersion": "hermes.runtime_bundle_manifest.v1",
                "digest": f"sha256:{'4' * 64}",
                "tools": tools,
            }
        ),
        encoding="utf-8",
    )
    contract = {
        "root": root,
        "manifestPath": manifest_path,
        "receiptDigest": receipt_digest,
        "bunIdentityDigest": bun_identity,
        "validatorFile": validator_file,
    }

    expected = env_loader._managed_start_expectations(contract)
    assert set(expected["closureFiles"]) == set(
        env_loader._GLADLY_GATEWAY_VALIDATOR_IMPORT_CLOSURE
    )

    (source / "runtime-release-gate.ts").write_text(
        "// forged release gate\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="runtime-release-gate.ts is not manifest-bound"):
        env_loader._managed_start_expectations(contract)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "e30",  # JSON object, not argv
        "W10",  # empty argv
        "WyIiXQ",  # empty item
        "WyJvayJd=",  # padding is intentionally non-canonical
    ],
)
def test_managed_gateway_validator_args_reject_noncanonical_shapes(raw):
    import hermes_cli.env_loader as env_loader

    with pytest.raises(ValueError, match="validator"):
        env_loader._decode_gateway_start_validator_args(raw)


def test_managed_gateway_validator_args_reject_noncanonical_json_bytes():
    import hermes_cli.env_loader as env_loader

    raw = base64.urlsafe_b64encode(b'["validate-start" ]').decode("ascii").rstrip("=")
    with pytest.raises(ValueError, match="canonical JSON"):
        env_loader._decode_gateway_start_validator_args(raw)


@pytest.mark.parametrize(
    "raw",
    [
        (
            '{"version":1,'
            f'"receiptDigest":"sha256:{"1" * 64}",'
            f'"receiptDigest":"sha256:{"1" * 64}",'
            f'"manifestDigest":"sha256:{"2" * 64}",'
            f'"taskEvidenceDigest":"sha256:{"3" * 64}"}}'
        ),
        (
            '{"version":1,'
            f'"receiptDigest":"sha256:{"1" * 64}",'
            f'"manifestDigest":"sha256:{"2" * 64}",'
            f'"taskEvidenceDigest":"sha256:{"3" * 64}",'
            '"unknown":true}'
        ),
        (
            '{"version":true,'
            f'"receiptDigest":"sha256:{"1" * 64}",'
            f'"manifestDigest":"sha256:{"2" * 64}",'
            f'"taskEvidenceDigest":"sha256:{"3" * 64}"}}'
        ),
        (
            '{"version":1,'
            f'"receiptDigest":"sha256:{"A" * 64}",'
            f'"manifestDigest":"sha256:{"2" * 64}",'
            f'"taskEvidenceDigest":"sha256:{"3" * 64}"}}'
        ),
    ],
)
def test_managed_gateway_provenance_rejects_duplicate_unknown_or_bad_fields(raw):
    import hermes_cli.env_loader as env_loader

    with pytest.raises(ValueError):
        env_loader._decode_gateway_start_provenance(raw)


def test_managed_gateway_validator_runs_after_dotenv_before_external_sources(
    tmp_path,
    monkeypatch,
):
    import hermes_cli.env_loader as env_loader
    import hermes_cli.gateway_windows as gateway_windows

    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    home = tmp_path / "home"
    cwd = tmp_path / "reviewed"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    values = _managed_gateway_lock_values(env_loader, home, cwd)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv(
        env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR,
        env_loader._encode_gateway_launch_env_lock(values, cwd),
    )
    poison = tmp_path / "poison.py"
    (home / ".env").write_text(
        "\n".join(
            (
                "NODE_OPTIONS=--require=poison.js",
                f"PYTHONSTARTUP={poison}",
                f"HERMES_RUNTIME_MANIFEST_DIGEST=sha256:{'f' * 64}",
                "DOTENV_READY=yes",
                "",
            )
        ),
        encoding="utf-8",
    )
    events: list[str] = []

    def fake_child_environment(launch_values):
        return {
            "PATH": launch_values["PATH"],
            "HERMES_HOME": launch_values["HERMES_HOME"],
        }

    monkeypatch.setattr(
        gateway_windows,
        "_managed_gateway_child_environment",
        fake_child_environment,
    )
    monkeypatch.setattr(env_loader, "_validator_file_identity", lambda _path: (1,) * 6)
    monkeypatch.setattr(env_loader, "_managed_install_contract", lambda: None)

    def fake_run(argv, **kwargs):
        events.append("validator")
        assert os.environ["DOTENV_READY"] == "yes"
        assert argv == [str(Path(sys.executable).resolve()), "validate-start"]
        assert "NODE_OPTIONS" not in kwargs["env"]
        assert "PYTHONSTARTUP" not in kwargs["env"]
        return SimpleNamespace(
            returncode=0,
            stdout=(
                '{"version":1,'
                f'"receiptDigest":"sha256:{"1" * 64}",'
                f'"manifestDigest":"sha256:{"2" * 64}",'
                f'"taskEvidenceDigest":"sha256:{"3" * 64}"}}'
            ),
            stderr="",
        )

    monkeypatch.setattr(env_loader.subprocess, "run", fake_run)
    monkeypatch.setattr(
        env_loader,
        "_apply_external_secret_sources",
        lambda _home: events.append("external"),
    )
    monkeypatch.setattr(env_loader, "_apply_managed_env", lambda: None)
    monkeypatch.setattr(
        env_loader, "_reapply_terminal_config_bridge", lambda _home: None
    )

    env_loader.load_hermes_dotenv(hermes_home=home)
    env_loader.load_hermes_dotenv(hermes_home=home)

    assert events == ["validator", "external", "external"]
    assert env_loader._gateway_start_provenance() == {
        "version": 1,
        "receiptDigest": f"sha256:{'1' * 64}",
        "manifestDigest": f"sha256:{'2' * 64}",
        "taskEvidenceDigest": f"sha256:{'3' * 64}",
    }


def test_managed_gateway_validator_blocks_concurrent_loaders_until_provenance(
    tmp_path, monkeypatch
):
    import hermes_cli.env_loader as env_loader
    import hermes_cli.gateway_windows as gateway_windows

    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    home = tmp_path / "home"
    cwd = tmp_path / "reviewed"
    home.mkdir()
    cwd.mkdir()
    values = _managed_gateway_lock_values(env_loader, home, cwd)
    monkeypatch.setattr(env_loader, "_GATEWAY_LAUNCH_ENV_STATE", (values, str(cwd)))
    monkeypatch.setattr(
        gateway_windows,
        "_managed_gateway_child_environment",
        lambda _values: {"PATH": values["PATH"]},
    )
    monkeypatch.setattr(env_loader, "_validator_file_identity", lambda _path: (1,) * 7)
    monkeypatch.setattr(env_loader, "_managed_install_contract", lambda: None)

    validator_entered = threading.Event()
    release_validator = threading.Event()
    second_entered = threading.Event()
    second_finished = threading.Event()
    calls: list[int] = []
    errors: list[BaseException] = []

    def fake_run(_argv, **_kwargs):
        calls.append(1)
        validator_entered.set()
        assert release_validator.wait(5)
        return SimpleNamespace(
            returncode=0,
            stdout=(
                '{"version":1,'
                f'"receiptDigest":"sha256:{"1" * 64}",'
                f'"manifestDigest":"sha256:{"2" * 64}",'
                f'"taskEvidenceDigest":"sha256:{"3" * 64}"}}'
            ),
            stderr="",
        )

    monkeypatch.setattr(env_loader.subprocess, "run", fake_run)

    def first_loader():
        try:
            env_loader._run_gateway_start_validator_if_needed()
        except BaseException as exc:  # noqa: BLE001 - surface thread failures
            errors.append(exc)

    def second_loader():
        second_entered.set()
        try:
            env_loader._run_gateway_start_validator_if_needed()
        except BaseException as exc:  # noqa: BLE001 - surface thread failures
            errors.append(exc)
        finally:
            second_finished.set()

    first = threading.Thread(target=first_loader)
    second = threading.Thread(target=second_loader)
    first.start()
    assert validator_entered.wait(5)
    second.start()
    assert second_entered.wait(5)
    assert not second_finished.wait(0.1)
    release_validator.set()
    first.join(5)
    second.join(5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert calls == [1]
    assert second_finished.is_set()


def test_gateway_launch_env_lock_survives_dotenv_and_later_reload(
    tmp_path, monkeypatch
):
    """Launcher provenance beats user/project/managed reloads for process life."""
    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    reviewed_cwd = tmp_path / "reviewed-repo"
    home = tmp_path / "runtime-home"
    venv = tmp_path / "reviewed-venv"
    reviewed_cwd.mkdir()
    home.mkdir()
    venv.mkdir()
    monkeypatch.chdir(reviewed_cwd)

    locked = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(reviewed_cwd),
        "PYTHONPATH": str(Path(env_loader.__file__).resolve().parent.parent),
        "VIRTUAL_ENV": str(venv),
        "HERMES_GATEWAY_RUNTIME_PATH": (
            r"C:\Reviewed\venv\Scripts;C:\Windows\System32"
        ),
        "PATH": r"C:\Reviewed\venv\Scripts;C:\Windows\System32",
        "HERMES_GATEWAY_START_VALIDATOR": str(Path(sys.executable).resolve()),
        "HERMES_GATEWAY_START_VALIDATOR_ARGS": (
            env_loader._encode_gateway_start_validator_args(["validate-start"])
        ),
    }
    for key, value in locked.items():
        monkeypatch.setenv(key, value)
    marker = env_loader._encode_gateway_launch_env_lock(locked, reviewed_cwd)
    monkeypatch.setenv(env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR, marker)

    poison = str(tmp_path / "old-host")
    (home / ".env").write_text(
        "\n".join(
            [
                *(f"{key}={poison}" for key in locked),
                f"{env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR}=not-the-launch-marker",
                "LOCK_RELOAD_PROBE=first",
                "",
            ]
        ),
        encoding="utf-8",
    )

    def poison_managed_env():
        for key in locked:
            os.environ[key] = poison + "-managed"

    def poison_config_bridge(_home):
        for key in locked:
            os.environ[key] = poison + "-config"

    monkeypatch.setattr(env_loader, "_apply_managed_env", poison_managed_env)
    monkeypatch.setattr(
        env_loader, "_reapply_terminal_config_bridge", poison_config_bridge
    )
    monkeypatch.setattr(
        env_loader, "_run_gateway_start_validator_if_needed", lambda: None
    )

    env_loader.load_hermes_dotenv(load_external_secrets=False)

    assert {key: os.environ[key] for key in locked} == locked
    assert env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR not in os.environ
    assert os.getcwd() == str(reviewed_cwd)
    assert os.environ["LOCK_RELOAD_PROBE"] == "first"

    # Simulate arbitrary in-process mutation before the gateway's per-turn
    # dotenv reload. The captured snapshot, not a newly injected marker, wins.
    for key in locked:
        monkeypatch.setenv(key, poison + "-between-turns")
    monkeypatch.setenv(env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR, "replacement")
    (home / ".env").write_text(
        (home / ".env").read_text(encoding="utf-8").replace("first", "second"),
        encoding="utf-8",
    )

    env_loader.load_hermes_dotenv(load_external_secrets=False)

    assert {key: os.environ[key] for key in locked} == locked
    assert env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR not in os.environ
    assert os.environ["LOCK_RELOAD_PROBE"] == "second"


def test_gateway_launch_env_lock_isolates_external_secret_source_mapping(
    tmp_path, monkeypatch
):
    """Secret plugins never receive process-global protected keys to mutate."""
    from types import SimpleNamespace

    from agent.secret_sources import registry

    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    home = tmp_path / "home"
    reviewed_cwd = tmp_path / "reviewed"
    home.mkdir()
    reviewed_cwd.mkdir()
    locked = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(reviewed_cwd),
        "PYTHONPATH": str(Path(env_loader.__file__).resolve().parent.parent),
        "VIRTUAL_ENV": str(tmp_path / "venv"),
    }
    for key, value in locked.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("HERMES_CRON_PAUSED", "false")
    monkeypatch.setattr(
        env_loader,
        "_GATEWAY_LAUNCH_ENV_STATE",
        (dict(locked), str(reviewed_cwd)),
    )
    monkeypatch.setattr(env_loader, "_APPLIED_HOMES", set())
    monkeypatch.setattr(
        env_loader,
        "_load_secrets_config",
        lambda _home: {"test-source": {"enabled": True}},
    )

    def fake_apply_all(_cfg, _home, *, environ=None):
        assert environ is not None
        assert environ is not os.environ
        # Simulate an operator pausing dispatch while a slow vault fetch is in
        # flight. Merging the entire baseline copy afterwards would undo it.
        os.environ["HERMES_CRON_PAUSED"] = "true"
        environ["HERMES_HOME"] = "poisoned-by-source"
        environ["UNLOCKED_SOURCE_PROBE"] = "applied"
        return SimpleNamespace(sources=[], applied_any=False, conflicts=[])

    monkeypatch.setattr(registry, "apply_all", fake_apply_all)

    env_loader._apply_external_secret_sources(home)

    assert os.environ["HERMES_HOME"] == str(home)
    assert os.environ["HERMES_CRON_PAUSED"] == "true"
    assert os.environ["UNLOCKED_SOURCE_PROBE"] == "applied"
    monkeypatch.setenv("HERMES_CRON_PAUSED", "false")
    from cron.jobs import is_cron_dispatch_paused

    assert is_cron_dispatch_paused() is True


def test_cron_pause_latches_across_later_profile_false_reload(
    tmp_path, monkeypatch
):
    import hermes_cli.env_loader as env_loader
    from cron.jobs import is_cron_dispatch_paused

    primary = tmp_path / "primary"
    secondary = tmp_path / "secondary"
    primary.mkdir()
    secondary.mkdir()
    (primary / ".env").write_text(
        "HERMES_CRON_PAUSED=true\n", encoding="utf-8"
    )
    (secondary / ".env").write_text(
        "HERMES_CRON_PAUSED=false\n", encoding="utf-8"
    )
    monkeypatch.delenv("HERMES_CRON_PAUSED", raising=False)
    monkeypatch.setattr(env_loader, "_apply_managed_env", lambda: None)

    env_loader.load_hermes_dotenv(
        hermes_home=primary, load_external_secrets=False
    )
    assert is_cron_dispatch_paused() is True

    env_loader.load_hermes_dotenv(
        hermes_home=secondary, load_external_secrets=False
    )
    assert os.environ["HERMES_CRON_PAUSED"] == "false"
    assert is_cron_dispatch_paused() is True


def test_inherited_cron_pause_latches_before_dotenv_false_override(
    tmp_path, monkeypatch
):
    import hermes_cli.env_loader as env_loader
    from cron.jobs import is_cron_dispatch_paused

    home = tmp_path / "home"
    home.mkdir()
    (home / ".env").write_text(
        "HERMES_CRON_PAUSED=false\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_CRON_PAUSED", "true")
    monkeypatch.setattr(env_loader, "_apply_managed_env", lambda: None)

    env_loader.load_hermes_dotenv(
        hermes_home=home, load_external_secrets=False
    )

    assert os.environ["HERMES_CRON_PAUSED"] == "false"
    assert is_cron_dispatch_paused() is True


def test_dotenv_cannot_activate_gateway_launch_lock_after_start(
    tmp_path, monkeypatch
):
    """Only the marker present before the first load can activate the lock."""
    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    home = tmp_path / "runtime-home"
    reviewed_cwd = tmp_path / "reviewed-repo"
    venv = tmp_path / "venv"
    home.mkdir()
    reviewed_cwd.mkdir()
    venv.mkdir()
    monkeypatch.chdir(reviewed_cwd)
    monkeypatch.setenv("HERMES_HOME", str(home))

    attacker_values = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(reviewed_cwd),
        "PYTHONPATH": "attacker-pythonpath",
        "VIRTUAL_ENV": "attacker-venv",
    }
    injected_marker = env_loader._encode_gateway_launch_env_lock(
        attacker_values, reviewed_cwd
    )
    (home / ".env").write_text(
        "\n".join(
            [
                *(f"{key}={value}" for key, value in attacker_values.items()),
                f"{env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR}={injected_marker}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(env_loader, "_apply_managed_env", lambda: None)
    monkeypatch.setattr(
        env_loader, "_reapply_terminal_config_bridge", lambda _home: None
    )

    env_loader.load_hermes_dotenv(load_external_secrets=False)
    assert env_loader._GATEWAY_LAUNCH_ENV_STATE is None
    assert env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR not in os.environ
    assert os.environ["VIRTUAL_ENV"] == "attacker-venv"

    # A second reload still cannot capture the marker that came from .env.
    env_loader.load_hermes_dotenv(hermes_home=home, load_external_secrets=False)
    assert env_loader._GATEWAY_LAUNCH_ENV_STATE is None
    assert env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR not in os.environ


def test_invalid_gateway_launch_env_lock_fails_closed(tmp_path, monkeypatch):
    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR, "not-base64")

    with pytest.raises(RuntimeError, match="Refusing detached gateway startup"):
        env_loader.load_hermes_dotenv(
            hermes_home=tmp_path,
            load_external_secrets=False,
        )


def test_gateway_launch_env_lock_rejects_wrong_initial_cwd(tmp_path, monkeypatch):
    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    actual_cwd = tmp_path / "actual"
    expected_cwd = tmp_path / "expected"
    home = tmp_path / "home"
    venv = tmp_path / "venv"
    for path in (actual_cwd, expected_cwd, home, venv):
        path.mkdir()
    monkeypatch.chdir(actual_cwd)
    locked = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(expected_cwd),
        "PYTHONPATH": str(expected_cwd),
        "VIRTUAL_ENV": str(venv),
    }
    monkeypatch.setenv(
        env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR,
        env_loader._encode_gateway_launch_env_lock(locked, expected_cwd),
    )

    with pytest.raises(RuntimeError, match="Refusing detached gateway startup"):
        env_loader.load_hermes_dotenv(
            hermes_home=home,
            load_external_secrets=False,
        )


def test_gateway_launch_env_lock_rejects_public_env_mismatch(
    tmp_path, monkeypatch
):
    env_loader = _reset_gateway_launch_env_lock(monkeypatch)
    reviewed_cwd = tmp_path / "reviewed"
    home = tmp_path / "home"
    venv = tmp_path / "venv"
    for path in (reviewed_cwd, home, venv):
        path.mkdir()
    monkeypatch.chdir(reviewed_cwd)
    locked = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(reviewed_cwd),
        "PYTHONPATH": str(Path(env_loader.__file__).resolve().parent.parent),
        "VIRTUAL_ENV": str(venv),
    }
    for key, value in locked.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("HERMES_RUNTIME_HOME", str(tmp_path / "stale-runtime"))
    monkeypatch.setenv(
        env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR,
        env_loader._encode_gateway_launch_env_lock(locked, reviewed_cwd),
    )

    with pytest.raises(RuntimeError, match="Refusing detached gateway startup"):
        env_loader.load_hermes_dotenv(
            hermes_home=home,
            load_external_secrets=False,
        )


# ---------------------------------------------------------------------------
# Profile .env isolation: inherited known-key cleanup
# ---------------------------------------------------------------------------


def test_known_keys_absent_from_user_env_are_cleared(tmp_path, monkeypatch):
    """Known Hermes keys inherited from parent process are removed when absent
    from the profile's .env.

    This is the startup equivalent of ``reload_env()``'s known-key cleanup and
    fixes the isolation gap where one profile's ACP/provider settings silently
    leak into another profile's runtime via ``os.environ`` inheritance.
    """
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text(
        "OPENAI_BASE_URL=https://profile.example/v1\n", encoding="utf-8"
    )

    # Inherited known keys from parent process / other profile
    monkeypatch.setenv("OPENAI_BASE_URL", "https://stale.example/v1")
    monkeypatch.setenv("HERMES_ACP_AUTH_METHOD", "cursor_login")
    monkeypatch.setenv("COPILOT_CLI_PATH", "/usr/bin/claude-code")
    # Unrelated shell var must NOT be touched
    monkeypatch.setenv("MY_SHELL_ONLY_VAR", "keep-me")

    load_hermes_dotenv(hermes_home=home)

    # OPENAI_BASE_URL is defined in the profile .env → overridden to the new value
    assert os.getenv("OPENAI_BASE_URL") == "https://profile.example/v1"
    # HERMES_ACP_AUTH_METHOD and COPILOT_CLI_PATH are NOT in the profile .env → cleared
    assert "HERMES_ACP_AUTH_METHOD" not in os.environ
    assert "COPILOT_CLI_PATH" not in os.environ
    # Unrelated shell vars must survive
    assert os.getenv("MY_SHELL_ONLY_VAR") == "keep-me"


def test_empty_assignment_in_user_env_is_preserved(tmp_path, monkeypatch):
    """An explicit ``KEY=`` (empty value) in the profile .env keeps the key
    in ``os.environ`` — distinct from a key absent from .env entirely.

    Empty ``HERMES_ACP_AUTH_METHOD=`` tells the ACP adapter to skip
    ``authenticate`` (the key exists, its value is just empty).  This is the
    documented workaround for the leak and must still work after the cleanup.
    """
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text("HERMES_ACP_AUTH_METHOD=\n", encoding="utf-8")

    monkeypatch.setenv("HERMES_ACP_AUTH_METHOD", "cursor_login")
    monkeypatch.setenv("COPILOT_CLI_PATH", "/usr/bin/sneaky")  # NOT in .env → cleared

    load_hermes_dotenv(hermes_home=home)

    # KEY= in .env keeps the key (now empty string)
    assert "HERMES_ACP_AUTH_METHOD" in os.environ
    assert os.environ["HERMES_ACP_AUTH_METHOD"] == ""
    # COPILOT_CLI_PATH is absent from .env → cleared
    assert "COPILOT_CLI_PATH" not in os.environ


def test_no_user_env_does_not_clear_anything(tmp_path, monkeypatch):
    """When no profile .env exists (bare profile), load_hermes_dotenv must not
    wipe inherited known keys — the bare-profile case follows #66930 / #67027
    semantics and the user's shell environment should not be mutilated.
    """
    home = tmp_path / "hermes"
    home.mkdir()
    # No .env in home — bare profile

    monkeypatch.setenv("HERMES_ACP_AUTH_METHOD", "cursor_login")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    load_hermes_dotenv(hermes_home=home)

    assert os.getenv("HERMES_ACP_AUTH_METHOD") == "cursor_login"
    assert os.getenv("PATH") == "/usr/bin:/bin"


def test_known_key_explicitly_set_in_user_env_is_kept(tmp_path, monkeypatch):
    """A known Hermes key that IS explicitly set in the profile .env survives
    the cleanup (overrides the inherited value).
    """
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text(
        "HERMES_ACP_AUTH_METHOD=claude_code_cli\n", encoding="utf-8"
    )

    monkeypatch.setenv("HERMES_ACP_AUTH_METHOD", "cursor_login")

    load_hermes_dotenv(hermes_home=home)

    assert os.getenv("HERMES_ACP_AUTH_METHOD") == "claude_code_cli"


def test_export_prefixed_known_key_in_user_env_is_kept(tmp_path, monkeypatch):
    """A known Hermes key defined with the bash-compatible ``export KEY=value``
    form in the profile .env must be recognized as defined and survive the
    cleanup - mirrors the ``export `` stripping in config.py's load_env()
    (#6659).
    """
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text(
        "export HERMES_ACP_AUTH_METHOD=claude_code_cli\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_ACP_AUTH_METHOD", "cursor_login")
    load_hermes_dotenv(hermes_home=home)
    assert os.getenv("HERMES_ACP_AUTH_METHOD") == "claude_code_cli"


def test_shell_exported_credentials_survive_cleanup(tmp_path, monkeypatch):
    """User-shell-exported provider credentials must NOT be scrubbed.

    ``export OPENAI_API_KEY=…`` in the shell with a ``.env`` that doesn't
    contain the key is a documented, legitimate flow (see
    test_dump_env_visibility.py). The startup cleanup is scoped to
    _PROFILE_MANAGED_ENV_KEYS (ACP routing keys) precisely so it can never
    delete shell-supplied credentials — a process cannot distinguish a
    shell export from parent-process leakage, so credential isolation is
    owned by read-time secret scoping instead.
    """
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text("SOME_OTHER_KEY=x\n", encoding="utf-8")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-shell")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-shell")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "12345:token-from-shell")
    # A profile-managed routing key inherited alongside them IS cleared.
    monkeypatch.setenv("HERMES_ACP_AUTH_METHOD", "cursor_login")

    load_hermes_dotenv(hermes_home=home)

    assert os.getenv("OPENAI_API_KEY") == "sk-from-shell"
    assert os.getenv("ANTHROPIC_API_KEY") == "sk-ant-from-shell"
    assert os.getenv("TELEGRAM_BOT_TOKEN") == "12345:token-from-shell"
    assert "HERMES_ACP_AUTH_METHOD" not in os.environ


def test_cleanup_scope_is_the_profile_managed_set():
    """Lock the invariant: the startup scrub set contains only behavioral
    ACP/routing keys — never credential-shaped keys. If this fails, someone
    widened _PROFILE_MANAGED_ENV_KEYS toward the full known-key set, which
    re-introduces the shell-export deletion bug.
    """
    from hermes_cli.env_loader import _PROFILE_MANAGED_ENV_KEYS

    for key in _PROFILE_MANAGED_ENV_KEYS:
        assert not key.endswith(("_API_KEY", "_TOKEN", "_SECRET")), (
            f"{key} looks credential-shaped; startup scrub must not "
            "cover credentials — read-time secret scoping owns those"
        )


# ---------------------------------------------------------------------------
# config.yaml terminal.* re-apply after dotenv loads (#29186 / #67323)
#
# load_hermes_dotenv loads .env with override=True, so a stale
# TERMINAL_ENV=docker in .env used to silently beat config.yaml's
# terminal.backend on every reload (gateway per-turn reload, cron standalone
# runs). The bridge re-applies config.yaml's EXPLICIT terminal keys last via
# the shared hermes_cli.config.apply_terminal_config_to_env helper.
# ---------------------------------------------------------------------------


def _seed_terminal_home(tmp_path, monkeypatch, *, config_yaml=None, env_text=None):
    home = tmp_path / "hermes"
    home.mkdir()
    if config_yaml is not None:
        (home / "config.yaml").write_text(config_yaml, encoding="utf-8")
    if env_text is not None:
        (home / ".env").write_text(env_text, encoding="utf-8")
    # The bridge is scoped to the process HERMES_HOME (a different profile's
    # load must not bridge this process's config), so point the process at
    # the seeded home like a real gateway/cron process would be.
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def test_config_yaml_terminal_backend_overrides_stale_env(tmp_path, monkeypatch):
    """Regression for #29186: a leftover TERMINAL_ENV=docker in ~/.hermes/.env
    must not silently override the user's choice in config.yaml. config.yaml
    is the documented source of truth, so its value must win after load."""
    home = _seed_terminal_home(
        tmp_path, monkeypatch,
        config_yaml="terminal:\n  backend: local\n",
        env_text="TERMINAL_ENV=docker\n",
    )

    monkeypatch.delenv("TERMINAL_ENV", raising=False)

    load_hermes_dotenv(hermes_home=home)

    assert os.getenv("TERMINAL_ENV") == "local"


def test_config_yaml_terminal_backend_overrides_stale_shell(tmp_path, monkeypatch):
    """config.yaml must also beat a stale TERMINAL_ENV exported in the shell
    (e.g. set in ~/.zshrc when the user was experimenting with docker)."""
    home = _seed_terminal_home(
        tmp_path, monkeypatch,
        config_yaml="terminal:\n  backend: local\n",
    )

    monkeypatch.setenv("TERMINAL_ENV", "docker")

    load_hermes_dotenv(hermes_home=home)

    assert os.getenv("TERMINAL_ENV") == "local"


def test_no_terminal_section_leaves_env_value_alone(tmp_path, monkeypatch):
    """When config.yaml has no terminal section, the .env value is still the
    user's active setting — the bridge must NOT clobber it with merged
    defaults."""
    home = _seed_terminal_home(
        tmp_path, monkeypatch,
        config_yaml="display:\n  streaming: true\n",
        env_text="TERMINAL_ENV=docker\n",
    )

    monkeypatch.delenv("TERMINAL_ENV", raising=False)

    load_hermes_dotenv(hermes_home=home)

    assert os.getenv("TERMINAL_ENV") == "docker"


def test_config_yaml_terminal_omitted_key_does_not_clear_env(tmp_path, monkeypatch):
    """If config.yaml has a terminal block but no `backend`, the .env value
    must survive (only explicit config keys override env)."""
    home = _seed_terminal_home(
        tmp_path, monkeypatch,
        config_yaml="terminal:\n  timeout: 600\n",
        env_text="TERMINAL_ENV=docker\n",
    )

    monkeypatch.delenv("TERMINAL_ENV", raising=False)

    load_hermes_dotenv(hermes_home=home)

    assert os.getenv("TERMINAL_ENV") == "docker"
    assert os.getenv("TERMINAL_TIMEOUT") == "600"


def test_other_profile_home_does_not_bridge_process_config(tmp_path, monkeypatch):
    """Loading a DIFFERENT profile's .env must not re-bridge this process's
    config.yaml — the shared bridge reads the process-global config, so
    applying it for another home would stamp the wrong profile's terminal
    settings into the env."""
    process_home = tmp_path / "process-home"
    process_home.mkdir()
    (process_home / "config.yaml").write_text(
        "terminal:\n  backend: local\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(process_home))

    other_home = tmp_path / "other-profile"
    other_home.mkdir()
    (other_home / ".env").write_text("TERMINAL_ENV=docker\n", encoding="utf-8")

    monkeypatch.delenv("TERMINAL_ENV", raising=False)

    load_hermes_dotenv(hermes_home=other_home)

    # The other profile's .env value stands; the process config was not applied.
    assert os.getenv("TERMINAL_ENV") == "docker"
