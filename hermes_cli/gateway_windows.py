"""Windows gateway service backend (Scheduled Task + Startup-folder fallback).

This mirrors the contract exposed by ``launchd_install`` / ``launchd_start`` /
``launchd_status`` etc. on macOS and ``systemd_install`` / ``systemd_start`` on
Linux. It uses ``schtasks`` under the hood with ``/SC ONLOGON`` and restart-on-
failure XML settings, and falls back to a ``%APPDATA%\\...\\Startup\\<name>.vbs``
dropper when Scheduled Task creation is denied (locked-down corporate boxes).

Design notes
------------
* ``schtasks /Create /SC ONLOGON /RL LIMITED`` means the task runs at the
  CURRENT USER's next logon without any elevation prompt. Manual starts and
  install ``--start-now`` use the direct hidden-console launcher instead
  of ``schtasks /Run`` so start/restart behavior is consistent.
* We write a shared ``gateway.cmd`` wrapper plus a console-less ``gateway.vbs``
  launcher. Scheduled Task and Startup-folder persistence both route through
  VBS/wscript; immediate manual starts route through direct ``subprocess`` spawn.
* Status = merge of "is the schtasks entry registered?" + "is the startup
  login item present?" + "is there a gateway process running?" so the status
  command keeps working regardless of which install path was taken.
* Quoting is tricky: schtasks parses ``/TR`` itself and cmd.exe parses the
  generated ``gateway.cmd``. Those are DIFFERENT parsers. We keep two
  separate quote helpers (same pattern OpenClaw uses) and never cross them.
* All of this is Windows-only. ``import`` paths are still safe on POSIX but
  the functions raise if called on non-Windows.
"""

from __future__ import annotations

import ctypes
import csv
import locale
import logging
import ntpath
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from xml.sax.saxutils import escape

from hermes_cli._subprocess_compat import (
    _WINDOWS_GATEWAY_BREAKAWAY_ENV,
    windows_detach_flags,
    windows_detach_flags_without_breakaway,
    windows_hide_flags,
)

logger = logging.getLogger(__name__)

# Short timeouts: schtasks occasionally wedges and we don't want to hang forever.
_SCHTASKS_TIMEOUT_S = 15
_SCHTASKS_NO_OUTPUT_TIMEOUT_S = 30
# Patterns in schtasks stderr that mean "fall back to the Startup folder".
_FALLBACK_PATTERNS = re.compile(
    r"(access is denied|acceso denegado|přístup byl odepřen|schtasks timed out|schtasks produced no output)",
    re.IGNORECASE,
)
_ACCESS_DENIED_PATTERN = re.compile(r"(access is denied|acceso denegado)", re.IGNORECASE)

_TASK_NAME_DEFAULT = "Hermes_Gateway"
_TASK_DESCRIPTION = "Hermes Agent Gateway - Messaging Platform Integration"
_TASK_LOGON_DELAY = "PT30S"
_TASK_RESTART_INTERVAL = "PT1M"
_TASK_RESTART_COUNT = 999


class _TaskInspectionError(RuntimeError):
    """Scheduled Task existence/definition could not be proved safely."""


def _schtasks_encoding() -> str:
    """Best-effort console encoding for decoding ``schtasks.exe`` output.

    On localized Windows (e.g. Chinese), ``schtasks`` emits text in the OEM/ANSI
    code page rather than UTF-8. Decoding with the wrong codec raised
    ``UnicodeDecodeError`` inside ``subprocess``' reader threads. Prefer the
    locale's preferred encoding and fall back to UTF-8.
    """
    try:
        return locale.getpreferredencoding(False) or "utf-8"
    except Exception:
        return "utf-8"


# ---------------------------------------------------------------------------
# Platform guard
# ---------------------------------------------------------------------------

def _assert_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeError("gateway_windows is Windows-only")


class _GUID(ctypes.Structure):
    _fields_ = (
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    )


_FOLDERID_STARTUP = _GUID(
    0xB97D20BB,
    0xF46A,
    0x4C97,
    (ctypes.c_ubyte * 8)(0xBA, 0x10, 0x5E, 0x36, 0x08, 0x43, 0x08, 0x54),
)
_FOLDERID_PROFILE = _GUID(
    0x5E6C858F,
    0x0E22,
    0x4760,
    (ctypes.c_ubyte * 8)(0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73),
)
_FOLDERID_ROAMING_APPDATA = _GUID(
    0x3EB685DB,
    0x65F9,
    0x4CF6,
    (ctypes.c_ubyte * 8)(0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D),
)
_FOLDERID_LOCAL_APPDATA = _GUID(
    0xF1B32785,
    0x6FBA,
    0x4FCF,
    (ctypes.c_ubyte * 8)(0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91),
)
def _windows_directory() -> Path:
    """Resolve the Windows directory from Kernel32, never mutable env."""
    _assert_windows()
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise RuntimeError("GetWindowsDirectoryW failed")
    path = Path(buffer.value)
    if not path.is_absolute():
        raise RuntimeError("GetWindowsDirectoryW returned a non-absolute path")
    return path


def _known_folder_path(folder_id: _GUID, label: str) -> Path:
    """Resolve a per-user path through SHGetKnownFolderPath."""
    _assert_windows()
    output = ctypes.c_wchar_p()
    status = ctypes.windll.shell32.SHGetKnownFolderPath(
        ctypes.byref(folder_id),
        0,
        None,
        ctypes.byref(output),
    )
    try:
        if status != 0 or not output.value:
            raise RuntimeError(f"SHGetKnownFolderPath({label}) failed: {status}")
        path = Path(output.value)
        if not path.is_absolute():
            raise RuntimeError(f"SHGetKnownFolderPath({label}) returned a non-absolute path")
        return path
    finally:
        if output:
            ctypes.windll.ole32.CoTaskMemFree(ctypes.cast(output, ctypes.c_void_p))


def _stable_system_executable(name: str) -> str:
    """Return an exact System32 executable after a closed-handle identity read."""
    path = _windows_directory() / "System32" / name
    before_path = path.lstat()
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise RuntimeError(f"reviewed System32 executable is not a regular file: {path}")
    if bool(getattr(before_path, "st_file_attributes", 0) & 0x400):
        raise RuntimeError(f"reviewed System32 executable is a reparse point: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened_before = os.fstat(descriptor)
        while os.read(descriptor, 1024 * 1024):
            pass
        opened_after = os.fstat(descriptor)
        after_path = path.lstat()
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        getattr(value, "st_file_attributes", 0),
    )
    if len({identity(before_path), identity(opened_before), identity(opened_after), identity(after_path)}) != 1:
        raise RuntimeError(f"reviewed System32 executable changed during validation: {path}")
    if stat.S_ISLNK(after_path.st_mode) or bool(
        getattr(after_path, "st_file_attributes", 0) & 0x400
    ):
        raise RuntimeError(f"reviewed System32 executable became a reparse point: {path}")
    return str(path.resolve(strict=True))


def _schtasks_executable() -> str:
    return _stable_system_executable("schtasks.exe")


def _trusted_windows_child_environment(runtime_path: str) -> dict[str, str]:
    """Return Windows process primitives derived only from OS APIs.

    Managed launchers do not inherit mutable ``SystemRoot``, profile, AppData,
    ProgramData, temp, ComSpec, or hook variables from the shell that
    staged/started them.
    """
    windows_dir = _windows_directory()
    profile = _known_folder_path(_FOLDERID_PROFILE, "Profile")
    roaming = _known_folder_path(_FOLDERID_ROAMING_APPDATA, "RoamingAppData")
    local = _known_folder_path(_FOLDERID_LOCAL_APPDATA, "LocalAppData")
    # SHGetKnownFolderPath(FOLDERID_ProgramData) can return PATH_NOT_FOUND in
    # the intentionally empty environment used by the managed launcher. The
    # machine-wide directory is rooted on the OS drive, so derive it from the
    # already trusted GetWindowsDirectoryW result and require it to exist.
    program_data = (Path(windows_dir.anchor) / "ProgramData").resolve(strict=True)
    if not program_data.is_dir():
        raise RuntimeError(f"ProgramData is not a directory: {program_data}")
    return {
        "SystemRoot": str(windows_dir),
        "SystemDrive": windows_dir.drive,
        "WINDIR": str(windows_dir),
        "USERPROFILE": str(profile),
        "HOME": str(profile),
        "APPDATA": str(roaming),
        "LOCALAPPDATA": str(local),
        "ProgramData": str(program_data),
        "TEMP": str(local / "Temp"),
        "TMP": str(local / "Temp"),
        "ComSpec": _stable_system_executable("cmd.exe"),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
        "PATH": runtime_path,
    }


def _managed_gateway_child_environment(
    launch_values: Mapping[str, str],
) -> dict[str, str]:
    """Build the complete allowlisted environment for one managed child.

    This function deliberately starts from an empty mapping.  Provider secrets
    and operator configuration are loaded by Hermes from its reviewed runtime
    home after Python starts; ambient shell variables, Python/Node/Bash hooks,
    path decoys, and stale checkout pointers never cross the process boundary.
    """
    from hermes_cli.env_loader import (
        _GATEWAY_LAUNCH_ENV_KEYS,
        _GATEWAY_LAUNCH_ENV_LOCK_VAR,
        _GATEWAY_MANAGED_LAUNCH_ENV_KEYS,
        _validate_gateway_managed_launch_values,
    )

    managed = _validate_gateway_managed_launch_values(launch_values)
    child = _trusted_windows_child_environment(managed["PATH"])
    allowed = {
        *_GATEWAY_LAUNCH_ENV_KEYS,
        *_GATEWAY_MANAGED_LAUNCH_ENV_KEYS,
        _GATEWAY_LAUNCH_ENV_LOCK_VAR,
        "LANG",
        "LC_ALL",
        "PYTHONUTF8",
        "PYTHONIOENCODING",
        "HERMES_GATEWAY_DETACHED",
        _WINDOWS_GATEWAY_BREAKAWAY_ENV,
    }
    for key in allowed:
        value = launch_values.get(key)
        if isinstance(value, str) and value:
            child[key] = value
    # The reviewed runtime policy is authoritative even if a caller omitted
    # PATH from an intermediate overlay (validation above normally rejects it).
    child.update(managed)
    return child


def _preserve_hermes_home_path(path: str | Path) -> str:
    """Render Hermes-owned paths under the configured HERMES_HOME spelling.

    Windows installs may keep ``%LOCALAPPDATA%\\hermes`` as a symlink/junction to
    another drive. Runtime state should still identify itself by the configured
    AppData path, so launcher files must not bake in the resolved target when a
    path lives under HERMES_HOME.
    """
    candidate = Path(path)
    try:
        from hermes_cli.config import get_hermes_home

        home = Path(get_hermes_home())
        resolved_home = home.resolve()
        resolved_candidate = candidate.resolve()
        home_key = os.path.normcase(str(resolved_home))
        candidate_key = os.path.normcase(str(resolved_candidate))
        if os.path.commonpath([home_key, candidate_key]) == home_key:
            rel = os.path.relpath(str(resolved_candidate), str(resolved_home))
            return str(home / rel)
    except Exception:
        pass
    return str(candidate)


# ---------------------------------------------------------------------------
# Quoting helpers (two DIFFERENT parsers — do not mix)
# ---------------------------------------------------------------------------

def _quote_cmd_script_arg(value: str) -> str:
    """Quote a single argument for use INSIDE a .cmd file, for cmd.exe parsing.

    cmd.exe splits on spaces/tabs outside of double quotes. Embedded quotes
    are doubled. We also refuse line breaks because they'd terminate the
    logical command line mid-script.
    """
    if "\r" in value or "\n" in value:
        raise ValueError(f"refusing to quote value containing newline: {value!r}")
    if not value:
        return '""'
    if not re.search(r'[ \t"]', value):
        return value
    return '"' + value.replace('"', '""') + '"'


def _quote_schtasks_arg(value: str) -> str:
    """Quote a single argument for schtasks.exe's /TR parser.

    Schtasks uses a different quoting convention than cmd.exe: embedded
    quotes are backslash-escaped, and the whole thing is wrapped in double
    quotes if it contains whitespace or quotes.
    """
    if not re.search(r'[ \t"]', value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


# ---------------------------------------------------------------------------
# schtasks.exe wrapper
# ---------------------------------------------------------------------------

def _exec_schtasks(args: list[str]) -> tuple[int, str, str]:
    """Run ``schtasks.exe`` with a hard timeout. Return (code, stdout, stderr).

    If schtasks wedges, returns code=124 with a synthetic stderr string —
    same convention OpenClaw uses, so the fallback detection regex matches.
    """
    _assert_windows()
    try:
        schtasks = _schtasks_executable()
    except (OSError, RuntimeError) as exc:
        return (1, "", f"reviewed schtasks.exe is unavailable: {exc}")
    try:
        proc = subprocess.run(
            [schtasks, *args],
            capture_output=True,
            text=True,
            # Localized Windows emits schtasks output in the console code page,
            # not UTF-8. Decode with the locale encoding and replace undecodable
            # bytes so a non-UTF-8 status line never surfaces a UnicodeDecodeError
            # traceback from subprocess' reader threads (issue #38172).
            encoding=_schtasks_encoding(),
            errors="replace",
            timeout=_SCHTASKS_TIMEOUT_S,
            # CREATE_NO_WINDOW avoids a flashing console window when the CLI
            # is itself hosted in a TUI. See tools/browser_tool.py for the
            # same pattern and the windows-subprocess-sigint-storm.md ref.
            creationflags=windows_hide_flags(),
        )
        return (proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired:
        return (124, "", f"schtasks timed out after {_SCHTASKS_TIMEOUT_S}s")
    except OSError as e:
        return (1, "", f"schtasks invocation failed: {e}")


def _should_fall_back(code: int, detail: str) -> bool:
    return code == 124 or bool(_FALLBACK_PATTERNS.search(detail or ""))


def _is_access_denied(detail: str) -> bool:
    return bool(_ACCESS_DENIED_PATTERN.search(detail or ""))


def _is_running_as_admin() -> bool:
    """Return True when the current Windows process is elevated."""
    _assert_windows()
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _current_profile_cli_args() -> list[str]:
    """Return CLI args that preserve the current Hermes profile."""
    return shlex.split(_locked_gateway_profile_arg())


def _locked_gateway_profile_arg(hermes_home: str | None = None) -> str:
    """Return an explicit profile selector for a provenance-locked launch.

    Ordinary bare Hermes commands intentionally follow ``active_profile``.
    A generated Windows service launcher cannot do that after baking a locked
    HERMES_HOME: changing the sticky profile before its next start would make
    bootstrap rewrite HERMES_HOME before the lock is captured.  Pin the
    built-in default explicitly when ``_profile_arg`` would otherwise be
    empty; named profiles keep their normal explicit selector. Reinstalling
    the service is therefore the intentional way to change its profile.
    """
    from hermes_cli.gateway import _profile_arg

    profile_arg = _profile_arg(hermes_home) if hermes_home is not None else _profile_arg()
    return profile_arg or "--profile default"


def _explicit_gateway_profile(argv: list[str]) -> str | None:
    """Return the one explicit profile selected by a gateway argv.

    Post-update restart can replay a gateway for a profile other than the
    updater process.  The launch lock must therefore derive HERMES_HOME from
    the replayed argv, not from the updater's current profile.  Reject
    malformed or ambiguous selectors rather than minting a lock for the wrong
    runtime home.
    """
    from hermes_cli.profiles import normalize_profile_name, validate_profile_name

    selected: list[str] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            break
        if arg in {"--profile", "-p"}:
            if index + 1 >= len(argv):
                raise ValueError(f"{arg} requires a profile name")
            selected.append(argv[index + 1])
            index += 2
            continue
        if arg.startswith("--profile="):
            selected.append(arg.split("=", 1)[1])
        index += 1

    if not selected:
        return None
    if len(selected) != 1:
        raise ValueError("gateway restart argv has multiple profile selectors")
    profile = normalize_profile_name(selected[0])
    validate_profile_name(profile)
    return profile


def _restart_hermes_home(current_home: str | Path, argv: list[str]) -> str:
    """Resolve the runtime home selected by a post-update restart argv."""
    current = Path(current_home).expanduser()
    profile = _explicit_gateway_profile(argv)
    if profile is None:
        target = current
    else:
        root = (
            current.parent.parent
            if current.parent.name.casefold() == "profiles"
            else current
        )
        target = root if profile == "default" else root / "profiles" / profile
    resolved = target.resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(resolved)
    return str(resolved)


def _launch_elevated_gateway_command(command: str, extra_args: list[str] | None = None) -> bool:
    """Launch an elevated gateway subcommand via UAC and return True on handoff.

    The elevated child is the console ``python.exe`` launched with
    ``SW_HIDE``: ShellExecuteW applies the show-command to a console app's
    console window, so the child owns a single *hidden* console that its own
    subprocess spawns (schtasks, taskkill, …) inherit — no visible window
    after the UAC approval, and no per-descendant conhost flashes (the
    console-less pythonw.exe alternative re-created #54220/#56747 for every
    console-subsystem child). All operator decisions are already collected in
    the parent shell before this point.
    """
    _assert_windows()
    args = ["-m", "hermes_cli.main", *_current_profile_cli_args(), "gateway", command]
    if extra_args:
        args.extend(extra_args)
    params = subprocess.list2cmdline(args)
    cwd = str(Path(__file__).resolve().parent.parent)
    elevated_python = sys.executable
    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            elevated_python,
            params,
            cwd,
            0,  # SW_HIDE: the child's console exists but is never shown.
        )
    except Exception as exc:
        print(f"⚠ Could not launch elevated gateway {command} prompt: {exc}")
        return False
    if result <= 32:
        print(f"⚠ Elevated gateway {command} prompt was not started (ShellExecuteW={result})")
        return False
    return True


def _launch_elevated_install(
    force: bool = False,
    *,
    start_now: bool | None = None,
    start_on_login: bool | None = None,
    install_disabled: bool = False,
) -> bool:
    """Launch an elevated gateway install via UAC and return True on handoff."""
    old_start_now = os.environ.get("HERMES_GATEWAY_INSTALL_START_NOW")
    old_start_on_login = os.environ.get("HERMES_GATEWAY_INSTALL_START_ON_LOGIN")
    old_handoff = os.environ.get("HERMES_GATEWAY_ELEVATED_HANDOFF")
    try:
        if start_now is not None:
            os.environ["HERMES_GATEWAY_INSTALL_START_NOW"] = "1" if start_now else "0"
        if start_on_login is not None:
            os.environ["HERMES_GATEWAY_INSTALL_START_ON_LOGIN"] = "1" if start_on_login else "0"
        os.environ["HERMES_GATEWAY_ELEVATED_HANDOFF"] = "1"
        extra_args = ["--elevated-handoff"]
        if force:
            extra_args.append("--force")
        if start_now is not None:
            extra_args.append("--start-now" if start_now else "--no-start-now")
        if start_on_login is not None:
            extra_args.append("--start-on-login" if start_on_login else "--no-start-on-login")
        if install_disabled:
            extra_args.append("--install-disabled")
        return _launch_elevated_gateway_command("install", extra_args)
    finally:
        for key, old in (
            ("HERMES_GATEWAY_INSTALL_START_NOW", old_start_now),
            ("HERMES_GATEWAY_INSTALL_START_ON_LOGIN", old_start_on_login),
            ("HERMES_GATEWAY_ELEVATED_HANDOFF", old_handoff),
        ):
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


def _launch_elevated_uninstall() -> bool:
    """Launch an elevated gateway uninstall via UAC and return True on handoff."""
    return _launch_elevated_gateway_command("uninstall")


# ---------------------------------------------------------------------------
# Paths: where we stash our task script and where Startup lives
# ---------------------------------------------------------------------------

def get_task_name() -> str:
    """Scheduled Task name, scoped per profile.

    Default profile: ``Hermes_Gateway``
    Named profile X: ``Hermes_Gateway_<X>``
    """
    _assert_windows()
    # Local import to avoid circular module initialization during hermes_cli boot.
    from hermes_cli.gateway import _profile_suffix

    suffix = _profile_suffix()
    if not suffix:
        return _TASK_NAME_DEFAULT
    return f"{_TASK_NAME_DEFAULT}_{suffix}"


def _sanitize_filename(value: str) -> str:
    """Remove characters illegal in Windows filenames."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value)


def get_task_script_path() -> Path:
    """The generated ``gateway.cmd`` wrapper kept beside the VBS launcher.

    Lives under ``%LOCALAPPDATA%\\hermes\\gateway-service\\<task_name>.cmd``
    (or ``<HERMES_HOME>/gateway-service/<task_name>.cmd`` so per-profile
    Hermes installs stay self-contained).
    """
    _assert_windows()
    script_path = _expected_task_script_path()
    script_path.parent.mkdir(parents=True, exist_ok=True)
    return script_path


def _expected_task_script_path() -> Path:
    """Return this profile's task script path without creating directories."""
    from hermes_cli.config import get_hermes_home

    script_dir = Path(get_hermes_home()) / "gateway-service"
    return script_dir / f"{_sanitize_filename(get_task_name())}.cmd"


def _startup_dir() -> Path:
    return _known_folder_path(_FOLDERID_STARTUP, "Startup")


def get_startup_entry_path() -> Path:
    _assert_windows()
    return _startup_dir() / f"{_sanitize_filename(get_task_name())}.vbs"


def _legacy_startup_entry_path() -> Path:
    _assert_windows()
    return _startup_dir() / f"{_sanitize_filename(get_task_name())}.cmd"


# ---------------------------------------------------------------------------
# Stable working directory
# ---------------------------------------------------------------------------

def _stable_gateway_working_dir(project_root: Path) -> str:
    """Return a stable cwd for detached/startup gateway runs.

    Mirror the POSIX service invariant: anchor at ``HERMES_HOME`` whenever it
    exists so Scheduled Task / Startup launches do not fail at the ``cd`` step
    after a transient checkout or worktree is moved away. Fall back to the
    source checkout only if ``HERMES_HOME`` cannot be used yet. Preserve the
    configured spelling instead of resolving symlinks so AppData installs backed
    by a junction/symlink still identify themselves as AppData.
    """
    from hermes_cli.config import get_hermes_home

    try:
        home = get_hermes_home()
        if home:
            home_path = Path(home)
            if home_path.is_dir():
                return str(home_path)
    except Exception:
        pass
    return str(project_root)


# ---------------------------------------------------------------------------
# Script rendering
# ---------------------------------------------------------------------------

def _add_gateway_launch_env_lock(
    env_overlay: dict[str, str],
    working_dir: str,
) -> str:
    """Add the private process-local provenance lock for detached gateways."""
    # Local import keeps this Windows backend importable during early recovery
    # without eagerly pulling python-dotenv into maintenance commands.
    from hermes_cli.env_loader import (
        _GATEWAY_LAUNCH_ENV_LOCK_VAR,
        _encode_gateway_launch_env_lock,
    )

    env_overlay[_GATEWAY_LAUNCH_ENV_LOCK_VAR] = _encode_gateway_launch_env_lock(
        env_overlay,
        working_dir,
    )
    return _GATEWAY_LAUNCH_ENV_LOCK_VAR


def _gateway_runtime_path_overlay() -> dict[str, str]:
    """Return the opt-in, immutable Windows runtime PATH overlay.

    Standalone Hermes keeps its historical inherited-PATH behaviour when the
    input is absent.  A managed install that provides the input gets the exact
    same value baked into both the public source variable and ``PATH`` for
    every launcher/respawn path.  Validation is intentionally syntactic here;
    the embedding runtime owns directory existence and payload attestation.
    """
    name = "HERMES_GATEWAY_RUNTIME_PATH"
    if name not in os.environ:
        return {}
    value = os.environ[name]
    if (
        not value
        or any(char in value for char in ("\x00", "\r", "\n", '"', "%", "!"))
    ):
        raise ValueError(f"{name} is empty or unsafe for a Windows launcher")

    entries = value.split(";")
    if any(not entry or entry != entry.strip() for entry in entries):
        raise ValueError(f"{name} must contain non-empty unpadded path entries")
    normalized: set[str] = set()
    for entry in entries:
        if not ntpath.isabs(entry):
            raise ValueError(f"{name} contains a non-absolute path entry: {entry!r}")
        if any(part in {".", ".."} for part in entry.replace("/", "\\").split("\\")):
            raise ValueError(f"{name} contains a relative path segment: {entry!r}")
        key = ntpath.normcase(ntpath.normpath(entry))
        if key in normalized:
            raise ValueError(f"{name} contains a duplicate path entry: {entry!r}")
        normalized.add(key)
    return {name: value, "PATH": value}


def _gateway_managed_launch_overlay() -> dict[str, str]:
    """Return the complete managed path + validator provenance.

    Gladly embedding is detected from the imported checkout. Public variables
    may confirm that contract, but their absence can never downgrade a managed
    install into the standalone launcher path.
    """
    from hermes_cli.env_loader import (
        _GATEWAY_MANAGED_PROVENANCE_ENV_KEYS,
        _managed_install_contract,
        _same_evidence_path,
        _validate_gateway_managed_launch_values,
    )

    contract = _managed_install_contract()
    opt_in_keys = (
        "HERMES_GATEWAY_RUNTIME_PATH",
        *_GATEWAY_MANAGED_PROVENANCE_ENV_KEYS,
    )
    if contract is None and not any(key in os.environ for key in opt_in_keys):
        return {}
    if contract is not None:
        expected = contract.get("managedValues")
        if not isinstance(expected, dict):
            raise ValueError("managed Gladly install contract is incomplete")
        for key in opt_in_keys:
            supplied = os.environ.get(key)
            if supplied is None:
                continue
            expected_value = expected.get(key)
            if key == "HERMES_GATEWAY_START_VALIDATOR":
                if not isinstance(expected_value, str) or not _same_evidence_path(
                    supplied,
                    expected_value,
                ):
                    raise ValueError(
                        "public managed validator redirects outside the receipt-bound install"
                    )
            elif supplied != expected_value:
                raise ValueError(f"public managed launch value {key} differs from receipt evidence")
        return _validate_gateway_managed_launch_values(expected)
    # Keep the path-specific diagnostics from the renderer, then apply the
    # complete v3 contract (which rejects partial provenance and mismatches).
    _gateway_runtime_path_overlay()
    return _validate_gateway_managed_launch_values(os.environ)


def _gateway_task_interpreter() -> str:
    """Return the task's reviewed VBScript interpreter.

    Legacy/standalone installs keep the historical system-resolved basename.
    A sealed managed runtime uses the exact System32 executable and requires
    that directory to be present in its reviewed PATH policy.
    """
    overlay = _gateway_managed_launch_overlay()
    if not overlay:
        return "wscript.exe"
    interpreter = _stable_system_executable("wscript.exe")
    system32 = ntpath.normcase(ntpath.dirname(interpreter))
    reviewed_directories = {
        ntpath.normcase(ntpath.normpath(entry))
        for entry in overlay["PATH"].split(";")
    }
    if system32 not in reviewed_directories:
        raise ValueError("sealed gateway PATH does not contain System32")
    path = Path(interpreter)
    try:
        status = path.lstat()
    except OSError as exc:
        raise ValueError("sealed gateway task interpreter is missing") from exc
    if path.is_symlink() or not path.is_file() or bool(
        getattr(status, "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("sealed gateway task interpreter is not a regular file")
    return str(path)


def _build_gateway_cmd_script(
    python_path: str,
    working_dir: str,
    hermes_home: str,
    profile_arg: str,
    *,
    code_root: str | None = None,
) -> str:
    """Build the ``gateway.cmd`` wrapper content (CRLF-terminated).

    The script:
      - cd's into a stable working directory
      - pins HERMES_HOME/HERMES_RUNTIME_HOME and the reviewed code root
      - exports UTF-8 locale/Python flags and VIRTUAL_ENV
      - invokes ``python -m hermes_cli.main [--profile X] gateway run``

    The .cmd is a compatibility/manual-run artifact: service persistence
    (Scheduled Task, Startup folder) routes through the ``.vbs`` launcher,
    which runs this same command line hidden (window style 0).  Run by hand
    in a real terminal, the console interpreter keeps the gateway attached
    to that terminal like a normal foreground ``hermes gateway run``.

    Standalone installs retain the inherited PATH. Managed installs may set
    ``HERMES_GATEWAY_RUNTIME_PATH`` to opt into an exact, immutable PATH that
    is rendered and launch-locked here.
    """
    lines = ["@echo off", f"rem {_TASK_DESCRIPTION}"]
    managed_overlay = _gateway_managed_launch_overlay()
    if managed_overlay:
        # The compatibility CMD artifact must not start Python with its ambient
        # cmd.exe environment. Route it through the exact reviewed wscript +
        # sibling VBS launcher; that launcher builds a from-empty allowlist
        # before it creates the gateway process. Scheduled Task/ONLOGON already
        # enters through this same VBS path directly.
        interpreter = _gateway_task_interpreter()
        lines.append(
            " ".join(
                (
                    _quote_cmd_script_arg(interpreter),
                    "//B",
                    "//Nologo",
                    '"%~dpn0.vbs"',
                )
            )
        )
        lines.append("exit /b %errorlevel%")
        return "\r\n".join(lines) + "\r\n"

    lines.append(f"cd /d {_quote_cmd_script_arg(working_dir)}")
    code_root = code_root or _preserve_hermes_home_path(
        Path(__file__).resolve().parent.parent
    )
    lines.append(f'set "HERMES_HOME={hermes_home}"')
    lines.append(f'set "HERMES_RUNTIME_HOME={hermes_home}"')
    lines.append(f'set "GLADLY_HERMES_CODE_ROOT={code_root}"')
    lines.append('set "LANG=C.UTF-8"')
    lines.append('set "LC_ALL=C.UTF-8"')
    lines.append('set "PYTHONUTF8=1"')
    lines.append('set "PYTHONIOENCODING=utf-8"')
    lines.append('set "HERMES_GATEWAY_DETACHED=1"')
    python_exe_path, venv_dir, extra_pythonpath = _resolve_detached_python(python_path)
    # VIRTUAL_ENV lets the gateway's own python detection find the venv
    # if someone imports hermes_constants-based logic during startup.
    lines.append(f'set "VIRTUAL_ENV={_preserve_hermes_home_path(venv_dir)}"')
    pythonpath_entries = [
        _preserve_hermes_home_path(Path(__file__).resolve().parent.parent),
        *[_preserve_hermes_home_path(entry) for entry in extra_pythonpath],
    ]
    # Never inherit a user-level PYTHONPATH into the service.  A stale checkout
    # there can otherwise shadow the reviewed module tree baked at install.
    static_pythonpath = ";".join(pythonpath_entries)
    lines.append(f'set "PYTHONPATH={static_pythonpath}"')
    launch_env = {
        "HERMES_HOME": hermes_home,
        "HERMES_RUNTIME_HOME": hermes_home,
        "GLADLY_HERMES_CODE_ROOT": code_root,
        "PYTHONPATH": static_pythonpath,
        "VIRTUAL_ENV": _preserve_hermes_home_path(venv_dir),
    }
    runtime_path_overlay = managed_overlay
    launch_env.update(runtime_path_overlay)
    for key in ("HERMES_GATEWAY_RUNTIME_PATH", "PATH"):
        if key in runtime_path_overlay:
            lines.append(f'set "{key}={runtime_path_overlay[key]}"')
    lock_name = _add_gateway_launch_env_lock(launch_env, working_dir)
    lock_value = launch_env[lock_name]
    lines.append(f'set "{lock_name}={lock_value}"')

    prog_args = [python_exe_path, "-m", "hermes_cli.main"]
    if profile_arg:
        prog_args.extend(profile_arg.split())
    prog_args.extend(["gateway", "run"])
    # Do NOT use `start` here; that creates an extra wrapper process and made
    # gateway lifecycle/status harder to reason about.
    # Do NOT use `--replace` for service-managed starts; repeated /Run calls
    # should be idempotent, not churn parent/child takeover loops.
    lines.append(" ".join(_quote_cmd_script_arg(a) for a in prog_args))
    lines.append("exit /b 0")
    return "\r\n".join(lines) + "\r\n"


def _quote_vbs_string(value: str) -> str:
    """Quote a value as a VBScript double-quoted string literal.

    VBScript escapes an embedded double-quote by doubling it. A newline cannot
    appear inside a literal, so refuse it (same guard as ``_quote_cmd_script_arg``).
    """
    if "\r" in value or "\n" in value:
        raise ValueError(f"refusing to quote VBScript value containing newline: {value!r}")
    return '"' + value.replace('"', '""') + '"'


def _build_gateway_vbs_script(
    python_path: str,
    working_dir: str,
    hermes_home: str,
    profile_arg: str,
    *,
    code_root: str | None = None,
) -> str:
    """Build a hidden-console ``gateway.vbs`` launcher (CRLF-terminated).

    The Scheduled Task runs this through ``wscript.exe`` instead of ``cmd.exe``.

    Why: issue #45599 root cause #1. Driving the gateway through ``cmd.exe``
    allocates a console, and during logon Windows broadcasts ``CTRL_CLOSE_EVENT``
    to console process groups — reaping cmd.exe and the half-initialized gateway
    with ``STATUS_CONTROL_C_EXIT`` (``0xC000013A``). Task Scheduler treats that
    code as a user cancel, so the ``RestartOnFailure`` policy never fires and the
    gateway silently disappears on every reboot.

    ``wscript.exe`` is a GUI-subsystem executable with no console, so this
    launcher receives no console control events. It ``Run``s the console
    ``python.exe`` with window style 0 (hidden): the gateway owns a single
    hidden console — never shown, never CTRL_CLOSE'd at logon, and inherited
    by every console-subsystem descendant (git, gh, node, …) so none of them
    allocate a visible flashing conhost (#54220/#56747; the previous
    console-less pythonw.exe gateway forced exactly that per-descendant
    flash). No cmd.exe anywhere in the chain. Mirrors
    ``_build_gateway_cmd_script`` (same env + argv via
    ``_resolve_detached_python``).
    """
    python_exe_path, venv_dir, extra_pythonpath = _resolve_detached_python(python_path)

    prog_args = [python_exe_path, "-m", "hermes_cli.main"]
    if profile_arg:
        prog_args.extend(profile_arg.split())
    prog_args.extend(["gateway", "run"])
    # list2cmdline gives CreateProcess-correct quoting for WScript.Shell.Run.
    command_line = subprocess.list2cmdline(prog_args)

    repo_root = _preserve_hermes_home_path(Path(__file__).resolve().parent.parent)
    static_pythonpath = os.pathsep.join(
        [repo_root, *[_preserve_hermes_home_path(entry) for entry in extra_pythonpath]]
    )
    code_root = code_root or repo_root
    launch_env = {
        "HERMES_HOME": hermes_home,
        "HERMES_RUNTIME_HOME": hermes_home,
        "GLADLY_HERMES_CODE_ROOT": code_root,
        "PYTHONPATH": static_pythonpath,
        "VIRTUAL_ENV": _preserve_hermes_home_path(venv_dir),
    }
    runtime_path_overlay = _gateway_managed_launch_overlay()
    launch_env.update(runtime_path_overlay)
    lock_name = _add_gateway_launch_env_lock(launch_env, working_dir)
    lock_value = launch_env[lock_name]

    if runtime_path_overlay:
        complete_launch_values = {
            **launch_env,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "HERMES_GATEWAY_DETACHED": "1",
        }
        child_env = _managed_gateway_child_environment(complete_launch_values)
        allowed_names = "|" + "|".join(
            sorted((key.upper() for key in child_env), key=str.casefold)
        ) + "|"
        lines = [
            f"' {_TASK_DESCRIPTION}",
            "Option Explicit",
            "Dim sh, env, inheritedEntry, inheritedName, equalsAt, keyCount, keyIndex, allowedNames",
            "Dim inheritedKeys()",
            'Set sh = CreateObject("WScript.Shell")',
            'Set env = sh.Environment("PROCESS")',
            "keyCount = -1",
            "For Each inheritedEntry In env",
            '  equalsAt = InStr(2, inheritedEntry, "=")',
            "  If equalsAt > 1 Then",
            "    inheritedName = Left(inheritedEntry, equalsAt - 1)",
            "    keyCount = keyCount + 1",
            "    ReDim Preserve inheritedKeys(keyCount)",
            "    inheritedKeys(keyCount) = inheritedName",
            "  End If",
            "Next",
            "On Error Resume Next",
            "For keyIndex = 0 To keyCount",
            "  env.Remove inheritedKeys(keyIndex)",
            "Next",
            "On Error GoTo 0",
            *[
                f"env.Item({_quote_vbs_string(key)}) = {_quote_vbs_string(value)}"
                for key, value in sorted(child_env.items(), key=lambda item: item[0].casefold())
            ],
            f"allowedNames = {_quote_vbs_string(allowed_names)}",
            "For Each inheritedEntry In env",
            '  equalsAt = InStr(2, inheritedEntry, "=")',
            "  If equalsAt > 1 Then",
            "    inheritedName = Left(inheritedEntry, equalsAt - 1)",
            '    If InStr(1, allowedNames, "|" & UCase(inheritedName) & "|", 1) = 0 Then',
            "      WScript.Quit 87",
            "    End If",
            "  End If",
            "Next",
            f"sh.CurrentDirectory = {_quote_vbs_string(working_dir)}",
            f"sh.Run {_quote_vbs_string(command_line)}, 0, False",
        ]
        return "\r\n".join(lines) + "\r\n"

    lines = [
        f"' {_TASK_DESCRIPTION}",
        "Option Explicit",
        "Dim sh, env",
        'Set sh = CreateObject("WScript.Shell")',
        'Set env = sh.Environment("PROCESS")',
        f"env.Item({_quote_vbs_string('HERMES_HOME')}) = {_quote_vbs_string(hermes_home)}",
        f"env.Item({_quote_vbs_string('HERMES_RUNTIME_HOME')}) = {_quote_vbs_string(hermes_home)}",
        f"env.Item({_quote_vbs_string('GLADLY_HERMES_CODE_ROOT')}) = {_quote_vbs_string(code_root)}",
        f"env.Item({_quote_vbs_string('LANG')}) = {_quote_vbs_string('C.UTF-8')}",
        f"env.Item({_quote_vbs_string('LC_ALL')}) = {_quote_vbs_string('C.UTF-8')}",
        f"env.Item({_quote_vbs_string('PYTHONUTF8')}) = {_quote_vbs_string('1')}",
        f"env.Item({_quote_vbs_string('PYTHONIOENCODING')}) = {_quote_vbs_string('utf-8')}",
        f"env.Item({_quote_vbs_string('HERMES_GATEWAY_DETACHED')}) = {_quote_vbs_string('1')}",
        f"env.Item({_quote_vbs_string('VIRTUAL_ENV')}) = {_quote_vbs_string(_preserve_hermes_home_path(venv_dir))}",
        # Replace, rather than extend, inherited PYTHONPATH.  This prevents a
        # stale user/worktree path from shadowing the reviewed install.
        f"env.Item({_quote_vbs_string('PYTHONPATH')}) = {_quote_vbs_string(static_pythonpath)}",
        *[
            f"env.Item({_quote_vbs_string(key)}) = {_quote_vbs_string(runtime_path_overlay[key])}"
            for key in ("HERMES_GATEWAY_RUNTIME_PATH", "PATH")
            if key in runtime_path_overlay
        ],
        f"env.Item({_quote_vbs_string(lock_name)}) = {_quote_vbs_string(lock_value)}",
        f"sh.CurrentDirectory = {_quote_vbs_string(working_dir)}",
        # Window style 0 = hidden; bWaitOnReturn False = detached/async. The
        # console python's one console is created hidden and inherited by all
        # descendants, so nothing ever flashes.
        f"sh.Run {_quote_vbs_string(command_line)}, 0, False",
    ]
    return "\r\n".join(lines) + "\r\n"


def _resolve_gateway_working_dir(project_root: Path, hermes_home: str) -> str:
    """Resolve a reviewed cwd for Windows service-managed gateway starts.

    Python searches its current directory before PYTHONPATH.  Therefore the
    production launcher must not honor inherited HERMES_GATEWAY_WORKING_DIR or
    use a writable runtime-home directory as cwd: either could shadow
    ``hermes_cli`` before the pinned module tree is considered.
    """
    return _resolve_gateway_code_root(project_root, hermes_home)


def _resolve_gateway_code_root(project_root: Path, hermes_home: str) -> str:
    """Return the reviewed repository root to bake into Gladly child jobs.

    An embedded Gladly checkout has ``<root>/home`` beside
    ``<root>/hermes-agent`` and the ``bin/gladly`` launcher.  Standalone
    Hermes installs fall back to the actual upstream checkout containing this
    module. Named profile homes are normalized from
    ``<root>/home/profiles/<name>`` back to ``<root>/home``. Junctioned homes
    are accepted only when the reviewed checkout's own ``home`` resolves to
    the same runtime root.

    The candidate Gladly root is derived from ``project_root``, never from
    HERMES_HOME. This proves that ``<candidate>/hermes-agent`` is the currently
    imported/reviewed tree and prevents an old, still-present checkout from
    redirecting cwd/code provenance. Inherited HERMES_GATEWAY_WORKING_DIR and
    GLADLY_HERMES_CODE_ROOT are intentionally ignored.
    """
    project_root = Path(project_root).resolve()
    home_path = Path(hermes_home).resolve()
    runtime_home_root = (
        home_path.parent.parent
        if home_path.parent.name.casefold() == "profiles"
        else home_path
    )
    candidate = project_root.parent
    try:
        if (
            (candidate / "hermes-agent").resolve() == project_root
            and (candidate / "home").is_dir()
            and (candidate / "home").resolve() == runtime_home_root.resolve()
            and (candidate / "bin" / "gladly").is_file()
        ):
            return str(candidate)
    except OSError:
        pass
    return str(project_root)


def _build_startup_launcher(script_path: Path) -> str:
    """The tiny .vbs that goes in the Startup folder and chains hidden.

    Defense-in-depth: bail out silently if the target script is gone. Test
    fixtures historically wrote Startup entries pointing at pytest tmp_path
    directories that vanish after the test session. Without the existence
    guard, every subsequent Windows login could attempt a stale launcher. The
    check + ``WScript.Quit 0`` keeps that case silent.
    """
    target = str(script_path.with_suffix(".vbs"))
    command = subprocess.list2cmdline(["wscript.exe", target])
    lines = [
        f"' {_TASK_DESCRIPTION}",
        "Option Explicit",
        "Dim fso, sh, target",
        f"target = {_quote_vbs_string(target)}",
        'Set fso = CreateObject("Scripting.FileSystemObject")',
        "If Not fso.FileExists(target) Then WScript.Quit 0",
        'Set sh = CreateObject("WScript.Shell")',
        f"sh.Run {_quote_vbs_string(command)}, 0, False",
    ]
    return "\r\n".join(lines) + "\r\n"


def _render_current_gateway_task_scripts() -> tuple[str, str]:
    """Render the exact CMD/VBS launchers for this reviewed install.

    Keeping ownership verification on the same renderer as writes makes the
    launcher itself the provenance proof. A shared HERMES_HOME path is not
    sufficient: another checkout can target the same filename while baking a
    different interpreter, cwd, code root, PYTHONPATH, or launch-env lock.
    """
    from hermes_cli.config import get_hermes_home
    from hermes_cli.gateway import PROJECT_ROOT, get_python_path

    python_path = _preserve_hermes_home_path(get_python_path())
    hermes_home = str(Path(get_hermes_home()).resolve())
    working_dir = _resolve_gateway_working_dir(PROJECT_ROOT, hermes_home)
    code_root = _resolve_gateway_code_root(PROJECT_ROOT, hermes_home)
    profile_arg = _locked_gateway_profile_arg(hermes_home)
    return (
        _build_gateway_cmd_script(
            python_path,
            working_dir,
            hermes_home,
            profile_arg,
            code_root=code_root,
        ),
        _build_gateway_vbs_script(
            python_path,
            working_dir,
            hermes_home,
            profile_arg,
            code_root=code_root,
        ),
    )


def _render_legacy_gateway_task_scripts_for_migration() -> tuple[str, str]:
    """Render the last pre-lock launcher generation for bounded migration.

    These bytes grant only ownership/migration rights; they are immediately
    replaced by the locked renderer during install/update. Inputs are derived
    from the current reviewed checkout and runtime home, so a same-home
    launcher baked by another checkout does not match. Older/unrecognized
    generations remain fail-closed and need explicit operator intervention.
    """
    from hermes_cli.config import get_hermes_home
    from hermes_cli.gateway import PROJECT_ROOT, _profile_arg, get_python_path

    python_path = _preserve_hermes_home_path(get_python_path())
    hermes_home = str(Path(get_hermes_home()).resolve())
    working_dir = _legacy_gateway_working_dir_for_migration(
        PROJECT_ROOT, hermes_home
    )
    profile_arg = _profile_arg(hermes_home)
    python_exe_path, venv_dir, extra_pythonpath = _resolve_detached_python(
        python_path
    )
    repo_root = _preserve_hermes_home_path(Path(__file__).resolve().parent.parent)
    pythonpath_entries = [
        repo_root,
        *[_preserve_hermes_home_path(entry) for entry in extra_pythonpath],
    ]
    prog_args = [python_exe_path, "-m", "hermes_cli.main"]
    if profile_arg:
        prog_args.extend(profile_arg.split())
    prog_args.extend(["gateway", "run"])

    cmd_lines = [
        "@echo off",
        f"rem {_TASK_DESCRIPTION}",
        f"cd /d {_quote_cmd_script_arg(working_dir)}",
        f'set "HERMES_HOME={hermes_home}"',
        'set "LANG=C.UTF-8"',
        'set "LC_ALL=C.UTF-8"',
        'set "PYTHONUTF8=1"',
        'set "PYTHONIOENCODING=utf-8"',
        'set "HERMES_GATEWAY_DETACHED=1"',
        f'set "VIRTUAL_ENV={_preserve_hermes_home_path(venv_dir)}"',
        f'set "PYTHONPATH={";".join([*pythonpath_entries, "%PYTHONPATH%"])}"',
        " ".join(_quote_cmd_script_arg(arg) for arg in prog_args),
        "exit /b 0",
    ]

    static_pythonpath = os.pathsep.join(pythonpath_entries)
    command_line = subprocess.list2cmdline(prog_args)
    vbs_lines = [
        f"' {_TASK_DESCRIPTION}",
        "Option Explicit",
        "Dim sh, env, existing_pp",
        'Set sh = CreateObject("WScript.Shell")',
        'Set env = sh.Environment("PROCESS")',
        f"env.Item({_quote_vbs_string('HERMES_HOME')}) = {_quote_vbs_string(hermes_home)}",
        f"env.Item({_quote_vbs_string('LANG')}) = {_quote_vbs_string('C.UTF-8')}",
        f"env.Item({_quote_vbs_string('LC_ALL')}) = {_quote_vbs_string('C.UTF-8')}",
        f"env.Item({_quote_vbs_string('PYTHONUTF8')}) = {_quote_vbs_string('1')}",
        f"env.Item({_quote_vbs_string('PYTHONIOENCODING')}) = {_quote_vbs_string('utf-8')}",
        f"env.Item({_quote_vbs_string('HERMES_GATEWAY_DETACHED')}) = {_quote_vbs_string('1')}",
        f"env.Item({_quote_vbs_string('VIRTUAL_ENV')}) = {_quote_vbs_string(_preserve_hermes_home_path(venv_dir))}",
        f"existing_pp = env.Item({_quote_vbs_string('PYTHONPATH')})",
        "If Len(existing_pp) > 0 Then",
        f"  env.Item({_quote_vbs_string('PYTHONPATH')}) = {_quote_vbs_string(static_pythonpath + os.pathsep)} & existing_pp",
        "Else",
        f"  env.Item({_quote_vbs_string('PYTHONPATH')}) = {_quote_vbs_string(static_pythonpath)}",
        "End If",
        f"sh.CurrentDirectory = {_quote_vbs_string(working_dir)}",
        f"sh.Run {_quote_vbs_string(command_line)}, 0, False",
    ]
    return (
        "\r\n".join(cmd_lines) + "\r\n",
        "\r\n".join(vbs_lines) + "\r\n",
    )


def _legacy_gateway_working_dir_for_migration(
    project_root: Path,
    hermes_home: str,
) -> str:
    """Reproduce the safe, deterministic part of the pre-lock cwd rules.

    The old generation used the Gladly parent only for a literal ``home``
    sibling of its imported ``hermes-agent`` tree. Named profiles and
    standalone installs fell back to their existing HERMES_HOME. An inherited
    HERMES_GATEWAY_WORKING_DIR override cannot be proven later and is
    deliberately not migration-owned.
    """
    project_root = Path(project_root).resolve()
    home_path = Path(hermes_home).resolve()
    parent = home_path.parent
    try:
        if (
            home_path.name.casefold() == "home"
            and (parent / "hermes-agent").resolve() == project_root
        ):
            return str(parent)
    except OSError:
        pass
    if home_path.is_dir():
        return str(home_path)
    return str(project_root)


def _normalize_generated_script(content: str) -> str:
    return content.lstrip("\ufeff").replace("\r\n", "\n")


def _gateway_launcher_belongs_to_current_install(path: Path) -> bool:
    """Prove a task target is the complete launcher rendered by this code.

    Legacy task/Startup actions are accepted only when their CMD target is an
    exact current render. Unlocked or otherwise unverifiable legacy launchers
    fail closed and require explicit operator migration; path equality alone
    never grants mutation authority.
    """
    expected_path = _expected_task_script_path()
    suffix = path.suffix.casefold()
    if suffix == ".vbs":
        expected_path = expected_path.with_suffix(".vbs")
        expected_index = 1
    elif suffix == ".cmd":
        expected_index = 0
    else:
        return False
    if not _same_windows_path(path, expected_path):
        return False
    try:
        actual = path.read_text(encoding="utf-8")
        expected = _render_current_gateway_task_scripts()[expected_index]
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return False
    normalized_actual = _normalize_generated_script(actual)
    if normalized_actual == _normalize_generated_script(expected):
        return True
    try:
        legacy = _render_legacy_gateway_task_scripts_for_migration()[expected_index]
    except (OSError, RuntimeError, ValueError):
        return False
    return normalized_actual == _normalize_generated_script(legacy)


def _write_task_script() -> Path:
    """Generate and write the gateway.cmd wrapper. Return its absolute path."""
    _assert_windows()
    content, vbs_content = _render_current_gateway_task_scripts()
    script_path = get_task_script_path()
    tmp = script_path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8", newline="")
    tmp.replace(script_path)

    # Also render the console-less .vbs launcher used by Scheduled Task and the
    # Startup-folder fallback via wscript.exe (issue #45599 fix A). The .cmd
    # wrapper stays as a generated helper/compatibility artifact.
    vbs_path = script_path.with_suffix(".vbs")
    vbs_tmp = vbs_path.with_name(vbs_path.name + ".tmp")
    vbs_tmp.write_text(vbs_content, encoding="utf-8", newline="")
    vbs_tmp.replace(vbs_path)
    return script_path


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------

def _resolve_task_user() -> str | None:
    """Return the current Windows identity without trusting mutable env."""
    if sys.platform == "win32":
        # NameSamCompatible returns DOMAIN\\USER and is accepted by Task
        # Scheduler. The first call obtains the required UTF-16 buffer size.
        required = ctypes.c_ulong(0)
        ctypes.windll.secur32.GetUserNameExW(2, None, ctypes.byref(required))
        if required.value:
            buffer = ctypes.create_unicode_buffer(required.value)
            if ctypes.windll.secur32.GetUserNameExW(
                2, buffer, ctypes.byref(required)
            ):
                value = buffer.value.strip()
                if value:
                    return value
        required = ctypes.c_ulong(32768)
        buffer = ctypes.create_unicode_buffer(required.value)
        if ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(required)):
            value = buffer.value.strip()
            if value:
                return value

    # Keep imports and host-independent tests functional off Windows.
    username = os.environ.get("USERNAME") or os.environ.get("USER") or os.environ.get("LOGNAME")
    if not username:
        return None
    if "\\" in username:
        return username
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{username}" if domain else username


def _resolve_task_user_sid() -> str | None:
    """Return the current process-token user's SID via trusted Windows APIs.

    Task Scheduler accepts the ``DOMAIN\\user`` spelling written during task
    registration, but exports that principal as its SID. Read the SID from the
    current process token instead of resolving mutable environment text or
    accepting an arbitrary SID found in exported XML.
    """
    if sys.platform != "win32":
        return None

    try:
        from ctypes import wintypes

        class _SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = (
                ("Sid", ctypes.c_void_p),
                ("Attributes", wintypes.DWORD),
            )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel32.LocalFree.restype = wintypes.HLOCAL
        advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

        token = wintypes.HANDLE()
        token_query = 0x0008
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)
        ):
            return None
        try:
            required = wintypes.DWORD(0)
            token_user = 1
            advapi32.GetTokenInformation(
                token, token_user, None, 0, ctypes.byref(required)
            )
            if not required.value:
                return None
            buffer = ctypes.create_string_buffer(required.value)
            if not advapi32.GetTokenInformation(
                token,
                token_user,
                buffer,
                required.value,
                ctypes.byref(required),
            ):
                return None
            sid = ctypes.cast(
                buffer, ctypes.POINTER(_SID_AND_ATTRIBUTES)
            ).contents.Sid
            if not sid:
                return None
            sid_text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
                return None
            try:
                value = (sid_text.value or "").strip()
                return value or None
            finally:
                if sid_text:
                    kernel32.LocalFree(ctypes.cast(sid_text, wintypes.HLOCAL))
        finally:
            kernel32.CloseHandle(token)
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _build_scheduled_task_xml(
    task_name: str,
    launcher_path: Path,
    user: str | None,
    *,
    enabled: bool = True,
) -> str:
    """Render a Task Scheduler XML definition with safe long-running defaults.

    ``launcher_path`` is the console-less ``.vbs`` the task runs via
    ``wscript.exe`` — not the ``.cmd`` (see ``_build_gateway_vbs_script`` /
    issue #45599 root cause #1).
    """
    user_principal = f"\n      <UserId>{escape(user)}</UserId>" if user else ""
    task_enabled = "true" if enabled else "false"
    task_interpreter = _gateway_task_interpreter()
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{escape(_TASK_DESCRIPTION)}</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>{_TASK_LOGON_DELAY}</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">{user_principal}
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>{task_enabled}</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>{_TASK_RESTART_INTERVAL}</Interval>
      <Count>{_TASK_RESTART_COUNT}</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(task_interpreter)}</Command>
      <Arguments>//B //Nologo "{escape(str(launcher_path))}"</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _write_scheduled_task_xml(
    task_name: str,
    launcher_path: Path,
    user: str | None,
    *,
    enabled: bool = True,
) -> Path:
    xml_path = launcher_path.with_suffix(".task.xml")
    xml_path.write_text(
        _build_scheduled_task_xml(task_name, launcher_path, user, enabled=enabled),
        encoding="utf-16",
        newline="",
    )
    return xml_path


def _install_scheduled_task(
    task_name: str,
    script_path: Path,
    *,
    enabled: bool = True,
) -> tuple[bool, str]:
    """Create or replace the Scheduled Task. Returns (success, detail).

    Always recreate instead of ``/Change``. Older Hermes builds and failed
    experiments may have left repeat/restart settings on the task; ``/Change``
    preserves those stale triggers and can make the gateway relaunch every
    minute. Delete+create gives us a clean ONLOGON task every install.
    """
    delete_code, delete_out, delete_err = _exec_schtasks(["/Delete", "/F", "/TN", task_name])
    delete_detail = (delete_err or delete_out or "").strip()
    if delete_code != 0 and delete_detail and "cannot find" not in delete_detail.lower():
        if _is_access_denied(delete_detail):
            return (False, f"schtasks /Delete failed (code {delete_code}): {delete_detail}")
        # Non-fatal: /Create /F below may still replace it. Keep the detail in
        # the final error if creation also fails.
    user = _resolve_task_user()
    # The Scheduled Task launches the console-less .vbs (issue #45599 fix A), not
    # the .cmd. Immediate manual starts use _spawn_detached().
    launcher_path = script_path.with_suffix(".vbs")
    # The enabled state lives in the XML passed to /Create, so a staged task is
    # disabled at registration time.  Never create enabled and race a later
    # ``schtasks /Change /Disable`` call.
    xml_path = _write_scheduled_task_xml(
        task_name,
        launcher_path,
        user,
        enabled=enabled,
    )
    base = ["/Create", "/F", "/TN", task_name, "/XML", str(xml_path)]
    variants = [[*base, "/RU", user, "/NP", "/IT"]] if user else []
    variants.append(base)

    last_code = 1
    last_err = ""
    try:
        for argv in variants:
            code, out, err = _exec_schtasks(argv)
            if code == 0:
                state = "enabled" if enabled else "disabled"
                return (True, f"Created Scheduled Task {task_name!r} ({state})")
            last_code, last_err = code, (err or out or "")
    finally:
        try:
            xml_path.unlink(missing_ok=True)
        except OSError:
            pass
    if delete_detail and "cannot find" not in delete_detail.lower():
        last_err = f"{last_err.strip()} (delete detail: {delete_detail})"
    return (False, f"schtasks /Create failed (code {last_code}): {last_err.strip()}")




def _install_startup_entry(script_path: Path) -> Path:
    """Write the Startup-folder fallback launcher. Returns its path."""
    entry = get_startup_entry_path()
    legacy_entry = _legacy_startup_entry_path()
    if entry.exists() and not _current_startup_entry_belongs_to_current_profile():
        raise RuntimeError(
            f"Refusing to replace foreign same-name Startup launcher: {entry}"
        )
    if legacy_entry.exists() and not _legacy_startup_entry_belongs_to_current_profile():
        raise RuntimeError(
            f"Refusing to remove foreign same-name Startup launcher: {legacy_entry}"
        )
    entry.parent.mkdir(parents=True, exist_ok=True)
    tmp = entry.with_suffix(".tmp")
    tmp.write_text(_build_startup_launcher(script_path), encoding="utf-8", newline="")
    tmp.replace(entry)
    try:
        if legacy_entry.exists():
            legacy_entry.unlink()
    except OSError:
        pass
    return entry


def _remove_startup_fallback_entries() -> None:
    """Remove profile-scoped Startup fallbacks before a disabled task install.

    A disabled Scheduled Task is not a quarantine if an older Startup-folder
    launcher can still run the same gateway at login.  Refuse to report a
    successful staged install unless both current and legacy entries are gone.
    """
    failures = []
    entries = (
        (
            get_startup_entry_path(),
            _current_startup_entry_belongs_to_current_profile,
        ),
        (
            _legacy_startup_entry_path(),
            _legacy_startup_entry_belongs_to_current_profile,
        ),
    )
    for path, belongs_to_current_profile in entries:
        try:
            if path.exists() and not belongs_to_current_profile():
                raise RuntimeError(
                    f"same-name launcher belongs to another installation: {path}"
                )
            path.unlink(missing_ok=True)
        except (OSError, RuntimeError) as exc:
            failures.append(f"{path}: {exc}")
    if failures:
        raise RuntimeError(
            "Could not remove an existing Windows Startup gateway launcher: "
            + "; ".join(failures)
        )


def _resolve_detached_python(python_exe: str) -> tuple[str, Path, list[str]]:
    """Return (hidden_console_python, venv_dir, extra_pythonpath) for detached runs.

    Returns the venv's **console** ``python.exe`` — deliberately NOT
    ``pythonw.exe``.  Every detached launch path pairs this interpreter with a
    hidden-console mechanism (``CREATE_NO_WINDOW`` creationflags, or
    ``WScript.Shell.Run`` window style 0), so the daemon owns a single hidden
    console that all of its console-subsystem descendants (git, gh, cmd, node,
    wmic, powershell, …) inherit instead of each allocating a visible flashing
    one.  A GUI-subsystem ``pythonw.exe`` daemon has NO console, which is what
    made every descendant spawn flash (#54220/#56747) and forced the endless
    per-call-site CREATE_NO_WINDOW sweep.  Root cause isolated + A/B verified
    on Windows 11 by the desktop backend fix (commit aa2ae36c3f).

    Two historical premises behind the old pythonw selection were re-tested on
    current Windows in that fix and did not hold up:

    - uv venv launcher: ``venv\\Scripts\\python.exe`` under ``CREATE_NO_WINDOW``
      re-execs the base interpreter *windowless* — the child inherits the
      shim's hidden console, so no conhost flashes (the #52239 concern).  The
      historical "CREATE_NO_WINDOW cannot suppress the second window"
      observations were made while ``DETACHED_PROCESS`` was in the flag
      bundle, where MSDN specifies CREATE_NO_WINDOW is IGNORED — the hide bit
      was dead, not ineffective.  The base-interpreter + PYTHONPATH-overlay
      detour is therefore unnecessary; the venv shim resolves imports itself.
    - Console python restores stdout/stderr, so daemon logs flow normally.

    ``extra_pythonpath`` is always empty now; the tuple shape is kept so the
    call sites (argv builders, cmd/vbs renderers, restart-spec rewriter,
    gateway watcher) stay unchanged.

    Legacy normalization: launchers and argv snapshots from pre-aa2ae36c3f
    installs lead with ``pythonw.exe``. When the sibling console
    ``python.exe`` exists, swap to it so respawns and regenerated launchers
    get the hidden-console design instead of resurrecting the console-less
    daemon (the #54220/#56747 flash class, plus the ``sys.stderr is None``
    startup-crash class from #71671).
    """
    p = Path(python_exe)
    if p.name.lower() in ("pythonw.exe", "pythonw"):
        sibling = p.with_name("python.exe" if p.suffix else "python")
        try:
            if sibling.exists():
                p = sibling
                python_exe = str(sibling)
        except OSError:
            # Can't stat the sibling — keep the original interpreter. A
            # console-less gateway is worse than a hidden-console one, but a
            # failed respawn is worse still.
            pass
    venv_dir = p.parent.parent
    return (python_exe, venv_dir, [])


def _prepend_pythonpath(env_overlay: dict[str, str], entries: list[str]) -> None:
    """Pin PYTHONPATH to reviewed entries without inheriting user overrides."""
    clean_entries = [entry for entry in entries if entry]
    if not clean_entries:
        return
    env_overlay["PYTHONPATH"] = os.pathsep.join(clean_entries)


def _build_gateway_argv() -> tuple[list[str], str, dict[str, str]]:
    """Build (argv, working_dir, env_overlay) for the gateway subprocess.

    Same logical command as what gateway.cmd runs, but assembled as a
    native argv for direct ``subprocess.Popen`` invocation — no cmd.exe
    layer in between.
    """
    _assert_windows()
    from hermes_cli.config import get_hermes_home
    from hermes_cli.gateway import PROJECT_ROOT, get_python_path

    python_exe, venv_dir, extra_pythonpath = _resolve_detached_python(
        _preserve_hermes_home_path(get_python_path())
    )
    project_root = _preserve_hermes_home_path(PROJECT_ROOT)
    hermes_home = str(Path(get_hermes_home()).resolve())
    working_dir = _resolve_gateway_working_dir(PROJECT_ROOT, hermes_home)
    code_root = _resolve_gateway_code_root(PROJECT_ROOT, hermes_home)
    profile_arg = _locked_gateway_profile_arg(hermes_home)

    argv = [python_exe, "-m", "hermes_cli.main"]
    if profile_arg:
        argv.extend(profile_arg.split())
    argv.extend(["gateway", "run"])

    env_overlay = {
        "HERMES_HOME": hermes_home,
        "HERMES_RUNTIME_HOME": hermes_home,
        "GLADLY_HERMES_CODE_ROOT": code_root,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "HERMES_GATEWAY_DETACHED": "1",
        "VIRTUAL_ENV": _preserve_hermes_home_path(venv_dir),
    }
    _prepend_pythonpath(
        env_overlay,
        [project_root, *[_preserve_hermes_home_path(entry) for entry in extra_pythonpath]]
        if extra_pythonpath
        else [project_root],
    )
    env_overlay.update(_gateway_managed_launch_overlay())
    _add_gateway_launch_env_lock(env_overlay, working_dir)
    return argv, working_dir, env_overlay


def windowless_gateway_restart_spec(
    run_argv: list[str],
) -> tuple[list[str], str, dict[str, str]]:
    """Return the (argv, cwd, env overlay) for a hidden-console gateway respawn.

    The post-update restart paths build their respawn command from
    ``get_python_path()`` (the venv's console ``python.exe``).  That is the
    right interpreter: the watcher launches it with ``CREATE_NO_WINDOW``
    detach flags, so the respawned gateway owns a single hidden console that
    all of its descendants inherit — nothing flashes (#54220/#56747; the old
    pythonw.exe rewrite here produced a console-less gateway whose every
    console-subsystem child allocated a visible conhost).  This helper now
    only normalizes the interpreter via ``_resolve_detached_python`` and
    supplies the stable cwd + env overlay (HERMES_HOME, VIRTUAL_ENV,
    PYTHONPATH) so the respawn doesn't depend on the watcher's transient
    working directory.

    Returns ``(new_argv, working_dir, env_overlay)``. ``new_argv`` preserves
    every argument after the interpreter (``-m hermes_cli.main [--profile X]
    gateway run [--replace]``), adding an explicit locked profile only when
    the captured argv omitted one. On non-Windows the helper is a no-op. On
    Windows, an incomplete interpreter/home/provenance spec raises: a
    post-update respawn must not silently inherit an unlocked environment
    after the original gateway consumed its launch marker.
    """
    if sys.platform != "win32":
        return run_argv, "", {}
    if not run_argv:
        raise RuntimeError("Windows gateway respawn requires a non-empty argv")

    from hermes_cli.config import get_hermes_home
    from hermes_cli.gateway import PROJECT_ROOT

    python_exe = run_argv[0]
    rest = run_argv[1:]

    # Normalize the leading interpreter token and derive the venv layout. A
    # bare command is resolved once, then pinned to the resulting file.
    try:
        if not Path(python_exe).is_absolute():
            discovered = shutil.which(python_exe)
            if not discovered:
                raise FileNotFoundError(python_exe)
            python_exe = discovered
        hidden_console_python, venv_dir, extra_pythonpath = _resolve_detached_python(
            python_exe
        )
        if not Path(hidden_console_python).is_file():
            raise FileNotFoundError(hidden_console_python)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError(
            "Windows gateway respawn could not pin its Python interpreter"
        ) from exc

    new_argv = [hidden_console_python, *rest]

    project_root = str(Path(PROJECT_ROOT).resolve())
    try:
        hermes_home = _restart_hermes_home(get_hermes_home(), new_argv[1:])
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError(
            "Windows gateway respawn could not pin its Hermes home"
        ) from exc
    has_profile_arg = any(
        arg in {"--profile", "-p"} or arg.startswith("--profile=")
        for arg in new_argv[1:]
    )
    if not has_profile_arg:
        try:
            gateway_index = new_argv.index("gateway", 1)
        except ValueError as exc:
            raise RuntimeError(
                "Windows gateway respawn argv has no gateway command"
            ) from exc
        new_argv[gateway_index:gateway_index] = shlex.split(
            _locked_gateway_profile_arg(hermes_home)
        )
    code_root = _resolve_gateway_code_root(PROJECT_ROOT, hermes_home)
    if not Path(code_root).is_dir():
        raise RuntimeError("Windows gateway respawn reviewed code root is missing")
    working_dir = code_root

    env_overlay: dict[str, str] = {
        "PYTHONIOENCODING": "utf-8",
        "HERMES_GATEWAY_DETACHED": "1",
        "VIRTUAL_ENV": str(venv_dir),
        "GLADLY_HERMES_CODE_ROOT": code_root,
    }
    env_overlay["HERMES_HOME"] = hermes_home
    env_overlay["HERMES_RUNTIME_HOME"] = hermes_home
    _prepend_pythonpath(
        env_overlay,
        [project_root, *extra_pythonpath] if extra_pythonpath else [project_root],
    )
    env_overlay.update(_gateway_managed_launch_overlay())
    _add_gateway_launch_env_lock(env_overlay, working_dir)
    return new_argv, working_dir, env_overlay


def _spawn_detached(script_path: Path | None = None) -> int:
    """Launch the gateway as a fully detached background process.

    We spawn ``python.exe -m hermes_cli.main gateway run`` directly — NOT
    through a cmd.exe shim — because on Windows a cmd.exe child inherits the
    parent session's console handle and tends to get reaped when the spawning
    shell exits.  With ``CREATE_NO_WINDOW`` the gateway gets its OWN hidden
    console instead of inheriting ours, so it survives our shell closing, and
    every console-subsystem descendant it spawns inherits that hidden console
    instead of flashing a visible one (#54220/#56747 — this is why we don't
    use console-less pythonw.exe here). Combined with
    CREATE_NEW_PROCESS_GROUP + DEVNULL stdin + a fresh env, the resulting
    process is independent of whichever shell started it.

    Arg ``script_path`` is accepted for API symmetry with older callers
    but ignored — we don't need it now that we go direct.

    Returns the spawned PID so callers can verify the process actually
    came up.
    """
    _assert_windows()
    argv, working_dir, env_overlay = _build_gateway_argv()

    # Generic installs retain their historical ambient environment. Managed
    # installs start from an OS-derived allowlist so shell hooks, path decoys,
    # stale checkout pointers, and ambient provider secrets cannot cross the
    # gateway process boundary.
    if "HERMES_GATEWAY_RUNTIME_PATH" in env_overlay:
        env = _managed_gateway_child_environment(env_overlay)
    else:
        env = {**os.environ, **env_overlay}
    primary_env = {**env, _WINDOWS_GATEWAY_BREAKAWAY_ENV: "1"}

    # CREATE_NEW_PROCESS_GROUP 0x00000200 — child gets its own group, won't
    #                                       receive Ctrl+C from our group
    # CREATE_NO_WINDOW         0x08000000 — child owns a hidden console:
    #                                       detached from our console's
    #                                       lifetime AND inheritable by its
    #                                       descendants (no conhost flashes)
    # CREATE_BREAKAWAY_FROM_JOB 0x01000000 — escape any job object the
    #                                       parent is in (prevents parent-
    #                                       job teardown from reaping us;
    #                                       some Windows Terminal versions
    #                                       wrap their children in a job).
    flags = windows_detach_flags()

    # Redirect any stray stdout/stderr output to a sidecar log. Python's
    # logging module writes to gateway.log through a FileHandler, so the
    # real gateway logs still land there — this just captures anything
    # that goes to print() or native stderr.
    from hermes_cli.config import get_hermes_home

    log_dir = Path(get_hermes_home()) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stray_log = log_dir / "gateway-stdio.log"

    try:
        with open(stray_log, "ab", buffering=0) as log_fh:
            proc = subprocess.Popen(
                argv,
                cwd=working_dir,
                env=primary_env,
                creationflags=flags,
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=log_fh,
                stderr=log_fh,
            )
    except OSError as exc:
        # CREATE_BREAKAWAY_FROM_JOB can fail with "access denied" when the
        # parent's job object doesn't permit breakaway (some Windows
        # Terminal configs). Retry without the breakaway flag — in most
        # setups the hidden-console CREATE_NO_WINDOW spawn is enough on
        # its own.
        error_code = getattr(exc, "winerror", None)
        if error_code is None:
            error_code = exc.errno
        logger.warning(
            "Gateway breakaway spawn failed (error=%s); retrying without "
            "CREATE_BREAKAWAY_FROM_JOB",
            error_code,
        )
        flags_no_breakaway = windows_detach_flags_without_breakaway()
        fallback_env = {**env, _WINDOWS_GATEWAY_BREAKAWAY_ENV: "0"}
        with open(stray_log, "ab", buffering=0) as log_fh:
            proc = subprocess.Popen(
                argv,
                cwd=working_dir,
                env=fallback_env,
                creationflags=flags_no_breakaway,
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=log_fh,
                stderr=log_fh,
            )
    return proc.pid


def _install_choice_from_env(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False
    return None


def _prompt_install_choices(
    start_now: bool | None = None,
    start_on_login: bool | None = None,
) -> tuple[bool, bool]:
    """Return (start_now, start_on_login), asking before any UAC escalation."""
    env_start_now = _install_choice_from_env("HERMES_GATEWAY_INSTALL_START_NOW")
    env_start_on_login = _install_choice_from_env("HERMES_GATEWAY_INSTALL_START_ON_LOGIN")
    if start_now is None:
        start_now = env_start_now
    if start_on_login is None:
        start_on_login = env_start_on_login
    if start_now is not None and start_on_login is not None:
        return start_now, start_on_login

    from hermes_cli.setup import prompt_yes_no

    if start_now is None:
        start_now = prompt_yes_no("Start the gateway now after install?", True)
    if start_on_login is None:
        start_on_login = prompt_yes_no(
            "Start the gateway automatically on Windows login with a Scheduled Task?",
            True,
        )
    return start_now, start_on_login


def _install_startup_fallback(script_path: Path, start_now: bool, detail: str) -> None:
    """Install the Startup-folder fallback and optionally start once."""
    print(f"↻ Scheduled Task install blocked ({detail.splitlines()[0]}) — using Startup folder fallback")
    entry = _install_startup_entry(script_path)
    print(f"✓ Installed Windows login item: {entry}")
    print(f"  Task script: {script_path}")

    # Re-running `hermes -p <profile> gateway install` must be safe.
    # Startup-folder fallback only installs login persistence. Starting is
    # controlled by the pre-UAC start_now answer so all user decisions happen
    # before any elevation prompt.
    from hermes_cli.gateway import _profile_arg

    running_pids = _gateway_pids()
    if running_pids:
        print(f"✓ Gateway already running (PID: {', '.join(map(str, running_pids))})")
    elif start_now:
        pid = _spawn_detached()
        _report_gateway_start(f"direct spawn (PID {pid})")
    else:
        profile_arg = _profile_arg()
        start_cmd = f"hermes {profile_arg} gateway start" if profile_arg else "hermes gateway start"
        print("ℹ Startup fallback installed; gateway not started now.")
        print(f"  Start manually with: {start_cmd}")
    _print_next_steps()


def install(
    force: bool = False,
    *,
    start_now: bool | None = None,
    start_on_login: bool | None = None,
    elevated_handoff: bool = False,
    install_disabled: bool = False,
) -> None:
    """Install the gateway as a Windows Scheduled Task (with Startup fallback).

    Idempotent: re-running updates the task to point at the current python/
    project paths. ``force`` is accepted for API parity with ``launchd_install``
    / ``systemd_install`` but isn't needed — we always reconcile.
    """
    _assert_windows()
    managed_launch = _gateway_managed_launch_overlay()
    if managed_launch and not install_disabled:
        raise RuntimeError(
            "Managed Gladly gateway installs must remain disabled. Stage with "
            "`hermes gateway install --install-disabled`, then use the Gladly "
            "runtime gateway-enable command so manifest/task evidence is "
            "checked with compare-and-swap before Settings/Enabled changes."
        )
    if install_disabled:
        # A disabled staging install always creates login persistence but must
        # never start the gateway.  Safety wins over contradictory CLI flags.
        start_now = False
        start_on_login = True
    start_now, start_on_login = _prompt_install_choices(start_now, start_on_login)

    if not start_on_login:
        print("ℹ Skipped Windows login auto-start install.")
        if start_now:
            running_pids = _gateway_pids()
            if running_pids:
                print(f"✓ Gateway already running (PID: {', '.join(map(str, running_pids))})")
            else:
                pid = _spawn_detached()
                _report_gateway_start(f"direct spawn (PID {pid})")
        else:
            print("ℹ Gateway not started and no auto-start service installed.")
            print("  Run later with: hermes gateway start")
        return

    task_name = get_task_name()
    if install_disabled:
        _assert_no_foreign_startup_collision()
        # Startup entries are current-user files and need no elevation. Remove
        # both generations before *any* UAC handoff so a decline, unavailable
        # elevation helper, launcher regeneration failure, or delayed elevated
        # child cannot leave an older auto-start path live during a staged /
        # quarantined install.
        _remove_startup_fallback_entries()

        try:
            owned_task_xml = _assert_no_foreign_task_collision()
        except _TaskInspectionError as exc:
            # A task that exists but cannot be queried may still be enabled.
            # Escalate without rewriting the target it can execute.
            if not _is_running_as_admin() and not elevated_handoff:
                from hermes_cli.setup import prompt_yes_no

                print(
                    "↻ Existing Scheduled Task must be inspected before its "
                    "launcher can be staged."
                )
                if prompt_yes_no("  Open the UAC prompt now?", False):
                    if _launch_elevated_install(
                        force=force,
                        start_now=start_now,
                        start_on_login=start_on_login,
                        install_disabled=True,
                    ):
                        print("✓ Launched elevated disabled gateway install prompt.")
                        return
            raise RuntimeError(
                "Could not inspect the existing Windows gateway Scheduled "
                "Task before staging; its launcher was left unchanged and "
                f"the task may still be enabled: {exc}"
            ) from exc

        if owned_task_xml is not None and _task_xml_is_enabled(owned_task_xml):
            disabled, disable_detail = _disable_owned_task_for_staging()
            if not disabled:
                # Do not rewrite the launcher while an enabled task can still
                # execute it. The elevated child repeats this disable step
                # before rendering any new provenance.
                if not _is_running_as_admin() and not elevated_handoff:
                    from hermes_cli.setup import prompt_yes_no

                    print(
                        "↻ Existing enabled Scheduled Task must be disabled "
                        "before its launcher can be staged."
                    )
                    if prompt_yes_no("  Open the UAC prompt now?", False):
                        if _launch_elevated_install(
                            force=force,
                            start_now=start_now,
                            start_on_login=start_on_login,
                            install_disabled=True,
                        ):
                            print("✓ Launched elevated disabled gateway install prompt.")
                            return
                raise RuntimeError(
                    "Could not disable the existing Windows gateway Scheduled "
                    "Task before staging; its launcher was left unchanged and "
                    f"the task may still be enabled: {disable_detail}"
                )
    else:
        _assert_no_foreign_persistence_collision()
    script_path = _write_task_script()

    # On machines where the current user's scheduled-task ACL is locked down,
    # schtasks /Create or /Change can sit for the timeout before returning
    # Access Denied. We already collected all intent questions above, so avoid
    # a mysterious post-question pause: ask for UAC before touching schtasks.
    if not _is_running_as_admin() and not elevated_handoff:
        from hermes_cli.setup import prompt_yes_no

        print("↻ Scheduled Task install may need administrator approval on this Windows account.")
        print("  UAC is Windows' admin approval prompt; it is needed to create/update the Scheduled Task.")
        if prompt_yes_no("  Open the UAC prompt now?", False):
            if _launch_elevated_install(
                force=force,
                start_now=start_now,
                start_on_login=start_on_login,
                install_disabled=install_disabled,
            ):
                print("✓ Launched elevated Hermes gateway install prompt.")
                if start_now:
                    print("  Approve the Windows UAC prompt; the elevated install will start the gateway afterwards.")
                else:
                    print("  Approve the Windows UAC prompt, then run: hermes gateway status")
                return
            if not install_disabled:
                print("⚠ Falling back to Startup folder because elevation was unavailable or cancelled.")
        else:
            if not install_disabled:
                print("  Skipped elevation. Falling back to Startup folder.")
        if install_disabled:
            raise RuntimeError(
                "Disabled Windows gateway install requires a Scheduled Task; "
                "no Startup-folder fallback was created."
            )
        _install_startup_fallback(script_path, start_now, "administrator approval was not used")
        return

    ok, detail = _install_scheduled_task(
        task_name,
        script_path,
        enabled=not install_disabled,
    )
    if ok:
        print(f"✓ {detail}")
        print(f"  Task script: {script_path}")
        if install_disabled:
            print("ℹ Gateway Scheduled Task is installed but disabled; it cannot auto-start or run on demand.")
            if managed_launch:
                print("  Enable only with: bin/gladly runtime gateway-enable")
            else:
                print("  Re-run 'hermes gateway install' without --install-disabled to enable it.")
        else:
            print("ℹ Gateway auto-start installed for Windows login.")
        if not install_disabled:
            if start_now:
                running_pids = _gateway_pids()
                if running_pids:
                    print(f"✓ Gateway already running (PID: {', '.join(map(str, running_pids))})")
                else:
                    pid = _spawn_detached()
                    _report_gateway_start(f"direct spawn (PID {pid})")
            else:
                print("ℹ Gateway not started now.")
                print("  Start manually with: hermes gateway start")
        _print_next_steps()
        return

    # schtasks create didn't work. Prefer a real Scheduled Task over the
    # Startup-folder fallback when the only blocker is elevation. This gives
    # users a UAC prompt instead of silently installing a less reliable login
    # item, and keeps the fallback for locked-down boxes / cancelled prompts.
    if _is_access_denied(detail) and not _is_running_as_admin():
        from hermes_cli.setup import prompt_yes_no

        print(f"↻ Scheduled Task install needs administrator approval ({detail.splitlines()[0]})")
        print("  UAC is Windows' admin approval prompt; it is needed to create/update the Scheduled Task.")
        if prompt_yes_no("  Open the UAC prompt now?", False):
            if _launch_elevated_install(
                force=force,
                start_now=start_now,
                start_on_login=start_on_login,
                install_disabled=install_disabled,
            ):
                print("✓ Launched elevated Hermes gateway install prompt.")
                if start_now:
                    print("  Approve the Windows UAC prompt; the elevated install will start the gateway afterwards.")
                else:
                    print("  Approve the Windows UAC prompt, then run: hermes gateway status")
                return
            if not install_disabled:
                print("⚠ Falling back to Startup folder because elevation was unavailable or cancelled.")
        else:
            if not install_disabled:
                print("  Skipped elevation. Falling back to Startup folder.")

    if install_disabled:
        raise RuntimeError(
            f"Disabled Windows gateway install failed and no Startup-folder "
            f"fallback was created: {detail}"
        )

    # schtasks create didn't work. See if it's a "fall back to startup" case.
    if _should_fall_back(1, detail):
        print(f"↻ Scheduled Task install blocked ({detail.splitlines()[0]}) — using Startup folder fallback")
        entry = _install_startup_entry(script_path)
        print(f"✓ Installed Windows login item: {entry}")
        print(f"  Task script: {script_path}")

        # Re-running `hermes -p <profile> gateway install` must be safe.
        # Startup-folder fallback only installs login persistence. Starting is
        # controlled by the pre-UAC start_now answer so all user decisions happen
        # before any elevation prompt.
        from hermes_cli.gateway import _profile_arg

        running_pids = _gateway_pids()
        if running_pids:
            print(f"✓ Gateway already running (PID: {', '.join(map(str, running_pids))})")
        elif start_now:
            pid = _spawn_detached()
            _report_gateway_start(f"direct spawn (PID {pid})")
        else:
            profile_arg = _profile_arg()
            start_cmd = f"hermes {profile_arg} gateway start" if profile_arg else "hermes gateway start"
            print("ℹ Startup fallback installed; gateway not started now.")
            print(f"  Start manually with: {start_cmd}")
        _print_next_steps()
        return

    # Unknown schtasks error — surface it and bail.
    raise RuntimeError(f"Windows gateway install failed: {detail}")


def _wait_for_gateway_ready(timeout_s: float = 6.0, interval_s: float = 0.4) -> list[int]:
    """Poll for a live gateway process for up to ``timeout_s`` seconds.

    Returns the list of PIDs found. Empty list means nothing came up in
    time — the caller should surface that to the user as a failed start.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        pids = _gateway_pids()
        if pids:
            return pids
        time.sleep(interval_s)
    return []


def _report_gateway_start(via: str) -> bool:
    pids = _wait_for_gateway_ready()
    if pids:
        print(f"✓ Gateway started via {via} (PID: {', '.join(map(str, pids))})")
        return True
    else:
        print(f"⚠ Launched gateway via {via}, but no process detected after 6s.")
        print("  Check the log for startup errors:")
        from hermes_cli.config import get_hermes_home
        print(f"    type {Path(get_hermes_home())}\\logs\\gateway.log")
        print(f"    type {Path(get_hermes_home())}\\logs\\gateway-stdio.log")
        return False


def _print_next_steps() -> None:
    from hermes_cli.config import get_hermes_home

    hermes_home = Path(get_hermes_home())
    print()
    print("Next steps:")
    print("  hermes gateway status                      # Check status")
    print(f"  type {hermes_home}\\logs\\gateway.log       # View logs")


def uninstall() -> None:
    """Remove both the Scheduled Task and the Startup-folder fallback, if present."""
    _assert_windows()
    task_name = get_task_name()
    script_path = _expected_task_script_path()
    vbs_script_path = script_path.with_suffix(".vbs")
    startup_entry = get_startup_entry_path()
    legacy_startup_entry = _legacy_startup_entry_path()

    owned_task = _owned_task_xml() is not None
    owned_current_startup = _current_startup_entry_belongs_to_current_profile()
    owned_legacy_startup = _legacy_startup_entry_belongs_to_current_profile()
    owned_cmd_launcher = _gateway_launcher_belongs_to_current_install(script_path)
    owned_vbs_launcher = _gateway_launcher_belongs_to_current_install(
        vbs_script_path
    )
    scheduled_task_removed = False
    if owned_task:
        code, _out, err = _exec_schtasks(["/Delete", "/F", "/TN", task_name])
        detail = err.strip()
        if code == 0:
            scheduled_task_removed = True
            print(f"✓ Removed Scheduled Task {task_name!r}")
        elif _is_access_denied(detail) and not _is_running_as_admin():
            from hermes_cli.setup import prompt_yes_no

            print(f"↻ Scheduled Task uninstall needs administrator approval ({detail or 'access denied'})")
            print("  UAC is Windows' admin approval prompt; it is needed to remove the Scheduled Task.")
            if prompt_yes_no("  Open the UAC prompt now?", False):
                if _launch_elevated_uninstall():
                    print("✓ Launched elevated Hermes gateway uninstall prompt.")
                    print("  Approve the Windows UAC prompt, then run: hermes gateway status")
                    return
                print("⚠ Elevated uninstall prompt was unavailable or cancelled.")
            else:
                print("  Skipped elevation. Scheduled Task was not removed.")
        else:
            print(f"⚠ schtasks /Delete returned code {code}: {detail}")

    for path, label, owned in [
        (startup_entry, "Windows login item", owned_current_startup),
        (legacy_startup_entry, "legacy Windows login item", owned_legacy_startup),
        (script_path, "Task script", owned_cmd_launcher),
        (vbs_script_path, "Task launcher", owned_vbs_launcher),
    ]:
        if not owned:
            continue
        try:
            path.unlink()
            print(f"✓ Removed {label}: {path}")
        except FileNotFoundError:
            pass

    if owned_task and is_task_registered() and not scheduled_task_removed:
        print(f"⚠ Scheduled Task still registered: {task_name}")


# ---------------------------------------------------------------------------
# Status / start / stop / restart
# ---------------------------------------------------------------------------

def is_task_registered() -> bool:
    try:
        return _task_registration_state()
    except _TaskInspectionError:
        return False


def is_startup_entry_installed() -> bool:
    return get_startup_entry_path().exists() or _legacy_startup_entry_path().exists()


def _same_windows_path(left: str | Path, right: str | Path) -> bool:
    try:
        left_path = Path(left).expanduser()
        right_path = Path(right).expanduser()
        if not left_path.is_absolute() or not right_path.is_absolute():
            return False
        return os.path.normcase(str(left_path.resolve())) == os.path.normcase(
            str(right_path.resolve())
        )
    except (OSError, RuntimeError, ValueError):
        return False


def _task_xml_belongs_to_current_profile(
    xml_text: str,
    *,
    allow_legacy_task_action: bool = True,
) -> bool:
    """Prove that a task's sole Exec action targets this profile's launcher.

    Install/uninstall migration may recognize the exact pre-VBS CMD action.
    Runtime attestation sets ``allow_legacy_task_action=False`` so only the
    current VBS action and reviewed interpreter can enter a sealed manifest.
    """
    try:
        from xml.etree import ElementTree

        root = ElementTree.fromstring(xml_text)
        actions = [
            element
            for element in root.iter()
            if element.tag.rsplit("}", 1)[-1] == "Actions"
        ]
        if len(actions) != 1:
            return False
        action_children = list(actions[0])
        if (
            len(action_children) != 1
            or action_children[0].tag.rsplit("}", 1)[-1] != "Exec"
        ):
            return False
        field_items = [
            (child.tag.rsplit("}", 1)[-1], (child.text or "").strip())
            for child in action_children[0]
        ]
        fields = dict(field_items)
        if len(fields) != len(field_items):
            return False
        command = fields.get("Command", "")
        arguments = fields.get("Arguments", "")
        expected_script = _expected_task_script_path()
        # Pre-VBS tasks registered the generated .cmd directly via schtasks
        # /TR. Recognize that exact current-profile path so updates can migrate
        # the legacy artifact, without accepting a same-name foreign task.
        if (
            allow_legacy_task_action
            and set(fields) == {"Command"}
            and _same_windows_path(command, expected_script)
        ):
            return _gateway_launcher_belongs_to_current_install(expected_script)
        # Current generated XML invokes the system-resolved executable by its
        # exact basename.  Accepting an arbitrary absolute path merely because
        # it ends in wscript.exe lets a foreign executable pass ownership.
        if set(fields) != {"Command", "Arguments"}:
            return False
        expected_interpreter = _gateway_task_interpreter()
        if expected_interpreter.casefold() == "wscript.exe":
            if command.casefold() != "wscript.exe":
                return False
        elif not _same_windows_path(command, expected_interpreter):
            return False
        match = re.fullmatch(
            r'//B\s+//Nologo\s+"([^"]+)"',
            arguments,
            flags=re.IGNORECASE,
        )
        if match is None:
            return False
        expected_vbs = expected_script.with_suffix(".vbs")
        return _same_windows_path(
            match.group(1), expected_vbs
        ) and _gateway_launcher_belongs_to_current_install(expected_vbs)
    except (ElementTree.ParseError, OSError, RuntimeError, ValueError):
        return False


def _task_xml_semantic_identity(element) -> tuple:
    """Return a formatting-independent, order-sensitive XML identity."""
    children = list(element)
    text = element.text or ""
    # Ignore only renderer/Task Scheduler indentation. Leaf values stay byte-
    # exact so leading/trailing spaces in Command, Arguments, UserId, policy
    # values, etc. cannot hide behind a generic ``strip()`` normalization.
    if children and not text.strip():
        text = ""
    tail = element.tail or ""
    if not tail.strip():
        tail = ""
    return (
        element.tag,
        tuple(sorted(element.attrib.items())),
        text,
        tail,
        tuple(_task_xml_semantic_identity(child) for child in children),
    )


def _scheduler_export_root_for_current_definition(
    renderer_root,
    *,
    task_name: str,
    user_sid: str,
):
    """Return the one exact Windows Scheduler export of our renderer XML.

    ``schtasks /Query /XML`` does not round-trip registration XML byte for
    byte. On current Windows it injects the task URI, resolves the principal
    to the current token SID, omits fixed schema defaults, enables the unified
    scheduling engine, and emits sections/settings in a deterministic order.
    Model only that complete known projection; foreign fields, principals,
    values, omissions, and actions still fail closed.
    """
    from copy import deepcopy
    from xml.etree import ElementTree

    namespace = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"

    def direct_child(parent, name: str):
        matches = [child for child in list(parent) if child.tag == f"{namespace}{name}"]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one Task Scheduler {name} element")
        return matches[0]

    export_root = deepcopy(renderer_root)
    registration = direct_child(export_root, "RegistrationInfo")
    uri = ElementTree.Element(f"{namespace}URI")
    uri.text = f"\\{task_name}"
    registration.append(uri)

    principals = direct_child(export_root, "Principals")
    principal = direct_child(principals, "Principal")
    user_id = direct_child(principal, "UserId")
    user_id.text = user_sid
    run_level = direct_child(principal, "RunLevel")
    if (run_level.text or "") != "LeastPrivilege":
        raise ValueError("Unexpected task RunLevel renderer default")
    principal.remove(run_level)

    triggers = direct_child(export_root, "Triggers")
    logon_trigger = direct_child(triggers, "LogonTrigger")
    trigger_enabled = direct_child(logon_trigger, "Enabled")
    if (trigger_enabled.text or "") != "true":
        raise ValueError("Unexpected LogonTrigger Enabled renderer default")
    logon_trigger.remove(trigger_enabled)

    settings = direct_child(export_root, "Settings")
    omitted_defaults = {
        "AllowHardTerminate": "true",
        "RunOnlyIfNetworkAvailable": "false",
        "AllowStartOnDemand": "true",
        "Hidden": "false",
        "RunOnlyIfIdle": "false",
        "WakeToRun": "false",
        "Priority": "7",
    }
    for name, expected_value in omitted_defaults.items():
        element = direct_child(settings, name)
        if (element.text or "") != expected_value:
            raise ValueError(f"Unexpected task {name} renderer default")
        settings.remove(element)

    restart = direct_child(settings, "RestartOnFailure")
    restart_count = direct_child(restart, "Count")
    restart_interval = direct_child(restart, "Interval")
    restart[:] = [restart_count, restart_interval]

    unified = ElementTree.Element(f"{namespace}UseUnifiedSchedulingEngine")
    unified.text = "true"
    settings.append(unified)
    scheduler_setting_order = (
        "DisallowStartIfOnBatteries",
        "StopIfGoingOnBatteries",
        "Enabled",
        "ExecutionTimeLimit",
        "MultipleInstancesPolicy",
        "RestartOnFailure",
        "StartWhenAvailable",
        "IdleSettings",
        "UseUnifiedSchedulingEngine",
    )
    settings_by_name = {
        child.tag.rsplit("}", 1)[-1]: child for child in list(settings)
    }
    if set(settings_by_name) != set(scheduler_setting_order):
        raise ValueError("Unexpected task Settings renderer shape")
    settings[:] = [settings_by_name[name] for name in scheduler_setting_order]

    scheduler_root_order = (
        "RegistrationInfo",
        "Principals",
        "Settings",
        "Triggers",
        "Actions",
    )
    root_by_name = {
        child.tag.rsplit("}", 1)[-1]: child for child in list(export_root)
    }
    if set(root_by_name) != set(scheduler_root_order):
        raise ValueError("Unexpected task renderer root shape")
    export_root[:] = [root_by_name[name] for name in scheduler_root_order]
    return export_root


def _task_xml_matches_current_definition(
    xml_text: str,
    *,
    allow_settings_enabled_overlay: bool = True,
) -> bool:
    """Compare the complete task XML to the exact current renderer.

    Comparison accepts either the direct renderer or the one exact projection
    exported by Windows Task Scheduler. Every element, attribute, text value,
    namespace, and child order must otherwise match. The sole mutable runtime
    overlay is the direct ``Task/Settings/Enabled`` value.
    """
    try:
        from xml.etree import ElementTree

        actual_root = ElementTree.fromstring(xml_text)
        namespace = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
        if actual_root.tag != f"{namespace}Task":
            return False
        settings = [
            child for child in list(actual_root) if child.tag == f"{namespace}Settings"
        ]
        if len(settings) != 1:
            return False
        direct_enabled = [
            child
            for child in list(settings[0])
            if child.tag == f"{namespace}Enabled"
        ]
        if len(direct_enabled) != 1:
            return False
        enabled_text = (direct_enabled[0].text or "").strip().casefold()
        if enabled_text not in {"true", "false"}:
            return False
        expected_enabled = enabled_text == "true"
        if not allow_settings_enabled_overlay and not expected_enabled:
            return False
        expected_xml = _build_scheduled_task_xml(
            get_task_name(),
            _expected_task_script_path().with_suffix(".vbs"),
            _resolve_task_user(),
            enabled=expected_enabled,
        )
        expected_root = ElementTree.fromstring(expected_xml)
        actual_identity = _task_xml_semantic_identity(actual_root)
        if actual_identity == _task_xml_semantic_identity(expected_root):
            return True
        user_sid = _resolve_task_user_sid()
        if not user_sid:
            return False
        exported_root = _scheduler_export_root_for_current_definition(
            expected_root,
            task_name=get_task_name(),
            user_sid=user_sid,
        )
        return actual_identity == _task_xml_semantic_identity(exported_root)
    except (ElementTree.ParseError, OSError, RuntimeError, ValueError):
        return False


def _enumerated_task_names() -> set[str]:
    code, out, err = _exec_schtasks(["/Query", "/FO", "CSV", "/NH"])
    if code != 0:
        detail = (err or out or "").strip()
        raise _TaskInspectionError(
            detail or "Scheduled Task enumeration failed"
        )
    names: set[str] = set()
    try:
        for row in csv.reader(out.splitlines()):
            if row and row[0].strip():
                names.add(row[0].strip().lstrip("\\").casefold())
    except (csv.Error, UnicodeError) as exc:
        raise _TaskInspectionError(
            "Scheduled Task enumeration was malformed"
        ) from exc
    return names


def _task_registration_state() -> bool:
    """Return existence, raising when a registered task is not inspectable."""
    code, out, err = _exec_schtasks(["/Query", "/TN", get_task_name()])
    if code == 0:
        return True
    expected = get_task_name().lstrip("\\").casefold()
    if expected not in _enumerated_task_names():
        return False
    detail = (err or out or "").strip()
    raise _TaskInspectionError(
        detail or "Registered Scheduled Task could not be queried"
    )


def _inspect_task_xml() -> str | None:
    code, out, err = _exec_schtasks(["/Query", "/TN", get_task_name(), "/XML"])
    if code == 0:
        if not out.strip():
            raise _TaskInspectionError("Scheduled Task query returned empty XML")
        return out
    detail = (err or out or "").strip()
    try:
        registered = _task_registration_state()
    except _TaskInspectionError as exc:
        raise _TaskInspectionError(detail or str(exc)) from exc
    if not registered:
        return None
    raise _TaskInspectionError(
        detail or "Registered Scheduled Task XML could not be queried"
    )


def _owned_task_xml() -> str | None:
    try:
        out = _inspect_task_xml()
    except _TaskInspectionError:
        return None
    if out is None or not _task_xml_belongs_to_current_profile(out):
        return None
    if _gateway_managed_launch_overlay() and not _task_xml_matches_current_definition(
        out,
        allow_settings_enabled_overlay=True,
    ):
        return None
    return out


def _task_xml_is_enabled(xml_text: str) -> bool:
    """Read Settings/Enabled (not a trigger's Enabled element)."""
    try:
        from xml.etree import ElementTree

        root = ElementTree.fromstring(xml_text)
        for settings in root.iter():
            if settings.tag.rsplit("}", 1)[-1] != "Settings":
                continue
            for element in settings:
                if element.tag.rsplit("}", 1)[-1] == "Enabled":
                    return (element.text or "").strip().casefold() != "false"
        return True
    except (ElementTree.ParseError, ValueError):
        return True


def _disable_owned_task_for_staging() -> tuple[bool, str]:
    """Disable an existing owned task and verify it before launcher writes."""
    task_name = get_task_name()
    code, out, err = _exec_schtasks(["/Change", "/TN", task_name, "/Disable"])
    detail = (err or out or "").strip()
    if code != 0:
        return False, detail or f"schtasks /Change failed with code {code}"
    refreshed = _owned_task_xml()
    if refreshed is None:
        return False, "disabled task ownership could not be re-verified"
    if _task_xml_is_enabled(refreshed):
        return False, "Scheduled Task still reports enabled after /Disable"
    return True, detail or "Scheduled Task disabled"


def _current_startup_entry_belongs_to_current_profile() -> bool:
    """Prove that the VBS Startup entry targets this profile."""
    expected_script = _expected_task_script_path()
    current_entry = get_startup_entry_path()
    try:
        if current_entry.is_file():
            content = current_entry.read_text(encoding="utf-8")
            expected = _build_startup_launcher(expected_script)
            normalized = content.lstrip("\ufeff").replace("\r\n", "\n")
            expected_normalized = expected.replace("\r\n", "\n")
            return normalized == expected_normalized and (
                _gateway_launcher_belongs_to_current_install(
                    expected_script.with_suffix(".vbs")
                )
            )
    except (OSError, UnicodeError):
        pass
    return False


def _legacy_startup_entry_belongs_to_current_profile() -> bool:
    """Prove that the legacy CMD Startup entry targets this profile."""
    expected_script = _expected_task_script_path()

    legacy_entry = _legacy_startup_entry_path()
    try:
        if legacy_entry.is_file():
            lines = legacy_entry.read_text(encoding="utf-8").lstrip("\ufeff").splitlines()
            if len(lines) != 3:
                return False
            if lines[0].strip().casefold() != "@echo off":
                return False
            if lines[1].strip().casefold() != f"rem {_TASK_DESCRIPTION}".casefold():
                return False
            match = re.fullmatch(
                r'\s*start\s+""\s+/min\s+cmd\.exe\s+/d\s+/c\s+(.+?)\s*',
                lines[2],
                flags=re.IGNORECASE,
            )
            if match is None:
                return False
            target = match.group(1)
            if len(target) >= 2 and target.startswith('"') and target.endswith('"'):
                target = target[1:-1].replace('""', '"')
            return _same_windows_path(
                target, expected_script
            ) and _gateway_launcher_belongs_to_current_install(expected_script)
    except (OSError, UnicodeError):
        pass
    return False


def _startup_entry_belongs_to_current_profile() -> bool:
    """Prove that a current or legacy Startup entry targets this profile."""
    return (
        _current_startup_entry_belongs_to_current_profile()
        or _legacy_startup_entry_belongs_to_current_profile()
    )


def _assert_no_foreign_task_collision() -> str | None:
    """Refuse task mutation unless absence or ownership is provable."""
    task_xml = _inspect_task_xml()
    if task_xml is not None and not _task_xml_belongs_to_current_profile(task_xml):
        raise RuntimeError(
            "Refusing to replace same-name Windows gateway persistence owned "
            f"by another installation: Scheduled Task {get_task_name()!r}"
        )
    return task_xml


def _assert_no_foreign_startup_collision() -> None:
    """Refuse same-name Startup mutations across installations."""
    collisions: list[str] = []
    current_entry = get_startup_entry_path()
    if current_entry.exists() and not _current_startup_entry_belongs_to_current_profile():
        collisions.append(str(current_entry))
    legacy_entry = _legacy_startup_entry_path()
    if legacy_entry.exists() and not _legacy_startup_entry_belongs_to_current_profile():
        collisions.append(str(legacy_entry))
    if collisions:
        raise RuntimeError(
            "Refusing to replace same-name Windows gateway persistence owned "
            "by another installation: "
            + ", ".join(collisions)
        )


def _assert_no_foreign_persistence_collision() -> None:
    """Refuse name-colliding task/Startup mutations across installations."""
    _assert_no_foreign_task_collision()
    _assert_no_foreign_startup_collision()


def is_installed() -> bool:
    """True only when persistence provably targets this profile's launcher."""
    return _owned_task_xml() is not None or _startup_entry_belongs_to_current_profile()


def _inspect_profile_persistence() -> bool:
    """Return installed state, raising when persistence cannot be inspected.

    Ordinary status probes stay fail-closed/boolean.  Multi-profile launcher
    migration needs a tri-state instead: treating an unreadable task XML as
    simply "not installed" silently omits that profile from the security
    refresh and can leave its old launcher active after a successful update.
    """
    if _startup_entry_belongs_to_current_profile():
        return True

    try:
        out = _inspect_task_xml()
    except _TaskInspectionError as exc:
        raise RuntimeError(str(exc)) from exc
    if out is None:
        return False
    try:
        from xml.etree import ElementTree

        ElementTree.fromstring(out)
    except (ElementTree.ParseError, ValueError) as exc:
        raise RuntimeError("Scheduled Task query returned malformed XML") from exc
    return _task_xml_belongs_to_current_profile(out)


def get_installed_profile_homes() -> list[Path]:
    """Return every profile home with Windows gateway persistence installed."""
    from hermes_constants import (
        reset_hermes_home_override,
        set_hermes_home_override,
    )
    from hermes_cli.config import get_hermes_home
    from hermes_cli.profiles import list_profiles

    candidates = [Path(get_hermes_home())]
    failures: list[str] = []
    try:
        candidates.extend(Path(profile.path) for profile in list_profiles())
    except Exception as exc:
        logger.debug("Could not enumerate Hermes profiles for launcher refresh: %s", exc)
        failures.append(f"profile enumeration: {exc}")

    installed: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            home = candidate.resolve()
            key = os.path.normcase(str(home))
            if key in seen or not home.is_dir():
                continue
            seen.add(key)
            token = set_hermes_home_override(str(home))
            try:
                if _inspect_profile_persistence():
                    installed.append(home)
            finally:
                reset_hermes_home_override(token)
        except Exception as exc:
            logger.debug(
                "Could not inspect Windows gateway persistence for %s: %s",
                candidate,
                exc,
            )
            failures.append(f"{candidate}: {exc}")
    if failures:
        raise RuntimeError("; ".join(failures))
    return installed


def is_autostart_enabled() -> bool:
    """Return whether installed Windows persistence is allowed to start.

    Startup entries are inherently enabled. Scheduled Task state is read from
    its XML so a quarantined ``--install-disabled`` task is never mistaken for
    a dead enabled task and cold-started after an update. Query/parse failures
    are fail-closed.
    """
    if _startup_entry_belongs_to_current_profile():
        return True
    out = _owned_task_xml()
    if out is None:
        return False
    return _task_xml_is_enabled(out)


def query_task_status() -> dict[str, str]:
    """Parse ``schtasks /Query /V /FO LIST`` and pull the interesting keys."""
    code, out, err = _exec_schtasks(["/Query", "/TN", get_task_name(), "/V", "/FO", "LIST"])
    if code != 0:
        return {}
    info: dict[str, str] = {}
    for raw in out.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        # Some Windows locales emit "Last Result" instead of "Last Run Result".
        if key in {"status", "last run time", "last run result", "last result"}:
            if key == "last result":
                info.setdefault("last run result", value)
            else:
                info[key] = value
    return info


def _gateway_pids() -> list[int]:
    """Return only gateway PIDs proven to belong to this installation.

    The default-profile process-table matcher necessarily sees bare
    ``gateway run`` commands from other checkouts. The current profile's
    lock/PID record is authoritative; every additional sweep result must pass
    full runtime/code-root/cwd provenance before status or a control command
    may treat it as ours.
    """
    from gateway.status import get_running_pid
    from hermes_cli.gateway import (
        _capture_current_install_gateway_argv,
        find_gateway_pids,
    )

    try:
        primary_pid = get_running_pid(cleanup_stale=False)
    except Exception:
        primary_pid = None
    try:
        candidates = list(find_gateway_pids())
    except Exception:
        candidates = []
    if primary_pid is not None and primary_pid not in candidates:
        candidates.insert(0, primary_pid)

    owned: list[int] = []
    for candidate in candidates:
        try:
            pid = int(candidate)
        except (TypeError, ValueError):
            continue
        if pid <= 0 or pid in owned:
            continue
        if primary_pid is not None and pid == int(primary_pid):
            owned.append(pid)
            continue
        try:
            if _capture_current_install_gateway_argv(pid):
                owned.append(pid)
        except Exception:
            continue
    return owned


def _print_deep_probes() -> None:
    """Print PASS/FAIL per individual probe of gateway liveness.

    The default ``status`` output collapses several signals into one
    ✓ / ✗ line, which is great when they agree and confusing when they
    don't. The deep-probe block shows each underlying check independently
    so the user can see exactly which signal is wrong.

    Probes:
      [1] PID file present
      [2] Lock file present and held by some process
      [3] gateway.status.get_running_pid() returns a PID
      [4] _pid_exists(pid) — OS confirms the process is alive
      [5] gateway_state.json exists and parses (and is fresh-ish)
      [6] Last lifecycle event in gateway-exit-diag.log
    """
    import json
    from datetime import datetime, timezone

    from hermes_cli.config import get_hermes_home

    home = Path(get_hermes_home())
    pid_path = home / "gateway.pid"
    lock_path = home / "gateway.lock"
    state_path = home / "gateway_state.json"
    diag_path = home / "logs" / "gateway-exit-diag.log"

    print()
    print("Deep probes:")

    def _mark(ok: bool) -> str:
        return "PASS" if ok else "FAIL"

    # [1] PID file
    pid_exists = pid_path.exists()
    pid_value: int | None = None
    if pid_exists:
        try:
            data = json.loads(pid_path.read_text(encoding="utf-8"))
            pid_value = int(data.get("pid")) if data.get("pid") is not None else None
            print(f"  [1] {_mark(True):4s}  PID file present: {pid_path} (pid={pid_value})")
        except Exception as exc:
            print(f"  [1] {_mark(False):4s}  PID file present but unreadable: {exc}")
    else:
        print(f"  [1] {_mark(False):4s}  PID file missing: {pid_path}")

    # [2] Lock file present + held
    lock_held = False
    lock_present = lock_path.exists()
    if lock_present:
        try:
            from gateway.status import is_gateway_runtime_lock_active

            lock_held = is_gateway_runtime_lock_active(lock_path)
            print(f"  [2] {_mark(lock_held):4s}  Lock file held by a live process: {lock_path}")
        except Exception as exc:
            print(f"  [2] {_mark(False):4s}  Could not probe lock: {exc}")
    else:
        print(f"  [2] {_mark(False):4s}  Lock file missing: {lock_path}")

    # [3] get_running_pid()
    running_pid: int | None = None
    try:
        from gateway.status import get_running_pid

        running_pid = get_running_pid(cleanup_stale=False)
        print(f"  [3] {_mark(running_pid is not None):4s}  get_running_pid() => {running_pid}")
    except Exception as exc:
        print(f"  [3] {_mark(False):4s}  get_running_pid() raised: {exc!r}")

    # [4] _pid_exists() on the probed PID
    candidate_pid = running_pid if running_pid is not None else pid_value
    if candidate_pid is not None:
        try:
            from gateway.status import _pid_exists

            alive = bool(_pid_exists(candidate_pid))
            print(f"  [4] {_mark(alive):4s}  _pid_exists({candidate_pid}) => {alive}")
        except Exception as exc:
            print(f"  [4] {_mark(False):4s}  _pid_exists raised: {exc!r}")
    else:
        print(f"  [4] {_mark(False):4s}  No candidate PID to verify")

    # [5] runtime status file
    if state_path.exists():
        try:
            state_data = json.loads(state_path.read_text(encoding="utf-8"))
            gateway_state = state_data.get("gateway_state")
            updated_at = state_data.get("updated_at")
            age_str = ""
            if updated_at:
                try:
                    updated_dt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    age_seconds = int((now - updated_dt).total_seconds())
                    age_str = f" (updated {age_seconds}s ago)"
                except Exception:
                    pass
            ok = gateway_state == "running"
            print(f"  [5] {_mark(ok):4s}  gateway_state.json state={gateway_state!r}{age_str}")
        except Exception as exc:
            print(f"  [5] {_mark(False):4s}  gateway_state.json present but unreadable: {exc}")
    else:
        print(f"  [5] {_mark(False):4s}  gateway_state.json missing: {state_path}")

    # [6] Last lifecycle event from the exit-diag log
    if diag_path.exists():
        try:
            with open(diag_path, "rb") as fh:
                # Read last ~4KB; one event is well under 500 bytes.
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - 4096))
                tail = fh.read().decode("utf-8", errors="replace").splitlines()
            last_event = next((ln for ln in reversed(tail) if ln.strip()), "")
            if last_event:
                try:
                    event = json.loads(last_event)
                    tag = event.get("tag", "?")
                    pid = event.get("pid", "?")
                    ts = event.get("ts", "?")
                    healthy = tag in ("gateway.start",)
                    print(f"  [6] {_mark(healthy):4s}  Last lifecycle event: tag={tag} pid={pid} ts={ts}")
                except Exception:
                    print(f"  [6] {_mark(False):4s}  Last lifecycle line not JSON: {last_event[:120]}")
            else:
                print(f"  [6] {_mark(False):4s}  exit-diag log empty: {diag_path}")
        except Exception as exc:
            print(f"  [6] {_mark(False):4s}  exit-diag log unreadable: {exc}")
    else:
        print(f"  [6] {_mark(False):4s}  exit-diag log missing: {diag_path}")


def status(deep: bool = False) -> None:
    """Print a status report for the Windows gateway service."""
    _assert_windows()
    task_name = get_task_name()
    task_installed = _owned_task_xml() is not None
    startup_installed = _startup_entry_belongs_to_current_profile()
    pids = _gateway_pids()

    if task_installed:
        print(f"✓ Scheduled Task registered: {task_name}")
        info = query_task_status()
        if info:
            for key in ("status", "last run time", "last run result"):
                if key in info:
                    print(f"  {key.title()}: {info[key]}")
    elif startup_installed:
        entry = get_startup_entry_path()
        if not entry.exists():
            entry = _legacy_startup_entry_path()
        print(f"✓ Windows login item installed: {entry}")
    else:
        print("✗ Gateway service not installed")

    if pids:
        print(f"✓ Gateway process running (PID: {', '.join(map(str, pids))})")
    else:
        print("✗ No gateway process detected")

    if deep:
        print()
        print(f"  Task name:        {task_name}")
        print(f"  Task script:      {get_task_script_path()}")
        print(f"  Startup entry:    {get_startup_entry_path()}")
        # Surface the per-probe truth so the user can see *which* signal
        # is lying when the high-level summary disagrees with reality.
        _print_deep_probes()

    if not task_installed and not startup_installed and not pids:
        print()
        print("To install:")
        print("  hermes gateway install")


def start() -> None:
    """Start the gateway using the canonical detached Windows launch path."""
    _assert_windows()
    managed_launch = _gateway_managed_launch_overlay()
    running_pids = _gateway_pids()
    if running_pids:
        print(f"✓ Gateway already running (PID: {', '.join(map(str, running_pids))})")
        return

    if managed_launch:
        # A managed start may never bypass the disabled Scheduled Task through
        # the historical direct spawn path. The parent runtime CLI owns the
        # compare-and-swap that flips only Settings/Enabled. Once enabled, run
        # the exact reviewed task: ONLOGON/manual start then converge on the
        # same VBS allowlist + process-start validator.
        task_xml = _inspect_task_xml()
        if task_xml is None or not _task_xml_matches_current_definition(task_xml):
            raise RuntimeError(
                "Managed Gladly Scheduled Task evidence is absent or drifted; "
                "refusing to start. Re-run runtime preparation."
            )
        if not _task_xml_is_enabled(task_xml):
            raise RuntimeError(
                "Managed Gladly Scheduled Task is disabled. Run "
                "`bin/gladly runtime gateway-enable` before starting it."
            )
        code, out, err = _exec_schtasks(["/Run", "/TN", get_task_name()])
        if code != 0:
            detail = (err or out or "").strip()
            raise RuntimeError(
                "Managed Gladly Scheduled Task could not be started: "
                f"{detail or f'schtasks exited {code}'}"
            )
        _report_gateway_start("reviewed Scheduled Task")
        return

    task_installed = _owned_task_xml() is not None
    startup_installed = _startup_entry_belongs_to_current_profile()

    if not task_installed and not startup_installed:
        from hermes_cli.setup import prompt_yes_no

        print("✗ Gateway service is not installed")
        if not prompt_yes_no("  Install it now so the gateway starts on login?", True):
            print("  Run: hermes gateway install")
            return
        install(force=False)
        task_installed = _owned_task_xml() is not None
        startup_installed = _startup_entry_belongs_to_current_profile()
        if not task_installed and not startup_installed:
            print("⚠ Gateway install did not complete in this process.")
            print("  If a UAC prompt opened, approve it, then run: hermes gateway start")
            return

    # Manual starts use the same console-less direct spawn path as restart()
    # and install --start-now. Scheduled Task / Startup entries are only login
    # persistence mechanisms.
    pid = _spawn_detached()
    _report_gateway_start(f"direct spawn (PID {pid})")


def _drain_gateway_pid(pid: int, drain_timeout: float) -> bool:
    """Write the planned-stop marker and wait for the gateway PID to exit.

    Windows cannot deliver POSIX signals to a Python asyncio loop
    (``loop.add_signal_handler`` raises NotImplementedError), so writing
    the marker is the ONLY way to ask a running gateway to drain
    in-flight agents and persist ``resume_pending`` before exit. The
    gateway's planned-stop watcher thread (gateway/run.py) polls for
    the marker and drives the same shutdown path the SIGTERM handler
    would have on POSIX.

    Returns True if the PID exited within the timeout, False if it
    didn't (caller should escalate to schtasks /End + taskkill).
    """
    if pid <= 0:
        return False
    try:
        from gateway.status import write_planned_stop_marker, _pid_exists
    except ImportError:
        return False

    try:
        write_planned_stop_marker(pid)
    except Exception:
        # Best-effort: if the marker can't be written, we have no choice
        # but to fall through to a hard kill.  Caller decides escalation.
        pass

    deadline = time.monotonic() + max(drain_timeout, 1.0)
    while time.monotonic() < deadline:
        if not _pid_exists(pid):
            return True
        time.sleep(0.5)
    return False


def _windows_stop_drain_timeout() -> float:
    """Return a bounded Windows gateway stop grace period."""
    try:
        from hermes_cli.gateway import _get_restart_drain_timeout

        configured = float(_get_restart_drain_timeout() or 30.0)
    except Exception:
        configured = 30.0
    # Windows CLI stop must not wedge forever. Give the gateway a real
    # graceful-drain window, then escalate to the known PID.
    return max(1.0, min(configured, 30.0))


def _force_terminate_known_gateway_pids(pids: list[int]) -> int:
    """Force-kill known gateway PIDs without a broad process sweep."""
    try:
        from gateway.status import _pid_exists, terminate_pid
    except ImportError:
        return 0

    own_pid = os.getpid()
    killed = 0
    seen: set[int] = set()
    for pid in pids:
        if pid <= 0 or pid == own_pid or pid in seen:
            continue
        seen.add(pid)
        try:
            if not _pid_exists(pid):
                continue
            terminate_pid(pid, force=True)
            killed += 1
        except ProcessLookupError:
            continue
        except PermissionError:
            print(f"⚠ Permission denied to kill PID {pid}")
        except OSError as exc:
            print(f"Failed to kill PID {pid}: {exc}")
    return killed


def _collect_gateway_stop_pids(primary_pid: int | None = None) -> list[int]:
    """Collect gateway PIDs for the active profile, preserving primary first."""
    pids: list[int] = []
    if primary_pid is not None and primary_pid > 0:
        pids.append(primary_pid)
    try:
        for pid in _gateway_pids():
            if pid > 0 and pid not in pids:
                pids.append(pid)
    except Exception:
        pass
    return pids


def stop() -> None:
    """Stop the gateway.

    Writes the planned-stop marker first so the gateway can drain
    in-flight agents and persist ``resume_pending`` before exit (the
    gateway's marker-watcher thread picks this up — Windows asyncio
    can't deliver SIGTERM to the loop, so the marker is our only IPC).
    Then escalates with bounded Windows process termination against the
    known gateway PID(s).
    """
    _assert_windows()
    from gateway.status import get_running_pid

    # Phase 1: ask the running gateway (if any) to drain itself by writing
    # the planned-stop marker, then wait briefly for it to exit cleanly.
    # On clean exit, sessions land with resume_pending=True and the next
    # boot will auto-resume them.
    pid = get_running_pid()
    stop_pids = _collect_gateway_stop_pids(pid)
    drained = False
    if pid is not None:
        drained = _drain_gateway_pid(pid, _windows_stop_drain_timeout())

    stopped_any = drained
    if _owned_task_xml() is not None:
        code, _out, err = _exec_schtasks(["/End", "/TN", get_task_name()])
        # schtasks returns nonzero when the task isn't currently running — don't treat that as an error.
        if code == 0:
            stopped_any = True
        elif "not running" not in (err or "").lower():
            print(f"⚠ schtasks /End returned code {code}: {err.strip()}")

    # Phase 3: hard-kill any still-known gateway processes. Avoid the generic
    # process sweep here: Windows direct-spawn starts are profile-scoped, and a
    # stop command must be bounded even if the scanner or shutdown path is wedged.
    stop_pids.extend(pid for pid in _collect_gateway_stop_pids() if pid not in stop_pids)
    killed = _force_terminate_known_gateway_pids(stop_pids)
    if killed:
        stopped_any = True
        print(f"✓ Killed {killed} gateway process(es)")
    if stopped_any:
        if drained:
            print("✓ Gateway stopped (drained cleanly)")
        else:
            print("✓ Gateway stopped")
    else:
        print("✗ No gateway was running")


def _wait_for_gateway_absent(timeout_s: float = 30.0, interval_s: float = 0.5) -> bool:
    """Block until no gateway process is detectable, or the timeout elapses.

    ``stop()`` can return while the previous gateway is still draining
    in-flight agents (the drain runs up to the restart-drain timeout). Uses the
    authoritative ``get_running_pid()`` (lock + liveness + start-time +
    gateway-shape) plus the now-strict ``_gateway_pids()`` scan so a relaunch
    never races a still-alive old process.
    """
    from gateway.status import get_running_pid

    deadline = time.monotonic() + max(timeout_s, interval_s)
    while time.monotonic() < deadline:
        if get_running_pid() is None and not _gateway_pids():
            return True
        time.sleep(interval_s)
    return get_running_pid() is None and not _gateway_pids()


def restart() -> None:
    """Stop the gateway then start it again.

    Waits for the old gateway to be authoritatively gone before relaunching --
    otherwise ``start()``'s "already running" guard sees the still-draining old
    process and no-ops, and when that process later exits nothing replaces it (a
    silent outage). Fails loudly if the process can't be cleared or the relaunch
    doesn't produce a running gateway.
    """
    _assert_windows()
    if _gateway_managed_launch_overlay():
        raise RuntimeError(
            "Managed Gladly gateway restart is authority-controlled. Use the "
            "Gladly runtime workflow; raw restart cannot bypass task evidence."
        )

    stop()

    if not _wait_for_gateway_absent(timeout_s=30.0):
        print("⚠ Gateway still present after stop; forcing termination before restart...")
        _force_terminate_known_gateway_pids(_collect_gateway_stop_pids())
        if not _wait_for_gateway_absent(timeout_s=10.0):
            raise RuntimeError(
                "Gateway process still detected after force kill; refusing to "
                "start a duplicate. Investigate stray PIDs before retrying."
            )

    # Give Windows a moment to release the listening port.
    time.sleep(1.0)
    start()

    if not _wait_for_gateway_ready(timeout_s=15.0):
        raise RuntimeError(
            "Gateway restart did not produce a running gateway process. "
            "Check logs/gateway.log and run `hermes gateway status`."
        )
