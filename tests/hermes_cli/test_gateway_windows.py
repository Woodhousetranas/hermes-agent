"""Tests for hermes_cli.gateway_windows."""

import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import hermes_cli.env_loader as env_loader
import hermes_cli.gateway as gateway
import hermes_cli.gateway_windows as gateway_windows
import hermes_cli.setup as setup


_BREAKAWAY_MARKER = "_HERMES_GATEWAY_BREAKAWAY"


@pytest.fixture(autouse=True)
def isolate_managed_install_receipt(monkeypatch):
    """Gateway unit tests must not depend on a live Gladly release receipt.

    Receipt/manifest binding has its own contract tests. These tests exercise
    launcher behavior with explicit managed values, so make the embedding
    detector neutral instead of borrowing whichever checkout happens to run
    the suite.
    """
    monkeypatch.setattr(env_loader, "_managed_install_contract", lambda: None)


def _managed_launch_values(runtime_path: str) -> dict[str, str]:
    return {
        "HERMES_GATEWAY_RUNTIME_PATH": runtime_path,
        "PATH": runtime_path,
        "HERMES_GATEWAY_START_VALIDATOR": str(Path(sys.executable).resolve()),
        "HERMES_GATEWAY_START_VALIDATOR_ARGS": (
            env_loader._encode_gateway_start_validator_args(["validate-start"])
        ),
    }


def _set_managed_launch_env(monkeypatch, runtime_path: str) -> dict[str, str]:
    values = _managed_launch_values(runtime_path)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values




def test_schtasks_encoding_falls_back_to_utf8(monkeypatch):
    """A broken/empty locale must not leave us without a decoder (issue #38172)."""

    monkeypatch.setattr(gateway_windows.locale, "getpreferredencoding", lambda *a, **k: "")
    assert gateway_windows._schtasks_encoding() == "utf-8"

    def _boom(*args, **kwargs):
        raise RuntimeError("locale exploded")

    monkeypatch.setattr(gateway_windows.locale, "getpreferredencoding", _boom)
    assert gateway_windows._schtasks_encoding() == "utf-8"




@pytest.mark.windows_only
def test_build_gateway_argv_keeps_venv_console_python_for_uv_venv(monkeypatch, tmp_path):
    """No pythonw / base-interpreter detour: the venv console python.exe is
    launched hidden (CREATE_NO_WINDOW) so descendants inherit its hidden
    console instead of flashing their own (#54220/#56747).

    Windows-only: ``_build_gateway_argv()`` asserts the host is Windows and the
    argv/env overlay it returns is built from real Windows path separators and
    ``Scripts/python.exe`` layout — a patched ``sys.platform`` covered the
    branch but not any of that.
    """

    project = tmp_path / "project"
    scripts = project / "venv" / "Scripts"
    site_packages = project / "venv" / "Lib" / "site-packages"
    hermes_home = tmp_path / "hermes-home"
    base = tmp_path / "uv" / "python" / "cpython-3.11-windows-x86_64-none"
    scripts.mkdir(parents=True)
    site_packages.mkdir(parents=True)
    hermes_home.mkdir()
    base.mkdir(parents=True)

    venv_python = scripts / "python.exe"
    venv_pythonw = scripts / "pythonw.exe"
    base_pythonw = base / "pythonw.exe"
    for exe in (venv_python, venv_pythonw, base_pythonw):
        exe.write_text("", encoding="utf-8")
    (project / "venv" / "pyvenv.cfg").write_text(
        f"home = {base}\nimplementation = CPython\nuv = 0.11.14\nversion_info = 3.11.15\n",
        encoding="utf-8",
    )

    import hermes_cli.gateway as gateway

    monkeypatch.setattr(gateway, "PROJECT_ROOT", project)
    monkeypatch.setattr(gateway, "get_python_path", lambda: str(venv_python))
    monkeypatch.setattr(gateway, "_profile_arg", lambda hermes_home: "")
    monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: str(hermes_home))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "stale-user-checkout"))
    monkeypatch.setenv(
        "HERMES_GATEWAY_WORKING_DIR", str(tmp_path / "stale-working-copy")
    )
    reviewed_runtime_path = r"C:\Reviewed\bin;C:\Windows\System32"
    monkeypatch.setenv("PATH", r"C:\poison")
    managed_values = _set_managed_launch_env(monkeypatch, reviewed_runtime_path)

    argv, cwd, env_overlay = gateway_windows._build_gateway_argv()

    assert argv[:3] == [str(venv_python), "-m", "hermes_cli.main"]
    assert argv[3:5] == ["--profile", "default"]
    assert argv[5:] == ["gateway", "run"]
    assert cwd == str(project.resolve())
    assert "stale-working-copy" not in cwd
    assert env_overlay["LANG"] == "C.UTF-8"
    assert env_overlay["LC_ALL"] == "C.UTF-8"
    assert env_overlay["PYTHONUTF8"] == "1"
    assert env_overlay["PYTHONIOENCODING"] == "utf-8"
    assert env_overlay["VIRTUAL_ENV"] == str(project / "venv")
    assert str(project) in env_overlay["PYTHONPATH"].split(gateway_windows.os.pathsep)
    assert str(tmp_path / "stale-user-checkout") not in env_overlay["PYTHONPATH"]
    assert env_overlay["HERMES_RUNTIME_HOME"] == str(hermes_home.resolve())
    assert env_overlay["GLADLY_HERMES_CODE_ROOT"] == str(project.resolve())
    assert env_overlay["PATH"] == reviewed_runtime_path
    assert env_overlay["HERMES_GATEWAY_RUNTIME_PATH"] == reviewed_runtime_path
    lock_values, lock_cwd = env_loader._decode_gateway_launch_env_lock(
        env_overlay[env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR]
    )
    assert lock_values == {
        key: env_overlay[key]
        for key in (
            *env_loader._GATEWAY_LAUNCH_ENV_KEYS,
            *env_loader._GATEWAY_MANAGED_LAUNCH_ENV_KEYS,
        )
    }
    assert {key: env_overlay[key] for key in managed_values} == managed_values
    assert lock_cwd == cwd


def test_locked_default_profile_bootstrap_ignores_later_sticky_profile(
    tmp_path,
):
    """A pinned default Windows launcher must not follow active_profile."""
    project_root = Path(env_loader.__file__).resolve().parent.parent
    home = tmp_path / "runtime-home"
    (home / "profiles" / "work").mkdir(parents=True)
    (home / "active_profile").write_text("work\n", encoding="utf-8")
    locked = {
        "HERMES_HOME": str(home.resolve()),
        "HERMES_RUNTIME_HOME": str(home.resolve()),
        "GLADLY_HERMES_CODE_ROOT": str(project_root),
        "PYTHONPATH": str(project_root),
        "VIRTUAL_ENV": str(Path(sys.prefix).resolve()),
    }
    marker = env_loader._encode_gateway_launch_env_lock(locked, project_root)
    child_env = {
        **os.environ,
        **locked,
        env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR: marker,
    }
    code = (
        "import os, sys; "
        "sys.argv = ['hermes', '--profile', 'default']; "
        "import hermes_cli.main; "
        "print('LOCKED_HOME=' + os.environ['HERMES_HOME'])"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project_root,
        env=child_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"LOCKED_HOME={home.resolve()}" in result.stdout


@pytest.mark.windows_only
def test_spawn_detached_marks_primary_breakaway_success(monkeypatch, tmp_path, caplog):
    """A successful breakaway spawn reports true without a warning."""
    argv = ["python.exe", "-m", "hermes_cli.main", "gateway", "run"]
    cwd = str(tmp_path)
    calls = []

    def fake_popen(call_argv, **kwargs):
        calls.append((call_argv, kwargs))
        return SimpleNamespace(pid=12345)

    monkeypatch.setattr(
        gateway_windows,
        "_build_gateway_argv",
        lambda: (argv, cwd, {"HERMES_GATEWAY_DETACHED": "1"}),
    )
    monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(gateway_windows.subprocess, "Popen", fake_popen)
    caplog.set_level(logging.WARNING, logger=gateway_windows.__name__)

    assert gateway_windows._spawn_detached() == 12345
    assert len(calls) == 1
    actual_argv, kwargs = calls[0]
    assert actual_argv == argv
    assert kwargs["cwd"] == cwd
    assert kwargs["creationflags"] == gateway_windows.windows_detach_flags()
    assert kwargs["env"][_BREAKAWAY_MARKER] == "1"
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is kwargs["stderr"]
    assert not caplog.records


@pytest.mark.windows_only
def test_managed_direct_spawn_passes_only_allowlisted_environment(
    monkeypatch,
    tmp_path,
):
    windows_dir = gateway_windows._windows_directory()
    runtime_path = f"{Path(sys.executable).parent};{windows_dir / 'System32'}"
    managed = _managed_launch_values(runtime_path)
    reviewed = tmp_path / "reviewed"
    home = tmp_path / "home"
    reviewed.mkdir()
    home.mkdir()
    overlay = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(reviewed),
        "PYTHONPATH": str(reviewed),
        "VIRTUAL_ENV": str(tmp_path / "venv"),
        "HERMES_GATEWAY_DETACHED": "1",
        **managed,
    }
    overlay[env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR] = (
        env_loader._encode_gateway_launch_env_lock(overlay, reviewed)
    )
    monkeypatch.setenv("NODE_OPTIONS", "--require=poison.js")
    monkeypatch.setenv("BASH_ENV", "poison.sh")
    calls = []
    monkeypatch.setattr(
        gateway_windows,
        "_build_gateway_argv",
        lambda: (
            [sys.executable, "-m", "hermes_cli.main", "gateway", "run"],
            str(reviewed),
            dict(overlay),
        ),
    )
    monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: home)
    monkeypatch.setattr(
        gateway_windows.subprocess,
        "Popen",
        lambda argv, **kwargs: calls.append((argv, kwargs))
        or SimpleNamespace(pid=54321),
    )

    assert gateway_windows._spawn_detached() == 54321
    child_env = calls[0][1]["env"]
    assert child_env["PATH"] == runtime_path
    assert child_env["HERMES_GATEWAY_START_VALIDATOR"] == managed[
        "HERMES_GATEWAY_START_VALIDATOR"
    ]
    assert child_env[_BREAKAWAY_MARKER] == "1"
    assert "NODE_OPTIONS" not in child_env
    assert "BASH_ENV" not in child_env


@pytest.mark.windows_only
def test_spawn_detached_warns_and_marks_no_breakaway_fallback(
    monkeypatch, tmp_path, caplog
):
    """A denied breakaway retries once with private false metadata."""
    argv = ["python.exe", "-m", "hermes_cli.main", "gateway", "run"]
    cwd = str(tmp_path)
    calls = []

    def fake_popen(call_argv, **kwargs):
        calls.append((call_argv, kwargs))
        if len(calls) == 1:
            error = OSError(13, "Access is denied")
            error.winerror = 5
            raise error
        return SimpleNamespace(pid=23456)

    monkeypatch.setattr(
        gateway_windows,
        "_build_gateway_argv",
        lambda: (
            argv,
            cwd,
            {"HERMES_GATEWAY_DETACHED": "1", "SECRET_SENTINEL": "do-not-log"},
        ),
    )
    monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(gateway_windows.subprocess, "Popen", fake_popen)
    caplog.set_level(logging.WARNING, logger=gateway_windows.__name__)

    assert gateway_windows._spawn_detached() == 23456
    assert len(calls) == 2
    (argv_primary, primary), (argv_fallback, fallback) = calls
    assert argv_primary == argv_fallback == argv
    assert primary["cwd"] == fallback["cwd"] == cwd
    assert primary["creationflags"] == gateway_windows.windows_detach_flags()
    assert (
        fallback["creationflags"]
        == gateway_windows.windows_detach_flags_without_breakaway()
    )
    assert primary["stdin"] is fallback["stdin"] is subprocess.DEVNULL
    assert primary["stdout"] is primary["stderr"]
    assert fallback["stdout"] is fallback["stderr"]
    assert Path(primary["stdout"].name) == Path(fallback["stdout"].name)
    assert primary["close_fds"] is fallback["close_fds"] is True
    assert primary["env"] is not fallback["env"]
    assert primary["env"][_BREAKAWAY_MARKER] == "1"
    assert fallback["env"][_BREAKAWAY_MARKER] == "0"
    assert {
        key: value for key, value in primary["env"].items() if key != _BREAKAWAY_MARKER
    } == {
        key: value for key, value in fallback["env"].items() if key != _BREAKAWAY_MARKER
    }

    warnings = [
        record for record in caplog.records if record.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "5" in warnings[0].getMessage()
    assert "do-not-log" not in warnings[0].getMessage()
    assert str(tmp_path) not in warnings[0].getMessage()


class TestStableWindowsGatewayWorkingDir:
    def test_stable_gateway_working_dir_uses_hermes_home(self, tmp_path, monkeypatch):
        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: home)
        assert gateway_windows._stable_gateway_working_dir(tmp_path / "checkout") == str(home.resolve())

    def test_stable_gateway_working_dir_falls_back_to_project_root(self, tmp_path, monkeypatch):
        missing = tmp_path / "missing" / ".hermes"
        project = tmp_path / "checkout"
        monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: missing)
        assert gateway_windows._stable_gateway_working_dir(project) == str(project)




def _arrange_startup_fallback(monkeypatch, tmp_path, running_pids):
    script_path = tmp_path / "Hermes_Gateway_alice.cmd"
    startup_entry = tmp_path / "Startup" / "Hermes_Gateway_alice.cmd"
    calls = []

    monkeypatch.setattr(gateway_windows, "_prompt_install_choices", lambda *args, **kwargs: (False, True))
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway_alice")
    monkeypatch.setattr(gateway_windows, "_write_task_script", lambda: script_path)
    monkeypatch.setattr(
        gateway_windows,
        "_install_scheduled_task",
        lambda task_name, script_path: (
            False,
            "schtasks /Create failed (code 1): ERROR: Access is denied.",
        ),
    )
    monkeypatch.setattr(gateway_windows, "_should_fall_back", lambda code, detail: True)
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: True)
    monkeypatch.setattr(
        gateway_windows,
        "_launch_elevated_install",
        lambda force=False, start_now=None, start_on_login=None: calls.append(("elevate", force, start_now, start_on_login)) or True,
    )

    def fake_install_startup_entry(path: Path) -> Path:
        calls.append(("install_startup", path))
        return startup_entry

    monkeypatch.setattr(gateway_windows, "_install_startup_entry", fake_install_startup_entry)
    monkeypatch.setattr(gateway_windows, "_spawn_detached", lambda path: calls.append(("spawn", path)) or 12345)
    monkeypatch.setattr(gateway_windows, "_report_gateway_start", lambda via: calls.append(("report_start", via)))
    monkeypatch.setattr(gateway_windows, "_print_next_steps", lambda: calls.append(("next_steps", None)))
    monkeypatch.setattr(gateway, "find_gateway_pids", lambda: running_pids)
    monkeypatch.setattr(gateway, "_profile_arg", lambda: "--profile alice")
    return script_path, calls




def test_gateway_cmd_script_pins_runtime_and_forces_utf8_environment(monkeypatch):
    """Scheduled Task starts must force UTF-8 for cron subprocess decoding."""
    monkeypatch.setenv("PYTHONPATH", r"C:\stale-user-checkout")
    content = gateway_windows._build_gateway_cmd_script(
        r"C:\Hermes\hermes-agent\venv\Scripts\python.exe",
        r"C:\Reviewed\Gladly-Hermes",
        r"C:\Hermes\home",
        "",
        code_root=r"C:\Reviewed\Gladly-Hermes",
    )

    assert 'set "HERMES_HOME=C:\\Hermes\\home"' in content
    assert 'set "HERMES_RUNTIME_HOME=C:\\Hermes\\home"' in content
    assert r'set "GLADLY_HERMES_CODE_ROOT=C:\Reviewed\Gladly-Hermes"' in content
    assert 'set "LANG=C.UTF-8"' in content
    assert 'set "LC_ALL=C.UTF-8"' in content
    assert 'set "PYTHONUTF8=1"' in content
    assert 'set "PYTHONIOENCODING=utf-8"' in content
    assert "%PYTHONPATH%" not in content
    assert "stale-user-checkout" not in content
    assert env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR in content


@pytest.mark.windows_only
def test_gateway_launchers_bake_exact_opt_in_runtime_path_and_lock_it(monkeypatch):
    reviewed_path = (
        r"C:\Reviewed\venv\Scripts;C:\Program Files\Git\usr\bin;"
        r"C:\Windows\System32"
    )
    monkeypatch.setenv("PATH", r"C:\poison")
    monkeypatch.setenv("NODE_OPTIONS", "--require=C:\\poison.js")
    monkeypatch.setenv("PYTHONSTARTUP", r"C:\poison.py")
    monkeypatch.setenv("BASH_ENV", r"C:\poison.sh")
    managed_values = _set_managed_launch_env(monkeypatch, reviewed_path)

    cmd = gateway_windows._build_gateway_cmd_script(
        r"C:\Reviewed\venv\Scripts\python.exe",
        r"C:\Reviewed",
        r"C:\Runtime\home",
        "",
        code_root=r"C:\Reviewed",
    )
    vbs = gateway_windows._build_gateway_vbs_script(
        r"C:\Reviewed\venv\Scripts\python.exe",
        r"C:\Reviewed",
        r"C:\Runtime\home",
        "",
        code_root=r"C:\Reviewed",
    )

    assert "wscript.exe" in cmd.casefold()
    assert '"%~dpn0.vbs"' in cmd
    assert r"C:\poison" not in cmd
    assert "--require=C:\\poison.js" not in vbs
    assert r"C:\poison.py" not in vbs
    assert r"C:\poison.sh" not in vbs
    assert "env.Remove inheritedKeys(keyIndex)" in vbs
    assert (
        'env.Item("HERMES_GATEWAY_RUNTIME_PATH") = '
        + gateway_windows._quote_vbs_string(reviewed_path)
    ) in vbs
    assert (
        'env.Item("PATH") = ' + gateway_windows._quote_vbs_string(reviewed_path)
    ) in vbs
    lock_line = next(
        line
        for line in vbs.splitlines()
        if line.startswith(
            f'env.Item("{env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR}") = '
        )
    )
    encoded = lock_line.split(" = ", 1)[1].strip('"')
    values, cwd = env_loader._decode_gateway_launch_env_lock(encoded)
    assert cwd == r"C:\Reviewed"
    assert values["PATH"] == reviewed_path
    assert values["HERMES_GATEWAY_RUNTIME_PATH"] == reviewed_path
    assert {key: values[key] for key in managed_values} == managed_values


@pytest.mark.windows_only
def test_managed_child_environment_is_from_empty_allowlist(monkeypatch, tmp_path):
    windows_dir = gateway_windows._windows_directory()
    runtime_path = f"{Path(sys.executable).parent};{windows_dir / 'System32'}"
    managed = _managed_launch_values(runtime_path)
    base = {
        "HERMES_HOME": str(tmp_path / "home"),
        "HERMES_RUNTIME_HOME": str(tmp_path / "home"),
        "GLADLY_HERMES_CODE_ROOT": str(tmp_path / "code"),
        "PYTHONPATH": str(tmp_path / "code"),
        "VIRTUAL_ENV": str(tmp_path / "venv"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "HERMES_GATEWAY_DETACHED": "1",
        **managed,
    }
    base[env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR] = (
        env_loader._encode_gateway_launch_env_lock(base, tmp_path / "code")
    )
    for key, value in {
        "NODE_OPTIONS": "--require=poison.js",
        "PYTHONSTARTUP": "poison.py",
        "PYTHONHOME": "poison-home",
        "BASH_ENV": "poison.sh",
        "ENV": "poison-env.sh",
        "SHELLOPTS": "xtrace",
    }.items():
        monkeypatch.setenv(key, value)

    child = gateway_windows._managed_gateway_child_environment(base)

    assert child["PATH"] == runtime_path
    assert child["SystemRoot"] == str(windows_dir)
    assert child["SystemDrive"] == windows_dir.drive
    assert child["ProgramData"] == str(
        (Path(windows_dir.anchor) / "ProgramData").resolve(strict=True)
    )
    assert child[env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR] == base[
        env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR
    ]
    for hostile in (
        "NODE_OPTIONS",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
    ):
        assert hostile not in child


def test_gateway_launchers_keep_legacy_inherited_path_when_opt_in_is_absent(
    monkeypatch,
):
    monkeypatch.delenv("HERMES_GATEWAY_RUNTIME_PATH", raising=False)
    content = gateway_windows._build_gateway_cmd_script(
        r"C:\Reviewed\venv\Scripts\python.exe",
        r"C:\Reviewed",
        r"C:\Runtime\home",
        "",
        code_root=r"C:\Reviewed",
    )

    assert 'set "HERMES_GATEWAY_RUNTIME_PATH=' not in content
    assert 'set "PATH=' not in content


@pytest.mark.parametrize(
    "runtime_path",
    [
        "",
        r"relative\bin;C:\Windows\System32",
        r"C:\Reviewed\bin;;C:\Windows\System32",
        r"C:\Reviewed\bin;C:\Reviewed\bin",
        r"C:\Reviewed\..\poison",
        r"C:\Reviewed\%POISON%",
    ],
)
def test_gateway_runtime_path_rejects_unsafe_or_noncanonical_input(
    monkeypatch, runtime_path
):
    _set_managed_launch_env(monkeypatch, runtime_path)

    with pytest.raises(ValueError, match="HERMES_GATEWAY_RUNTIME_PATH"):
        gateway_windows._gateway_runtime_path_overlay()


def test_resolve_gateway_working_dir_ignores_inherited_override(monkeypatch, tmp_path):
    project = tmp_path / "hermes-agent"
    repo_root = tmp_path / "Gladly-Hermes"
    repo_root.mkdir()
    monkeypatch.setenv("HERMES_GATEWAY_WORKING_DIR", str(repo_root))

    assert gateway_windows._resolve_gateway_working_dir(
        project, str(tmp_path / "home")
    ) == str(project.resolve())


def test_resolve_gateway_working_dir_uses_embedded_repo_parent(monkeypatch, tmp_path):
    project = tmp_path / "Gladly-Hermes" / "hermes-agent"
    hermes_home = tmp_path / "Gladly-Hermes" / "home"
    project.mkdir(parents=True)
    hermes_home.mkdir()
    (hermes_home.parent / "bin").mkdir()
    (hermes_home.parent / "bin" / "gladly").write_text(
        "launcher", encoding="utf-8"
    )
    monkeypatch.delenv("HERMES_GATEWAY_WORKING_DIR", raising=False)

    assert gateway_windows._resolve_gateway_working_dir(project, str(hermes_home)) == str(hermes_home.parent.resolve())


def test_legacy_gateway_working_dir_reproduces_pre_lock_default_layout(tmp_path):
    repo_root = tmp_path / "Gladly-Hermes"
    project = repo_root / "hermes-agent"
    hermes_home = repo_root / "home"
    project.mkdir(parents=True)
    hermes_home.mkdir()

    assert gateway_windows._legacy_gateway_working_dir_for_migration(
        project, str(hermes_home)
    ) == str(repo_root.resolve())


@pytest.mark.parametrize("layout", ["named", "standalone"])
def test_legacy_launcher_bytes_preserve_pre_lock_home_cwd(
    monkeypatch, tmp_path, layout
):
    project = tmp_path / "reviewed" / "hermes-agent"
    python_path = project / "venv" / "Scripts" / "python.exe"
    python_path.parent.mkdir(parents=True)
    python_path.write_text("", encoding="utf-8")
    if layout == "named":
        runtime_root = tmp_path / "runtime"
        hermes_home = runtime_root / "profiles" / "work"
        expected_profile_arg = "--profile work"
    else:
        runtime_root = tmp_path / "other-default"
        hermes_home = tmp_path / "standalone-runtime"
        expected_profile_arg = None
    hermes_home.mkdir(parents=True)
    monkeypatch.setattr(gateway, "PROJECT_ROOT", project)
    monkeypatch.setattr(gateway, "get_python_path", lambda: str(python_path))
    monkeypatch.setattr(
        gateway_windows,
        "__file__",
        str(project / "hermes_cli" / "gateway_windows.py"),
    )
    monkeypatch.setattr(
        "hermes_cli.config.get_hermes_home", lambda: str(hermes_home)
    )
    monkeypatch.setattr(
        "hermes_constants.get_default_hermes_root", lambda: runtime_root
    )

    cmd, vbs = gateway_windows._render_legacy_gateway_task_scripts_for_migration()
    expected_cwd = str(hermes_home.resolve())

    assert (
        f"cd /d {gateway_windows._quote_cmd_script_arg(expected_cwd)}" in cmd
    )
    assert (
        "sh.CurrentDirectory = "
        f"{gateway_windows._quote_vbs_string(expected_cwd)}" in vbs
    )
    if expected_profile_arg:
        assert expected_profile_arg in cmd
        assert expected_profile_arg in vbs
    else:
        assert "--profile" not in cmd
        assert "--profile" not in vbs


def test_pre_lock_same_home_foreign_checkout_bytes_are_not_migration_owned(
    monkeypatch, tmp_path
):
    hermes_home = tmp_path / "shared-runtime"
    hermes_home.mkdir()
    expected_script = hermes_home / "gateway-service" / "Hermes_Gateway.cmd"
    expected_script.parent.mkdir()
    monkeypatch.setattr(
        "hermes_cli.config.get_hermes_home", lambda: str(hermes_home)
    )
    monkeypatch.setattr(
        "hermes_constants.get_default_hermes_root", lambda: hermes_home
    )
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )

    def render_legacy(project: Path) -> tuple[str, str]:
        python_path = project / "venv" / "Scripts" / "python.exe"
        python_path.parent.mkdir(parents=True)
        python_path.write_text("", encoding="utf-8")
        monkeypatch.setattr(gateway, "PROJECT_ROOT", project)
        monkeypatch.setattr(
            gateway, "get_python_path", lambda: str(python_path)
        )
        monkeypatch.setattr(
            gateway_windows,
            "__file__",
            str(project / "hermes_cli" / "gateway_windows.py"),
        )
        return gateway_windows._render_legacy_gateway_task_scripts_for_migration()

    _, foreign_vbs = render_legacy(tmp_path / "foreign" / "hermes-agent")
    reviewed_cmd, reviewed_vbs = render_legacy(
        tmp_path / "reviewed" / "hermes-agent"
    )
    monkeypatch.setattr(
        gateway_windows,
        "_render_current_gateway_task_scripts",
        lambda: ("locked reviewed cmd\r\n", "locked reviewed vbs\r\n"),
    )

    vbs_path = expected_script.with_suffix(".vbs")
    vbs_path.write_text(foreign_vbs, encoding="utf-8", newline="")
    assert not gateway_windows._gateway_launcher_belongs_to_current_install(vbs_path)

    vbs_path.write_text(reviewed_vbs, encoding="utf-8", newline="")
    assert gateway_windows._gateway_launcher_belongs_to_current_install(vbs_path)
    assert reviewed_cmd != "locked reviewed cmd\r\n"


def test_resolve_gateway_code_root_uses_embedded_reviewed_repo(tmp_path):
    repo_root = tmp_path / "Gladly-Hermes"
    project = repo_root / "hermes-agent"
    hermes_home = repo_root / "home"
    project.mkdir(parents=True)
    hermes_home.mkdir()
    (repo_root / "bin").mkdir()
    (repo_root / "bin" / "gladly").write_text("launcher", encoding="utf-8")

    assert gateway_windows._resolve_gateway_code_root(project, str(hermes_home)) == str(
        repo_root.resolve()
    )


def test_resolve_gateway_code_root_normalizes_named_profile_home(tmp_path):
    repo_root = tmp_path / "Gladly-Hermes"
    project = repo_root / "hermes-agent"
    hermes_home = repo_root / "home" / "profiles" / "work"
    project.mkdir(parents=True)
    hermes_home.mkdir(parents=True)
    (repo_root / "bin").mkdir()
    (repo_root / "bin" / "gladly").write_text("launcher", encoding="utf-8")

    assert gateway_windows._resolve_gateway_code_root(project, str(hermes_home)) == str(
        repo_root.resolve()
    )


def test_resolve_gateway_code_root_rejects_stale_lookalike_home(tmp_path):
    reviewed_root = tmp_path / "reviewed" / "Gladly-Hermes"
    reviewed_project = reviewed_root / "hermes-agent"
    reviewed_project.mkdir(parents=True)
    (reviewed_root / "home").mkdir()
    (reviewed_root / "bin").mkdir()
    (reviewed_root / "bin" / "gladly").write_text(
        "reviewed launcher", encoding="utf-8"
    )

    stale_root = tmp_path / "old-host" / "Gladly-Hermes"
    stale_home = stale_root / "home"
    (stale_root / "hermes-agent").mkdir(parents=True)
    stale_home.mkdir()
    (stale_root / "bin").mkdir()
    (stale_root / "bin" / "gladly").write_text(
        "stale launcher", encoding="utf-8"
    )

    assert gateway_windows._resolve_gateway_code_root(
        reviewed_project, str(stale_home)
    ) == str(reviewed_project.resolve())


def test_write_task_script_bakes_canonical_home_and_reviewed_repo(
    monkeypatch, tmp_path
):
    repo_root = tmp_path / "Gladly-Hermes"
    project = repo_root / "hermes-agent"
    hermes_home = repo_root / "home"
    python_path = project / "venv" / "Scripts" / "python.exe"
    script_path = hermes_home / "gateway-service" / "Hermes_Gateway.cmd"
    python_path.parent.mkdir(parents=True)
    script_path.parent.mkdir(parents=True)
    (repo_root / "bin").mkdir()
    (repo_root / "bin" / "gladly").write_text("launcher", encoding="utf-8")
    monkeypatch.setenv("HERMES_RUNTIME_HOME", str(tmp_path / "old-runtime"))
    monkeypatch.setenv("GLADLY_HERMES_CODE_ROOT", str(tmp_path / "old-code"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "old-pythonpath"))
    monkeypatch.setenv(
        "HERMES_GATEWAY_WORKING_DIR", str(tmp_path / "old-working-copy")
    )
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(gateway_windows, "get_task_script_path", lambda: script_path)
    monkeypatch.setattr(gateway, "PROJECT_ROOT", project)
    monkeypatch.setattr(gateway, "get_python_path", lambda: str(python_path))
    monkeypatch.setattr(gateway, "_profile_arg", lambda home: "")
    monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: str(hermes_home))

    assert gateway_windows._write_task_script() == script_path

    vbs = script_path.with_suffix(".vbs").read_text(encoding="utf-8")
    assert f'"HERMES_RUNTIME_HOME") = "{hermes_home.resolve()}"' in vbs
    assert f'"GLADLY_HERMES_CODE_ROOT") = "{repo_root.resolve()}"' in vbs
    assert "old-runtime" not in vbs
    assert "old-code" not in vbs
    assert "old-pythonpath" not in vbs
    assert "old-working-copy" not in vbs
    assert env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR in vbs
    assert "--profile default" in vbs


@pytest.mark.windows_only
def test_restart_spec_replaces_inherited_runtime_roots_and_working_dir(
    monkeypatch, tmp_path
):
    project = tmp_path / "reviewed-hermes-agent"
    hermes_home = tmp_path / "runtime-home"
    python_path = project / "venv" / "Scripts" / "python.exe"
    python_path.parent.mkdir(parents=True)
    python_path.write_text("", encoding="utf-8")
    hermes_home.mkdir()
    monkeypatch.setattr(gateway, "PROJECT_ROOT", project)
    monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: str(hermes_home))
    monkeypatch.setenv("HERMES_RUNTIME_HOME", str(tmp_path / "old-runtime"))
    monkeypatch.setenv("GLADLY_HERMES_CODE_ROOT", str(tmp_path / "old-code"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "old-pythonpath"))
    monkeypatch.setenv(
        "HERMES_GATEWAY_WORKING_DIR", str(tmp_path / "old-working-copy")
    )
    reviewed_runtime_path = r"C:\Reviewed\bin;C:\Windows\System32"
    monkeypatch.setenv("PATH", r"C:\poison")
    managed_values = _set_managed_launch_env(monkeypatch, reviewed_runtime_path)

    argv, cwd, overlay = gateway_windows.windowless_gateway_restart_spec(
        [str(python_path), "-m", "hermes_cli.main", "gateway", "run"]
    )

    assert argv[0] == str(python_path)
    assert argv[3:5] == ["--profile", "default"]
    assert cwd == str(project.resolve())
    assert overlay["HERMES_HOME"] == str(hermes_home.resolve())
    assert overlay["HERMES_RUNTIME_HOME"] == str(hermes_home.resolve())
    assert overlay["GLADLY_HERMES_CODE_ROOT"] == str(project.resolve())
    assert str(tmp_path / "old-pythonpath") not in overlay["PYTHONPATH"]
    assert "old-working-copy" not in cwd
    assert overlay["PATH"] == reviewed_runtime_path
    assert overlay["HERMES_GATEWAY_RUNTIME_PATH"] == reviewed_runtime_path
    lock_values, lock_cwd = env_loader._decode_gateway_launch_env_lock(
        overlay[env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR]
    )
    assert lock_values == {
        key: overlay[key]
        for key in (
            *env_loader._GATEWAY_LAUNCH_ENV_KEYS,
            *env_loader._GATEWAY_MANAGED_LAUNCH_ENV_KEYS,
        )
    }
    assert {key: overlay[key] for key in managed_values} == managed_values
    assert lock_cwd == cwd


@pytest.mark.windows_only
def test_restart_spec_locks_home_for_replayed_named_profile(monkeypatch, tmp_path):
    """A default-profile updater may restart a different mapped profile."""
    project_root = Path(env_loader.__file__).resolve().parent.parent
    runtime_root = tmp_path / "runtime-home"
    work_home = runtime_root / "profiles" / "work"
    work_home.mkdir(parents=True)
    (runtime_root / "active_profile").write_text("default\n", encoding="utf-8")
    monkeypatch.setattr(gateway, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(
        "hermes_cli.config.get_hermes_home", lambda: str(runtime_root)
    )

    argv, cwd, overlay = gateway_windows.windowless_gateway_restart_spec(
        [
            sys.executable,
            "-m",
            "hermes_cli.main",
            "--profile",
            "work",
            "gateway",
            "run",
            "--replace",
        ]
    )

    assert argv[3:5] == ["--profile", "work"]
    assert overlay["HERMES_HOME"] == str(work_home.resolve())
    assert overlay["HERMES_RUNTIME_HOME"] == str(work_home.resolve())
    lock_values, lock_cwd = env_loader._decode_gateway_launch_env_lock(
        overlay[env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR]
    )
    assert lock_values["HERMES_HOME"] == str(work_home.resolve())
    assert lock_cwd == cwd

    child_env = {**os.environ, **overlay}
    code = (
        "import os, sys; "
        "sys.argv = ['hermes', '--profile', 'work']; "
        "import hermes_cli.main; "
        "print('LOCKED_HOME=' + os.environ['HERMES_HOME'])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=cwd,
        env=child_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"LOCKED_HOME={work_home.resolve()}" in result.stdout


@pytest.mark.windows_only
def test_restart_spec_fails_closed_for_missing_interpreter(monkeypatch, tmp_path):
    missing = tmp_path / "missing-venv" / "Scripts" / "python.exe"
    monkeypatch.setattr(gateway, "PROJECT_ROOT", tmp_path)

    with pytest.raises(RuntimeError, match="pin its Python interpreter"):
        gateway_windows.windowless_gateway_restart_spec(
            [str(missing), "-m", "hermes_cli.main", "gateway", "run"]
        )


@pytest.mark.windows_only
def test_restart_spec_fails_closed_when_runtime_home_is_unavailable(
    monkeypatch, tmp_path
):
    python_path = tmp_path / "venv" / "Scripts" / "python.exe"
    python_path.parent.mkdir(parents=True)
    python_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(gateway, "PROJECT_ROOT", tmp_path)

    def fail_home():
        raise OSError("runtime home unavailable")

    monkeypatch.setattr("hermes_cli.config.get_hermes_home", fail_home)

    with pytest.raises(RuntimeError, match="pin its Hermes home"):
        gateway_windows.windowless_gateway_restart_spec(
            [str(python_path), "-m", "hermes_cli.main", "gateway", "run"]
        )


@pytest.mark.windows_only
def test_restart_watcher_refuses_unlocked_windows_respawn(monkeypatch):
    def fail_spec(_argv):
        raise RuntimeError("no complete launch lock")

    monkeypatch.setattr(
        gateway_windows, "windowless_gateway_restart_spec", fail_spec
    )
    monkeypatch.setattr(
        gateway.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("unlocked watcher was spawned"),
    )

    assert gateway._spawn_gateway_restart_watcher(
        1234,
        ["python.exe", "-m", "hermes_cli.main", "gateway", "run"],
    ) is False


@pytest.mark.windows_only
def test_restart_watcher_refuses_runtime_path_opt_in_without_sealed_path(
    monkeypatch, tmp_path
):
    reviewed = tmp_path / "reviewed"
    reviewed.mkdir()
    monkeypatch.setenv(
        "HERMES_GATEWAY_RUNTIME_PATH",
        r"C:\Reviewed\bin;C:\Windows\System32",
    )
    incomplete = {
        "HERMES_HOME": str(tmp_path / "home"),
        "HERMES_RUNTIME_HOME": str(tmp_path / "home"),
        "GLADLY_HERMES_CODE_ROOT": str(reviewed),
        "PYTHONPATH": str(reviewed),
        "VIRTUAL_ENV": str(tmp_path / "venv"),
        env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR: "locked-marker",
    }
    monkeypatch.setattr(
        gateway_windows,
        "windowless_gateway_restart_spec",
        lambda argv: (list(argv), str(reviewed), incomplete),
    )
    monkeypatch.setattr(
        gateway.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("unsealed watcher was spawned"),
    )

    assert gateway._spawn_gateway_restart_watcher(
        1234,
        ["python.exe", "-m", "hermes_cli.main", "gateway", "run"],
    ) is False


@pytest.mark.windows_only
def test_restart_watcher_process_is_pinned_on_primary_and_fallback_spawn(
    monkeypatch, tmp_path
):
    reviewed = tmp_path / "reviewed"
    reviewed.mkdir()
    overlay = {
        "HERMES_HOME": str(tmp_path / "home"),
        "HERMES_RUNTIME_HOME": str(tmp_path / "home"),
        "GLADLY_HERMES_CODE_ROOT": str(reviewed),
        "PYTHONPATH": str(reviewed / "hermes-agent"),
        "VIRTUAL_ENV": str(tmp_path / "venv"),
        env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR: "locked-marker",
    }
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "poison-home"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "poison-code"))
    monkeypatch.setenv(
        "HERMES_GATEWAY_WORKING_DIR", str(tmp_path / "poison-cwd")
    )
    monkeypatch.setattr(
        gateway_windows,
        "windowless_gateway_restart_spec",
        lambda argv: (list(argv), str(reviewed), dict(overlay)),
    )
    calls = []

    def fake_popen(*args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 1:
            raise OSError("breakaway denied")
        return object()

    monkeypatch.setattr(gateway.subprocess, "Popen", fake_popen)

    assert gateway._spawn_gateway_restart_watcher(
        1234,
        ["python.exe", "-m", "hermes_cli.main", "gateway", "run"],
    ) is True
    assert len(calls) == 2
    for _args, kwargs in calls:
        assert kwargs["cwd"] == str(reviewed)
        assert kwargs["env"]["PYTHONPATH"] == overlay["PYTHONPATH"]
        assert kwargs["env"]["GLADLY_HERMES_CODE_ROOT"] == str(reviewed)
        assert "poison-code" not in kwargs["env"]["PYTHONPATH"]
        assert "HERMES_GATEWAY_WORKING_DIR" not in kwargs["env"]


@pytest.mark.windows_only
def test_managed_restart_watcher_environment_is_allowlisted(monkeypatch, tmp_path):
    windows_dir = gateway_windows._windows_directory()
    runtime_path = f"{Path(sys.executable).parent};{windows_dir / 'System32'}"
    managed = _set_managed_launch_env(monkeypatch, runtime_path)
    reviewed = tmp_path / "reviewed"
    home = tmp_path / "home"
    reviewed.mkdir()
    home.mkdir()
    overlay = {
        "HERMES_HOME": str(home),
        "HERMES_RUNTIME_HOME": str(home),
        "GLADLY_HERMES_CODE_ROOT": str(reviewed),
        "PYTHONPATH": str(reviewed),
        "VIRTUAL_ENV": str(tmp_path / "venv"),
        **managed,
    }
    overlay[env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR] = (
        env_loader._encode_gateway_launch_env_lock(overlay, reviewed)
    )
    monkeypatch.setenv("NODE_OPTIONS", "--require=poison.js")
    monkeypatch.setenv("BASH_ENV", "poison.sh")
    monkeypatch.setattr(
        gateway_windows,
        "windowless_gateway_restart_spec",
        lambda argv: (list(argv), str(reviewed), dict(overlay)),
    )
    calls = []
    monkeypatch.setattr(
        gateway.subprocess,
        "Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)) or SimpleNamespace(),
    )

    assert gateway._spawn_gateway_restart_watcher(
        1234,
        [sys.executable, "-m", "hermes_cli.main", "gateway", "run"],
    ) is True
    watcher_env = calls[0][1]["env"]
    assert watcher_env["PATH"] == runtime_path
    assert watcher_env[env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR] == overlay[
        env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR
    ]
    assert "NODE_OPTIONS" not in watcher_env
    assert "BASH_ENV" not in watcher_env


def test_exec_schtasks_replaces_undecodable_localized_output(monkeypatch):
    calls = []

    class Result:
        returncode = 1
        stdout = ""
        stderr = "ERROR"

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        gateway_windows,
        "_schtasks_executable",
        lambda: r"C:\Windows\System32\schtasks.exe",
    )
    monkeypatch.setattr(gateway_windows.subprocess, "run", fake_run)

    gateway_windows._exec_schtasks(["/Query", "/TN", "Hermes_Gateway"])

    assert calls[0][1]["text"] is True
    assert calls[0][1]["errors"] == "replace"


@pytest.mark.windows_only
def test_exec_schtasks_ignores_path_decoy(monkeypatch, tmp_path):
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / "schtasks.exe").write_bytes(b"decoy")
    monkeypatch.setenv("PATH", str(decoy))
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(gateway_windows.subprocess, "run", fake_run)

    assert gateway_windows._exec_schtasks(["/Query"])[0] == 0
    expected = gateway_windows._windows_directory() / "System32" / "schtasks.exe"
    assert Path(calls[0][0][0]) == expected
    assert Path(calls[0][0][0]) != decoy / "schtasks.exe"


@pytest.mark.windows_only
def test_elevated_gateway_command_uses_hidden_console_python(monkeypatch):
    """UAC handoff launches console python with SW_HIDE — a single hidden
    console, not console-less pythonw (#54220/#56747), and no visible
    elevated cmd.exe window left open.

    Windows-only: the code path runs behind ``_assert_windows()`` and goes
    through ``ctypes.windll.shell32``, neither of which exists on a faked
    host. ShellExecuteW itself stays mocked — it would raise a real UAC
    prompt — but the host identity is genuine.
    """
    calls = []

    class FakeShell32:
        def ShellExecuteW(self, hwnd, verb, executable, params, cwd, show):
            calls.append((hwnd, verb, executable, params, cwd, show))
            return 33

    class FakeWindll:
        shell32 = FakeShell32()

    monkeypatch.setattr(gateway_windows, "_current_profile_cli_args", lambda: ["--profile", "alice"])
    monkeypatch.setattr(gateway_windows.sys, "executable", r"C:\Hermes\venv\Scripts\python.exe")
    monkeypatch.setattr(gateway_windows.ctypes, "windll", FakeWindll(), raising=False)

    assert gateway_windows._launch_elevated_gateway_command("install", ["--start-now", "--elevated-handoff"])

    assert len(calls) == 1
    _hwnd, verb, executable, params, cwd, show = calls[0]
    assert verb == "runas"
    assert executable == r"C:\Hermes\venv\Scripts\python.exe"
    assert "--profile alice gateway install --start-now --elevated-handoff" in params
    assert show == 0
    assert cwd

    calls = []

    class FakeShell32:
        def ShellExecuteW(self, hwnd, verb, executable, params, cwd, show):
            calls.append((hwnd, verb, executable, params, cwd, show))
            return 33

    class FakeWindll:
        shell32 = FakeShell32()

    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(gateway_windows, "_current_profile_cli_args", lambda: ["--profile", "alice"])
    monkeypatch.setattr(gateway_windows.sys, "executable", r"C:\Hermes\venv\Scripts\python.exe")
    monkeypatch.setattr(gateway_windows.ctypes, "windll", FakeWindll(), raising=False)

    assert gateway_windows._launch_elevated_gateway_command("install", ["--start-now", "--elevated-handoff"])

    assert len(calls) == 1
    _hwnd, verb, executable, params, cwd, show = calls[0]
    assert verb == "runas"
    assert executable == r"C:\Hermes\venv\Scripts\python.exe"
    assert "--profile alice gateway install --start-now --elevated-handoff" in params
    assert show == 0
    assert cwd


def test_install_scheduled_task_recreates_atomically_disabled(monkeypatch, tmp_path):
    """Install must delete+create so stale minute-repeat task settings are not preserved.

    Host-agnostic on purpose: ``_install_scheduled_task`` only renders the task
    XML and shells out through ``_exec_schtasks`` (mocked here as the genuine
    external dependency), so no platform fake is needed.
    """
    calls = []
    script_path = tmp_path / "Hermes_Gateway_alice.cmd"
    xml_seen = {}

    monkeypatch.setattr(gateway_windows, "_resolve_task_user", lambda: r"DOMAIN\\alice")

    def fake_schtasks(args):
        calls.append(tuple(args))
        if args[0] == "/Delete":
            return (0, "SUCCESS", "")
        if args[0] == "/Create":
            xml_path = Path(args[args.index("/XML") + 1])
            xml_seen["text"] = xml_path.read_text(encoding="utf-16")
            return (0, "SUCCESS", "")
        raise AssertionError(f"unexpected schtasks args: {args}")

    monkeypatch.setattr(gateway_windows, "_exec_schtasks", fake_schtasks)
    ok, detail = gateway_windows._install_scheduled_task(
        "Hermes_Gateway_alice",
        script_path,
        enabled=False,
    )

    assert ok is True
    assert "disabled" in detail
    assert "/Change" not in [arg for call in calls for arg in call]
    assert calls[0][:4] == ("/Delete", "/F", "/TN", "Hermes_Gateway_alice")
    assert calls[1][0] == "/Create"
    assert "/XML" in calls[1]
    assert "/SC" not in calls[1]
    assert "<Delay>PT30S</Delay>" in xml_seen["text"]
    assert "<StartWhenAvailable>true</StartWhenAvailable>" in xml_seen["text"]
    assert "<StopOnIdleEnd>false</StopOnIdleEnd>" in xml_seen["text"]
    assert "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" in xml_seen["text"]
    assert "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>" in xml_seen["text"]
    assert "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" in xml_seen["text"]
    assert "<RestartOnFailure>" in xml_seen["text"]
    assert "<Count>999</Count>" in xml_seen["text"]
    assert "<LogonTrigger>\n      <Enabled>true</Enabled>" in xml_seen["text"]
    settings = xml_seen["text"].split("<Settings>", 1)[1].split("</Settings>", 1)[0]
    assert "<Enabled>false</Enabled>" in settings
    # Scheduled Task launches the console-less .vbs via wscript.exe, never cmd.exe
    # (issue #45599 fix A: no console -> no logon CTRL_CLOSE_EVENT / 0xC000013A).
    assert "<Command>wscript.exe</Command>" in xml_seen["text"]
    assert "//B //Nologo" in xml_seen["text"]
    assert "Hermes_Gateway_alice.vbs" in xml_seen["text"]
    assert "cmd.exe" not in xml_seen["text"]


def test_gateway_vbs_script_is_console_less_and_pins_runtime(monkeypatch):
    """The .vbs launcher must avoid cmd.exe entirely and Run pythonw hidden
    (issue #45599 fix A: no console -> no logon CTRL_CLOSE_EVENT / 0xC000013A)."""
    monkeypatch.setattr(
        gateway_windows,
        "_resolve_detached_python",
        lambda exe: (r"C:\venv\Scripts\pythonw.exe", Path(r"C:\venv"), []),
    )
    content = gateway_windows._build_gateway_vbs_script(
        r"C:\venv\Scripts\python.exe",
        r"C:\Reviewed\Gladly-Hermes",
        r"C:\Hermes\home",
        "--profile work",
        code_root=r"C:\Reviewed\Gladly-Hermes",
    )
    assert "cmd.exe" not in content.lower()
    assert 'CreateObject("WScript.Shell")' in content
    assert "pythonw.exe" in content
    assert "hermes_cli.main" in content
    assert "gateway run" in content
    assert ", 0, False" in content  # hidden window, detached/async
    for var in (
        "HERMES_HOME",
        "HERMES_RUNTIME_HOME",
        "GLADLY_HERMES_CODE_ROOT",
        "PYTHONIOENCODING",
        "HERMES_GATEWAY_DETACHED",
        "VIRTUAL_ENV",
        "PYTHONPATH",
    ):
        assert var in content
    assert '"HERMES_RUNTIME_HOME") = "C:\\Hermes\\home"' in content
    assert '"GLADLY_HERMES_CODE_ROOT") = "C:\\Reviewed\\Gladly-Hermes"' in content
    assert "existing_pp" not in content
    assert "--profile" in content and "work" in content
    assert content.endswith("\r\n")


@pytest.mark.windows_only
def test_sealed_task_xml_uses_exact_system32_wscript_despite_path_decoy(
    monkeypatch, tmp_path
):
    system_root = Path(os.environ["SystemRoot"])
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / "wscript.exe").write_text("decoy", encoding="utf-8")
    reviewed_path = f"{decoy};{system_root / 'System32'}"
    _set_managed_launch_env(monkeypatch, reviewed_path)

    xml = gateway_windows._build_scheduled_task_xml(
        "Hermes_Gateway",
        tmp_path / "Hermes_Gateway.vbs",
        None,
        enabled=False,
    )

    expected = Path(gateway_windows._stable_system_executable("wscript.exe"))
    assert f"<Command>{expected}</Command>" in xml
    assert f"<Command>{decoy / 'wscript.exe'}</Command>" not in xml


@pytest.mark.windows_only
def test_task_xml_complete_renderer_allows_only_direct_settings_enabled_overlay(
    monkeypatch,
):
    for key in env_loader._GATEWAY_MANAGED_LAUNCH_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    xml = gateway_windows._build_scheduled_task_xml(
        gateway_windows.get_task_name(),
        gateway_windows._expected_task_script_path().with_suffix(".vbs"),
        gateway_windows._resolve_task_user(),
        enabled=False,
    )

    assert gateway_windows._task_xml_matches_current_definition(xml)
    enabled_xml = xml.replace(
        "    <Enabled>false</Enabled>",
        "    <Enabled>true</Enabled>",
        1,
    )
    assert gateway_windows._task_xml_matches_current_definition(enabled_xml)

    hostile_variants = (
        xml.replace("<RunLevel>LeastPrivilege</RunLevel>", "<RunLevel>HighestAvailable</RunLevel>"),
        xml.replace("<Delay>PT30S</Delay>", "<Delay>PT1S</Delay>"),
        xml.replace("<StartWhenAvailable>true</StartWhenAvailable>", "<StartWhenAvailable>false</StartWhenAvailable>"),
        xml.replace("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>", "<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>"),
        xml.replace("<Description>Hermes Agent", "<Description>Foreign Hermes Agent"),
        xml.replace("<Actions Context=\"Author\">", "<Actions Context=\"Foreign\">"),
        xml.replace("      <Enabled>true</Enabled>", "      <Enabled>false</Enabled>", 1),
        xml.replace("<Arguments>//B", "<Arguments> //B"),
    )
    assert all(
        not gateway_windows._task_xml_matches_current_definition(candidate)
        for candidate in hostile_variants
    )


def test_task_xml_accepts_only_exact_windows_scheduler_export_normalization(
    monkeypatch,
):
    from copy import deepcopy
    from xml.etree import ElementTree

    for key in env_loader._GATEWAY_MANAGED_LAUNCH_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    task_name = gateway_windows.get_task_name()
    user = r"DOMAIN\alice"
    sid = "S-1-5-21-111-222-333-1001"
    monkeypatch.setattr(gateway_windows, "_resolve_task_user", lambda: user)
    monkeypatch.setattr(gateway_windows, "_resolve_task_user_sid", lambda: sid)
    renderer_xml = gateway_windows._build_scheduled_task_xml(
        task_name,
        gateway_windows._expected_task_script_path().with_suffix(".vbs"),
        user,
        enabled=False,
    )

    namespace = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"

    def child(parent, name):
        return next(node for node in list(parent) if node.tag == f"{namespace}{name}")

    def exported_xml(source):
        root = deepcopy(ElementTree.fromstring(source))
        registration = child(root, "RegistrationInfo")
        uri = ElementTree.Element(f"{namespace}URI")
        uri.text = f"\\{task_name}"
        registration.append(uri)
        principal = child(child(root, "Principals"), "Principal")
        child(principal, "UserId").text = sid
        principal.remove(child(principal, "RunLevel"))
        trigger = child(child(root, "Triggers"), "LogonTrigger")
        trigger.remove(child(trigger, "Enabled"))
        settings = child(root, "Settings")
        for name in (
            "AllowHardTerminate",
            "RunOnlyIfNetworkAvailable",
            "AllowStartOnDemand",
            "Hidden",
            "RunOnlyIfIdle",
            "WakeToRun",
            "Priority",
        ):
            settings.remove(child(settings, name))
        restart = child(settings, "RestartOnFailure")
        restart[:] = [child(restart, "Count"), child(restart, "Interval")]
        unified = ElementTree.Element(f"{namespace}UseUnifiedSchedulingEngine")
        unified.text = "true"
        settings.append(unified)
        setting_order = (
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
            node.tag.rsplit("}", 1)[-1]: node for node in list(settings)
        }
        settings[:] = [settings_by_name[name] for name in setting_order]
        root_order = (
            "RegistrationInfo",
            "Principals",
            "Settings",
            "Triggers",
            "Actions",
        )
        root_by_name = {node.tag.rsplit("}", 1)[-1]: node for node in list(root)}
        root[:] = [root_by_name[name] for name in root_order]
        return ElementTree.tostring(root, encoding="unicode")

    exported = exported_xml(renderer_xml)
    assert gateway_windows._task_xml_matches_current_definition(exported)
    assert not gateway_windows._task_xml_matches_current_definition(
        exported,
        allow_settings_enabled_overlay=False,
    )
    enabled_export = exported.replace(
        "<ns0:Enabled>false</ns0:Enabled>",
        "<ns0:Enabled>true</ns0:Enabled>",
    )
    assert gateway_windows._task_xml_matches_current_definition(enabled_export)
    assert gateway_windows._task_xml_matches_current_definition(
        enabled_export,
        allow_settings_enabled_overlay=False,
    )

    hostile_variants = (
        exported.replace(f"\\{task_name}", "\\Foreign_Gateway"),
        exported.replace(sid, "S-1-5-21-111-222-333-1002"),
        exported.replace(
            "<ns0:UseUnifiedSchedulingEngine>true</ns0:UseUnifiedSchedulingEngine>",
            "<ns0:UseUnifiedSchedulingEngine>false</ns0:UseUnifiedSchedulingEngine>",
        ),
        exported.replace("<ns0:Count>999</ns0:Count>", "<ns0:Count>998</ns0:Count>"),
        exported.replace(
            "</ns0:Settings>",
            "<ns0:ForeignPolicy>true</ns0:ForeignPolicy></ns0:Settings>",
        ),
    )
    assert all(
        not gateway_windows._task_xml_matches_current_definition(candidate)
        for candidate in hostile_variants
    )


@pytest.mark.windows_only
def test_task_user_sid_is_read_from_current_windows_token():
    sid = gateway_windows._resolve_task_user_sid()
    assert sid is not None
    assert re.fullmatch(r"S-\d+(?:-\d+)+", sid)


def test_elevated_install_propagates_disabled_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(
        gateway_windows,
        "_launch_elevated_gateway_command",
        lambda command, extra_args=None: calls.append((command, extra_args)) or True,
    )

    assert gateway_windows._launch_elevated_install(
        force=True,
        start_now=False,
        start_on_login=True,
        install_disabled=True,
    ) is True

    assert calls == [
        (
            "install",
            [
                "--elevated-handoff",
                "--force",
                "--no-start-now",
                "--start-on-login",
                "--install-disabled",
            ],
        )
    ]


def test_current_profile_cli_args_pins_default_for_uac_child(monkeypatch):
    monkeypatch.setattr(gateway, "_profile_arg", lambda: "")

    assert gateway_windows._current_profile_cli_args() == [
        "--profile",
        "default",
    ]


def test_install_disabled_never_starts_and_registers_disabled(
    monkeypatch, tmp_path, capsys
):
    calls = []
    script_path = tmp_path / "Hermes_Gateway.cmd"
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_startup_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_task_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows,
        "_prompt_install_choices",
        lambda start_now, start_on_login: calls.append(
            ("choices", start_now, start_on_login)
        )
        or (start_now, start_on_login),
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(gateway_windows, "_write_task_script", lambda: script_path)
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: True)
    monkeypatch.setattr(
        gateway_windows,
        "_remove_startup_fallback_entries",
        lambda: calls.append(("remove_startup",)),
    )
    monkeypatch.setattr(
        gateway_windows,
        "_install_scheduled_task",
        lambda task_name, path, enabled=True: calls.append(
            ("install", task_name, path, enabled)
        )
        or (True, "Created Scheduled Task 'Hermes_Gateway' (disabled)"),
    )
    monkeypatch.setattr(
        gateway_windows,
        "_spawn_detached",
        lambda *args, **kwargs: pytest.fail("disabled install started gateway"),
    )
    monkeypatch.setattr(gateway_windows, "_print_next_steps", lambda: None)

    gateway_windows.install(
        start_now=True,
        start_on_login=False,
        install_disabled=True,
    )

    assert calls == [
        ("choices", False, True),
        ("remove_startup",),
        ("install", "Hermes_Gateway", script_path, False),
    ]
    output = capsys.readouterr().out
    assert "installed but disabled" in output
    assert "Start manually" not in output


@pytest.mark.windows_only
def test_managed_runtime_rejects_raw_install_enable_and_direct_start(
    monkeypatch,
):
    windows_dir = gateway_windows._windows_directory()
    _set_managed_launch_env(
        monkeypatch,
        f"{Path(sys.executable).parent};{windows_dir / 'System32'}",
    )
    monkeypatch.setattr(
        gateway_windows,
        "_write_task_script",
        lambda: pytest.fail("raw managed install reached a filesystem write"),
    )
    monkeypatch.setattr(
        gateway_windows,
        "_spawn_detached",
        lambda *args, **kwargs: pytest.fail("raw managed start spawned a process"),
    )
    monkeypatch.setattr(gateway_windows, "_gateway_pids", lambda: [])
    monkeypatch.setattr(gateway_windows, "_inspect_task_xml", lambda: "disabled")
    monkeypatch.setattr(
        gateway_windows,
        "_task_xml_matches_current_definition",
        lambda _xml: True,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_task_xml_is_enabled",
        lambda _xml: False,
    )

    with pytest.raises(RuntimeError, match="must remain disabled"):
        gateway_windows.install(install_disabled=False)
    with pytest.raises(RuntimeError, match="gateway-enable"):
        gateway_windows.start()

    task_calls = []
    monkeypatch.setattr(
        gateway_windows,
        "_task_xml_is_enabled",
        lambda _xml: True,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_exec_schtasks",
        lambda args: task_calls.append(args) or (0, "started", ""),
    )
    monkeypatch.setattr(
        gateway_windows,
        "_report_gateway_start",
        lambda via: task_calls.append([via]) or True,
    )

    gateway_windows.start()

    assert task_calls == [
        ["/Run", "/TN", gateway_windows.get_task_name()],
        ["reviewed Scheduled Task"],
    ]


def test_disabled_scheduled_task_is_not_autostart_enabled(monkeypatch, tmp_path):
    expected_script = tmp_path / "current" / "Hermes_Gateway.cmd"
    disabled_xml = gateway_windows._build_scheduled_task_xml(
        "Hermes_Gateway",
        expected_script.with_suffix(".vbs"),
        None,
        enabled=False,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_startup_entry_belongs_to_current_profile",
        lambda: False,
    )
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows,
        "_exec_schtasks",
        lambda _args: (
            0,
            disabled_xml,
            "",
        ),
    )

    assert gateway_windows.is_autostart_enabled() is False


def test_startup_fallback_is_autostart_enabled_without_task_query(monkeypatch):
    monkeypatch.setattr(
        gateway_windows,
        "_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_exec_schtasks",
        lambda _args: pytest.fail("Startup persistence needs no task query"),
    )

    assert gateway_windows.is_autostart_enabled() is True


def test_is_installed_rejects_foreign_same_name_task_action(monkeypatch, tmp_path):
    expected_script = tmp_path / "current" / "Hermes_Gateway.cmd"
    foreign_script = tmp_path / "foreign" / "Hermes_Gateway.cmd"
    task_xml = gateway_windows._build_scheduled_task_xml(
        "Hermes_Gateway",
        foreign_script.with_suffix(".vbs"),
        None,
    )
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows,
        "_startup_entry_belongs_to_current_profile",
        lambda: False,
    )
    monkeypatch.setattr(
        gateway_windows, "_exec_schtasks", lambda _args: (0, task_xml, "")
    )

    assert gateway_windows.is_installed() is False


def test_is_installed_accepts_exact_current_task_action(monkeypatch, tmp_path):
    expected_script = tmp_path / "current" / "Hermes_Gateway.cmd"
    task_xml = gateway_windows._build_scheduled_task_xml(
        "Hermes_Gateway",
        expected_script.with_suffix(".vbs"),
        None,
    )
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows,
        "_startup_entry_belongs_to_current_profile",
        lambda: False,
    )
    monkeypatch.setattr(
        gateway_windows, "_exec_schtasks", lambda _args: (0, task_xml, "")
    )
    monkeypatch.setattr(
        gateway_windows,
        "_gateway_launcher_belongs_to_current_install",
        lambda _path: True,
    )

    assert gateway_windows.is_installed() is True
    assert gateway_windows._task_xml_belongs_to_current_profile(
        task_xml,
        allow_legacy_task_action=False,
    ) is True


def test_task_ownership_rejects_extra_action_and_foreign_wscript(
    monkeypatch, tmp_path
):
    expected_script = tmp_path / "current" / "Hermes_Gateway.cmd"
    task_xml = gateway_windows._build_scheduled_task_xml(
        "Hermes_Gateway",
        expected_script.with_suffix(".vbs"),
        None,
    )
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )

    extra_action = task_xml.replace(
        "  </Actions>",
        "    <ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId>"
        "</ComHandler>\n  </Actions>",
    )
    assert gateway_windows._task_xml_belongs_to_current_profile(extra_action) is False

    foreign_wscript = task_xml.replace(
        "<Command>wscript.exe</Command>",
        f"<Command>{tmp_path / 'foreign' / 'wscript.exe'}</Command>",
    )
    assert (
        gateway_windows._task_xml_belongs_to_current_profile(foreign_wscript)
        is False
    )


def test_profile_persistence_inspection_raises_on_malformed_task_xml(monkeypatch):
    monkeypatch.setattr(
        gateway_windows,
        "_startup_entry_belongs_to_current_profile",
        lambda: False,
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows,
        "_exec_schtasks",
        lambda _args: (0, "<Task><broken>", ""),
    )

    with pytest.raises(RuntimeError, match="malformed XML"):
        gateway_windows._inspect_profile_persistence()


def test_profile_persistence_missing_task_is_locale_independent(monkeypatch):
    monkeypatch.setattr(
        gateway_windows,
        "_startup_entry_belongs_to_current_profile",
        lambda: False,
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")

    def fake_schtasks(args):
        if "/XML" in args:
            return 1, "", "FEL: Det går inte att hitta den angivna filen."
        if "/TN" in args:
            return 1, "", "FEL: Det går inte att hitta den angivna filen."
        assert args == ["/Query", "/FO", "CSV", "/NH"]
        return 0, '"\\Hermes_Gateway_work","N/A","Ready"\n', ""

    monkeypatch.setattr(gateway_windows, "_exec_schtasks", fake_schtasks)

    assert gateway_windows._inspect_profile_persistence() is False


def test_profile_enumeration_keeps_installed_default_when_named_task_missing(
    monkeypatch, tmp_path
):
    from hermes_cli import profiles

    default_home = tmp_path / "home"
    work_home = default_home / "profiles" / "work"
    work_home.mkdir(parents=True)
    monkeypatch.setattr(
        "hermes_cli.config.get_hermes_home", lambda: str(default_home)
    )
    monkeypatch.setattr(
        profiles,
        "list_profiles",
        lambda: [SimpleNamespace(name="work", path=work_home)],
    )
    monkeypatch.setattr(
        gateway_windows,
        "_startup_entry_belongs_to_current_profile",
        lambda: False,
    )

    def current_task_name():
        from hermes_constants import get_hermes_home

        return (
            "Hermes_Gateway_work"
            if Path(get_hermes_home()).resolve() == work_home.resolve()
            else "Hermes_Gateway"
        )

    monkeypatch.setattr(gateway_windows, "get_task_name", current_task_name)

    def fake_schtasks(args):
        task_name = current_task_name()
        if "/XML" in args and task_name == "Hermes_Gateway":
            return 0, "<Task><Actions /></Task>", ""
        if "/XML" in args:
            return 1, "", "FEL: Aktiviteten finns inte."
        if "/TN" in args:
            return 1, "", "FEL: Aktiviteten finns inte."
        return 0, '"\\Hermes_Gateway","N/A","Ready"\n', ""

    monkeypatch.setattr(gateway_windows, "_exec_schtasks", fake_schtasks)
    monkeypatch.setattr(
        gateway_windows,
        "_task_xml_belongs_to_current_profile",
        lambda xml: True,
    )

    assert gateway_windows.get_installed_profile_homes() == [default_home.resolve()]


def test_is_installed_accepts_exact_legacy_cmd_task_action(monkeypatch, tmp_path):
    expected_script = tmp_path / "current" / "Hermes_Gateway.cmd"
    task_xml = f"""<?xml version="1.0"?>
    <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Actions><Exec><Command>{expected_script}</Command></Exec></Actions>
    </Task>"""
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows,
        "_startup_entry_belongs_to_current_profile",
        lambda: False,
    )
    monkeypatch.setattr(
        gateway_windows, "_exec_schtasks", lambda _args: (0, task_xml, "")
    )
    monkeypatch.setattr(
        gateway_windows,
        "_gateway_launcher_belongs_to_current_install",
        lambda _path: True,
    )

    assert gateway_windows.is_installed() is True
    assert gateway_windows._task_xml_belongs_to_current_profile(
        task_xml,
        allow_legacy_task_action=False,
    ) is False


def test_startup_ownership_requires_exact_current_vbs_target(monkeypatch, tmp_path):
    expected_script = tmp_path / "current" / "Hermes_Gateway.cmd"
    foreign_script = tmp_path / "foreign" / "Hermes_Gateway.cmd"
    startup_entry = tmp_path / "Startup" / "Hermes_Gateway.vbs"
    legacy_entry = startup_entry.with_suffix(".cmd")
    startup_entry.parent.mkdir()
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )
    monkeypatch.setattr(
        gateway_windows, "get_startup_entry_path", lambda: startup_entry
    )
    monkeypatch.setattr(
        gateway_windows, "_legacy_startup_entry_path", lambda: legacy_entry
    )
    monkeypatch.setattr(
        gateway_windows,
        "_gateway_launcher_belongs_to_current_install",
        lambda _path: True,
    )

    startup_entry.write_text(
        gateway_windows._build_startup_launcher(foreign_script),
        encoding="utf-8",
        newline="",
    )
    assert gateway_windows._startup_entry_belongs_to_current_profile() is False

    startup_entry.write_text(
        gateway_windows._build_startup_launcher(expected_script),
        encoding="utf-8",
        newline="",
    )
    assert gateway_windows._startup_entry_belongs_to_current_profile() is True

    startup_entry.unlink()
    legacy_entry.write_text(
        "@echo off\n"
        + f"rem {gateway_windows._TASK_DESCRIPTION}\n"
        + 'start "" /min cmd.exe /d /c '
        + gateway_windows._quote_cmd_script_arg(str(expected_script))
        + "\n",
        encoding="utf-8",
    )
    assert gateway_windows._startup_entry_belongs_to_current_profile() is True


def test_startup_ownership_rejects_decoy_target_with_extra_command(
    monkeypatch, tmp_path
):
    expected_script = tmp_path / "current" / "Hermes_Gateway.cmd"
    startup_entry = tmp_path / "Startup" / "Hermes_Gateway.vbs"
    legacy_entry = startup_entry.with_suffix(".cmd")
    startup_entry.parent.mkdir()
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )
    monkeypatch.setattr(
        gateway_windows, "get_startup_entry_path", lambda: startup_entry
    )
    monkeypatch.setattr(
        gateway_windows, "_legacy_startup_entry_path", lambda: legacy_entry
    )

    startup_entry.write_text(
        gateway_windows._build_startup_launcher(expected_script)
        + 'CreateObject("WScript.Shell").Run "foreign.exe"\r\n',
        encoding="utf-8",
        newline="",
    )
    assert gateway_windows._current_startup_entry_belongs_to_current_profile() is False

    startup_entry.unlink()
    legacy_entry.write_text(
        "@echo off\n"
        + f"rem {gateway_windows._TASK_DESCRIPTION}\n"
        + 'start "" /min cmd.exe /d /c '
        + gateway_windows._quote_cmd_script_arg(str(expected_script))
        + "\nforeign.exe\n",
        encoding="utf-8",
    )
    assert gateway_windows._legacy_startup_entry_belongs_to_current_profile() is False


def test_task_ownership_rejects_same_home_launcher_from_foreign_code_root(
    monkeypatch, tmp_path
):
    expected_script = tmp_path / "shared-home" / "gateway-service" / "Hermes_Gateway.cmd"
    expected_script.parent.mkdir(parents=True)
    home = str(tmp_path / "shared-home")
    python = str(tmp_path / "reviewed" / "venv" / "Scripts" / "python.exe")
    reviewed_root = str(tmp_path / "reviewed")
    foreign_root = str(tmp_path / "foreign")
    expected_cmd = gateway_windows._build_gateway_cmd_script(
        python,
        reviewed_root,
        home,
        "--profile default",
        code_root=reviewed_root,
    )
    expected_vbs = gateway_windows._build_gateway_vbs_script(
        python,
        reviewed_root,
        home,
        "--profile default",
        code_root=reviewed_root,
    )
    foreign_vbs = gateway_windows._build_gateway_vbs_script(
        python,
        foreign_root,
        home,
        "--profile default",
        code_root=foreign_root,
    )
    vbs_path = expected_script.with_suffix(".vbs")
    vbs_path.write_text(foreign_vbs, encoding="utf-8", newline="")
    task_xml = gateway_windows._build_scheduled_task_xml(
        "Hermes_Gateway", vbs_path, None
    )
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )
    monkeypatch.setattr(
        gateway_windows,
        "_render_current_gateway_task_scripts",
        lambda: (expected_cmd, expected_vbs),
    )

    assert gateway_windows._task_xml_belongs_to_current_profile(task_xml) is False

    vbs_path.write_text(expected_vbs, encoding="utf-8", newline="")
    assert gateway_windows._task_xml_belongs_to_current_profile(task_xml) is True


def test_pre_lock_launcher_has_bounded_migration_ownership(
    monkeypatch, tmp_path
):
    expected_script = tmp_path / "shared-home" / "gateway-service" / "Hermes_Gateway.cmd"
    expected_script.parent.mkdir(parents=True)
    locked_cmd = "locked current cmd\r\n"
    locked_vbs = "locked current vbs\r\n"
    legacy_cmd = "legacy reviewed cmd\r\n"
    legacy_vbs = (
        "legacy reviewed vbs\r\n"
        "sh.CurrentDirectory = \"C:\\Reviewed\\Gladly-Hermes\"\r\n"
    )
    foreign_vbs = legacy_vbs.replace("Reviewed", "Foreign")
    vbs_path = expected_script.with_suffix(".vbs")
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: expected_script
    )
    monkeypatch.setattr(
        gateway_windows,
        "_render_current_gateway_task_scripts",
        lambda: (locked_cmd, locked_vbs),
    )
    monkeypatch.setattr(
        gateway_windows,
        "_render_legacy_gateway_task_scripts_for_migration",
        lambda: (legacy_cmd, legacy_vbs),
    )

    vbs_path.write_text(legacy_vbs, encoding="utf-8", newline="")
    assert gateway_windows._gateway_launcher_belongs_to_current_install(vbs_path)

    vbs_path.write_text(foreign_vbs, encoding="utf-8", newline="")
    assert not gateway_windows._gateway_launcher_belongs_to_current_install(vbs_path)


def test_install_disabled_refuses_startup_folder_fallback(monkeypatch, tmp_path):
    script_path = tmp_path / "Hermes_Gateway.cmd"
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_persistence_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_task_collision", lambda: None
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(gateway_windows, "_write_task_script", lambda: script_path)
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: True)
    monkeypatch.setattr(
        gateway_windows,
        "_remove_startup_fallback_entries",
        lambda: None,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_install_scheduled_task",
        lambda *args, **kwargs: (False, "schtasks unavailable"),
    )
    monkeypatch.setattr(
        gateway_windows,
        "_install_startup_entry",
        lambda *args, **kwargs: pytest.fail("disabled install used Startup fallback"),
    )

    with pytest.raises(RuntimeError, match="no Startup-folder fallback"):
        gateway_windows.install(install_disabled=True)


def test_install_disabled_uac_decline_never_creates_startup_fallback(
    monkeypatch, tmp_path
):
    current = tmp_path / "Hermes_Gateway.vbs"
    legacy = tmp_path / "Hermes_Gateway.cmd"
    current.write_text("current", encoding="utf-8")
    legacy.write_text("legacy", encoding="utf-8")
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_persistence_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_task_collision", lambda: None
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows,
        "_write_task_script",
        lambda: tmp_path / "Hermes_Gateway.cmd",
    )
    monkeypatch.setattr(gateway_windows, "get_startup_entry_path", lambda: current)
    monkeypatch.setattr(
        gateway_windows, "_legacy_startup_entry_path", lambda: legacy
    )
    monkeypatch.setattr(
        gateway_windows,
        "_current_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_legacy_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: False)
    monkeypatch.setattr(setup, "prompt_yes_no", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        gateway_windows,
        "_install_startup_fallback",
        lambda *args, **kwargs: pytest.fail("disabled install used Startup fallback"),
    )

    with pytest.raises(RuntimeError, match="no Startup-folder fallback"):
        gateway_windows.install(install_disabled=True)

    assert current.exists() is False
    assert legacy.exists() is False


@pytest.mark.parametrize("request_uac", [False, True])
def test_install_disabled_does_not_rewrite_launcher_while_owned_task_is_enabled(
    monkeypatch, tmp_path, request_uac
):
    enabled_xml = gateway_windows._build_scheduled_task_xml(
        "Hermes_Gateway",
        tmp_path / "Hermes_Gateway.vbs",
        None,
        enabled=True,
    )
    writes = []
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_startup_collision", lambda: None
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows, "_remove_startup_fallback_entries", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows,
        "_assert_no_foreign_task_collision",
        lambda: enabled_xml,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_disable_owned_task_for_staging",
        lambda: (False, "Access denied"),
    )
    monkeypatch.setattr(
        gateway_windows,
        "_write_task_script",
        lambda: writes.append("write") or tmp_path / "Hermes_Gateway.cmd",
    )
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: False)
    monkeypatch.setattr(
        setup,
        "prompt_yes_no",
        lambda *args, **kwargs: request_uac,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_launch_elevated_install",
        lambda **kwargs: False,
    )

    with pytest.raises(RuntimeError, match="launcher was left unchanged"):
        gateway_windows.install(install_disabled=True)

    assert writes == []


@pytest.mark.parametrize("request_uac", [False, True])
def test_install_disabled_does_not_write_when_existing_task_query_is_denied(
    monkeypatch, tmp_path, request_uac
):
    writes = []
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_startup_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows, "_remove_startup_fallback_entries", lambda: None
    )

    def fake_schtasks(args):
        if args == ["/Query", "/FO", "CSV", "/NH"]:
            return 0, '"\\Hermes_Gateway","N/A","Ready"\n', ""
        return 1, "", "Åtkomst nekad"

    monkeypatch.setattr(gateway_windows, "_exec_schtasks", fake_schtasks)
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: False)
    monkeypatch.setattr(
        setup,
        "prompt_yes_no",
        lambda *args, **kwargs: request_uac,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_launch_elevated_install",
        lambda **kwargs: False,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_write_task_script",
        lambda: writes.append("write") or tmp_path / "Hermes_Gateway.cmd",
    )

    with pytest.raises(RuntimeError, match="launcher was left unchanged"):
        gateway_windows.install(install_disabled=True)

    assert writes == []


def test_install_disabled_fails_closed_if_owned_task_recheck_becomes_unreadable(
    monkeypatch, tmp_path
):
    enabled_xml = gateway_windows._build_scheduled_task_xml(
        "Hermes_Gateway",
        tmp_path / "Hermes_Gateway.vbs",
        None,
        enabled=True,
    )
    xml_queries = 0
    writes = []
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_startup_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows, "_remove_startup_fallback_entries", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows,
        "_task_xml_belongs_to_current_profile",
        lambda _xml: True,
    )

    def fake_schtasks(args):
        nonlocal xml_queries
        if "/XML" in args:
            xml_queries += 1
            if xml_queries == 1:
                return 0, enabled_xml, ""
            return 1, "", "Åtkomst nekad"
        if "/Disable" in args:
            return 0, "SUCCESS", ""
        if args == ["/Query", "/FO", "CSV", "/NH"]:
            return 0, '"\\Hermes_Gateway","N/A","Ready"\n', ""
        return 1, "", "Åtkomst nekad"

    monkeypatch.setattr(gateway_windows, "_exec_schtasks", fake_schtasks)
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: False)
    monkeypatch.setattr(setup, "prompt_yes_no", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        gateway_windows,
        "_write_task_script",
        lambda: writes.append("write") or tmp_path / "Hermes_Gateway.cmd",
    )

    with pytest.raises(RuntimeError, match="launcher was left unchanged"):
        gateway_windows.install(install_disabled=True)

    assert xml_queries == 2
    assert writes == []


def test_install_disabled_uac_unavailable_removes_stale_startup_first(
    monkeypatch, tmp_path
):
    current = tmp_path / "Hermes_Gateway.vbs"
    legacy = tmp_path / "Hermes_Gateway.cmd"
    current.write_text("current", encoding="utf-8")
    legacy.write_text("legacy", encoding="utf-8")
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_persistence_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_task_collision", lambda: None
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows,
        "_write_task_script",
        lambda: tmp_path / "task" / "Hermes_Gateway.cmd",
    )
    monkeypatch.setattr(gateway_windows, "get_startup_entry_path", lambda: current)
    monkeypatch.setattr(
        gateway_windows, "_legacy_startup_entry_path", lambda: legacy
    )
    monkeypatch.setattr(
        gateway_windows,
        "_current_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_legacy_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: False)
    monkeypatch.setattr(setup, "prompt_yes_no", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        gateway_windows,
        "_launch_elevated_install",
        lambda **kwargs: False,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_install_startup_fallback",
        lambda *args, **kwargs: pytest.fail("disabled install used Startup fallback"),
    )

    with pytest.raises(RuntimeError, match="no Startup-folder fallback"):
        gateway_windows.install(install_disabled=True)

    assert current.exists() is False
    assert legacy.exists() is False


def test_install_disabled_removes_stale_startup_before_uac_handoff(
    monkeypatch, tmp_path
):
    current = tmp_path / "Hermes_Gateway.vbs"
    legacy = tmp_path / "Hermes_Gateway.cmd"
    current.write_text("current", encoding="utf-8")
    legacy.write_text("legacy", encoding="utf-8")
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_persistence_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_task_collision", lambda: None
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows,
        "_write_task_script",
        lambda: tmp_path / "task" / "Hermes_Gateway.cmd",
    )
    monkeypatch.setattr(gateway_windows, "get_startup_entry_path", lambda: current)
    monkeypatch.setattr(
        gateway_windows, "_legacy_startup_entry_path", lambda: legacy
    )
    monkeypatch.setattr(
        gateway_windows,
        "_current_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_legacy_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(gateway_windows, "_is_running_as_admin", lambda: False)
    monkeypatch.setattr(setup, "prompt_yes_no", lambda *args, **kwargs: True)

    def launch_elevated(**kwargs):
        assert current.exists() is False
        assert legacy.exists() is False
        assert kwargs["install_disabled"] is True
        return True

    monkeypatch.setattr(
        gateway_windows, "_launch_elevated_install", launch_elevated
    )
    monkeypatch.setattr(
        gateway_windows,
        "_install_scheduled_task",
        lambda *args, **kwargs: pytest.fail("parent created Scheduled Task"),
    )

    gateway_windows.install(install_disabled=True)

    assert current.exists() is False
    assert legacy.exists() is False


def test_install_disabled_removes_stale_startup_before_launcher_write(
    monkeypatch, tmp_path
):
    current = tmp_path / "Hermes_Gateway.vbs"
    legacy = tmp_path / "Hermes_Gateway.cmd"
    current.write_text("current", encoding="utf-8")
    legacy.write_text("legacy", encoding="utf-8")
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_persistence_collision", lambda: None
    )
    monkeypatch.setattr(
        gateway_windows, "_assert_no_foreign_task_collision", lambda: None
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(gateway_windows, "get_startup_entry_path", lambda: current)
    monkeypatch.setattr(
        gateway_windows, "_legacy_startup_entry_path", lambda: legacy
    )
    monkeypatch.setattr(
        gateway_windows,
        "_current_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_legacy_startup_entry_belongs_to_current_profile",
        lambda: True,
    )

    def fail_write():
        assert current.exists() is False
        assert legacy.exists() is False
        raise OSError("launcher write failed")

    monkeypatch.setattr(gateway_windows, "_write_task_script", fail_write)

    with pytest.raises(OSError, match="launcher write failed"):
        gateway_windows.install(install_disabled=True)

    assert current.exists() is False
    assert legacy.exists() is False


def test_disabled_install_cleanup_removes_both_startup_launchers(
    monkeypatch, tmp_path
):
    current = tmp_path / "Hermes_Gateway.vbs"
    legacy = tmp_path / "Hermes_Gateway.cmd"
    current.write_text("current", encoding="utf-8")
    legacy.write_text("legacy", encoding="utf-8")
    monkeypatch.setattr(gateway_windows, "get_startup_entry_path", lambda: current)
    monkeypatch.setattr(gateway_windows, "_legacy_startup_entry_path", lambda: legacy)
    monkeypatch.setattr(
        gateway_windows,
        "_current_startup_entry_belongs_to_current_profile",
        lambda: True,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_legacy_startup_entry_belongs_to_current_profile",
        lambda: True,
    )

    gateway_windows._remove_startup_fallback_entries()

    assert current.exists() is False
    assert legacy.exists() is False


def test_gateway_command_forwards_install_disabled_to_windows(monkeypatch):
    calls = []
    monkeypatch.setattr(gateway, "is_managed", lambda: False)
    monkeypatch.setattr(gateway, "is_windows", lambda: True)
    monkeypatch.setattr(gateway, "is_termux", lambda: False)
    monkeypatch.setattr(gateway, "supports_systemd_services", lambda: False)
    monkeypatch.setattr(gateway, "is_macos", lambda: False)
    monkeypatch.setattr(
        gateway_windows,
        "install",
        lambda **kwargs: calls.append(kwargs),
    )

    gateway._gateway_command_inner(
        SimpleNamespace(
            gateway_command="install",
            force=True,
            system=False,
            run_as_user=None,
            start_now=False,
            start_on_login=True,
            elevated_handoff=True,
            install_disabled=True,
        )
    )

    assert calls == [
        {
            "force": True,
            "start_now": False,
            "start_on_login": True,
            "elevated_handoff": True,
            "install_disabled": True,
        }
    ]














# ---------------------------------------------------------------------------
# stop() drain semantics — issue #33778
#
# Background: on Windows, asyncio.add_signal_handler raises NotImplementedError,
# so the gateway's SIGTERM handler (which drains in-flight agents and writes
# resume_pending=True) never fires when `hermes gateway stop` kills the
# process. The fix: stop() writes the planned_stop_marker first, waits for
# the gateway's marker-watcher thread to drain + exit cleanly, then escalates
# to taskkill if drain times out.
# ---------------------------------------------------------------------------


def test_gateway_pid_sweep_keeps_primary_and_rejects_foreign_default(
    monkeypatch,
):
    import gateway.status as status_mod

    monkeypatch.setattr(
        status_mod,
        "get_running_pid",
        lambda cleanup_stale=False: 101,
    )
    monkeypatch.setattr(gateway, "find_gateway_pids", lambda: [101, 202, 303])
    monkeypatch.setattr(
        gateway,
        "_capture_current_install_gateway_argv",
        lambda pid: ["python.exe", "gateway", "run"] if pid == 202 else None,
    )

    assert gateway_windows._gateway_pids() == [101, 202]


def test_gateway_ready_probe_does_not_accept_foreign_default_gateway(
    monkeypatch,
):
    import gateway.status as status_mod

    monkeypatch.setattr(
        status_mod,
        "get_running_pid",
        lambda cleanup_stale=False: None,
    )
    monkeypatch.setattr(gateway, "find_gateway_pids", lambda: [909])
    monkeypatch.setattr(
        gateway,
        "_capture_current_install_gateway_argv",
        lambda pid: None,
    )

    assert gateway_windows._wait_for_gateway_ready(
        timeout_s=0.01, interval_s=0.001
    ) == []


def test_startup_fallback_starts_current_when_only_foreign_gateway_exists(
    monkeypatch, tmp_path
):
    import gateway.status as status_mod

    script_path = tmp_path / "Hermes_Gateway.cmd"
    spawned = []
    monkeypatch.setattr(
        gateway_windows,
        "_install_startup_entry",
        lambda _path: tmp_path / "Startup" / "Hermes_Gateway.vbs",
    )
    monkeypatch.setattr(
        status_mod,
        "get_running_pid",
        lambda cleanup_stale=False: None,
    )
    monkeypatch.setattr(gateway, "find_gateway_pids", lambda: [909])
    monkeypatch.setattr(
        gateway,
        "_capture_current_install_gateway_argv",
        lambda pid: None,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_spawn_detached",
        lambda: spawned.append(True) or 123,
    )
    monkeypatch.setattr(gateway_windows, "_report_gateway_start", lambda _via: True)
    monkeypatch.setattr(gateway_windows, "_print_next_steps", lambda: None)

    gateway_windows._install_startup_fallback(
        script_path, True, "Access is denied"
    )

    assert spawned == [True]


def test_stop_never_terminates_foreign_default_gateway_sweep(monkeypatch):
    import gateway.status as status_mod

    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(
        status_mod,
        "get_running_pid",
        lambda cleanup_stale=True: None,
    )
    monkeypatch.setattr(gateway, "find_gateway_pids", lambda: [909])
    monkeypatch.setattr(
        gateway,
        "_capture_current_install_gateway_argv",
        lambda pid: None,
    )
    monkeypatch.setattr(gateway_windows, "_owned_task_xml", lambda: None)
    killed = []
    monkeypatch.setattr(
        gateway_windows,
        "_force_terminate_known_gateway_pids",
        lambda pids: killed.extend(pids) or 0,
    )

    gateway_windows.stop()

    assert killed == []


def test_stop_does_not_end_foreign_same_name_task(monkeypatch):
    import gateway.status as status_mod

    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(status_mod, "get_running_pid", lambda: None)
    monkeypatch.setattr(gateway_windows, "_collect_gateway_stop_pids", lambda *_a: [])
    monkeypatch.setattr(
        gateway_windows, "_force_terminate_known_gateway_pids", lambda _pids: 0
    )
    monkeypatch.setattr(gateway_windows, "_owned_task_xml", lambda: None)
    monkeypatch.setattr(
        gateway_windows,
        "_exec_schtasks",
        lambda args: pytest.fail(f"foreign task received schtasks mutation: {args}"),
    )

    gateway_windows.stop()


def test_uninstall_does_not_delete_foreign_same_name_persistence(
    monkeypatch, tmp_path
):
    startup_entry = tmp_path / "Startup" / "Hermes_Gateway.vbs"
    legacy_entry = startup_entry.with_suffix(".cmd")
    script_path = tmp_path / "current" / "Hermes_Gateway.cmd"
    for path in (startup_entry, legacy_entry, script_path, script_path.with_suffix(".vbs")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("artifact", encoding="utf-8")
    monkeypatch.setattr(gateway_windows, "_assert_windows", lambda: None)
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows, "_expected_task_script_path", lambda: script_path
    )
    monkeypatch.setattr(
        gateway_windows, "get_startup_entry_path", lambda: startup_entry
    )
    monkeypatch.setattr(
        gateway_windows, "_legacy_startup_entry_path", lambda: legacy_entry
    )
    monkeypatch.setattr(gateway_windows, "_owned_task_xml", lambda: None)
    monkeypatch.setattr(
        gateway_windows,
        "_current_startup_entry_belongs_to_current_profile",
        lambda: False,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_legacy_startup_entry_belongs_to_current_profile",
        lambda: False,
    )
    monkeypatch.setattr(
        gateway_windows,
        "_exec_schtasks",
        lambda args: pytest.fail(f"foreign task received schtasks mutation: {args}"),
    )

    gateway_windows.uninstall()

    assert startup_entry.exists()
    assert legacy_entry.exists()
    assert script_path.exists() is True
    assert script_path.with_suffix(".vbs").exists() is True


def test_install_refuses_foreign_same_name_task_collision(monkeypatch, tmp_path):
    startup_entry = tmp_path / "Startup" / "Hermes_Gateway.vbs"
    monkeypatch.setattr(
        gateway_windows, "_inspect_task_xml", lambda: "<foreign-task />"
    )
    monkeypatch.setattr(
        gateway_windows,
        "_task_xml_belongs_to_current_profile",
        lambda _xml: False,
    )
    monkeypatch.setattr(gateway_windows, "get_task_name", lambda: "Hermes_Gateway")
    monkeypatch.setattr(
        gateway_windows, "get_startup_entry_path", lambda: startup_entry
    )
    monkeypatch.setattr(
        gateway_windows,
        "_legacy_startup_entry_path",
        lambda: startup_entry.with_suffix(".cmd"),
    )

    with pytest.raises(RuntimeError, match="another installation"):
        gateway_windows._assert_no_foreign_persistence_collision()
