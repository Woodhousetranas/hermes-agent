"""Legacy pythonw launcher normalization + post-update launcher refresh.

Covers the two halves of the "legacy pythonw gateways survive updates
forever" gap:

1. ``gateway_windows._resolve_detached_python`` — normalizes a legacy
   ``pythonw.exe`` interpreter (pre-aa2ae36c3f launchers / argv snapshots)
   to the sibling console ``python.exe`` so respawns and regenerated
   launchers use the hidden-console design (#54220/#56747) and don't die
   with ``RuntimeError: sys.stderr is None`` (#71671).
2. ``hermes_cli.main._refresh_windows_gateway_launchers`` — ``hermes
   update`` regenerates the installed Scheduled Task / Startup launcher
   scripts instead of leaving install-time artifacts stale forever.

``_resolve_detached_python`` is a pure path helper and runs on any host.
``windowless_gateway_restart_spec`` returns its argv unchanged off Windows,
so the test that exercises the rewrite is ``windows_only`` rather than run
against a faked ``sys.platform``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

import hermes_cli.gateway as gateway
import hermes_cli.gateway_windows as gateway_windows
import hermes_cli.main as cli_main
import hermes_cli.profiles as profiles
from hermes_cli import env_loader


# ---------------------------------------------------------------------------
# _resolve_detached_python: legacy pythonw normalization
# ---------------------------------------------------------------------------


def _make_venv(tmp_path: Path, *, with_console_python: bool) -> tuple[Path, Path]:
    scripts = tmp_path / "venv" / "Scripts"
    scripts.mkdir(parents=True)
    pythonw = scripts / "pythonw.exe"
    pythonw.write_text("", encoding="utf-8")
    python = scripts / "python.exe"
    if with_console_python:
        python.write_text("", encoding="utf-8")
    return pythonw, python


def test_resolve_detached_python_swaps_legacy_pythonw_for_console_sibling(tmp_path):
    pythonw, python = _make_venv(tmp_path, with_console_python=True)

    exe, venv_dir, extra = gateway_windows._resolve_detached_python(str(pythonw))

    assert exe == str(python)
    assert venv_dir == tmp_path / "venv"
    assert extra == []




@pytest.mark.windows_only
def test_restart_spec_normalizes_legacy_pythonw_argv(tmp_path):
    """A pre-rework Scheduled Task argv snapshot (leading pythonw.exe) must be
    respawned through the console python + hidden-console launch, with every
    argument after the interpreter preserved verbatim.

    ``windows_only``: ``windowless_gateway_restart_spec`` returns the argv
    untouched off Windows, so the fake was the only thing making the rewrite
    (and its ``Scripts/``-layout venv derivation) run at all.
    """
    pythonw, python = _make_venv(tmp_path, with_console_python=True)

    argv = [str(pythonw), "-m", "hermes_cli.main", "gateway", "run"]
    with mock.patch.object(
        gateway_windows, "_resolve_gateway_code_root", return_value=str(tmp_path)
    ), mock.patch("hermes_cli.config.get_hermes_home", return_value=str(tmp_path)):
        new_argv, cwd, env = gateway_windows.windowless_gateway_restart_spec(list(argv))

    assert new_argv[0] == str(python)
    assert new_argv[1:] == [
        "-m",
        "hermes_cli.main",
        "--profile",
        "default",
        "gateway",
        "run",
    ]
    assert cwd == str(tmp_path)
    assert env["VIRTUAL_ENV"] == str(tmp_path / "venv")


# ---------------------------------------------------------------------------
# _refresh_windows_gateway_launchers: hermes update regenerates launchers
# ---------------------------------------------------------------------------


@pytest.mark.windows_only
def test_refresh_regenerates_locked_launchers_for_all_installed_profiles(
    monkeypatch,
    tmp_path,
):
    repo_root = tmp_path / "Gladly-Hermes"
    project = repo_root / "hermes-agent"
    default_home = repo_root / "home"
    work_home = default_home / "profiles" / "work"
    python_exe = project / "venv" / "Scripts" / "python.exe"
    python_exe.parent.mkdir(parents=True)
    python_exe.write_text("", encoding="utf-8")
    work_home.mkdir(parents=True)
    (repo_root / "bin").mkdir()
    (repo_root / "bin" / "gladly").write_text("", encoding="utf-8")

    monkeypatch.setenv("HERMES_HOME", str(default_home))
    monkeypatch.setattr(gateway, "PROJECT_ROOT", project)
    monkeypatch.setattr(gateway, "get_python_path", lambda: str(python_exe))
    monkeypatch.setattr(
        profiles,
        "list_profiles",
        lambda: [
            SimpleNamespace(path=default_home),
            SimpleNamespace(path=work_home),
        ],
    )
    monkeypatch.setattr(
        gateway_windows, "_inspect_profile_persistence", lambda: True
    )

    result = cli_main._refresh_windows_gateway_launchers()

    default_vbs = (
        default_home / "gateway-service" / "Hermes_Gateway.vbs"
    ).read_text(encoding="utf-8")
    work_vbs = (
        work_home / "gateway-service" / "Hermes_Gateway_work.vbs"
    ).read_text(encoding="utf-8")
    assert f'"HERMES_HOME") = "{default_home.resolve()}"' in default_vbs
    assert "--profile default" in default_vbs
    assert f'"HERMES_HOME") = "{work_home.resolve()}"' in work_vbs
    assert "--profile work" in work_vbs
    assert env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR in default_vbs
    assert env_loader._GATEWAY_LAUNCH_ENV_LOCK_VAR in work_vbs
    assert f'"GLADLY_HERMES_CODE_ROOT") = "{repo_root.resolve()}"' in default_vbs
    assert f'"GLADLY_HERMES_CODE_ROOT") = "{repo_root.resolve()}"' in work_vbs
    assert result == {"refreshed": ["default", "work"], "failed": {}}


@pytest.mark.windows_only
def test_refresh_returns_per_profile_write_failure(monkeypatch, tmp_path):
    default_home = tmp_path / "home"
    work_home = default_home / "profiles" / "work"
    work_home.mkdir(parents=True)
    monkeypatch.setattr(
        gateway_windows,
        "get_installed_profile_homes",
        lambda: [default_home, work_home],
    )
    calls = []

    def write_launcher():
        calls.append(True)
        if len(calls) == 2:
            raise OSError("write denied")

    monkeypatch.setattr(gateway_windows, "_write_task_script", write_launcher)

    result = cli_main._refresh_windows_gateway_launchers()

    assert result == {
        "refreshed": ["default"],
        "failed": {"work": "write denied"},
    }


@pytest.mark.windows_only
def test_profile_inspection_failure_makes_launcher_refresh_incomplete(
    monkeypatch, tmp_path
):
    from hermes_cli.config import get_hermes_home

    default_home = tmp_path / "home"
    work_home = default_home / "profiles" / "work"
    work_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(default_home))
    monkeypatch.setattr(
        profiles,
        "list_profiles",
        lambda: [SimpleNamespace(path=work_home)],
    )

    def inspect():
        if Path(get_hermes_home()).resolve() == work_home.resolve():
            raise RuntimeError("task XML query failed")
        return True

    monkeypatch.setattr(
        gateway_windows, "_inspect_profile_persistence", inspect
    )
    monkeypatch.setattr(
        gateway_windows,
        "_write_task_script",
        lambda: pytest.fail("no launcher writes after incomplete inspection"),
    )

    result = cli_main._refresh_windows_gateway_launchers()

    assert result["refreshed"] == []
    assert "task XML query failed" in result["failed"]["*"]


@pytest.mark.windows_only
def test_partial_launcher_refresh_blocks_only_failed_profile_restart(
    monkeypatch, capsys
):
    launched = []
    monkeypatch.setattr(
        cli_main,
        "_refresh_windows_gateway_launchers",
        lambda: {
            "refreshed": ["default"],
            "failed": {"work": "access denied"},
        },
    )
    monkeypatch.setattr(
        gateway,
        "launch_detached_profile_gateway_restart",
        lambda profile, pid: launched.append((profile, pid)) or True,
    )

    token = {
        "resume_needed": True,
        "profiles": {"default": 101, "work": 202},
        "unmapped": [],
    }
    assert cli_main._resume_windows_gateways_after_update(token) is False

    assert launched == [("default", 101)]
    output = capsys.readouterr().out
    assert "Update incomplete" in output
    assert "launcher profile work: access denied" in output
    assert "Restarting Windows gateway profile(s): default" in output


@pytest.mark.windows_only
def test_restart_helper_false_and_unmapped_exception_are_operator_visible(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        cli_main,
        "_refresh_windows_gateway_launchers",
        lambda: {"refreshed": ["default"], "failed": {}},
    )
    monkeypatch.setattr(
        gateway,
        "launch_detached_profile_gateway_restart",
        lambda _profile, _pid: False,
    )
    monkeypatch.setattr(
        gateway,
        "launch_detached_gateway_restart_by_cmdline",
        lambda _pid, _argv: (_ for _ in ()).throw(RuntimeError("spec refused")),
    )

    token = {
        "resume_needed": True,
        "profiles": {"default": 101},
        "unmapped": [
            {
                "pid": 303,
                "argv": [
                    "python.exe",
                    "-m",
                    "hermes_cli.main",
                    "--profile",
                    "default",
                    "gateway",
                    "run",
                ],
            }
        ],
    }
    assert cli_main._resume_windows_gateways_after_update(token) is False

    output = capsys.readouterr().out
    assert "profile default (old PID 101) was not scheduled" in output
    assert "unmapped gateway PID 303 failed: spec refused" in output
    assert "hermes gateway restart" in output


@pytest.mark.windows_only
def test_failed_cold_start_is_operator_visible(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_main,
        "_refresh_windows_gateway_launchers",
        lambda: {"refreshed": ["default"], "failed": {}},
    )
    monkeypatch.setattr(
        cli_main, "_cold_start_windows_gateway_after_update", lambda: False
    )
    token = {
        "resume_needed": True,
        "profiles": {},
        "unmapped": [],
        "cold_start_if_installed": True,
    }

    assert cli_main._resume_windows_gateways_after_update(token) is False
    assert "installed gateway did not cold-start" in capsys.readouterr().out
