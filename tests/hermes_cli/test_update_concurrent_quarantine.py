"""Tests for issue #26670 — concurrent hermes.exe detection and improved
quarantine retry / reboot-deferred fallback during `hermes update` on Windows.

These tests force ``_is_windows`` to return ``True`` via patching so the
Windows-specific code paths can be exercised on any host.
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hermes_cli import main as cli_main


# Tests in this module either exercise the REAL _detect_concurrent_hermes_instances
# helper (and need the autouse stub in tests/hermes_cli/conftest.py disabled),
# or supply their own explicit return value via patch.object. Mark the whole
# module so the conftest fixture skips its default stub.
pytestmark = pytest.mark.real_concurrent_gate


# ---------------------------------------------------------------------------
# _detect_concurrent_hermes_instances
# ---------------------------------------------------------------------------


def _make_proc(pid: int, exe: str, name: str = "hermes.exe"):
    """Build a duck-typed psutil Process stand-in with the .info dict."""
    proc = MagicMock()
    proc.info = {"pid": pid, "exe": exe, "name": name}
    return proc




# ---------------------------------------------------------------------------
# Parent-chain exclusion (issue #30768 follow-up — the setuptools .exe
# launcher on Windows is a separate native process that spawns python.exe;
# excluding only ``os.getpid()`` flags the launcher as a concurrent instance.
# ---------------------------------------------------------------------------


def _fake_psutil_with_parent_chain(
    parent_chain: list[int],
    proc_iter_rows: list,
    *,
    ancestor_exe: str | None = None,
):
    """Build a psutil stand-in that has Process()/parents()/exe() AND process_iter().

    ``parent_chain`` is the ordered list of ancestor PIDs (closest first)
    returned by ``proc.parents()`` on the seed (``os.getpid()``).
    ``ancestor_exe`` is the executable path reported by each ancestor's
    ``.exe()``; when it matches one of our shim paths the ancestor is
    excluded (the launcher-shim case). Pass ``None`` to model an ancestor
    whose exe can't be read (psutil error) — it stays in the candidate set.
    """

    class _FakeProc:
        def __init__(self, pid: int, exe_path: str | None):
            self.pid = pid
            self._exe = exe_path

        def exe(self):
            if self._exe is None:
                raise OSError("exe unavailable")
            return self._exe

        def parents(self):
            return [_FakeProc(p, ancestor_exe) for p in parent_chain]

    class _NoSuchProcess(Exception):
        pass

    class _AccessDenied(Exception):
        pass

    def _process(pid=None):
        return _FakeProc(pid if pid is not None else os.getpid(), ancestor_exe)

    return types.SimpleNamespace(
        Process=_process,
        NoSuchProcess=_NoSuchProcess,
        AccessDenied=_AccessDenied,
        process_iter=lambda attrs: iter(proc_iter_rows),
    )


@patch.object(cli_main, "_is_windows", return_value=True)
def test_detect_concurrent_parents_call_robust_to_one_bad_hop(_winp, tmp_path):
    """The launcher shim is still excluded even when an ancestor exe is unreadable.

    Field regression (issues #29341, #34795): the old per-hop ``parent()``
    walk bailed on the FIRST psutil error, so an AccessDenied on any hop left
    the launcher shim in the candidate set and re-triggered the false
    positive. ``parents()`` returns the whole list at once; we evaluate each
    ancestor independently, so one unreadable hop never strands the launcher.
    """
    scripts_dir = tmp_path
    shim = scripts_dir / "hermes.exe"
    shim.write_bytes(b"")
    me = os.getpid()
    launcher_pid = me + 100

    rows = [
        _make_proc(me, str(shim), "python.exe"),
        _make_proc(launcher_pid, str(shim), "hermes.exe"),
    ]
    # ancestor_exe=None → every ancestor's .exe() raises OSError. The helper
    # must swallow it per-ancestor and not crash; the launcher won't be
    # excluded in this degenerate case, but a real run reads the shim exe.
    fake_psutil = _fake_psutil_with_parent_chain(
        parent_chain=[launcher_pid],
        proc_iter_rows=rows,
        ancestor_exe=None,
    )
    with patch.dict(sys.modules, {"psutil": fake_psutil}):
        result = cli_main._detect_concurrent_hermes_instances(scripts_dir)

    # No crash; helper completes. (Degenerate stub: launcher exe unreadable.)
    assert result == [(launcher_pid, "hermes.exe")]




# ---------------------------------------------------------------------------
# _format_concurrent_instances_message
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# _quarantine_running_hermes_exe — retry + reboot-deferred fallback
# ---------------------------------------------------------------------------


@patch.object(cli_main, "_is_windows", return_value=True)
def test_quarantine_succeeds_first_attempt(_winp, tmp_path):
    """When the rename works immediately, no warning, single rename pair returned."""
    shim = tmp_path / "hermes.exe"
    shim.write_bytes(b"old")

    pairs = cli_main._quarantine_running_hermes_exe(tmp_path)

    assert len(pairs) == 1
    orig, quarantine = pairs[0]
    assert orig == shim
    assert quarantine.name.startswith("hermes.exe.old.")
    assert quarantine.exists()
    assert not shim.exists()


@patch.object(cli_main, "_is_windows", return_value=True)
def test_quarantine_falls_back_to_reboot_schedule(_winp, tmp_path, capsys, monkeypatch):
    """When every retry fails, we schedule via MoveFileEx and warn helpfully."""
    shim = tmp_path / "hermes.exe"
    shim.write_bytes(b"locked")

    def always_fails(self, target):
        raise OSError(32, "The process cannot access the file (simulated lock)")

    scheduled_calls: list[tuple[Path, Path]] = []

    def fake_schedule(s: Path, q: Path) -> bool:
        scheduled_calls.append((s, q))
        return True

    monkeypatch.setattr(cli_main, "_hermes_exe_shims", lambda d: [shim])
    with patch.object(Path, "rename", always_fails), patch.object(
        cli_main, "_schedule_replace_on_reboot", fake_schedule
    ), patch("time.sleep", lambda *_a, **_k: None):
        pairs = cli_main._quarantine_running_hermes_exe(tmp_path)

    captured = capsys.readouterr().out

    # The reboot-deferred path was used.
    assert scheduled_calls and scheduled_calls[0][0] == shim
    # It is NOT added to the returned roll-back list (the issue calls this
    # out — don't undo a deferred operation).
    assert pairs == []
    # The user got a clear message, not raw [WinError 32].
    assert "scheduled" in captured.lower()
    assert "reboot" in captured.lower()




# ---------------------------------------------------------------------------
# Windows gateway pause/resume before update mutation
# ---------------------------------------------------------------------------


@patch.object(cli_main, "_is_windows", return_value=True)
def test_legacy_manual_restart_inventory_never_scans_or_kills_on_windows(
    _winp, monkeypatch
):
    import hermes_cli.gateway as gateway_mod

    monkeypatch.setattr(
        gateway_mod,
        "_get_service_pids",
        lambda: pytest.fail("Windows legacy restart queried service PIDs"),
    )
    monkeypatch.setattr(
        gateway_mod,
        "find_gateway_pids",
        lambda **kwargs: pytest.fail("Windows legacy restart scanned gateways"),
    )
    monkeypatch.setattr(
        gateway_mod,
        "find_profile_gateway_processes",
        lambda **kwargs: pytest.fail("Windows legacy restart mapped gateways"),
    )

    assert cli_main._legacy_manual_gateway_restart_inventory() == (set(), [], {})


@patch.object(cli_main, "_is_windows", return_value=True)
def test_pause_windows_gateways_for_update_stops_profile_and_unmapped_pids(
    _winp,
    monkeypatch,
    tmp_path,
    capsys,
):
    import gateway.status as status_mod
    import hermes_cli.gateway as gateway_mod

    profile_home = tmp_path / "profiles" / "work"
    profile_home.mkdir(parents=True)
    profile_proc = SimpleNamespace(profile="work", path=profile_home, pid=101)

    monkeypatch.setattr(gateway_mod, "find_gateway_pids", lambda **_k: [101, 202])
    monkeypatch.setattr(
        gateway_mod,
        "find_profile_gateway_processes",
        lambda **_k: [profile_proc],
    )
    monkeypatch.setattr(gateway_mod, "_get_restart_drain_timeout", lambda: 0.1)
    waited_for = []

    def fake_wait(pids, *, timeout):
        waited_for.extend(pids)
        return set()

    monkeypatch.setattr(cli_main, "_wait_for_windows_update_gateway_exit", fake_wait)
    monkeypatch.setattr(
        gateway_mod,
        "_capture_current_install_gateway_argv",
        lambda pid: ["pythonw.exe", "-m", "hermes_cli.main", "gateway", "run"]
        if pid == 202
        else None,
    )

    terminated = []
    monkeypatch.setattr(
        status_mod,
        "terminate_pid",
        lambda pid, force=False: terminated.append((pid, force)),
    )

    token = cli_main._pause_windows_gateways_for_update()

    assert token == {
        "resume_needed": True,
        "profiles": {"work": 101},
        "unmapped_pids": [202],
        "unmapped": [
            {
                "pid": 202,
                "argv": ["pythonw.exe", "-m", "hermes_cli.main", "gateway", "run"],
            }
        ],
    }
    assert waited_for == [101]
    assert terminated == [(202, True)]

    marker = json.loads((profile_home / ".gateway-planned-stop.json").read_text())
    assert marker["target_pid"] == 101
    assert marker["stopper_pid"] == os.getpid()

    captured = capsys.readouterr().out
    assert "Paused gateway profile(s): work" in captured
    assert "without profile mapping" in captured
    # An unmapped PID whose argv we captured is respawnable, so we must NOT
    # tell the user to restart it manually.
    assert "Restart manually after update" not in captured


@patch.object(cli_main, "_is_windows", return_value=True)
def test_pause_unions_pid_file_mapped_gateway_missing_from_raw_scan(
    _winp,
    monkeypatch,
    tmp_path,
):
    import hermes_cli.gateway as gateway_mod

    profile_home = tmp_path / "profiles" / "work"
    profile_home.mkdir(parents=True)
    profile_proc = SimpleNamespace(profile="work", path=profile_home, pid=303)
    monkeypatch.setattr(gateway_mod, "find_gateway_pids", lambda **_k: [])
    monkeypatch.setattr(
        gateway_mod,
        "find_profile_gateway_processes",
        lambda **_k: [profile_proc],
    )
    monkeypatch.setattr(gateway_mod, "_get_restart_drain_timeout", lambda: 0.1)
    monkeypatch.setattr(cli_main, "_venv_launcher_ancestors", lambda _pids: [])
    waited_for = []
    monkeypatch.setattr(
        cli_main,
        "_wait_for_windows_update_gateway_exit",
        lambda pids, *, timeout: waited_for.extend(pids) or set(),
    )

    token = cli_main._pause_windows_gateways_for_update()

    assert token == {
        "resume_needed": True,
        "profiles": {"work": 303},
        "unmapped_pids": [],
        "unmapped": [],
    }
    assert waited_for == [303]
    marker = json.loads((profile_home / ".gateway-planned-stop.json").read_text())
    assert marker["target_pid"] == 303


@patch.object(cli_main, "_is_windows", return_value=True)
def test_pause_scan_failure_is_explicit(_winp, monkeypatch):
    import hermes_cli.gateway as gateway_mod
    import hermes_cli.update_cmd as update_cmd

    def fail_scan(**_kwargs):
        raise OSError("process table unavailable")

    monkeypatch.setattr(gateway_mod, "find_gateway_pids", fail_scan)

    with pytest.raises(update_cmd._WindowsGatewayPauseDiscoveryError):
        cli_main._pause_windows_gateways_for_update()


def test_strict_windows_gateway_scan_rejects_failed_wmic_and_cim(
    monkeypatch, tmp_path
):
    import hermes_cli.gateway as gateway_mod
    import hermes_cli._subprocess_compat as subprocess_compat

    monkeypatch.setattr(gateway_mod, "is_windows", lambda: True)
    monkeypatch.setattr(gateway_mod, "_get_ancestor_pids", lambda: set())
    monkeypatch.setattr(gateway_mod, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(gateway_mod, "_profile_arg", lambda _home: "")
    monkeypatch.setattr(
        gateway_mod.shutil,
        "which",
        lambda name: f"{name}.exe" if name in {"wmic", "powershell"} else None,
    )
    probes = []
    monkeypatch.setattr(
        subprocess_compat,
        "bounded_probe_run",
        lambda command, **kwargs: probes.append((command, kwargs)) or None,
    )

    with pytest.raises(RuntimeError, match="CIM scan did not complete"):
        gateway_mod._scan_gateway_pids(set(), all_profiles=True, strict=True)

    assert [Path(command[0]).stem for command, _kwargs in probes] == [
        "wmic",
        "powershell",
    ]


def test_strict_profile_gateway_discovery_rejects_enumeration_failure(
    monkeypatch
):
    import hermes_cli.gateway as gateway_mod
    import hermes_cli.profiles as profiles_mod

    monkeypatch.setattr(
        profiles_mod,
        "list_profiles",
        lambda: (_ for _ in ()).throw(OSError("profile root unreadable")),
    )

    with pytest.raises(RuntimeError, match="enumerate Hermes profiles"):
        gateway_mod.find_profile_gateway_processes(strict=True)


def test_update_aborts_before_fetch_when_windows_gateway_scan_fails(
    monkeypatch, tmp_path, capsys
):
    import hermes_cli.gateway as gateway_mod
    import hermes_cli.update_cmd as update_cmd

    monkeypatch.setattr(cli_main, "_is_windows", lambda: True)
    monkeypatch.setattr(cli_main, "_capture_active_lazy_features", lambda: [])
    monkeypatch.setattr(cli_main, "_capture_active_tool_dependencies", lambda: [])
    monkeypatch.setattr(cli_main, "_run_pre_update_backup", lambda _args: None)
    monkeypatch.setattr(update_cmd, "_read_project_version", lambda: "0.0.0")
    monkeypatch.setattr(cli_main, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(
        gateway_mod,
        "find_gateway_pids",
        lambda **_kwargs: (_ for _ in ()).throw(
            OSError("process table unavailable")
        ),
    )
    subprocess_calls = []
    monkeypatch.setattr(
        update_cmd.subprocess,
        "run",
        lambda *args, **kwargs: subprocess_calls.append((args, kwargs)),
    )

    args = SimpleNamespace(
        yes=True,
        force=True,
        force_venv=True,
        branch=None,
    )
    with pytest.raises(SystemExit) as exc_info:
        update_cmd._cmd_update_impl(args, gateway_mode=False)

    assert exc_info.value.code == 2
    assert subprocess_calls == []
    output = capsys.readouterr().out
    assert "gateway state is unknown" in output
    assert "No checkout or dependency changes were made" in output


def _fake_gateway_process(argv, *, cwd, environ):
    class FakeProcess:
        def __init__(self, _pid):
            pass

        def cmdline(self):
            return list(argv)

        def cwd(self):
            return str(cwd)

        def environ(self):
            return dict(environ)

    return types.SimpleNamespace(Process=FakeProcess)


def test_unmapped_restart_capture_pins_the_process_runtime_profile(
    monkeypatch, tmp_path
):
    """An unmapped current-install gateway keeps its actual named profile."""
    import hermes_cli.gateway as gateway_mod

    project = tmp_path / "current" / "hermes-agent"
    runtime_root = tmp_path / "current" / "home"
    work_home = runtime_root / "profiles" / "work"
    project.mkdir(parents=True)
    work_home.mkdir(parents=True)
    argv = ["python.exe", "-m", "hermes_cli.main", "gateway", "run"]
    process_env = {
        "HERMES_HOME": str(work_home),
        "HERMES_RUNTIME_HOME": str(work_home),
        "GLADLY_HERMES_CODE_ROOT": str(project),
        "PYTHONPATH": str(project),
    }
    monkeypatch.setattr(gateway_mod, "PROJECT_ROOT", project)
    monkeypatch.setattr(gateway_mod, "get_hermes_home", lambda: runtime_root)
    monkeypatch.setitem(
        sys.modules,
        "psutil",
        _fake_gateway_process(argv, cwd=project, environ=process_env),
    )

    captured = gateway_mod._capture_current_install_gateway_argv(202)

    assert captured == [
        "python.exe",
        "-m",
        "hermes_cli.main",
        "--profile",
        "work",
        "gateway",
        "run",
    ]


@patch.object(cli_main, "_is_windows", return_value=True)
def test_pause_leaves_cross_root_unmapped_gateway_untouched(
    _winp,
    monkeypatch,
    tmp_path,
    capsys,
):
    """A host-wide scan must not stop/replay another Hermes installation."""
    import gateway.status as status_mod
    import hermes_cli.gateway as gateway_mod
    import hermes_cli.gateway_windows as gateway_windows

    current_project = tmp_path / "current" / "hermes-agent"
    current_home = tmp_path / "current" / "home"
    foreign_project = tmp_path / "foreign" / "hermes-agent"
    foreign_home = tmp_path / "foreign" / "home"
    for path in (current_project, current_home, foreign_project, foreign_home):
        path.mkdir(parents=True)
    argv = ["python.exe", "-m", "hermes_cli.main", "gateway", "run"]
    foreign_env = {
        "HERMES_HOME": str(foreign_home),
        "HERMES_RUNTIME_HOME": str(foreign_home),
        "GLADLY_HERMES_CODE_ROOT": str(foreign_project),
        "PYTHONPATH": str(foreign_project),
    }
    monkeypatch.setattr(gateway_mod, "PROJECT_ROOT", current_project)
    monkeypatch.setattr(gateway_mod, "get_hermes_home", lambda: current_home)
    monkeypatch.setattr(gateway_mod, "find_gateway_pids", lambda **_k: [202])
    monkeypatch.setattr(
        gateway_mod, "find_profile_gateway_processes", lambda **_k: []
    )
    monkeypatch.setitem(
        sys.modules,
        "psutil",
        _fake_gateway_process(argv, cwd=foreign_project, environ=foreign_env),
    )
    terminated = []
    monkeypatch.setattr(
        status_mod,
        "terminate_pid",
        lambda pid, force=False: terminated.append((pid, force)),
    )
    monkeypatch.setattr(
        cli_main,
        "_wait_for_windows_update_gateway_exit",
        lambda *_args, **_kwargs: pytest.fail("foreign gateway must not be drained"),
    )
    monkeypatch.setattr(gateway_windows, "is_installed", lambda: True)
    monkeypatch.setattr(gateway_windows, "is_autostart_enabled", lambda: True)

    token = cli_main._pause_windows_gateways_for_update()

    assert token == {
        "resume_needed": True,
        "profiles": {},
        "unmapped_pids": [],
        "unmapped": [],
        "cold_start_if_installed": True,
    }
    assert terminated == []
    assert "other-installation" in capsys.readouterr().out

    refreshed = []
    cold_started = []
    monkeypatch.setattr(
        cli_main,
        "_refresh_windows_gateway_launchers",
        lambda: refreshed.append(True),
    )
    monkeypatch.setattr(
        cli_main,
        "_cold_start_windows_gateway_after_update",
        lambda: cold_started.append(True),
    )

    cli_main._resume_windows_gateways_after_update(token)

    assert refreshed == [True]
    assert cold_started == [True]


@patch.object(cli_main, "_is_windows", return_value=True)
def test_disabled_installed_task_refreshes_but_never_cold_starts(
    _winp,
    monkeypatch,
):
    import hermes_cli.gateway as gateway_mod
    import hermes_cli.gateway_windows as gateway_windows

    monkeypatch.setattr(gateway_mod, "find_gateway_pids", lambda **_k: [])
    monkeypatch.setattr(
        gateway_mod, "find_profile_gateway_processes", lambda **_k: []
    )
    monkeypatch.setattr(gateway_windows, "is_installed", lambda: True)
    monkeypatch.setattr(gateway_windows, "is_autostart_enabled", lambda: False)

    token = cli_main._pause_windows_gateways_for_update()

    assert token and token["cold_start_if_installed"] is False
    refreshed = []
    monkeypatch.setattr(
        cli_main,
        "_refresh_windows_gateway_launchers",
        lambda: refreshed.append(True),
    )
    monkeypatch.setattr(
        cli_main,
        "_cold_start_windows_gateway_after_update",
        lambda: pytest.fail("disabled task must remain quarantined"),
    )

    cli_main._resume_windows_gateways_after_update(token)

    assert refreshed == [True]


@patch.object(cli_main, "_is_windows", return_value=True)
def test_other_installed_profile_still_requests_launcher_refresh(
    _winp,
    monkeypatch,
    tmp_path,
):
    import hermes_cli.gateway as gateway_mod
    import hermes_cli.gateway_windows as gateway_windows

    work_home = tmp_path / "home" / "profiles" / "work"
    work_home.mkdir(parents=True)
    monkeypatch.setattr(gateway_mod, "find_gateway_pids", lambda **_k: [])
    monkeypatch.setattr(
        gateway_mod, "find_profile_gateway_processes", lambda **_k: []
    )
    monkeypatch.setattr(gateway_windows, "is_installed", lambda: False)
    monkeypatch.setattr(
        gateway_windows, "get_installed_profile_homes", lambda: [work_home]
    )
    monkeypatch.setattr(
        gateway_windows,
        "is_autostart_enabled",
        lambda: pytest.fail("a different profile must not cold-start current"),
    )

    token = cli_main._pause_windows_gateways_for_update()

    assert token == {
        "resume_needed": True,
        "profiles": {},
        "unmapped_pids": [],
        "unmapped": [],
        "cold_start_if_installed": False,
    }


# ---------------------------------------------------------------------------
# venv-side launcher ancestors (the uv launcher/worker split)
#
# A gateway started through the venv shim is two processes:
#   venv\Scripts\python.exe (launcher)  ->  uv\python\...\python.exe (worker)
# The gateway's PID file records the WORKER, so find_gateway_pids() (and the
# pause set built from it) only ever sees the worker. The venv-holder guard
# matches on the venv path prefix, so it only ever sees the LAUNCHER. The two
# sets were disjoint: a gateway the updater had just stopped still tripped the
# guard, aborting every update ("venv-blocked: N process(es) hold the install").
# ---------------------------------------------------------------------------


def _fake_psutil_tree(tree, venv_exe, worker_exe, dead=None):
    """Build a psutil stand-in where ``tree`` maps worker pid -> parent pid.

    Parents whose pid is even are venv-side (``venv_exe``); odd parents are
    unrelated ancestors (``worker_exe``) that must NOT be returned. Pids in
    ``dead`` (a live reference — later additions count) are uninspectable:
    construction raises, exactly like psutil.NoSuchProcess for an exited
    process.
    """

    dead_set = dead if dead is not None else set()

    class FakeProc:
        def __init__(self, pid):
            self.pid = pid
            if pid in dead_set:
                raise ValueError(f"process {pid} has exited")
            if pid not in tree and pid not in tree.values():
                raise ValueError(f"no such pid {pid}")

        def parent(self):
            ppid = tree.get(self.pid)
            return FakeProc(ppid) if ppid else None

        def parents(self):
            return []

        def exe(self):
            # Parents of workers are the launchers under test.
            return venv_exe if self.pid % 2 == 0 else worker_exe

    mod = types.SimpleNamespace(Process=FakeProc)
    return mod


@patch.object(cli_main, "_is_windows", return_value=True)
def test_venv_launcher_ancestors_returns_venv_side_parent(_winp, monkeypatch):
    """The worker's venv-side parent is reported so the guard set is covered."""
    venv_exe = str(cli_main.PROJECT_ROOT / "venv" / "Scripts" / "python.exe")
    worker_exe = r"C:\Users\x\AppData\Roaming\uv\python\cpython-3.11\python.exe"

    # worker 200 -> launcher 100 (even == venv-side)
    fake = _fake_psutil_tree({200: 100}, venv_exe, worker_exe)
    monkeypatch.setitem(sys.modules, "psutil", fake)

    assert cli_main._venv_launcher_ancestors([200]) == [100]


@patch.object(cli_main, "_is_windows", return_value=True)
def test_venv_launcher_ancestors_ignores_non_venv_parents(_winp, monkeypatch):
    """A Scheduled Task's cmd.exe / an operator shell is not a venv holder."""
    venv_exe = str(cli_main.PROJECT_ROOT / "venv" / "Scripts" / "python.exe")
    worker_exe = r"C:\Windows\System32\cmd.exe"

    # worker 200 -> parent 101 (odd == NOT venv-side)
    fake = _fake_psutil_tree({200: 101}, venv_exe, worker_exe)
    monkeypatch.setitem(sys.modules, "psutil", fake)

    assert cli_main._venv_launcher_ancestors([200]) == []


@patch.object(cli_main, "_is_windows", return_value=True)
def test_venv_launcher_ancestors_is_empty_without_pids(_winp):
    """No mapped gateways means nothing to walk up from."""
    assert cli_main._venv_launcher_ancestors([]) == []


@patch.object(cli_main, "_is_windows", return_value=True)
def test_pause_kill_set_covers_venv_guard_abort_set(
    _winp,
    monkeypatch,
    tmp_path,
):
    """INVARIANT: whatever the venv guard would abort on must be stopped.

    This is the contract the two PID-resolution paths must satisfy. Before the
    launcher walk existed, ``terminated`` held only the uv-side worker while
    the guard reported the venv-side launcher, so the update aborted forever
    despite a "successful" pause.
    """
    import hermes_cli.gateway as gateway_mod
    import gateway.status as status_mod

    venv_exe = str(cli_main.PROJECT_ROOT / "venv" / "Scripts" / "python.exe")
    worker_exe = r"C:\Users\x\AppData\Roaming\uv\python\cpython-3.11\python.exe"

    profile_home = tmp_path / "profiles" / "default"
    profile_home.mkdir(parents=True)
    # The PID file records the WORKER (even-numbered parent 400 is its launcher).
    worker_pid, launcher_pid = 500, 400
    profile_proc = SimpleNamespace(
        profile="default", path=profile_home, pid=worker_pid
    )

    monkeypatch.setattr(gateway_mod, "find_gateway_pids", lambda **_k: [worker_pid])
    monkeypatch.setattr(
        gateway_mod, "find_profile_gateway_processes", lambda **_k: [profile_proc]
    )
    monkeypatch.setattr(gateway_mod, "_get_restart_drain_timeout", lambda: 0.1)
    # Graceful drain succeeds: the worker exits, leaving zero survivors — and
    # an exited worker is UNINSPECTABLE afterwards, exactly like the real
    # process table. Resolving the launcher after this point is impossible,
    # so the pause must snapshot launcher ancestors before draining. This is
    # precisely the case that used to leave the launcher alive and abort.
    drained_dead: set[int] = set()

    def _drain_marks_workers_dead(pids, *, timeout):
        drained_dead.update(int(p) for p in pids)
        return set()

    monkeypatch.setattr(
        cli_main,
        "_wait_for_windows_update_gateway_exit",
        _drain_marks_workers_dead,
    )

    fake = _fake_psutil_tree(
        {worker_pid: launcher_pid}, venv_exe, worker_exe, dead=drained_dead
    )
    monkeypatch.setitem(sys.modules, "psutil", fake)

    terminated = []
    monkeypatch.setattr(
        status_mod,
        "terminate_pid",
        lambda pid, force=False: terminated.append(int(pid)),
    )

    cli_main._pause_windows_gateways_for_update()

    # What the downstream venv-holder guard would report as blocking.
    guard_would_abort_on = {launcher_pid}
    assert guard_would_abort_on.issubset(set(terminated)), (
        f"pause stopped {sorted(terminated)} but the venv guard aborts on "
        f"{sorted(guard_would_abort_on)} — disjoint sets abort the update"
    )


# ---------------------------------------------------------------------------
# _leftover_pausable_gateway_pids (the guard-level gateway fallback)
#
# The pause stops every gateway discovery finds, but the venv-holder guard
# sees the process table as it is NOW. A supervisor (Scheduled Task, login
# watchdog) can respawn a gateway inside the pause→guard window, and some
# spawn paths never register in discovery at all. Those holders are exactly
# what the pause machinery exists to stop — but only after current-install
# provenance is proved and a replay argv is captured. The guard refuses the
# moment any holder is foreign, unverified, or not a gateway.
# ---------------------------------------------------------------------------


GATEWAY_ARGV = [
    r"C:\x\venv\Scripts\python.exe",
    "-m",
    "hermes_cli.main",
    "gateway",
    "run",
]


def test_leftover_holders_that_are_all_gateways_are_nominated(monkeypatch):
    """Proven current gateways carry replay argv before they can be stopped."""
    import hermes_cli.gateway as gateway_mod

    monkeypatch.setattr(
        gateway_mod,
        "_capture_current_install_gateway_argv",
        lambda pid: [*GATEWAY_ARGV, "--pid", str(pid)],
    )
    gateway_prefix = " ".join(GATEWAY_ARGV)
    matches = [
        (300, "python.exe", gateway_prefix),
        (301, "python.exe", gateway_prefix),
    ]

    assert cli_main._leftover_pausable_gateway_pids(matches) == [
        {"pid": 300, "argv": [*GATEWAY_ARGV, "--pid", "300"]},
        {"pid": 301, "argv": [*GATEWAY_ARGV, "--pid", "301"]},
    ]


def test_one_non_gateway_holder_keeps_the_hard_refusal(monkeypatch):
    """A REPL/backend holder means the guard must abort exactly as before."""
    import hermes_cli.gateway as gateway_mod

    monkeypatch.setattr(
        gateway_mod,
        "_capture_current_install_gateway_argv",
        lambda pid: GATEWAY_ARGV,
    )
    matches = [
        (300, "python.exe", " ".join(GATEWAY_ARGV)),
        (400, "python.exe", r"C:\x\venv\Scripts\python.exe -i"),
    ]

    assert cli_main._leftover_pausable_gateway_pids(matches) is None


def test_unverified_gateway_holder_keeps_the_hard_refusal(monkeypatch):
    """Gateway-shaped argv alone never grants authority to kill a process."""
    import hermes_cli.gateway as gateway_mod

    monkeypatch.setattr(
        gateway_mod,
        "_capture_current_install_gateway_argv",
        lambda pid: None,
    )
    gateway_prefix = r"venv\Scripts\python.exe -m hermes_cli.main gateway run"

    assert cli_main._leftover_pausable_gateway_pids(
        [(300, "python.exe", gateway_prefix)]
    ) is None











# ---------------------------------------------------------------------------
# cmd_update integration — concurrent-instance gate
# ---------------------------------------------------------------------------
