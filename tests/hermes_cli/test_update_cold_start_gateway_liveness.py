"""#84185: a Windows gateway cold-started after update that dies immediately
(e.g. a job object denying breakaway) must not be reported as started.

``_cold_start_windows_gateway_after_update`` used to print the success line
straight off a successful ``Popen`` return, which only proves the process was
created, not that it survived. This asserts the observable output: the
success line is gated on the process actually being found alive afterwards,
same as every other ``_spawn_detached`` caller.
"""

from __future__ import annotations

from pathlib import Path

from hermes_cli import gateway as hermes_gateway
from hermes_cli import gateway_windows
from hermes_cli import main as cli_main
from hermes_cli import update_cmd


def _run_cold_start(monkeypatch, capsys, *, surviving_pids):
    monkeypatch.setattr(cli_main, "_is_windows", lambda: True)

    # The pre-spawn re-check (``all_profiles=True``) must find nothing
    # running so the cold-start path proceeds and actually spawns.
    monkeypatch.setattr(
        hermes_gateway,
        "find_gateway_pids",
        lambda all_profiles=False, **_kwargs: (
            [] if all_profiles else surviving_pids
        ),
    )
    monkeypatch.setattr(
        hermes_gateway,
        "find_profile_gateway_processes",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(gateway_windows, "_spawn_detached", lambda: 4242)
    # Avoid the real 6s/0.4s poll loop in _report_gateway_start.
    monkeypatch.setattr(
        gateway_windows, "_wait_for_gateway_ready", lambda *a, **k: surviving_pids
    )

    update_cmd._cold_start_windows_gateway_after_update()

    return capsys.readouterr().out


def test_cold_start_reports_failure_when_process_does_not_survive(monkeypatch, capsys):
    out = _run_cold_start(monkeypatch, capsys, surviving_pids=[])

    assert "✓ Starting Windows gateway after update" not in out
    assert "no process detected" in out


def test_cold_start_reports_success_when_process_survives(monkeypatch, capsys):
    out = _run_cold_start(monkeypatch, capsys, surviving_pids=[4242])

    assert "✓ Gateway started via cold-start after update" in out


def test_cold_start_ignores_proven_foreign_gateway(monkeypatch, tmp_path):
    """Another installation's gateway must not suppress this installed task."""
    current_home = tmp_path / "current" / "home"
    foreign_home = tmp_path / "foreign" / "home"
    current_home.mkdir(parents=True)
    foreign_home.mkdir(parents=True)
    monkeypatch.setattr(cli_main, "_is_windows", lambda: True)
    monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: current_home)
    monkeypatch.setattr(
        hermes_gateway, "find_profile_gateway_processes", lambda **_kwargs: []
    )
    monkeypatch.setattr(
        hermes_gateway,
        "find_gateway_pids",
        lambda all_profiles=False, **_kwargs: [77],
    )
    monkeypatch.setattr(
        hermes_gateway,
        "_capture_current_install_gateway_argv",
        lambda _pid: None,
    )
    monkeypatch.setattr(
        hermes_gateway,
        "_gateway_process_runtime_root",
        lambda _pid: Path(foreign_home),
    )
    spawned = []
    monkeypatch.setattr(
        gateway_windows, "_spawn_detached", lambda: spawned.append(True) or 4242
    )
    monkeypatch.setattr(gateway_windows, "_report_gateway_start", lambda _label: None)

    update_cmd._cold_start_windows_gateway_after_update()

    assert spawned == [True]


def test_cold_start_blocks_on_ambiguous_gateway_provenance(monkeypatch, tmp_path):
    """An unreadable candidate stays a fail-closed duplicate-start blocker."""
    current_home = tmp_path / "current" / "home"
    current_home.mkdir(parents=True)
    monkeypatch.setattr(cli_main, "_is_windows", lambda: True)
    monkeypatch.setattr("hermes_cli.config.get_hermes_home", lambda: current_home)
    monkeypatch.setattr(
        hermes_gateway, "find_profile_gateway_processes", lambda **_kwargs: []
    )
    monkeypatch.setattr(
        hermes_gateway,
        "find_gateway_pids",
        lambda all_profiles=False, **_kwargs: [77],
    )
    monkeypatch.setattr(
        hermes_gateway,
        "_capture_current_install_gateway_argv",
        lambda _pid: None,
    )
    monkeypatch.setattr(
        hermes_gateway, "_gateway_process_runtime_root", lambda _pid: None
    )
    monkeypatch.setattr(
        gateway_windows,
        "_spawn_detached",
        lambda: (_ for _ in ()).throw(
            AssertionError("ambiguous gateway must block cold-start")
        ),
    )

    update_cmd._cold_start_windows_gateway_after_update()


def test_cold_start_blocks_when_strict_process_scan_fails(monkeypatch):
    monkeypatch.setattr(cli_main, "_is_windows", lambda: True)
    monkeypatch.setattr(
        hermes_gateway, "find_profile_gateway_processes", lambda **_kwargs: []
    )
    monkeypatch.setattr(hermes_gateway, "_get_service_pids", lambda: set())
    monkeypatch.setattr(
        hermes_gateway, "supports_systemd_services", lambda: False
    )

    def unavailable_scan(
        _exclude,
        *,
        all_profiles=False,
        include_restart_managers=False,
        strict=False,
    ):
        if strict:
            raise RuntimeError("process table unavailable")
        return []

    monkeypatch.setattr(hermes_gateway, "_scan_gateway_pids", unavailable_scan)
    monkeypatch.setattr(
        gateway_windows,
        "_spawn_detached",
        lambda: (_ for _ in ()).throw(
            AssertionError("unknown process state must block cold-start")
        ),
    )

    assert update_cmd._cold_start_windows_gateway_after_update() is False
