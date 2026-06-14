from __future__ import annotations

import shutil

import pytest


def test_inline_shell_replaces_non_utf8_output(tmp_path):
    if shutil.which("bash") is None:
        pytest.skip("bash is required for inline-shell preprocessing")

    from agent.skill_preprocessing import run_inline_shell

    output = run_inline_shell('printf "\\366"', tmp_path, timeout=5)

    assert "[inline-shell error:" not in output
    assert "\ufffd" in output
