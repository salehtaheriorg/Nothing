"""Regression tests for ReconHunter's ProjectDiscovery httpx selection.

These tests are network-free. They verify that a Python `httpx` executable in
venv/bin is ignored when the real ProjectDiscovery binary exists in ~/go/bin.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

from hunters.recon_hunter import ReconHunter


def _make_executable(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_prefers_projectdiscovery_go_binary_over_venv_httpx(tmp_path: Path) -> None:
    go_httpx = _make_executable(
        tmp_path / "go" / "bin" / "httpx",
        "#!/bin/sh\necho '[INF] Current Version: v1.11.0'\n",
    )
    bad_httpx = _make_executable(
        tmp_path / "venv" / "bin" / "httpx",
        "#!/bin/sh\necho \"Usage: httpx [OPTIONS] URL\" 1>&2\nexit 2\n",
    )

    # Simulate the user's Termux situation: PATH resolves to venv/bin/httpx,
    # but the standard Go-installed ProjectDiscovery binary is also present.
    with patch.dict(os.environ, {}, clear=False), patch(
        "hunters.recon_hunter.Path.home", return_value=tmp_path
    ), patch("hunters.recon_hunter.shutil.which", return_value=str(bad_httpx)):
        os.environ.pop("PROJECTDISCOVERY_HTTPX", None)
        selected = ReconHunter._find_projectdiscovery_httpx()

    assert selected == str(go_httpx)


def test_accepts_explicit_projectdiscovery_httpx_override(tmp_path: Path) -> None:
    override = _make_executable(
        tmp_path / "custom" / "httpx",
        "#!/bin/sh\necho '[INF] Current Version: v1.11.0'\n",
    )

    with patch.dict(os.environ, {"PROJECTDISCOVERY_HTTPX": str(override)}):
        selected = ReconHunter._find_projectdiscovery_httpx()

    assert selected == str(override)
