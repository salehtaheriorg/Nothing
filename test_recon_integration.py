"""Network-free integration regression test for ReconHunter httpx selection."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from core.findings_store import FindingsStore
from core.rate_limiter import RateLimiter
from core.scope import ScopeGuard
from core.task_store import TaskStore
from hunters.recon_hunter import ReconHunter


def test_execute_uses_projectdiscovery_httpx_path(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({"program_name": "test", "in_scope": ["example.com"], "out_of_scope": []}),
        encoding="utf-8",
    )

    hunter = ReconHunter(
        scope=ScopeGuard(scope_file),
        store=TaskStore(tmp_path / "tasks.db"),
        findings=FindingsStore(tmp_path / "findings.db"),
        rate_limiter=RateLimiter(),
    )

    selected = tmp_path / "go" / "bin" / "httpx"

    with patch.object(hunter, "_run_subfinder", return_value=[]), \
         patch.object(hunter, "_find_projectdiscovery_httpx", return_value=str(selected)), \
         patch.object(hunter, "_run_httpx", return_value=["https://example.com"] ) as run_httpx, \
         patch("hunters.recon_hunter.shutil.which", side_effect=lambda name: "/fake/katana" if name == "katana" else "/fake/subfinder") , \
         patch.object(hunter, "_run_katana", return_value=[]):
        result = hunter.execute("example.com", {})

    run_httpx.assert_called_once_with(["example.com"], str(selected))
    assert result["live_hosts"] == ["https://example.com"]


def test_execute_collapses_path_target_to_hostname(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({"program_name": "test", "in_scope": ["example.com"], "out_of_scope": []}),
        encoding="utf-8",
    )
    hunter = ReconHunter(
        scope=ScopeGuard(scope_file),
        store=TaskStore(tmp_path / "tasks.db"),
        findings=FindingsStore(tmp_path / "findings.db"),
        rate_limiter=RateLimiter(),
    )
    selected = tmp_path / "go" / "bin" / "httpx"
    with patch.object(hunter, "_run_subfinder", return_value=[]) as run_subfinder, \
         patch.object(hunter, "_find_projectdiscovery_httpx", return_value=str(selected)), \
         patch.object(hunter, "_run_httpx", return_value=["https://example.com"]) as run_httpx, \
         patch("hunters.recon_hunter.shutil.which", side_effect=lambda name: "/fake/katana" if name == "katana" else "/fake/subfinder"), \
         patch.object(hunter, "_run_katana", return_value=[]):
        result = hunter.execute("https://example.com/robots.txt", {})
    run_subfinder.assert_called_once_with("example.com")
    run_httpx.assert_called_once_with(["example.com"], str(selected))
    assert result["target"] == "example.com"
