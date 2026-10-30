from __future__ import annotations
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock

from core.findings_store import FindingsStore
from core.rate_limiter import RateLimiter
from core.scope import ScopeGuard
from core.task_store import TaskStore
from hunters.cors_redirect_hunter import CorsRedirectHunter
from hunters.idor_hunter import find_id_like_path_segments
from hunters.recon_hunter import ReconHunter
from hunters.xss_hunter import XSSHunter


def _scope(tmp_path: Path) -> ScopeGuard:
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"program_name": "t", "in_scope": ["example.com"], "out_of_scope": []}), encoding="utf-8")
    return ScopeGuard(p)


def _hunter(cls, tmp_path: Path):
    return cls(scope=_scope(tmp_path), store=TaskStore(tmp_path/"tasks.db"), findings=FindingsStore(tmp_path/"findings.db"), rate_limiter=RateLimiter(1000))


def test_path_identifier_detection():
    hits = find_id_like_path_segments("https://example.com/users/123/orders/550e8400-e29b-41d4-a716-446655440000")
    assert [x[1] for x in hits] == ["123", "550e8400-e29b-41d4-a716-446655440000"]


def test_xss_path_reflection_candidate(tmp_path: Path):
    h = _hunter(XSSHunter, tmp_path)
    marker_response = SimpleNamespace(text="hello XSS_PATH_deadbeef world", status_code=200)
    with patch("hunters.xss_hunter.requests.get", return_value=marker_response):
        out = h._test_path("https://example.com/item/123", 1, "XSS_PATH_deadbeef", "https://example.com/item/XSS_PATH_deadbeef")
    assert len(out) == 1


def test_cors_preflight_candidate(tmp_path: Path):
    h = _hunter(CorsRedirectHunter, tmp_path)
    def fake_get(url, headers=None, timeout=10):
        origin = headers["Origin"]
        return SimpleNamespace(headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Vary": "Origin"}, status_code=200, text="")

    def fake_options(url, headers=None, timeout=10):
        origin = headers["Origin"]
        return SimpleNamespace(headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Credentials": "true", "Access-Control-Allow-Headers": "Authorization, Content-Type"}, status_code=204, text="")

    with patch("hunters.cors_redirect_hunter.requests.get", side_effect=fake_get), patch("hunters.cors_redirect_hunter.requests.options", side_effect=fake_options):
        out = h._check_cors("https://example.com/api")
    assert len(out) >= 2


def test_recon_well_known_discovery_is_scope_filtered(tmp_path: Path):
    h = _hunter(ReconHunter, tmp_path)
    def fake_get(url, timeout=10):
        if url.endswith("/robots.txt"):
            return SimpleNamespace(status_code=200, text="Sitemap: https://example.com/sitemap.xml\nAllow: /api/public")
        return SimpleNamespace(status_code=200, text="<urlset></urlset>")
    with patch("hunters.recon_hunter.requests.get", side_effect=fake_get):
        out = h._discover_well_known(["https://example.com"])
    assert "https://example.com/robots.txt" in out
    assert "https://example.com/sitemap.xml" in out


def test_param_miner_ignores_identical_random_baseline(tmp_path: Path):
    from hunters.param_miner_hunter import ParamMinerHunter

    h = _hunter(ParamMinerHunter, tmp_path)

    class Resp:
        status_code = 200
        content = b"same response"
        text = "same response"
        headers = {"Content-Type": "text/html", "Server": "test"}
        elapsed = SimpleNamespace(total_seconds=lambda: 0.01)

    with patch("hunters.param_miner_hunter.requests.get", return_value=Resp()):
        out = h.execute("https://example.com/", {"url": "https://example.com/"})

    assert out["raw_candidates"] == 0
    assert out["discovered"] == []
    assert out["findings"] == []


def test_param_miner_requires_reproducible_difference(tmp_path: Path):
    from hunters.param_miner_hunter import ParamMinerHunter

    h = _hunter(ParamMinerHunter, tmp_path)
    calls = {"n": 0}

    class Resp:
        headers = {"Content-Type": "text/html", "Server": "test"}
        elapsed = SimpleNamespace(total_seconds=lambda: 0.01)

        def __init__(self, changed: bool):
            self.status_code = 200 if not changed else 302
            self.text = "baseline" if not changed else "redirected"
            self.content = self.text.encode()

    def fake_get(url, timeout=10, allow_redirects=False):
        calls["n"] += 1
        if "debug=1" in url:
            # First candidate probe looks different, repeat probe is stable.
            return Resp(True)
        return Resp(False)

    with patch("hunters.param_miner_hunter.requests.get", side_effect=fake_get):
        out = h.execute("https://example.com/", {"url": "https://example.com/"})

    assert "debug" in out["discovered"]
    assert len(out["findings"]) == 1
    finding = h.findings.all_findings()[0]
    assert finding["confidence"] == "candidate"
    assert finding["verified"] == 0
    assert finding["evidence"]


def test_param_miner_ignores_tiny_body_difference(tmp_path: Path):
    from hunters.param_miner_hunter import ParamMinerHunter, ResponseFingerprint

    base = ResponseFingerprint(200, 1000, "a" * 1000, "", "text/html", "test")
    tiny = ResponseFingerprint(200, 1002, "a" * 998 + "bb", "", "text/html", "test")
    baseline = {"status": 200, "length_median": 1000, "representative": base, "samples": []}
    assert not ParamMinerHunter._is_differential_candidate(baseline, tiny)


def test_task_store_dedupes_equivalent_targets_within_run(tmp_path: Path):
    store = TaskStore(tmp_path / "tasks.db")
    a = store.add_task("xss", "HTTPS://EXAMPLE.COM/", {"url": "https://example.com/"}, run_id="run-1")
    b = store.add_task("xss", "https://example.com", {"url": "https://example.com/"}, run_id="run-1")
    c = store.add_task("xss", "https://example.com", {"url": "https://example.com/"}, run_id="run-2")
    assert a == b
    assert c != a
    assert len(store.board()["todo"]) == 2


def test_task_store_purges_stale_pending(tmp_path: Path):
    store = TaskStore(tmp_path / "tasks.db")
    store.add_task("xss", "https://example.com", run_id="old")
    store.add_task("nuclei", "https://example.com", run_id="old")
    assert store.purge_pending() == 2
    assert not store.board()["todo"]


def test_findings_store_dedupes_same_candidate(tmp_path: Path):
    store = FindingsStore(tmp_path / "findings.db")
    evidence = {"param": "debug", "probe_url": "https://example.com/?debug=1"}
    a = store.add_finding("param_miner", "https://example.com/", "Hidden Parameter Candidate", "info", evidence)
    b = store.add_finding("param_miner", "https://example.com/", "Hidden Parameter Candidate", "info", evidence)
    assert a == b
    assert store.summary()["total"] == 1


def test_overseer_repeated_recon_same_run_does_not_duplicate_jobs(tmp_path: Path):
    from core.overseer import Overseer
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"program_name":"t","in_scope":["example.com"],"out_of_scope":[]}), encoding="utf-8")
    with patch("core.overseer.GeminiTextClient", return_value=Mock()):
        ov = Overseer(str(scope_file), db_path=str(tmp_path/"tasks.db"), diff_db_path=str(tmp_path/"diff.db"), knowledge_db_path=str(tmp_path/"knowledge.db"), run_id="run-1")
    result = {
        "subdomains": ["example.com"],
        "live_hosts": ["https://example.com"],
        "urls": ["https://EXAMPLE.com/", "https://example.com"],
    }
    a = ov.seed_vuln_hunters_from_recon(result, use_diff=False)
    b = ov.seed_vuln_hunters_from_recon(result, use_diff=False)
    assert a["param_miner"] == 1
    assert b["param_miner"] == 0
    board = ov.store.board()
    assert len(board["todo"]) <= 10


def test_ssrf_oob_probe_does_not_create_finding_without_callback(tmp_path: Path):
    from hunters.ssrf_hunter import SSRFHunter
    settings = tmp_path / 'settings.json'
    settings.write_text(json.dumps({'ssrf_oob_domain': 'oob.example.test'}), encoding='utf-8')
    h = SSRFHunter(scope=_scope(tmp_path), store=TaskStore(tmp_path/'tasks.db'), findings=FindingsStore(tmp_path/'findings.db'), rate_limiter=RateLimiter(1000), settings_file=str(settings))
    class Resp:
        status_code = 200
        text = 'normal response'
        content = b'normal response'
    with patch('hunters.ssrf_hunter.requests.get', return_value=Resp()):
        out = h.execute('https://example.com/?url=https%3A%2F%2Fexample.org', {'url':'https://example.com/?url=https%3A%2F%2Fexample.org'})
    assert out['oob_probes']
    assert out['findings'] == []
    assert h.findings.summary()['total'] == 0


def test_secrets_ignores_common_placeholders(tmp_path: Path):
    from hunters.secrets_hunter import SecretsHunter
    h = _hunter(SecretsHunter, tmp_path)
    class Resp:
        status_code = 200
        text = 'api_key="your_api_key" secret_key="changeme"'
        content = text.encode()
        headers = {'Content-Type':'application/javascript'}
    with patch('hunters.secrets_hunter.requests.get', return_value=Resp()):
        out = h.execute('https://example.com/app.js', {'url':'https://example.com/app.js'})
    assert out['findings'] == []


def test_cors_wildcard_without_credentials_is_candidate(tmp_path: Path):
    h = _hunter(CorsRedirectHunter, tmp_path)
    class Resp:
        status_code = 200
        headers = {'Access-Control-Allow-Origin':'*'}
        text = ''
    with patch('hunters.cors_redirect_hunter.requests.get', return_value=Resp()):
        out = h._check_cors('https://example.com/api')
    assert out
    finding = h.findings.get(out[0])
    assert finding['confidence'] == 'candidate'


def test_template_forge_does_not_create_finding_without_execution(tmp_path: Path):
    from hunters.template_forge_hunter import TemplateForgeHunter
    settings = tmp_path / 'settings.json'
    settings.write_text(json.dumps({'template_forge_auto_execute': False}), encoding='utf-8')
    with patch('hunters.template_forge_hunter.GeminiTextClient', return_value=Mock()):
        h = TemplateForgeHunter(scope=_scope(tmp_path), store=TaskStore(tmp_path/'tasks.db'), findings=FindingsStore(tmp_path/'findings.db'), rate_limiter=RateLimiter(1000), settings_file=str(settings))
    proposal = {
        'title':'test', 'severity':'medium', 'rationale':'test',
        'template_yaml':'id: safe-test\ninfo:\n  name: test\n  severity: medium\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/"\n'
    }
    with patch('hunters.template_forge_hunter.TEMPLATES_DIR', tmp_path/'templates'):
        assert h._process_proposal('https://example.com', proposal) == []
    assert h.findings.summary()['total'] == 0


def test_scope_normalizes_pasted_urls_to_hostnames(tmp_path: Path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "program_name": "t",
        "in_scope": ["https://Example.COM/robots.txt", "*.Example.COM/"],
        "out_of_scope": ["https://status.Example.COM/health"],
    }), encoding="utf-8")
    scope = ScopeGuard(p)
    assert scope.in_scope == ["example.com", "*.example.com"]
    assert scope.out_of_scope == ["status.example.com"]
    assert scope.check("https://example.com/anything").allowed
    assert not scope.check("https://status.example.com/anything").allowed


def test_seed_recon_is_host_only_and_deduplicated(tmp_path: Path):
    from core.overseer import Overseer
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "program_name": "t",
        "in_scope": ["https://example.com/robots.txt", "example.com", "*.example.com/"],
        "out_of_scope": [],
    }), encoding="utf-8")
    with patch("core.overseer.GeminiTextClient", return_value=Mock()):
        ov = Overseer(str(scope_file), db_path=str(tmp_path/"tasks.db"), diff_db_path=str(tmp_path/"diff.db"), knowledge_db_path=str(tmp_path/"knowledge.db"), run_id="run-1")
    ov.seed_recon()
    recon_tasks = ov.store.board()["todo"]
    assert len(recon_tasks) == 1
    assert recon_tasks[0]["hunter"] == "recon"
    assert recon_tasks[0]["target"] == "example.com"


def test_planning_recon_path_is_collapsed_and_deduped(tmp_path: Path):
    from core.overseer import Overseer
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"program_name":"t", "in_scope":["example.com"], "out_of_scope":[]}), encoding="utf-8")
    client = Mock()
    client.generate_text.return_value = json.dumps([
        {"hunter":"recon", "target":"https://example.com/robots.txt", "reason":"recheck"},
        {"hunter":"recon", "target":"https://example.com/sitemap.xml", "reason":"recheck"},
    ])
    with patch("core.overseer.GeminiTextClient", return_value=client):
        ov = Overseer(str(scope_file), db_path=str(tmp_path/"tasks.db"), diff_db_path=str(tmp_path/"diff.db"), knowledge_db_path=str(tmp_path/"knowledge.db"), run_id="run-1")
    ov.seed_recon()
    # The original seed already owns the host-level Recon identity.
    accepted = ov.plan_next_steps({"target":"example.com"})
    assert len(accepted) == 2
    recon_tasks = [x for x in ov.store.board()["todo"] if x["hunter"] == "recon"]
    assert len(recon_tasks) == 1
    assert recon_tasks[0]["target"] == "example.com"
