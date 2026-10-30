from pathlib import Path
import ast
import re

ROOT = Path(__file__).resolve().parent
APP = ROOT / 'dashboard' / 'app.py'
HTML = ROOT / 'dashboard' / 'templates' / 'index.html'


def test_app_compiles():
    ast.parse(APP.read_text(encoding='utf-8'))


def test_html_has_all_sections():
    s = HTML.read_text(encoding='utf-8')
    for sec in ('scan','domains','hunters','findings','keys','knowledge','history','settings'):
        assert f'id="section-{sec}"' in s


def test_all_api_routes_have_frontend_references_or_are_get_only():
    app = APP.read_text(encoding='utf-8')
    html = HTML.read_text(encoding='utf-8')
    routes = re.findall(r'@app\.route\("([^"]+)"(?:,\s*methods=\[([^]]*)\])?', app)
    for path, methods in routes:
        if methods and 'POST' in methods:
            # POST endpoints must be invoked by the JS or be intentionally backend-only.
            if path.endswith('/report'):
                continue
            if path == '/api/findings/<finding_id>/verify':
                assert 'findings/${id}/verify' in html
            elif path == '/api/diffscan/reset':
                assert '/api/diffscan/reset' in html
            elif path.startswith('/api/knowledge/'):
                assert '/api/knowledge/${id}/' in html
            else:
                assert '/api/' + path[len('/api/'):] in html or path.replace('<finding_id>', '${id}') in html or path in html


def test_frontend_functions_and_ids():
    s = HTML.read_text(encoding='utf-8')
    for fn in ('startScan','stopScan','addDomain','removeDomain','saveProgramName','saveProgram','loadProgram',
               'toggleHunter','resetDiffScan','verifyFinding','updateSubmission','viewReport','saveGeminiKey',
               'saveSession','addKnowledge','deleteKnowledge','suggestPatterns','saveSettings'):
        assert re.search(rf'function\s+{fn}\s*\(', s), fn
    for el in ('http-timeout-input','findings-table','hunters-table','runs-table','logbox','summary-cards','kanban-cards'):
        assert f'id="{el}"' in s


def test_csrf_is_sent_by_frontend():
    s = HTML.read_text(encoding='utf-8')
    assert 'X-CSRF-Token' in s
    assert "meta[name=\"csrf-token\"]" in s


def test_dashboard_is_localhost_only():
    s = APP.read_text(encoding='utf-8')
    assert "app.run(host=\"127.0.0.1\", port=5000, debug=False)" in s


def test_settings_validation_present():
    s = APP.read_text(encoding='utf-8')
    assert 'requests_per_second باید بین 0.1 و 50 باشد' in s
    assert 'http_timeout_seconds باید بین 1 و 120 باشد' in s
