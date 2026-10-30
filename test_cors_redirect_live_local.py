from __future__ import annotations
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from tempfile import TemporaryDirectory
from hunters.cors_redirect_hunter import CorsRedirectHunter
from core.scope import ScopeGuard
from core.task_store import TaskStore
from core.findings_store import FindingsStore
from core.rate_limiter import RateLimiter

class Handler(BaseHTTPRequestHandler):
    vulnerable_cors = False
    vulnerable_redirect = False
    def do_OPTIONS(self):
        if self.vulnerable_cors:
            origin = self.headers.get('Origin','')
            self.send_response(204)
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
            self.send_header('Access-Control-Allow-Credentials', 'true')
        else:
            self.send_response(204)
        self.end_headers()
    def do_GET(self):
        p=urlparse(self.path); q=parse_qs(p.query)
        if self.vulnerable_redirect and p.path == '/redirect' and 'url' in q:
            self.send_response(302); self.send_header('Location', q['url'][0]); self.end_headers(); return
        self.send_response(200)
        if self.vulnerable_cors:
            origin=self.headers.get('Origin','')
            if origin:
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Access-Control-Allow-Credentials','true')
        self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *args): pass

def make_hunter(td, host):
    scope_file=Path(td)/'scope.json'
    scope_file.write_text(json.dumps({'program_name':'local','in_scope':[host],'out_of_scope':[]}))
    return CorsRedirectHunter(ScopeGuard(scope_file), TaskStore(Path(td)/'tasks.db'), FindingsStore(Path(td)/'findings.db'), RateLimiter(1000))

def run(vcors, vredir):
    Handler.vulnerable_cors=vcors; Handler.vulnerable_redirect=vredir
    srv=ThreadingHTTPServer(('127.0.0.1',0), Handler); t=threading.Thread(target=srv.serve_forever,daemon=True); t.start()
    host=f'127.0.0.1:{srv.server_address[1]}'
    with TemporaryDirectory() as td:
        h=make_hunter(td, host)
        cors_url=f'http://{host}/api'
        redir_url=f'http://{host}/redirect?url=https%3A%2F%2Fexample.com'
        # Only call the relevant checker for deterministic local tests.
        cors=h._check_cors(cors_url)
        redir=h._check_open_redirect(redir_url)
        findings=h.findings.all_findings()
    srv.shutdown(); srv.server_close()
    return cors,redir,findings

# Positive vulnerable server: must detect both families.
cors_p, redir_p, f_p = run(True, True)
assert cors_p, 'positive CORS was not detected'
assert any('Preflight' in f['vuln_type'] for f in f_p), 'positive preflight was not detected'
assert redir_p, 'positive open redirect was not detected'
assert any(f['vuln_type']=='Open Redirect' for f in f_p), 'redirect finding missing'

# Negative server: must not report either vulnerability.
cors_n, redir_n, f_n = run(False, False)
assert cors_n == [], f'negative CORS produced findings: {f_n}'
assert redir_n == [], f'negative redirect produced findings: {f_n}'
print('LOCAL POSITIVE: PASS — CORS + Preflight + Open Redirect detected')
print('LOCAL NEGATIVE: PASS — no CORS/redirect findings')
