from __future__ import annotations
import json
import re
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from hunters.base_hunter import BaseHunter

METADATA_SIGNATURES = [
    ('AWS', re.compile(r'(?i)ami-id|instance-id|iam/security-credentials|local-ipv4')),
    ('GCP', re.compile(r'(?i)project-id|instance/zone|compute\.internal|Metadata-Flavor')),
    ('Azure', re.compile(r'(?i)azEnvironment|vmId|osType|subscriptionId')),
]

INTERNAL_PROBES = [
    ('aws_metadata', 'http://169.254.169.254/latest/meta-data/'),
    ('loopback', 'http://127.0.0.1/'),
    ('localhost', 'http://localhost/'),
]

def _set_query_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[key] = [value]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))

def _load_oob_domain(path: str = None) -> str:
    if path is None:
        path = str(Path(__file__).resolve().parent.parent / 'config' / 'settings.json')
    p = Path(path)
    if not p.exists():
        return ''
    try:
        return str(json.loads(p.read_text(encoding='utf-8')).get('ssrf_oob_domain') or '').strip()
    except Exception:
        return ''

class SSRFHunter(BaseHunter):
    name = 'ssrf'
    def __init__(self, *args, settings_file: str = 'config/settings.json', **kwargs):
        super().__init__(*args, **kwargs)
        self.oob_domain = _load_oob_domain(settings_file)

    def execute(self, target: str, payload: dict) -> dict:
        url = payload.get('url', target)
        params = parse_qs(urlparse(url).query, keep_blank_values=True)
        if not params:
            return {'target': url, 'status': 'no_params', 'findings': []}
        findings: list[str] = []
        oob_probes: list[dict] = []
        for param in params:
            findings.extend(self._test_param(url, param))
            if self.oob_domain:
                token = secrets.token_hex(6)
                probe = f'https://{token}.{self.oob_domain}/'
                test_url = _set_query_param(url, param, probe)
                self.rate_limiter.wait()
                try:
                    requests.get(test_url, timeout=8, allow_redirects=False)
                except requests.RequestException:
                    pass
                oob_probes.append({'param': param, 'token': token, 'probe_url': probe, 'request_url': test_url})
                # این نسخه قبلاً اینجا هیچ finding ای ثبت نمی‌کرد -- فقط
                # توی result خام (که هیچ‌جای داشبورد نمایش داده نمی‌شه،
                # نه توی تب Findings نه توی گزارش‌ها نه توی شمارش severity)
                # می‌موند. یعنی عملاً بعد از این تسک، هیچ ردی از این‌که
                # اصلاً یه پروب OOB فرستاده شده، جایی که کاربر واقعاً نگاه
                # می‌کنه دیده نمی‌شد -- باید دستی می‌رفت تو دیتابیس خام
                # tasks.db رو می‌گشت. این با تست مستقیم پیدا شد.
                #
                # فیکس: مثل قبل، یه finding با confidence=candidate ثبت
                # می‌شه (نه confirmed -- چون خودِ ابزار نمی‌تونه callback
                # رو تأیید کنه) تا حداقل توی تب Findings و گزارش‌ها قابل
                # پیگیریه، دقیقاً مثل بقیه‌ی findingهای این پروژه.
                fid = self.report_finding(
                    target=test_url,
                    vuln_type='SSRF (candidate - نیاز به تأیید OOB)',
                    severity='high',
                    confidence='candidate',
                    evidence={
                        'param': param,
                        'oob_token': token,
                        'probe_url': probe,
                        'note': 'این یه پروب OOB blind SSRF است -- ابزار خودش نمی‌تونه callback رو ببینه. برای تأیید، باید دستی داشبورد سرویس OOB خودت (مثلاً interactsh) رو برای توکن بالا چک کنی.',
                    },
                )
                findings.append(fid)
        result = {'target': url, 'params_tested': list(params), 'findings': findings}
        if oob_probes:
            result['oob_probes'] = oob_probes
            result['note'] = 'OOB probes are telemetry only; no finding is created until an external callback is observed.'
        else:
            result['note'] = 'No OOB domain configured; only reflected/internal SSRF signals are checked.'
        return result

    def _test_param(self, url: str, param: str) -> list[str]:
        for label, probe in INTERNAL_PROBES:
            test_url = _set_query_param(url, param, probe)
            self.rate_limiter.wait()
            try:
                resp = requests.get(test_url, timeout=8, allow_redirects=False)
            except requests.RequestException:
                continue
            text = resp.text[:200000]
            for cloud, signature in METADATA_SIGNATURES:
                if signature.search(text):
                    fid = self.report_finding(
                        target=test_url,
                        vuln_type=f'SSRF (reflected internal fetch - {cloud})',
                        severity='critical',
                        confidence='confirmed',
                        evidence={
                            'param': param,
                            'probe_target': probe,
                            'matched_cloud_provider': cloud,
                            'response_status': resp.status_code,
                            'response_length': len(resp.content),
                            'manual_verification_required': False,
                        },
                    )
                    return [fid]
        return []
