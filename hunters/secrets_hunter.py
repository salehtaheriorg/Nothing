from __future__ import annotations
import math
import re
from collections import Counter
from urllib.parse import urlparse

import requests

from hunters.base_hunter import BaseHunter

SECRET_PATTERNS = [
    ('AWS Access Key ID', re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'critical'),
    ('Google API Key', re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), 'high'),
    ('Slack Token', re.compile(r'\bxox[baprs]-[0-9A-Za-z-]{10,48}\b'), 'high'),
    ('Stripe Live Secret Key', re.compile(r'\bsk_live_[0-9A-Za-z]{24,}\b'), 'critical'),
    ('GitHub Token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'), 'critical'),
    ('Private Key Block', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 'critical'),
    ('SendGrid API Key', re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b'), 'high'),
    ('npm Token', re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'), 'critical'),
    ('JWT Token', re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'), 'low'),
    ('Generic API Key Assignment', re.compile(r'(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{16,128})["\']'), 'medium'),
]
TEXT_EXTENSIONS = ('.js','.json','.map','.txt','.xml','.yml','.yaml','.env','.config','.html','.htm')
PLACEHOLDERS = {'changeme','change_me','example','example_key','your_api_key','your-key','test','testing','placeholder','dummy','sample','null','undefined','none'}

def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return '*' * len(value)
    return value[:4] + '*' * max(4, len(value)-8) + value[-4:]

def entropy(value: str) -> float:
    if not value: return 0.0
    counts = Counter(value); n = len(value)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def looks_placeholder(value: str) -> bool:
    x = value.strip().lower()
    return x in PLACEHOLDERS or x.startswith(('your_','your-','replace_','replace-','example_'))

def redact_all_secrets(text: str) -> str:
    """کل SECRET_PATTERNS رو روی یه تکه‌متن (مثلاً context یه finding دیگه)
    دوباره اجرا می‌کنه و هر secret ای که پیدا کنه رو [REDACTED] می‌کنه.

    قبلاً context_redacted هر finding فقط secret خودش رو redact می‌کرد --
    اگه دو تا secret متفاوت نزدیک هم توی فایل بودن (خیلی رایجه، مثلاً یه
    آبجکت config با چند تا کلید)، context هرکدوم secret اون یکی رو کامل
    و بدون redact نشون می‌داد. این با تست مستقیم (AWS key + Stripe key
    کنار هم) پیدا شد.
    """
    for _name, pattern, _severity in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if val:
                text = text.replace(val, '[REDACTED]')
    return text


class SecretsHunter(BaseHunter):
    name = 'secrets'
    def execute(self, target: str, payload: dict) -> dict:
        url = payload.get('url', target)
        if not self._looks_textual(url):
            return {'target': url, 'status': 'skipped_non_text_extension', 'findings': []}
        self.rate_limiter.wait()
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False)
        except requests.RequestException:
            return {'target': url, 'status': 'unreachable', 'findings': []}
        ct = resp.headers.get('Content-Type','').lower()
        if resp.status_code >= 400:
            return {'target': url, 'status': f'http_{resp.status_code}', 'findings': []}
        if not any(x in ct for x in ('text/','javascript','json','xml')) and not self._looks_textual(url):
            return {'target': url, 'status': 'skipped_binary', 'findings': []}

        body = resp.text
        findings: list[str] = []
        seen: set[tuple[str,str,int]] = set()
        for name, pattern, severity in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                captured = match.group(1) if match.lastindex else match.group(0)
                if looks_placeholder(captured):
                    continue
                if name == 'Generic API Key Assignment' and entropy(captured) < 3.2:
                    continue
                key = (name, captured, match.start())
                if key in seen: continue
                seen.add(key)
                context = body[max(0, match.start()-60):match.end()+80]
                fid = self.report_finding(
                    target=url,
                    vuln_type=f'Exposed Secret ({name})',
                    severity=severity,
                    confidence='candidate',
                    evidence={
                        'pattern': name,
                        'masked_value': mask_secret(captured),
                        'context_redacted': redact_all_secrets(context),
                        'entropy': round(entropy(captured), 3),
                        'manual_verification_required': True,
                    },
                )
                findings.append(fid)
        return {'target': url, 'findings': findings, 'checked_patterns': len(SECRET_PATTERNS)}

    @staticmethod
    def _looks_textual(url: str) -> bool:
        path = urlparse(url).path.lower()
        return path.endswith(TEXT_EXTENSIONS) or '.' not in path.rsplit('/',1)[-1]
