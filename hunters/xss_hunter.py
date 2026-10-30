from __future__ import annotations
import html as html_lib
import re
import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from hunters.base_hunter import BaseHunter

STATIC_EXTENSIONS = ('.js','.css','.png','.jpg','.jpeg','.gif','.svg','.woff','.woff2','.ttf','.ico','.map','.mp4','.webp','.pdf')


def _set_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[key] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _set_path_segment(url: str, index: int, value: str) -> str:
    parsed = urlparse(url)
    parts = parsed.path.split('/')
    positions = [i for i, p in enumerate(parts) if p]
    if index >= len(positions):
        return url
    parts[positions[index]] = value
    return urlunparse(parsed._replace(path='/'.join(parts)))


def _payloads(marker: str) -> list[str]:
    return [
        f"<img src=x onerror=alert('{marker}')>",
        f"<svg onload=alert('{marker}')>",
        f"\"><img src=x onerror=alert('{marker}')>",
        f"'><svg onload=alert('{marker}')>",
    ]


class XSSHunter(BaseHunter):
    name = 'xss'

    def execute(self, target: str, payload: dict) -> dict:
        url = payload.get('url', target)
        parsed = urlparse(url)
        findings: list[str] = []
        tested: list[str] = []

        for param in parse_qs(parsed.query, keep_blank_values=True):
            tested.append(param)
            findings.extend(self._test_param(url, param))

        for idx, part in enumerate(p for p in parsed.path.split('/') if p):
            if len(part) < 2 or url.lower().split('?',1)[0].endswith(STATIC_EXTENSIONS):
                continue
            marker = f'XSSPATH_{secrets.token_hex(5)}'
            findings.extend(self._test_path(url, idx, marker))

        return {'target': url, 'params_tested': tested, 'findings': findings}

    def _test_param(self, url: str, param: str) -> list[str]:
        for payload_value in _payloads(secrets.token_hex(5)):
            marker = re.search(r"alert\('([^']+)'\)", payload_value).group(1)
            test_url = _set_query_param(url, param, payload_value)
            self.rate_limiter.wait()
            try:
                resp = requests.get(test_url, timeout=10, allow_redirects=False)
            except requests.RequestException:
                continue
            if payload_value not in resp.text:
                continue

            context = self._reflection_context(resp.text, payload_value)
            executable_context = self._looks_executable(context, payload_value)
            browser_confirmed = self._confirm_with_browser(test_url, marker) if executable_context else False
            confidence = 'confirmed' if browser_confirmed else 'candidate'
            severity = 'high' if browser_confirmed else 'medium'
            fid = self.report_finding(
                target=test_url,
                vuln_type='Reflected XSS',
                severity=severity,
                confidence=confidence,
                evidence={
                    'param': param,
                    'payload': payload_value,
                    'reflection_context': context,
                    'reflection_context_looks_executable': executable_context,
                    'browser_confirmed': browser_confirmed,
                    'manual_verification_required': not browser_confirmed,
                },
            )
            return [fid]
        return []

    def _test_path(self, original_url: str, idx: int, marker: str, probe_url: str | None = None) -> list[str]:
        test_url = probe_url or _set_path_segment(original_url, idx, marker)
        self.rate_limiter.wait()
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
        except requests.RequestException:
            return []
        if marker not in resp.text:
            return []
        context = self._reflection_context(resp.text, marker)
        fid = self.report_finding(
            target=original_url,
            vuln_type='Potential Reflected XSS (path)',
            severity='medium',
            confidence='candidate',
            evidence={
                'location': 'path',
                'segment_index': idx,
                'marker': marker,
                'probe_url': test_url,
                'reflection_context': context,
                'manual_verification_required': True,
            },
        )
        return [fid]

    @staticmethod
    def _reflection_context(text: str, needle: str, radius: int = 180) -> str:
        pos = text.find(needle)
        if pos < 0:
            return ''
        return text[max(0, pos-radius):pos+len(needle)+radius]

    @staticmethod
    def _looks_executable(context: str, payload: str) -> bool:
        if not context:
            return False  # بدون context نمی‌تونیم تشخیص بدیم — false positive بهتر از guess کوره
        if payload in context:
            return True
        # Avoid treating escaped HTML as executable reflection.
        escaped = html_lib.escape(payload, quote=True)
        return escaped not in context

    @staticmethod
    def _confirm_with_browser(url: str, marker: str) -> bool:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return False
        fired = {'ok': False}
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                def on_dialog(dialog):
                    if marker in dialog.message:
                        fired['ok'] = True
                    dialog.dismiss()
                page.on('dialog', on_dialog)
                page.goto(url, timeout=10000, wait_until='domcontentloaded')
                page.wait_for_timeout(800)
                browser.close()
        except Exception:
            return False
        return fired['ok']
