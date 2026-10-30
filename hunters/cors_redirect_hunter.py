from __future__ import annotations
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from hunters.base_hunter import BaseHunter

REDIRECT_STATUS_CODES = {301,302,303,307,308}

def _set_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[key] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

class CorsRedirectHunter(BaseHunter):
    name = "cors_redirect"

    def execute(self, target: str, payload: dict) -> dict:
        url = payload.get("url", target)
        findings = self._check_cors(url)
        findings += self._check_open_redirect(url)
        return {"target": url, "findings": findings}

    def _check_cors(self, url: str) -> list[str]:
        results: list[str] = []
        token = secrets.token_hex(5)
        host = urlparse(url).hostname or ""
        cases = [
            (f"https://cors-poc-{token}.invalid", "arbitrary_origin_reflected"),
            ("null", "null_origin_trusted"),
            (f"https://{host}.{token}-evil.invalid", "prefix_match_bypass"),
        ]
        for origin, kind in cases:
            self.rate_limiter.wait()
            try:
                resp = requests.get(url, headers={"Origin": origin}, timeout=10)
            except requests.RequestException:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
            vary = resp.headers.get("Vary", "")
            # Reflected untrusted origin is a strong signal; wildcard without credentials remains a candidate.
            if acao == origin:
                conf = "confirmed" if acac else "candidate"
                sev = "high" if acac else "medium"
                results.append(self.report_finding(url, f"CORS Misconfiguration ({kind})", sev, {
                    "sent_origin": origin, "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac, "vary_header": vary,
                    "test_type": kind,
                }, conf))
            elif acao == "*":
                results.append(self.report_finding(url, f"CORS Misconfiguration ({kind})", "medium", {
                    "sent_origin": origin, "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac, "vary_header": vary,
                    "test_type": kind,
                    "manual_verification_required": True,
                    "note": "Wildcard ACAO does not by itself prove credentialed data exposure.",
                }, "candidate"))

            # Preserve the stronger preflight coverage from the previous implementation.
            if origin != "null":
                self.rate_limiter.wait()
                try:
                    pre = requests.options(url, headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "Authorization, Content-Type",
                    }, timeout=10)
                except requests.RequestException:
                    continue
                pre_acao = pre.headers.get("Access-Control-Allow-Origin", "").strip()
                pre_methods = pre.headers.get("Access-Control-Allow-Methods", "")
                if pre_acao == origin and "GET" in pre_methods.upper():
                    pre_acac = pre.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
                    results.append(self.report_finding(url, f"CORS Preflight Misconfiguration ({kind})", "high" if pre_acac else "medium", {
                        "sent_origin": origin, "preflight_status": pre.status_code,
                        "allow_origin": pre_acao, "allow_methods": pre_methods,
                        "allow_headers": pre.headers.get("Access-Control-Allow-Headers", ""),
                        "allow_credentials": pre_acac,
                    }, "confirmed" if pre_acac else "candidate"))
        return results

    def _check_open_redirect(self, url: str) -> list[str]:
        params = parse_qs(urlparse(url).query, keep_blank_values=True)
        if not params:
            return []
        marker = f"evil-{secrets.token_hex(6)}.invalid"
        payloads = [f"https://{marker}", f"//{marker}", f"/\\/\\{marker}"]
        results: list[str] = []
        for param in params:
            for value in payloads:
                test_url = _set_query_param(url, param, value)
                self.rate_limiter.wait()
                try:
                    # Critical: inspect the server's immediate redirect response; never follow it.
                    resp = requests.get(test_url, timeout=10, allow_redirects=False)
                except requests.RequestException:
                    continue
                if resp.status_code in REDIRECT_STATUS_CODES:
                    location = resp.headers.get("Location", "")
                    if marker in location:
                        results.append(self.report_finding(test_url, "Open Redirect", "medium", {
                            "param": param, "payload": value, "status": resp.status_code,
                            "location_header": location,
                        }, "confirmed"))
                        break
        return results
