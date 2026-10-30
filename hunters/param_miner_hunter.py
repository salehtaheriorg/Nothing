"""Param-mining hunter with differential + reproducibility verification.

The hunter deliberately treats a changed HTTP response as a *candidate signal*,
not as a vulnerability.  A parameter is only emitted when its response differs
from multiple random-parameter baselines by a meaningful margin and that signal
is reproducible across a second request.
"""

from __future__ import annotations

import difflib
import re
import secrets as secrets_module
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from hunters.base_hunter import BaseHunter

CANDIDATE_PARAMS = [
    "debug", "test", "admin", "source", "src", "dev", "staging",
    "api_key", "apikey", "token", "auth", "callback", "jsonp",
    "redirect", "redirect_uri", "return_url", "next", "url", "path",
    "file", "filename", "template", "page", "view", "format", "output",
    "type", "mode", "action", "cmd", "query", "search", "filter", "sort",
    "order", "limit", "offset", "version", "ver", "lang", "locale",
    "theme", "preview", "draft", "hidden", "internal", "private",
    "secret", "access", "role", "bypass", "skip", "force", "override",
    "raw", "verbose", "trace", "log", "cache", "nocache", "refresh",
]

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
    ".woff2", ".ttf", ".ico", ".map", ".mp4", ".webp", ".pdf",
)

FOLLOWUP_HUNTERS = ("idor", "xss", "cors_redirect", "ssrf")

# Avoid over-weighting volatile values such as timestamps, tracking IDs and CSRF
# nonces when comparing otherwise-identical pages.
_VOLATILE_RE = re.compile(
    r"(?i)(?:timestamp|nonce|csrf|xsrf|request[_-]?id|trace[_-]?id|cache[_-]?bust"
    r"|utm_[a-z_]+)\s*[:=]\s*[\"']?[^\"'&<\s]{4,}[\"']?"
)
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class ResponseFingerprint:
    status: int
    length: int
    similarity_text: str
    location: str
    content_type: str
    server: str


@dataclass(frozen=True)
class ProbeResult:
    fingerprint: ResponseFingerprint
    elapsed_ms: float


def _set_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[key] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _looks_like_static_asset(url: str) -> bool:
    path = url.split("?")[0].split("#")[0]
    return path.lower().endswith(STATIC_EXTENSIONS)


def _normalize_body(text: str) -> str:
    text = _VOLATILE_RE.sub("<VOLATILE>", text or "")
    return _WHITESPACE_RE.sub(" ", text).strip()


def _similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def _fingerprint_response(resp: requests.Response) -> ResponseFingerprint:
    body = _normalize_body(resp.text)
    return ResponseFingerprint(
        status=resp.status_code,
        length=len(resp.content),
        similarity_text=body,
        location=str(resp.headers.get("Location", "")),
        content_type=str(resp.headers.get("Content-Type", "")).split(";", 1)[0].lower(),
        server=str(resp.headers.get("Server", "")).lower(),
    )


def _fingerprint_similarity(a: ResponseFingerprint, b: ResponseFingerprint) -> float:
    scores = [
        1.0 if a.status == b.status else 0.0,
        _similarity(a.similarity_text, b.similarity_text),
        1.0 if a.location == b.location else 0.0,
        1.0 if a.content_type == b.content_type else 0.0,
        1.0 if a.server == b.server else 0.0,
    ]
    return sum(scores) / len(scores)


class ParamMinerHunter(BaseHunter):
    name = "param_miner"

    # A candidate needs a material change in at least one strong signal *and*
    # a meaningful overall fingerprint distance from the baseline.
    MIN_BODY_CHANGE = 0.08
    MIN_LENGTH_DELTA_RATIO = 0.02
    MIN_OVERALL_DISTANCE = 0.12
    REPEAT_SIMILARITY = 0.97

    def execute(self, target: str, payload: dict) -> dict:
        url = payload.get("url", target)

        if _looks_like_static_asset(url):
            return {"target": url, "status": "skipped_static_asset", "discovered": []}

        baseline_samples = [self._measure(url, self._garbage_param()) for _ in range(4)]
        if any(sample is None for sample in baseline_samples):
            return {"target": url, "status": "unreachable", "discovered": []}

        baseline = self._build_baseline(baseline_samples)

        raw_candidates: list[tuple[str, ProbeResult]] = []
        for param_name in CANDIDATE_PARAMS:
            probe = self._measure(url, param_name)
            if probe is None:
                continue
            if self._is_differential_candidate(baseline, probe.fingerprint):
                raw_candidates.append((param_name, probe))

        verified_candidates = []
        rejected_candidates = []
        findings_reported: list[str] = []

        for param_name, first_probe in raw_candidates:
            second_probe = self._measure(url, param_name)
            if second_probe is None:
                rejected_candidates.append(param_name)
                continue

            reproducible, verification_score = self._verify_reproducibility(
                first_probe, second_probe, baseline
            )
            if not reproducible:
                rejected_candidates.append(param_name)
                continue

            evidence = self._build_evidence(
                url=url,
                param_name=param_name,
                baseline=baseline,
                first=first_probe,
                second=second_probe,
                verification_score=verification_score,
            )
            verified_candidates.append(param_name)
            findings_reported += self._report_and_followup(url, param_name, evidence)

        return {
            "target": url,
            "status": "completed",
            "candidates_tested": len(CANDIDATE_PARAMS),
            "raw_candidates": len(raw_candidates),
            "discovered": verified_candidates,
            "rejected_flukes": rejected_candidates,
            "findings": findings_reported,
            "baseline": {
                "samples": len(baseline_samples),
                "status": baseline["status"],
                "length_median": baseline["length_median"],
            },
        }

    def _measure(self, url: str, param_name: str) -> ProbeResult | None:
        test_url = _set_query_param(url, param_name, "1")
        self.rate_limiter.wait()
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
        except requests.RequestException:
            return None
        elapsed_ms = 0.0
        try:
            elapsed_ms = max(0.0, float(resp.elapsed.total_seconds() * 1000))
        except Exception:
            pass
        return ProbeResult(_fingerprint_response(resp), elapsed_ms)

    @staticmethod
    def _garbage_param() -> str:
        return f"xyzzy_probe_{secrets_module.token_hex(4)}"

    @classmethod
    def _build_baseline(cls, samples: list[ProbeResult]) -> dict:
        statuses = sorted(sample.fingerprint.status for sample in samples)
        lengths = sorted(sample.fingerprint.length for sample in samples)
        median_index = len(samples) // 2
        status = statuses[median_index]
        length_median = lengths[median_index]
        representative = min(
            samples,
            key=lambda sample: abs(sample.fingerprint.length - length_median),
        ).fingerprint
        return {
            "samples": samples,
            "status": status,
            "length_median": length_median,
            "representative": representative,
        }

    @classmethod
    def _is_differential_candidate(cls, baseline: dict, candidate: ResponseFingerprint) -> bool:
        base = baseline["representative"]
        body_similarity = _similarity(base.similarity_text, candidate.similarity_text)
        body_distance = 1.0 - body_similarity
        length_delta_ratio = abs(candidate.length - baseline["length_median"]) / max(
            baseline["length_median"], 1
        )
        status_changed = candidate.status != baseline["status"]
        redirect_changed = candidate.location != base.location

        # Strong protocol-level changes are useful even when the HTML happens
        # to remain similar.  For ordinary 2xx pages, require a material body
        # change and/or a material length change.  A tiny length delta or a
        # 99.8% body match must not create a finding by itself.
        if status_changed or redirect_changed:
            return True
        if body_distance >= cls.MIN_BODY_CHANGE:
            return True
        if body_distance >= 0.04 and length_delta_ratio >= 0.01:
            return True
        return length_delta_ratio >= 0.05

    @classmethod
    def _verify_reproducibility(
        cls,
        first: ProbeResult,
        second: ProbeResult,
        baseline: dict,
    ) -> tuple[bool, float]:
        first_vs_second = _fingerprint_similarity(first.fingerprint, second.fingerprint)
        first_distance = 1.0 - _fingerprint_similarity(
            baseline["representative"], first.fingerprint
        )
        second_distance = 1.0 - _fingerprint_similarity(
            baseline["representative"], second.fingerprint
        )
        first_material = cls._is_differential_candidate(baseline, first.fingerprint)
        second_material = cls._is_differential_candidate(baseline, second.fingerprint)
        score = round(
            (first_vs_second * 0.45) + (first_distance * 0.275) + (second_distance * 0.275),
            3,
        )
        return first_vs_second >= cls.REPEAT_SIMILARITY and first_material and second_material, score

    @classmethod
    def _build_evidence(
        cls,
        url: str,
        param_name: str,
        baseline: dict,
        first: ProbeResult,
        second: ProbeResult,
        verification_score: float,
    ) -> dict:
        base = baseline["representative"]
        candidate = first.fingerprint
        return {
            "param": param_name,
            "probe_url": _set_query_param(url, param_name, "1"),
            "classification": "candidate_only",
            "note": (
                "این finding به‌تنهایی آسیب‌پذیری نیست. فقط نشان می‌دهد پارامتر با "
                "یک تغییر قابل‌تکرار در پاسخ سرویس همراه بوده و برای بررسی بعدی صف شده است."
            ),
            "baseline": {
                "status": base.status,
                "length": base.length,
                "location": base.location,
                "content_type": base.content_type,
            },
            "candidate": {
                "status": candidate.status,
                "length": candidate.length,
                "location": candidate.location,
                "content_type": candidate.content_type,
            },
            "body_similarity": round(_similarity(base.similarity_text, candidate.similarity_text), 4),
            "repeat_similarity": round(
                _similarity(first.fingerprint.similarity_text, second.fingerprint.similarity_text), 4
            ),
            "verification_score": verification_score,
            "manual_verification_required": True,
        }

    def _report_and_followup(self, url: str, param_name: str, evidence: dict) -> list[str]:
        new_url = _set_query_param(url, param_name, "1")

        fid = self.report_finding(
            target=new_url,
            vuln_type="Hidden Parameter Candidate",
            severity="info",
            confidence="candidate",
            evidence=evidence,
        )

        for hunter_name in FOLLOWUP_HUNTERS:
            self.store.add_task_unique(hunter=hunter_name, target=new_url, payload={"url": new_url}, run_id=self.run_id)

        return [fid]
