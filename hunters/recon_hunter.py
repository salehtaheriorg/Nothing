"""
hunters/recon_hunter.py

pipeline: subfinder -> [فیلتر scope] -> httpx (زنده‌بودن + تک‌فناوری) -> katana (کراول)

نکته‌ی مهم: subfinder می‌تونه ساب‌دامین‌هایی برگردونه که تکنیکاً به
root domain مربوطن ولی توی scope.json به‌صراحت out_of_scope علامت
خوردن (مثل blog.example.com). به همین خاطر خروجی subfinder همیشه از
scope.filter_list() رد می‌شه قبل از این‌که httpx/katana روش اجرا بشه.
"""

from __future__ import annotations
import os
import subprocess
import shutil
import requests
from urllib.parse import urljoin
from pathlib import Path

from core.logger import log
from core.scope import normalize_hostname
from hunters.base_hunter import BaseHunter


class ReconHunter(BaseHunter):
    name = "recon"

    def execute(self, target: str, payload: dict) -> dict:
        # Recon is host-level by design. If a queued task ever contains a URL
        # path (e.g. /robots.txt), collapse it to its hostname before invoking
        # subfinder/httpx/katana. This is the final defense against Recon loops.
        target = normalize_hostname(target)
        result = {"target": target, "subdomains": [], "live_hosts": [], "urls": []}
        if not target:
            return {**result, "warning": "Recon target hostname نامعتبر است"}

        if not shutil.which("subfinder"):
            return {**result, "warning": "subfinder نصب نیست - این محیط فقط برای توسعه‌ی کده"}

        # 1) subfinder برای پیدا کردن ساب‌دامین‌ها
        subdomains = self._run_subfinder(target)

        # 2) خود target اصلی هم باید بررسی شود. subfinder ممکن است هیچ
        # subdomainی پیدا نکند، اما این نباید باعث توقف Recon روی target اصلی شود.
        # target + خروجی subfinder سپس از ScopeGuard عبور می‌کنند.
        candidates = [target, *subdomains]
        candidates = list(dict.fromkeys(candidates))

        # فیلتر اجباری scope - قبل از هر اسکن بعدی
        in_scope_subdomains = self.scope.filter_list(candidates)
        result["subdomains"] = in_scope_subdomains

        if not in_scope_subdomains:
            return result

        # هر مرحله‌ی بعدی هم جدا چک می‌شه که باینریش نصب باشه.
        # پکیج Python به نام `httpx` نیز executable همنام می‌سازد و اگر
        # venv/bin قبل از ~/go/bin باشد، shutil.which به‌اشتباه همان را می‌دهد.
        # اینجا فقط باینری ProjectDiscovery را می‌پذیریم.
        httpx_bin = self._find_projectdiscovery_httpx()
        if not httpx_bin:
            return {**result, "warning": "ProjectDiscovery httpx نصب نیست یا executable اشتباه است"}
        log(f"[recon] httpx executable: {httpx_bin}")

        # 3) httpx برای چک زنده‌بودن
        live_hosts = self._run_httpx(in_scope_subdomains, httpx_bin)
        # حتی خروجی httpx هم دوباره فیلتر می‌شه - defense in depth
        result["live_hosts"] = self.scope.filter_list(live_hosts)

        # 4) katana برای کراول کردن URLها
        if result["live_hosts"]:
            if not shutil.which("katana"):
                return {**result, "warning": "katana نصب نیست - این محیط فقط برای توسعه‌ی کده"}
            urls = self._run_katana(result["live_hosts"])
            urls.extend(self._discover_well_known(result["live_hosts"]))
            result["urls"] = list(dict.fromkeys(self.scope.filter_list(urls)))

        return result

    @staticmethod
    def _run_subfinder(domain: str) -> list[str]:
        out = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=300,
        )
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]

    @staticmethod
    def _find_projectdiscovery_httpx() -> str | None:
        """فقط executable مربوط به ProjectDiscovery httpx را پیدا و validate می‌کند.

        ترتیب انتخاب:
        1) PROJECTDISCOVERY_HTTPX (برای override صریح)
        2) ~/go/bin/httpx (مسیر استاندارد `go install`)
        3) موارد موجود در PATH که واقعاً ProjectDiscovery باشند

        این تابع عمداً به صرف `shutil.which("httpx")` اعتماد نمی‌کند، چون
        پکیج Python `httpx` نیز executable همنام می‌سازد و می‌تواند داخل venv
        قرار بگیرد.
        """
        candidates: list[str] = []

        configured = os.environ.get("PROJECTDISCOVERY_HTTPX", "").strip()
        if configured:
            candidates.append(configured)

        # مسیر استاندارد نصب Go در Termux/Linux
        candidates.append(str(Path.home() / "go" / "bin" / "httpx"))

        # هر httpx دیگری که در PATH باشد؛ بعداً با probe حذف می‌شود اگر PD نباشد.
        path_httpx = shutil.which("httpx")
        if path_httpx:
            candidates.append(path_httpx)

        seen: set[str] = set()
        for candidate in candidates:
            candidate = os.path.expanduser(candidate)
            if candidate in seen:
                continue
            seen.add(candidate)
            resolved = shutil.which(candidate) if not os.path.isabs(candidate) else candidate
            if not resolved or not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
                continue

            try:
                probe = subprocess.run(
                    [resolved, "-version"],
                    capture_output=True, text=True, timeout=10,
                )
            except (OSError, subprocess.SubprocessError):
                continue

            probe_text = f"{probe.stdout}\n{probe.stderr}".lower()
            # امضای قابل اتکای ProjectDiscovery: لوگوی domain یا نسخه‌ی Current Version.
            if "projectdiscovery.io" in probe_text or "current version:" in probe_text:
                return resolved

        return None

    @staticmethod
    def _run_httpx(hosts: list[str], httpx_bin: str) -> list[str]:
        proc = subprocess.run(
            [httpx_bin, "-silent"],
            input="\n".join(hosts), capture_output=True, text=True, timeout=300,
        )
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]

    def _discover_well_known(self, hosts: list[str]) -> list[str]:
        """Lightweight deterministic discovery of robots.txt/sitemap URLs."""
        discovered = []
        for base in hosts:
            base = base.rstrip("/")
            for path in ("/robots.txt", "/sitemap.xml"):
                self.rate_limiter.wait()
                try:
                    resp = requests.get(base + path, timeout=10)
                except requests.RequestException:
                    continue
                if not (200 <= resp.status_code < 300):
                    continue
                discovered.append(base + path)
                if path == "/robots.txt":
                    for line in resp.text.splitlines():
                        if line.lower().startswith(("allow:", "sitemap:")):
                            value = line.split(":", 1)[1].strip()
                            if value.startswith(("http://", "https://")):
                                discovered.append(value)
                            elif value.startswith("/"):
                                discovered.append(urljoin(base, value))
        return discovered

    @staticmethod
    def _run_katana(hosts: list[str]) -> list[str]:
        proc = subprocess.run(
            ["katana", "-silent", "-jc"],
            input="\n".join(hosts), capture_output=True, text=True, timeout=600,
        )
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
