"""Directory and file bruteforcer using httpx."""
import asyncio
import httpx
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from ..base import BaseTool
from ..models import ToolResult, ToolStatus
from ...safety.models import Target


# Common directories and files to check
COMMON_PATHS = [
    # Admin panels
    "admin", "administrator", "admin.php", "admin.html", "admin/login",
    "wp-admin", "wp-login.php", "phpmyadmin", "cpanel", "webmail",
    # Config files
    ".env", ".git/config", ".htaccess", "web.config", "config.php",
    "config.yml", "settings.py", "database.yml", ".svn/entries",
    # Backup files
    "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql",
    "backup.tar.gz", "site.zip", "www.zip",
    # Sensitive files
    "robots.txt", "sitemap.xml", ".DS_Store", "crossdomain.xml",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    # API endpoints
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger.json",
    "api-docs", "openapi.json", ".well-known/security.txt",
    # Common directories
    "uploads", "upload", "files", "images", "img", "static",
    "assets", "media", "tmp", "temp", "cache", "logs", "log",
    # CMS specific
    "wp-content", "wp-includes", "sites/default/files",
    "administrator/index.php", "user/login", "node",
    # Dev/Debug
    "debug", "test", "dev", "staging", "beta", "console",
    ".git", ".svn", ".hg", "CVS",
]

# Extensions to try
EXTENSIONS = ["", ".php", ".asp", ".aspx", ".jsp", ".html", ".txt", ".bak", ".old"]


@dataclass
class DirResult:
    path: str
    status: int
    size: int
    redirect: str = ""
    content_type: str = ""


class DirBruteforcer(BaseTool):
    """Async directory and file bruteforcer."""

    name = "dir_bruteforce"
    description = "Directory and file enumeration via HTTP requests"
    category = "web"

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 50):
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def execute(self, target: Target, params: Optional[Dict] = None) -> ToolResult:
        """Execute directory bruteforce on target."""
        params = params or {}
        wordlist = params.get("wordlist", COMMON_PATHS)
        extensions = params.get("extensions", [""])
        follow_redirects = params.get("follow_redirects", False)

        # Build URL
        base_url = self._normalize_url(target.value)

        # Generate paths to check
        paths = self._generate_paths(wordlist, extensions)

        # Scan paths
        results = await self._scan_paths(base_url, paths, follow_redirects)

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

    def _generate_paths(self, wordlist: List[str], extensions: List[str]) -> List[str]:
        """Generate paths with extensions."""
        paths = set()
        for word in wordlist:
            for ext in extensions:
                paths.add(f"/{word}{ext}")
        return list(paths)

    async def _scan_paths(self, base_url: str, paths: List[str], follow_redirects: bool) -> List[DirResult]:
        """Scan multiple paths concurrently."""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        results = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=follow_redirects,
            verify=False
        ) as client:
            tasks = [self._check_path(client, base_url, path, semaphore) for path in paths]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for r in responses:
                if isinstance(r, DirResult) and r.status not in [404, 0]:
                    results.append(r)

        return results

    async def _check_path(self, client: httpx.AsyncClient, base_url: str, path: str, semaphore: asyncio.Semaphore) -> DirResult:
        """Check a single path."""
        async with semaphore:
            url = f"{base_url}{path}"
            try:
                response = await client.get(url)
                redirect = ""
                if response.is_redirect:
                    redirect = response.headers.get("location", "")

                return DirResult(
                    path=path,
                    status=response.status_code,
                    size=len(response.content),
                    redirect=redirect,
                    content_type=response.headers.get("content-type", "")
                )
            except Exception:
                return DirResult(path=path, status=0, size=0)

    def _parse_results(self, base_url: str, results: List[DirResult]) -> Dict[str, Any]:
        """Parse scan results."""
        findings = []
        discovered = []

        for r in results:
            severity = "info"
            finding_type = "discovered_path"

            # Classify findings
            if r.status == 200:
                # Sensitive files
                if any(s in r.path.lower() for s in [".env", ".git", ".svn", "config", "backup", ".sql"]):
                    severity = "high"
                    finding_type = "sensitive_file"
                elif any(s in r.path.lower() for s in ["admin", "phpmyadmin", "cpanel", "login"]):
                    severity = "medium"
                    finding_type = "admin_panel"
                elif any(s in r.path.lower() for s in ["phpinfo", "debug", "test"]):
                    severity = "medium"
                    finding_type = "debug_endpoint"
                elif any(s in r.path.lower() for s in ["api", "swagger", "graphql"]):
                    severity = "low"
                    finding_type = "api_endpoint"

            elif r.status in [301, 302, 303, 307, 308]:
                severity = "info"
                finding_type = "redirect"

            elif r.status == 403:
                severity = "low"
                finding_type = "forbidden_path"

            elif r.status == 401:
                severity = "low"
                finding_type = "auth_required"

            discovered.append({
                "path": r.path,
                "url": f"{base_url}{r.path}",
                "status": r.status,
                "size": r.size,
                "content_type": r.content_type,
                "redirect": r.redirect
            })

            findings.append({
                "type": finding_type,
                "severity": severity,
                "path": r.path,
                "status": r.status,
                "description": f"Found {r.path} (HTTP {r.status}, {r.size} bytes)",
                "url": f"{base_url}{r.path}"
            })

        # Sort by severity
        severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

        return {
            "base_url": base_url,
            "total_found": len(results),
            "discovered": discovered,
            "findings": findings,
            "summary": {
                "sensitive_files": len([f for f in findings if f["type"] == "sensitive_file"]),
                "admin_panels": len([f for f in findings if f["type"] == "admin_panel"]),
                "api_endpoints": len([f for f in findings if f["type"] == "api_endpoint"]),
            }
        }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        return {"raw": raw_output}

    def validate_params(self, params: Dict) -> bool:
        return True
