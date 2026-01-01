"""Web directory and file scanner."""
import asyncio
import httpx
from typing import List, Dict, Any, Optional

COMMON_PATHS = [
    "admin", "login", "wp-admin", "wp-login.php", "phpmyadmin",
    ".env", ".git/config", ".htaccess", "robots.txt", "sitemap.xml",
    "backup", "backup.zip", "backup.sql", "db.sql",
    "api", "api/v1", "swagger", "graphql", "swagger.json",
    "uploads", "static", "assets", "images", "files",
    "config.php", "config.yml", "settings.py", "web.config",
    "phpinfo.php", "test.php", "debug", "console",
    ".git", ".svn", ".DS_Store", "crossdomain.xml",
]


class WebScanner:
    """Web directory and file bruteforcer."""

    def __init__(self, timeout: float = 10.0, concurrency: int = 50):
        self.timeout = timeout
        self.concurrency = concurrency

    async def scan(self, url: str, paths: List[str] = None, extensions: List[str] = None) -> Dict[str, Any]:
        """Scan for directories and files."""
        url = url.rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        paths = paths or COMMON_PATHS
        extensions = extensions or [""]

        # Generate all paths
        all_paths = set()
        for p in paths:
            for ext in extensions:
                all_paths.add(f"/{p}{ext}")

        sem = asyncio.Semaphore(self.concurrency)
        results = []

        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=False) as client:
            tasks = [self._check_path(client, url, p, sem) for p in all_paths]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for r in responses:
                if isinstance(r, dict) and r.get("status") not in [404, 0]:
                    results.append(r)

        # Classify findings
        findings = []
        for r in results:
            severity = "info"
            ftype = "path"

            if r["status"] == 200:
                if any(s in r["path"].lower() for s in [".env", ".git", "config", "backup", ".sql"]):
                    severity, ftype = "high", "sensitive"
                elif any(s in r["path"].lower() for s in ["admin", "phpmyadmin", "login"]):
                    severity, ftype = "medium", "admin"
                elif any(s in r["path"].lower() for s in ["phpinfo", "debug", "test"]):
                    severity, ftype = "medium", "debug"
                elif any(s in r["path"].lower() for s in ["api", "swagger", "graphql"]):
                    severity, ftype = "low", "api"

            findings.append({**r, "severity": severity, "type": ftype})

        findings.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2, "info": 3}[x["severity"]])

        return {
            "url": url,
            "findings": findings,
            "total": len(findings),
            "summary": {
                "sensitive": len([f for f in findings if f["type"] == "sensitive"]),
                "admin": len([f for f in findings if f["type"] == "admin"]),
                "api": len([f for f in findings if f["type"] == "api"]),
            }
        }

    async def _check_path(self, client: httpx.AsyncClient, base: str, path: str, sem: asyncio.Semaphore) -> Dict:
        async with sem:
            try:
                r = await client.get(f"{base}{path}")
                return {
                    "path": path,
                    "url": f"{base}{path}",
                    "status": r.status_code,
                    "size": len(r.content),
                    "content_type": r.headers.get("content-type", "")
                }
            except:
                return {"path": path, "status": 0, "size": 0}
