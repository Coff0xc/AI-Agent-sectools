"""DNS subdomain enumeration."""
import asyncio
import dns.asyncresolver
from typing import List, Dict, Any, Set

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "mx", "blog", "dev", "staging", "test", "api", "app",
    "admin", "portal", "secure", "vpn", "remote", "m", "mobile",
    "shop", "cdn", "static", "assets", "img", "media", "beta",
    "db", "mysql", "postgres", "redis", "mongo", "elastic",
    "git", "gitlab", "jenkins", "ci", "build", "deploy",
    "docs", "help", "support", "status", "monitor", "grafana",
    "auth", "login", "sso", "oauth", "id", "accounts",
    "internal", "intranet", "corp", "office", "backup", "old",
    "web", "server", "node", "cloud", "aws", "s3", "storage",
    "proxy", "gateway", "lb", "cache", "exchange", "owa",
]


class SubdomainScanner:
    """DNS subdomain enumeration."""

    def __init__(self, timeout: float = 3.0, concurrency: int = 50):
        self.timeout = timeout
        self.concurrency = concurrency

    async def scan(self, domain: str, wordlist: List[str] = None) -> Dict[str, Any]:
        """Enumerate subdomains."""
        # Clean domain
        if domain.startswith(("http://", "https://")):
            domain = domain.split("://")[1]
        domain = domain.split("/")[0].split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        wordlist = wordlist or COMMON_SUBDOMAINS
        sem = asyncio.Semaphore(self.concurrency)

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        tasks = [self._check_subdomain(resolver, f"{sub}.{domain}", sem) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found = [r for r in results if isinstance(r, dict) and r.get("exists")]
        unique_ips: Set[str] = set()
        for r in found:
            unique_ips.update(r.get("ips", []))

        # Classify
        findings = []
        for r in found:
            sub = r["subdomain"].lower()
            severity, ftype = "info", "subdomain"

            if any(s in sub for s in ["admin", "internal", "intranet", "corp"]):
                severity, ftype = "medium", "internal"
            elif any(s in sub for s in ["dev", "staging", "test", "uat"]):
                severity, ftype = "low", "dev"
            elif any(s in sub for s in ["db", "mysql", "postgres", "redis", "mongo"]):
                severity, ftype = "medium", "database"
            elif any(s in sub for s in ["backup", "bak", "old"]):
                severity, ftype = "medium", "backup"

            findings.append({**r, "severity": severity, "type": ftype})

        return {
            "domain": domain,
            "subdomains": found,
            "unique_ips": list(unique_ips),
            "total": len(found),
            "findings": findings
        }

    async def _check_subdomain(self, resolver, subdomain: str, sem: asyncio.Semaphore) -> Dict:
        async with sem:
            result = {"subdomain": subdomain, "exists": False, "ips": [], "cname": None}

            try:
                answers = await resolver.resolve(subdomain, 'A')
                result["exists"] = True
                result["ips"] = [str(r) for r in answers]
            except dns.resolver.NXDOMAIN:
                return result
            except:
                pass

            if not result["ips"]:
                try:
                    answers = await resolver.resolve(subdomain, 'CNAME')
                    result["exists"] = True
                    result["cname"] = str(answers[0].target)
                except:
                    pass

            return result
