"""Subdomain enumeration tool."""
import asyncio
import socket
import dns.resolver
import dns.asyncresolver
from typing import List, Dict, Any, Optional, Set
from ..base import BaseTool
from ..models import ToolResult, ToolStatus
from ...safety.models import Target


# Common subdomain prefixes
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "staging", "test",
    "api", "app", "admin", "portal", "secure", "vpn", "remote", "m", "mobile",
    "shop", "store", "cdn", "static", "assets", "img", "images", "media",
    "beta", "alpha", "demo", "sandbox", "uat", "qa", "prod", "production",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy",
    "docs", "doc", "help", "support", "status", "monitor", "grafana", "kibana",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts",
    "internal", "intranet", "extranet", "corp", "corporate", "office",
    "backup", "bak", "old", "new", "v1", "v2", "api-v1", "api-v2",
    "web", "web1", "web2", "server", "server1", "server2", "node", "node1",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "files", "upload",
    "proxy", "gateway", "lb", "loadbalancer", "cache", "varnish", "nginx",
    "exchange", "autodiscover", "owa", "outlook", "calendar", "contacts",
    "crm", "erp", "hr", "finance", "sales", "marketing", "analytics",
]


class SubdomainEnumerator(BaseTool):
    """Async subdomain enumeration via DNS."""

    name = "subdomain_enum"
    description = "Subdomain enumeration via DNS resolution"
    category = "recon"

    def __init__(self, timeout: float = 3.0, max_concurrent: int = 50):
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def execute(self, target: Target, params: Optional[Dict] = None) -> ToolResult:
        """Execute subdomain enumeration."""
        params = params or {}
        wordlist = params.get("wordlist", COMMON_SUBDOMAINS)
        resolve_ips = params.get("resolve_ips", True)

        # Extract domain
        domain = self._extract_domain(target.value)

        # Enumerate subdomains
        results = await self._enumerate_subdomains(domain, wordlist, resolve_ips)

        # Parse results
        parsed = self._parse_results(domain, results)

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            raw_output=str(results),
            parsed_data=parsed,
            execution_time=0.0
        )

    def _extract_domain(self, target: str) -> str:
        """Extract base domain from target."""
        if target.startswith(("http://", "https://")):
            target = target.split("://")[1]
        target = target.split("/")[0].split(":")[0]

        # Remove www prefix
        if target.startswith("www."):
            target = target[4:]

        return target

    async def _enumerate_subdomains(self, domain: str, wordlist: List[str], resolve_ips: bool) -> List[Dict]:
        """Enumerate subdomains concurrently."""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        results = []

        # Create async resolver
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        tasks = [
            self._check_subdomain(resolver, f"{sub}.{domain}", semaphore, resolve_ips)
            for sub in wordlist
        ]

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for r in responses:
            if isinstance(r, dict) and r.get("exists"):
                results.append(r)

        return results

    async def _check_subdomain(self, resolver, subdomain: str, semaphore: asyncio.Semaphore, resolve_ips: bool) -> Dict:
        """Check if subdomain exists."""
        async with semaphore:
            result = {"subdomain": subdomain, "exists": False, "ips": [], "cname": None}

            try:
                # Try A record
                answers = await resolver.resolve(subdomain, 'A')
                result["exists"] = True
                result["ips"] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                return result
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                pass

            # Try CNAME if no A record
            if not result["ips"]:
                try:
                    answers = await resolver.resolve(subdomain, 'CNAME')
                    result["exists"] = True
                    result["cname"] = str(answers[0].target)
                except:
                    pass

            return result

    def _parse_results(self, domain: str, results: List[Dict]) -> Dict[str, Any]:
        """Parse enumeration results."""
        findings = []
        subdomains = []
        unique_ips: Set[str] = set()

        for r in results:
            subdomains.append({
                "subdomain": r["subdomain"],
                "ips": r["ips"],
                "cname": r["cname"]
            })

            unique_ips.update(r["ips"])

            # Classify findings
            severity = "info"
            finding_type = "subdomain"

            sub_lower = r["subdomain"].lower()
            if any(s in sub_lower for s in ["admin", "internal", "intranet", "corp"]):
                severity = "medium"
                finding_type = "internal_subdomain"
            elif any(s in sub_lower for s in ["dev", "staging", "test", "uat", "qa"]):
                severity = "low"
                finding_type = "dev_subdomain"
            elif any(s in sub_lower for s in ["api", "gateway", "auth"]):
                severity = "low"
                finding_type = "api_subdomain"
            elif any(s in sub_lower for s in ["db", "mysql", "postgres", "redis", "mongo"]):
                severity = "medium"
                finding_type = "database_subdomain"
            elif any(s in sub_lower for s in ["backup", "bak", "old"]):
                severity = "medium"
                finding_type = "backup_subdomain"

            findings.append({
                "type": finding_type,
                "severity": severity,
                "subdomain": r["subdomain"],
                "ips": r["ips"],
                "description": f"Found subdomain: {r['subdomain']}" + (f" -> {', '.join(r['ips'])}" if r['ips'] else "")
            })

        return {
            "domain": domain,
            "total_found": len(results),
            "unique_ips": list(unique_ips),
            "subdomains": subdomains,
            "findings": findings,
            "summary": {
                "total_subdomains": len(subdomains),
                "unique_ips": len(unique_ips),
                "internal": len([f for f in findings if f["type"] == "internal_subdomain"]),
                "dev_staging": len([f for f in findings if f["type"] == "dev_subdomain"]),
            }
        }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        return {"raw": raw_output}

    def validate_params(self, params: Dict) -> bool:
        return True
