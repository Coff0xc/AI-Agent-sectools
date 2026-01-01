"""Pure Python async port scanner - no external dependencies."""
import asyncio
import socket
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from ..base import BaseTool
from ..models import ToolResult, ToolStatus
from ...safety.models import Target


# Common service ports and their names
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb"
}

# Service banners for identification
SERVICE_BANNERS = {
    b"SSH-": "ssh", b"220 ": "ftp/smtp", b"HTTP/": "http",
    b"+OK": "pop3", b"* OK": "imap", b"MySQL": "mysql",
}


@dataclass
class PortResult:
    port: int
    state: str  # open, closed, filtered
    service: str
    banner: str = ""
    version: str = ""


class PortScanner(BaseTool):
    """Async TCP port scanner with service detection."""

    name = "port_scanner"
    description = "Fast async TCP port scanner with service/banner detection"
    category = "network"

    def __init__(self, timeout: float = 2.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = None

    async def execute(self, target: Target, params: Optional[Dict] = None) -> ToolResult:
        """Execute port scan on target."""
        params = params or {}
        ports = params.get("ports", list(COMMON_PORTS.keys()))
        grab_banner = params.get("grab_banner", True)

        # Parse target
        host = self._extract_host(target.value)

        # Initialize semaphore for concurrency control
        self.semaphore = asyncio.Semaphore(self.max_concurrent)

        # Scan ports
        results = await self._scan_ports(host, ports, grab_banner)

        # Parse results
        parsed = self._parse_results(host, results)

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            raw_output=str(results),
            parsed_data=parsed,
            execution_time=0.0
        )

    async def _scan_ports(self, host: str, ports: List[int], grab_banner: bool) -> List[PortResult]:
        """Scan multiple ports concurrently."""
        tasks = [self._scan_port(host, port, grab_banner) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, PortResult) and r.state == "open"]

    async def _scan_port(self, host: str, port: int, grab_banner: bool) -> PortResult:
        """Scan a single port."""
        async with self.semaphore:
            try:
                # Try to connect
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )

                service = COMMON_PORTS.get(port, "unknown")
                banner = ""
                version = ""

                # Grab banner if enabled
                if grab_banner:
                    try:
                        # Send probe for HTTP
                        if port in [80, 8080, 8000, 8888]:
                            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                        elif port == 443:
                            pass  # SSL handled separately
                        else:
                            writer.write(b"\r\n")

                        await writer.drain()
                        banner_data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                        banner = banner_data.decode('utf-8', errors='ignore').strip()[:200]

                        # Identify service from banner
                        for sig, svc in SERVICE_BANNERS.items():
                            if sig in banner_data:
                                service = svc
                                break

                        # Extract version info
                        version = self._extract_version(banner)
                    except:
                        pass

                writer.close()
                await writer.wait_closed()

                return PortResult(port=port, state="open", service=service, banner=banner, version=version)

            except asyncio.TimeoutError:
                return PortResult(port=port, state="filtered", service="")
            except ConnectionRefusedError:
                return PortResult(port=port, state="closed", service="")
            except Exception:
                return PortResult(port=port, state="filtered", service="")

    def _extract_host(self, target: str) -> str:
        """Extract hostname from target."""
        if target.startswith(("http://", "https://")):
            target = target.split("://")[1]
        return target.split("/")[0].split(":")[0]

    def _extract_version(self, banner: str) -> str:
        """Extract version info from banner."""
        import re
        patterns = [
            r'(\d+\.\d+\.\d+)',  # x.x.x
            r'(\d+\.\d+)',       # x.x
            r'Server: ([^\r\n]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        return ""

    def _parse_results(self, host: str, results: List[PortResult]) -> Dict[str, Any]:
        """Parse scan results into structured format."""
        findings = []
        open_ports = []
        services = {}

        for r in results:
            open_ports.append(r.port)
            services[r.port] = {
                "service": r.service,
                "banner": r.banner,
                "version": r.version
            }

            # Generate findings for interesting ports
            severity = "info"
            if r.port in [21, 23, 3389, 5900]:  # Risky services
                severity = "medium"
            elif r.port in [22, 3306, 5432, 6379, 27017]:  # Database/admin
                severity = "low"

            findings.append({
                "type": "open_port",
                "severity": severity,
                "port": r.port,
                "service": r.service,
                "description": f"Port {r.port}/{r.service} is open" + (f" ({r.version})" if r.version else ""),
                "banner": r.banner
            })

        return {
            "host": host,
            "open_ports": open_ports,
            "services": services,
            "total_open": len(open_ports),
            "findings": findings
        }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        return {"raw": raw_output}

    def validate_params(self, params: Dict) -> bool:
        return True
