"""Async TCP port scanner."""
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb"
}

SERVICE_BANNERS = {
    b"SSH-": "ssh", b"220 ": "ftp/smtp", b"HTTP/": "http",
    b"+OK": "pop3", b"* OK": "imap", b"MySQL": "mysql",
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str = ""


class PortScanner:
    """Async TCP port scanner with banner grabbing."""

    def __init__(self, timeout: float = 2.0, concurrency: int = 100):
        self.timeout = timeout
        self.concurrency = concurrency

    async def scan(self, host: str, ports: List[int] = None, grab_banner: bool = True) -> Dict[str, Any]:
        """Scan ports on target host."""
        ports = ports or list(COMMON_PORTS.keys())
        sem = asyncio.Semaphore(self.concurrency)

        tasks = [self._scan_port(host, p, grab_banner, sem) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = [r for r in results if isinstance(r, PortResult) and r.state == "open"]

        return {
            "host": host,
            "open_ports": [{"port": p.port, "service": p.service, "banner": p.banner} for p in open_ports],
            "total_open": len(open_ports),
            "scanned": len(ports)
        }

    async def _scan_port(self, host: str, port: int, grab_banner: bool, sem: asyncio.Semaphore) -> PortResult:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )

                service = COMMON_PORTS.get(port, "unknown")
                banner = ""

                if grab_banner:
                    try:
                        if port in [80, 8080, 8000]:
                            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                        else:
                            writer.write(b"\r\n")
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(512), timeout=2.0)
                        banner = data.decode('utf-8', errors='ignore').strip()[:200]

                        for sig, svc in SERVICE_BANNERS.items():
                            if sig in data:
                                service = svc
                                break
                    except:
                        pass

                writer.close()
                await writer.wait_closed()
                return PortResult(port, "open", service, banner)

            except asyncio.TimeoutError:
                return PortResult(port, "filtered", "")
            except ConnectionRefusedError:
                return PortResult(port, "closed", "")
            except:
                return PortResult(port, "error", "")
