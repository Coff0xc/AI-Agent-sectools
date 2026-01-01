"""MCP Security Scanner Server - Pure MCP-based penetration testing toolkit."""
import json
import asyncio
import logging
from mcp.server.stdio import stdio_server
from mcp.server import Server
from mcp.types import Tool, TextContent
from .auth import AuthManager


class SecurityMCPServer:
    """MCP Server for security scanning tools."""

    def __init__(self):
        self.server = Server("security-scanner")
        self.auth = AuthManager()
        self.logger = logging.getLogger(__name__)
        self._register_tools()

    def _register_tools(self):
        """Register all MCP tools."""

        @self.server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="scan_ports",
                    description="TCP port scan with service detection and banner grabbing",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target IP or hostname"},
                            "ports": {"type": "array", "items": {"type": "integer"}, "description": "Ports to scan (default: common ports)"},
                            "grab_banner": {"type": "boolean", "default": True, "description": "Grab service banners"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="scan_web",
                    description="Web directory and file enumeration",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target URL"},
                            "paths": {"type": "array", "items": {"type": "string"}, "description": "Custom paths to check"},
                            "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="scan_subdomains",
                    description="DNS subdomain enumeration",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target domain"},
                            "wordlist": {"type": "array", "items": {"type": "string"}, "description": "Custom subdomain wordlist"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="scan_ssl",
                    description="SSL/TLS certificate and configuration analysis",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target domain or URL"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="scan_vulns",
                    description="Web vulnerability scan (SQLi, XSS, LFI, SSRF)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target URL"},
                            "scan_types": {"type": "array", "items": {"type": "string", "enum": ["sqli", "xss", "lfi", "ssrf"]}, "description": "Vulnerability types"},
                            "params": {"type": "array", "items": {"type": "string"}, "description": "Parameters to test"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="full_scan",
                    description="Full reconnaissance: subdomains + ports + web + SSL + vulns",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target domain"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="add_target",
                    description="Add target to whitelist for scanning",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Domain or IP pattern to whitelist"}
                        },
                        "required": ["target"]
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict):
            try:
                target = arguments.get("target", "")

                # Authorization check (except for add_target)
                if name != "add_target" and not self.auth.is_authorized(self._extract_domain(target)):
                    return [TextContent(type="text", text=json.dumps({
                        "success": False,
                        "error": f"Target '{target}' not authorized. Use add_target to whitelist it first."
                    }, indent=2))]

                # Route to handler
                if name == "scan_ports":
                    result = await self._scan_ports(**arguments)
                elif name == "scan_web":
                    result = await self._scan_web(**arguments)
                elif name == "scan_subdomains":
                    result = await self._scan_subdomains(**arguments)
                elif name == "scan_ssl":
                    result = await self._scan_ssl(**arguments)
                elif name == "scan_vulns":
                    result = await self._scan_vulns(**arguments)
                elif name == "full_scan":
                    result = await self._full_scan(**arguments)
                elif name == "add_target":
                    result = self._add_target(**arguments)
                else:
                    result = {"success": False, "error": f"Unknown tool: {name}"}

                self.auth.log_audit(name, target, "success" if result.get("success", True) else "failed")
                return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

            except Exception as e:
                self.logger.error(f"Tool error: {e}", exc_info=True)
                return [TextContent(type="text", text=json.dumps({"success": False, "error": str(e)}))]

    def _extract_domain(self, target: str) -> str:
        """Extract domain from target."""
        if target.startswith(("http://", "https://")):
            target = target.split("://")[1]
        return target.split("/")[0].split(":")[0]

    async def _scan_ports(self, target: str, ports: list = None, grab_banner: bool = True) -> dict:
        from ..scanner import PortScanner
        scanner = PortScanner()
        result = await scanner.scan(target, ports, grab_banner)
        return {"success": True, **result}

    async def _scan_web(self, target: str, paths: list = None, extensions: list = None) -> dict:
        from ..scanner import WebScanner
        scanner = WebScanner()
        result = await scanner.scan(target, paths, extensions)
        return {"success": True, **result}

    async def _scan_subdomains(self, target: str, wordlist: list = None) -> dict:
        from ..scanner import SubdomainScanner
        scanner = SubdomainScanner()
        result = await scanner.scan(target, wordlist)
        return {"success": True, **result}

    async def _scan_ssl(self, target: str) -> dict:
        from ..scanner import SSLScanner
        scanner = SSLScanner()
        result = scanner.scan(target)
        return {"success": True, **result}

    async def _scan_vulns(self, target: str, scan_types: list = None, params: list = None) -> dict:
        from ..scanner import VulnScanner
        scanner = VulnScanner()
        result = await scanner.scan(target, scan_types, params)
        return {"success": True, **result}

    async def _full_scan(self, target: str) -> dict:
        """Run full reconnaissance."""
        domain = self._extract_domain(target)
        results = {"target": domain, "phases": {}}

        # Subdomains
        try:
            results["phases"]["subdomains"] = await self._scan_subdomains(domain)
        except Exception as e:
            results["phases"]["subdomains"] = {"error": str(e)}

        # Ports
        try:
            results["phases"]["ports"] = await self._scan_ports(domain)
        except Exception as e:
            results["phases"]["ports"] = {"error": str(e)}

        # SSL
        try:
            results["phases"]["ssl"] = await self._scan_ssl(domain)
        except Exception as e:
            results["phases"]["ssl"] = {"error": str(e)}

        # Web
        try:
            results["phases"]["web"] = await self._scan_web(f"https://{domain}")
        except Exception as e:
            results["phases"]["web"] = {"error": str(e)}

        # Vulns
        try:
            results["phases"]["vulns"] = await self._scan_vulns(f"https://{domain}")
        except Exception as e:
            results["phases"]["vulns"] = {"error": str(e)}

        # Summary
        results["summary"] = {
            "subdomains": results["phases"].get("subdomains", {}).get("total", 0),
            "open_ports": results["phases"].get("ports", {}).get("total_open", 0),
            "ssl_issues": len(results["phases"].get("ssl", {}).get("findings", [])),
            "web_findings": results["phases"].get("web", {}).get("total", 0),
            "vulnerabilities": results["phases"].get("vulns", {}).get("total", 0),
        }

        return {"success": True, **results}

    def _add_target(self, target: str) -> dict:
        """Add target to whitelist."""
        self.auth.add_whitelist(target)
        return {"success": True, "message": f"Added '{target}' to whitelist"}

    async def run(self):
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream, self.server.create_initialization_options())


def main():
    """Entry point."""
    import asyncio
    logging.basicConfig(level=logging.INFO)
    server = SecurityMCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
