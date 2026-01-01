"""MCP server implementation."""
import logging
from mcp.server.stdio import stdio_server
from mcp.server import Server
from mcp.types import Tool, TextContent
from .config import MCPConfig
from .auth import AuthorizationManager
from .tools import MCPToolsHandler


class PentestMCPServer:
    """AI Penetration Testing MCP Server."""

    def __init__(self):
        self.server = Server("ai-pentest")
        self.config = MCPConfig.from_env()
        self.auth_manager = AuthorizationManager()
        self.tools_handler = None
        self.logger = logging.getLogger(__name__)

    async def initialize(self):
        """Initialize server components."""
        from ..core.llm import LLMProvider, LLMConfig
        from ..core.llm.registry import LLMRegistry
        from ..core.agent import Orchestrator
        from ..tools import ToolManager
        from ..safety import SecurityManager

        # Initialize LLM
        llm_config = LLMConfig(
            provider=LLMProvider[self.config.default_llm_provider.upper()],
            model=self.config.default_llm_model,
            api_key=self.config.openai_api_key if self.config.default_llm_provider == "openai" else self.config.anthropic_api_key,
            temperature=0.7,
            max_tokens=2000
        )
        llm_provider = LLMRegistry.get_provider(llm_config)

        # Initialize components
        tool_manager = ToolManager()
        security_manager = SecurityManager()

        # Configure security
        security_manager.scope_validator.add_allowed_domain("*.example.com")
        security_manager.scope_validator.add_allowed_domain("httpbin.org")

        # Create orchestrator
        orchestrator = Orchestrator(
            llm_provider=llm_provider,
            tool_manager=tool_manager,
            security_manager=security_manager,
            max_iterations=self.config.max_iterations
        )

        # Initialize tools handler
        self.tools_handler = MCPToolsHandler(
            orchestrator=orchestrator,
            tool_manager=tool_manager,
            security_manager=security_manager,
            auth_manager=self.auth_manager,
            config=self.config
        )

        self.logger.info("MCP server initialized successfully")

    def register_tools(self):
        """Register MCP tools."""

        @self.server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="pentest_scan",
                    description="Execute AI-driven penetration test scan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target to scan (domain/IP/URL)"},
                            "scan_type": {"type": "string", "enum": ["web", "network", "api"], "description": "Type of scan"},
                            "llm_provider": {"type": "string", "enum": ["openai", "anthropic", "ollama"], "description": "LLM provider (optional)"},
                            "max_iterations": {"type": "integer", "description": "Max iterations (optional)"}
                        },
                        "required": ["target", "scan_type"]
                    }
                ),
                Tool(
                    name="pentest_get_results",
                    description="Get detailed scan results",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_id": {"type": "string", "description": "Scan ID"}
                        },
                        "required": ["scan_id"]
                    }
                ),
                Tool(
                    name="pentest_list_scans",
                    description="List all scan history",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "description": "Limit number of results (optional)"}
                        }
                    }
                ),
                Tool(
                    name="pentest_get_scan_status",
                    description="Get current scan status",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_id": {"type": "string", "description": "Scan ID"}
                        },
                        "required": ["scan_id"]
                    }
                ),
                Tool(
                    name="pentest_configure_llm",
                    description="Configure LLM provider",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "provider": {"type": "string", "enum": ["openai", "anthropic", "ollama"], "description": "LLM provider"},
                            "model": {"type": "string", "description": "Model name (optional)"},
                            "api_key": {"type": "string", "description": "API key (optional)"}
                        },
                        "required": ["provider"]
                    }
                ),
                Tool(
                    name="pentest_list_tools",
                    description="List available penetration testing tools",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "category": {"type": "string", "description": "Tool category filter (optional)"}
                        }
                    }
                ),
                Tool(
                    name="pentest_configure_scope",
                    description="Configure scan scope (whitelist)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "allowed_domains": {"type": "array", "items": {"type": "string"}, "description": "Allowed domains"},
                            "allowed_ips": {"type": "array", "items": {"type": "string"}, "description": "Allowed IPs"},
                            "blacklist": {"type": "array", "items": {"type": "string"}, "description": "Blacklist patterns"}
                        }
                    }
                ),
                Tool(
                    name="pentest_get_config",
                    description="Get current configuration",
                    inputSchema={"type": "object", "properties": {}}
                ),
                # === Pure Python Scanner Tools ===
                Tool(
                    name="scan_ports",
                    description="Scan TCP ports (pure Python, no nmap required)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target IP or hostname"},
                            "ports": {"type": "array", "items": {"type": "integer"}, "description": "Ports to scan (optional)"},
                            "grab_banner": {"type": "boolean", "description": "Grab service banners (default: true)"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="scan_directories",
                    description="Bruteforce directories and files on web target",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target URL"},
                            "wordlist": {"type": "array", "items": {"type": "string"}, "description": "Custom wordlist (optional)"},
                            "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions (optional)"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="enum_subdomains",
                    description="Enumerate subdomains via DNS",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target domain"},
                            "wordlist": {"type": "array", "items": {"type": "string"}, "description": "Custom subdomain wordlist (optional)"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="scan_ssl",
                    description="Scan SSL/TLS configuration and certificate",
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
                    description="Scan for web vulnerabilities (SQLi, XSS, LFI)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target URL"},
                            "scan_types": {"type": "array", "items": {"type": "string", "enum": ["sqli", "xss", "lfi", "ssrf"]}, "description": "Vulnerability types to scan (optional)"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="full_recon",
                    description="Run full reconnaissance: subdomains, ports, directories, SSL, vulns",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target domain"}
                        },
                        "required": ["target"]
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict):
            import json

            try:
                if name == "pentest_scan":
                    result = await self.tools_handler.pentest_scan(**arguments)
                elif name == "pentest_get_results":
                    result = await self.tools_handler.pentest_get_results(**arguments)
                elif name == "pentest_list_scans":
                    result = await self.tools_handler.pentest_list_scans(**arguments)
                elif name == "pentest_get_scan_status":
                    result = await self.tools_handler.pentest_get_scan_status(**arguments)
                elif name == "pentest_configure_llm":
                    result = await self.tools_handler.pentest_configure_llm(**arguments)
                elif name == "pentest_list_tools":
                    result = await self.tools_handler.pentest_list_tools(**arguments)
                elif name == "pentest_configure_scope":
                    result = await self.tools_handler.pentest_configure_scope(**arguments)
                elif name == "pentest_get_config":
                    result = await self.tools_handler.pentest_get_config()
                # Pure Python scanner tools
                elif name == "scan_ports":
                    result = await self.tools_handler.scan_ports(**arguments)
                elif name == "scan_directories":
                    result = await self.tools_handler.scan_directories(**arguments)
                elif name == "enum_subdomains":
                    result = await self.tools_handler.enum_subdomains(**arguments)
                elif name == "scan_ssl":
                    result = await self.tools_handler.scan_ssl(**arguments)
                elif name == "scan_vulns":
                    result = await self.tools_handler.scan_vulns(**arguments)
                elif name == "full_recon":
                    result = await self.tools_handler.full_recon(**arguments)
                else:
                    result = {"success": False, "error": f"Unknown tool: {name}"}

                return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

            except Exception as e:
                self.logger.error(f"Tool call error: {e}", exc_info=True)
                return [TextContent(type="text", text=json.dumps({"success": False, "error": str(e)}, ensure_ascii=False))]

    async def run(self):
        """Run the MCP server."""
        self.register_tools()
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream, self.server.create_initialization_options())
