"""MCP tools implementation."""
from typing import Dict, Any, Optional
from datetime import datetime


class MCPToolsHandler:
    """Handles MCP tool calls."""

    def __init__(self, orchestrator, tool_manager, security_manager, auth_manager, config):
        self.orchestrator = orchestrator
        self.tool_manager = tool_manager
        self.security_manager = security_manager
        self.auth_manager = auth_manager
        self.config = config
        self.scan_results = {}  # In-memory storage

    async def pentest_scan(
        self,
        target: str,
        scan_type: str,
        llm_provider: Optional[str] = None,
        max_iterations: Optional[int] = None
    ) -> Dict[str, Any]:
        """Execute AI-driven penetration test scan."""
        # Check authorization
        if not self.auth_manager.is_authorized(target):
            self.auth_manager.log_audit("pentest_scan", target, "unauthorized")
            return {
                "success": False,
                "error": f"Target {target} is not authorized. Please add it to whitelist in mcp_auth_config.yaml"
            }

        # Generate auth token
        from ...safety import Target, TargetType
        target_obj = self._create_target(target)
        auth_token = self.security_manager.auth_manager.generate_token(
            user_id="mcp_user",
            target=target_obj,
            permissions=["scan", "report"]
        )

        # Run scan
        try:
            context = await self.orchestrator.run_scan(
                target=target,
                scan_type=scan_type,
                auth_token=auth_token
            )

            # Store results
            self.scan_results[context.scan_id] = {
                "context": context,
                "timestamp": datetime.now().isoformat()
            }

            self.auth_manager.log_audit("pentest_scan", target, "success")

            return {
                "success": True,
                "scan_id": context.scan_id,
                "target": context.target,
                "scan_type": context.scan_type,
                "state": context.state.value,
                "findings_count": len(context.findings),
                "summary": f"Scan completed with {len(context.findings)} findings"
            }

        except Exception as e:
            self.auth_manager.log_audit("pentest_scan", target, f"failed: {str(e)}")
            return {"success": False, "error": str(e)}

    async def pentest_get_results(self, scan_id: str) -> Dict[str, Any]:
        """Get detailed scan results."""
        if scan_id not in self.scan_results:
            return {"success": False, "error": f"Scan ID {scan_id} not found"}

        result = self.scan_results[scan_id]
        context = result["context"]

        findings = []
        for finding in context.findings:
            findings.append({
                "type": finding.get("type", "unknown"),
                "severity": finding.get("severity", "unknown"),
                "description": finding.get("description", ""),
                "location": finding.get("location", "")
            })

        analysis = context.metadata.get("analysis", {})

        return {
            "success": True,
            "scan_id": context.scan_id,
            "target": context.target,
            "scan_type": context.scan_type,
            "state": context.state.value,
            "timestamp": result["timestamp"],
            "findings": findings,
            "risk_score": analysis.get("risk_score", 0),
            "severity_distribution": analysis.get("severity_distribution", {}),
            "recommendations": analysis.get("recommendations", [])
        }

    async def pentest_list_scans(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """List all scan history."""
        scans = []
        for scan_id, result in self.scan_results.items():
            context = result["context"]
            scans.append({
                "scan_id": scan_id,
                "target": context.target,
                "scan_type": context.scan_type,
                "state": context.state.value,
                "findings_count": len(context.findings),
                "timestamp": result["timestamp"]
            })

        # Sort by timestamp (newest first)
        scans.sort(key=lambda x: x["timestamp"], reverse=True)

        if limit:
            scans = scans[:limit]

        return {"success": True, "scans": scans, "total": len(self.scan_results)}

    async def pentest_get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status."""
        if scan_id not in self.scan_results:
            return {"success": False, "error": f"Scan ID {scan_id} not found"}

        result = self.scan_results[scan_id]
        context = result["context"]

        return {
            "success": True,
            "scan_id": scan_id,
            "state": context.state.value,
            "actions_executed": len(context.observations),
            "findings_count": len(context.findings),
            "timestamp": result["timestamp"]
        }

    async def pentest_configure_llm(
        self,
        provider: str,
        model: Optional[str] = None,
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Configure LLM provider."""
        try:
            self.config.default_llm_provider = provider
            if model:
                self.config.default_llm_model = model
            if api_key:
                if provider == "openai":
                    self.config.openai_api_key = api_key
                elif provider == "anthropic":
                    self.config.anthropic_api_key = api_key

            return {
                "success": True,
                "provider": provider,
                "model": model or self.config.default_llm_model,
                "message": "LLM configuration updated"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def pentest_list_tools(self, category: Optional[str] = None) -> Dict[str, Any]:
        """List available tools."""
        tools = []
        for tool_name, tool in self.tool_manager.tools.items():
            tool_info = {
                "name": tool_name,
                "description": tool.__doc__ or "No description",
                "category": getattr(tool, "category", "general")
            }
            if not category or tool_info["category"] == category:
                tools.append(tool_info)

        return {"success": True, "tools": tools, "total": len(tools)}

    async def pentest_configure_scope(
        self,
        allowed_domains: Optional[list] = None,
        allowed_ips: Optional[list] = None,
        blacklist: Optional[list] = None
    ) -> Dict[str, Any]:
        """Configure scan scope."""
        try:
            if allowed_domains:
                for domain in allowed_domains:
                    self.security_manager.scope_validator.add_allowed_domain(domain)

            if allowed_ips:
                for ip in allowed_ips:
                    self.security_manager.scope_validator.add_allowed_ip(ip)

            return {
                "success": True,
                "message": "Scope configuration updated",
                "allowed_domains": allowed_domains or [],
                "allowed_ips": allowed_ips or []
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def pentest_get_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "success": True,
            "llm": {
                "provider": self.config.default_llm_provider,
                "model": self.config.default_llm_model,
                "max_iterations": self.config.max_iterations
            },
            "tools": {
                "available": list(self.tool_manager.tools.keys())
            },
            "security": {
                "authorization_mode": self.auth_manager.config.get("authorization", {}).get("mode", "whitelist")
            }
        }

    def _create_target(self, target_value: str):
        """Create Target object."""
        from ...safety import Target, TargetType
        if target_value.startswith("http"):
            return Target(target_value, TargetType.URL)
        elif "/" in target_value:
            return Target(target_value, TargetType.CIDR)
        elif all(c.isdigit() or c == "." for c in target_value):
            return Target(target_value, TargetType.IP)
        else:
            return Target(target_value, TargetType.DOMAIN)
