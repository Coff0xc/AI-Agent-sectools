"""Web应用扫描工具。"""
import time
import httpx
from typing import Dict, Any, Optional
from ..base import BaseTool
from ..models import ToolResult, ToolConfig, ToolStatus, ToolCategory
from ...safety.models import Target


class WebScanner(BaseTool):
    """基础Web应用扫描器。"""

    def __init__(self, config: Optional[ToolConfig] = None):
        if config is None:
            config = ToolConfig(
                name="web_scanner",
                category=ToolCategory.WEB,
                timeout=180
            )
        super().__init__(config)

    async def execute(
        self,
        target: Target,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """执行Web扫描。"""
        start_time = time.time()
        params = params or {}

        try:
            # 基础HTTP检查
            findings = []
            async with httpx.AsyncClient(timeout=30.0) as client:
                # 检查HTTP响应
                response = await client.get(
                    target.value if target.value.startswith("http") else f"http://{target.value}",
                    follow_redirects=True
                )

                # 检查安全头
                security_headers = self._check_security_headers(response.headers)
                findings.extend(security_headers)

                # 检查服务器信息泄露
                server_info = self._check_server_disclosure(response.headers)
                if server_info:
                    findings.append(server_info)

                parsed_data = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "findings": findings,
                    "url": str(response.url)
                }

            execution_time = time.time() - start_time

            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.SUCCESS,
                output=f"扫描完成，发现 {len(findings)} 个问题",
                parsed_data=parsed_data,
                execution_time=execution_time
            )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILED,
                output="",
                error=str(e),
                execution_time=time.time() - start_time
            )

    def _check_security_headers(self, headers: httpx.Headers) -> list:
        """检查安全响应头。"""
        findings = []
        required_headers = {
            "X-Frame-Options": "缺少X-Frame-Options头，可能存在点击劫持风险",
            "X-Content-Type-Options": "缺少X-Content-Type-Options头",
            "Strict-Transport-Security": "缺少HSTS头，不强制HTTPS",
            "Content-Security-Policy": "缺少CSP头，可能存在XSS风险"
        }

        for header, description in required_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                findings.append({
                    "type": "missing_security_header",
                    "severity": "medium",
                    "description": description,
                    "header": header
                })

        return findings

    def _check_server_disclosure(self, headers: httpx.Headers) -> Optional[Dict]:
        """检查服务器信息泄露。"""
        server = headers.get("Server")
        if server:
            return {
                "type": "information_disclosure",
                "severity": "low",
                "description": f"服务器信息泄露: {server}",
                "value": server
            }
        return None

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """解析输出。"""
        return {"raw": raw_output}
