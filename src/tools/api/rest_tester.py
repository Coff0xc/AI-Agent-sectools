"""REST API安全测试工具。"""
import time
import httpx
from typing import Dict, Any, Optional, List
from ..base import BaseTool
from ..models import ToolResult, ToolConfig, ToolStatus, ToolCategory
from ...safety.models import Target


class RESTTester(BaseTool):
    """REST API安全测试工具。"""

    def __init__(self, config: Optional[ToolConfig] = None):
        if config is None:
            config = ToolConfig(
                name="rest_tester",
                category=ToolCategory.API,
                timeout=120
            )
        super().__init__(config)

    async def execute(
        self,
        target: Target,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """执行API测试。"""
        start_time = time.time()
        params = params or {}

        try:
            findings = []
            async with httpx.AsyncClient(timeout=30.0) as client:
                base_url = target.value if target.value.startswith("http") else f"http://{target.value}"

                # 测试常见HTTP方法
                methods_findings = await self._test_http_methods(client, base_url)
                findings.extend(methods_findings)

                # 测试认证
                auth_findings = await self._test_authentication(client, base_url)
                findings.extend(auth_findings)

                # 测试CORS
                cors_findings = await self._test_cors(client, base_url)
                findings.extend(cors_findings)

                parsed_data = {
                    "findings": findings,
                    "tested_url": base_url
                }

            execution_time = time.time() - start_time

            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.SUCCESS,
                output=f"API测试完成，发现 {len(findings)} 个问题",
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

    async def _test_http_methods(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """测试HTTP方法。"""
        findings = []
        dangerous_methods = ["PUT", "DELETE", "PATCH"]

        for method in dangerous_methods:
            try:
                response = await client.request(method, url)
                if response.status_code not in [405, 501]:
                    findings.append({
                        "type": "dangerous_http_method",
                        "severity": "medium",
                        "description": f"允许危险的HTTP方法: {method}",
                        "method": method,
                        "status_code": response.status_code
                    })
            except:
                pass

        return findings

    async def _test_authentication(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """测试认证机制。"""
        findings = []

        try:
            # 测试无认证访问
            response = await client.get(url)
            if response.status_code == 200:
                # 检查是否返回敏感数据
                content = response.text.lower()
                if any(keyword in content for keyword in ["password", "token", "secret", "key"]):
                    findings.append({
                        "type": "missing_authentication",
                        "severity": "high",
                        "description": "API端点缺少认证，可能泄露敏感信息"
                    })
        except:
            pass

        return findings

    async def _test_cors(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """测试CORS配置。"""
        findings = []

        try:
            response = await client.options(
                url,
                headers={"Origin": "https://evil.com"}
            )

            cors_header = response.headers.get("Access-Control-Allow-Origin")
            if cors_header == "*":
                findings.append({
                    "type": "insecure_cors",
                    "severity": "medium",
                    "description": "CORS配置过于宽松，允许任意源访问",
                    "value": cors_header
                })
        except:
            pass

        return findings

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """解析输出。"""
        return {"raw": raw_output}
