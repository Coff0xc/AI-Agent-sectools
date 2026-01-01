"""Nmap网络扫描工具包装器。"""
import json
import re
import time
from typing import Dict, Any, Optional
from ..base import BaseTool
from ..models import ToolResult, ToolConfig, ToolStatus, ToolCategory
from ...safety.models import Target
from ...utils.docker_manager import DockerManager


class NmapTool(BaseTool):
    """Nmap端口扫描工具。"""

    def __init__(self, config: Optional[ToolConfig] = None):
        if config is None:
            config = ToolConfig(
                name="nmap",
                category=ToolCategory.NETWORK,
                docker_image="instrumentisto/nmap",
                timeout=600,
                default_args=["-sV", "-sC"]
            )
        super().__init__(config)
        self.docker_manager = DockerManager()

    async def execute(
        self,
        target: Target,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """执行Nmap扫描。"""
        start_time = time.time()
        params = params or {}

        try:
            # 构建Nmap命令
            command = self._build_command(target.value, params)

            # 在Docker容器中执行
            stdout, stderr, exit_code = await self.docker_manager.execute_in_container(
                image=self.config.docker_image,
                command=command,
                timeout=self.config.timeout
            )

            execution_time = time.time() - start_time

            # 解析输出
            parsed_data = self.parse_output(stdout)

            status = ToolStatus.SUCCESS if exit_code == 0 else ToolStatus.FAILED

            return ToolResult(
                tool_name=self.name,
                status=status,
                output=stdout,
                parsed_data=parsed_data,
                error=stderr if stderr else None,
                execution_time=execution_time,
                metadata={
                    "exit_code": exit_code,
                    "command": command
                }
            )

        except TimeoutError as e:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.TIMEOUT,
                output="",
                error=str(e),
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILED,
                output="",
                error=str(e),
                execution_time=time.time() - start_time
            )

    def _build_command(self, target: str, params: Dict[str, Any]) -> str:
        """构建Nmap命令。"""
        args = params.get("args", self.config.default_args)
        ports = params.get("ports", "")

        cmd_parts = ["nmap"]

        # 添加参数
        if isinstance(args, list):
            cmd_parts.extend(args)
        elif isinstance(args, str):
            cmd_parts.append(args)

        # 添加端口范围
        if ports:
            cmd_parts.extend(["-p", str(ports)])

        # 添加目标
        cmd_parts.append(target)

        return " ".join(cmd_parts)

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """解析Nmap输出。"""
        result = {
            "hosts": [],
            "open_ports": [],
            "services": [],
            "findings": []
        }

        if not raw_output:
            return result

        # 解析开放端口
        port_pattern = r"(\d+)/(\w+)\s+open\s+(\S+)"
        for match in re.finditer(port_pattern, raw_output):
            port, protocol, service = match.groups()
            port_info = {
                "port": int(port),
                "protocol": protocol,
                "service": service
            }
            result["open_ports"].append(port_info)
            result["services"].append(service)

            # 添加发现
            result["findings"].append({
                "type": "open_port",
                "severity": "info",
                "description": f"开放端口: {port}/{protocol} ({service})"
            })

        # 解析主机状态
        host_pattern = r"Nmap scan report for (.+)"
        hosts = re.findall(host_pattern, raw_output)
        result["hosts"] = hosts

        return result
