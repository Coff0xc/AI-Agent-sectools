"""工具注册表和管理器。"""
from typing import Dict, Type, Optional, List
from .base import BaseTool
from .models import ToolConfig, ToolCategory
from .network.nmap_wrapper import NmapTool
from .web.scanner import WebScanner
from .api.rest_tester import RESTTester
# Pure Python scanners (no external dependencies)
from .scanner import PortScanner, DirBruteforcer, SubdomainEnumerator, SSLScanner, VulnScanner


class ToolRegistry:
    """工具注册表。"""

    _tools: Dict[str, Type[BaseTool]] = {
        # External tool wrappers
        "nmap": NmapTool,
        "web_scanner": WebScanner,
        "rest_tester": RESTTester,
        # Pure Python scanners
        "port_scanner": PortScanner,
        "dir_bruteforce": DirBruteforcer,
        "subdomain_enum": SubdomainEnumerator,
        "ssl_scanner": SSLScanner,
        "vuln_scanner": VulnScanner,
    }

    @classmethod
    def register(cls, name: str, tool_class: Type[BaseTool]) -> None:
        """注册新工具。"""
        cls._tools[name] = tool_class

    @classmethod
    def get_tool(cls, name: str, config: Optional[ToolConfig] = None) -> BaseTool:
        """获取工具实例。"""
        tool_class = cls._tools.get(name)
        if not tool_class:
            raise ValueError(f"未知的工具: {name}")

        if config:
            return tool_class(config)
        return tool_class()

    @classmethod
    def list_tools(cls) -> List[str]:
        """列出所有已注册的工具。"""
        return list(cls._tools.keys())

    @classmethod
    def get_tools_by_category(cls, category: ToolCategory) -> List[str]:
        """按类别获取工具列表。"""
        tools = []
        for name, tool_class in cls._tools.items():
            # 创建临时实例以获取配置
            instance = tool_class()
            if instance.config.category == category:
                tools.append(name)
        return tools


class ToolManager:
    """工具管理器。"""

    def __init__(self):
        self._instances: Dict[str, BaseTool] = {}

    def get_or_create(self, name: str, config: Optional[ToolConfig] = None) -> BaseTool:
        """获取或创建工具实例。"""
        key = f"{name}:{config.name if config else 'default'}"

        if key not in self._instances:
            self._instances[key] = ToolRegistry.get_tool(name, config)

        return self._instances[key]

    async def execute_tool(
        self,
        tool_name: str,
        target,
        params: Optional[Dict] = None
    ):
        """执行工具。"""
        tool = self.get_or_create(tool_name)
        return await tool.execute(target, params)

    def list_available_tools(self) -> List[str]:
        """列出可用工具。"""
        return ToolRegistry.list_tools()

    def get_tools_by_category(self, category: ToolCategory) -> List[str]:
        """按类别获取工具。"""
        return ToolRegistry.get_tools_by_category(category)
