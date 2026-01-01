"""工具基础接口。"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from .models import ToolResult, ToolConfig, ToolStatus
from ..safety.models import Target


class BaseTool(ABC):
    """工具基础抽象类。"""

    def __init__(self, config: ToolConfig):
        self.config = config
        self.name = config.name

    @abstractmethod
    async def execute(
        self,
        target: Target,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        执行工具。

        Args:
            target: 目标对象
            params: 执行参数

        Returns:
            ToolResult: 执行结果
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        解析工具输出。

        Args:
            raw_output: 原始输出

        Returns:
            Dict: 解析后的结构化数据
        """
        pass

    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        验证参数。

        Args:
            params: 参数字典

        Returns:
            bool: 参数是否有效
        """
        return True

    async def __aenter__(self):
        """异步上下文管理器入口。"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口。"""
        pass
