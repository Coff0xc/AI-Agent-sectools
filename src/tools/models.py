"""工具执行相关的数据模型。"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum


class ToolStatus(str, Enum):
    """工具执行状态。"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ToolCategory(str, Enum):
    """工具类别。"""
    WEB = "web"
    NETWORK = "network"
    API = "api"
    MOBILE = "mobile"


@dataclass
class ToolResult:
    """工具执行结果。"""
    tool_name: str
    status: ToolStatus
    output: str
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_success(self) -> bool:
        """检查是否执行成功。"""
        return self.status == ToolStatus.SUCCESS

    def has_findings(self) -> bool:
        """检查是否有发现。"""
        return bool(self.parsed_data.get("findings"))


@dataclass
class ToolConfig:
    """工具配置。"""
    name: str
    category: ToolCategory
    docker_image: Optional[str] = None
    timeout: int = 300
    enabled: bool = True
    default_args: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
