"""安全相关的数据模型和异常类。"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from enum import Enum


class TargetType(str, Enum):
    """目标类型。"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    CIDR = "cidr"


@dataclass
class Target:
    """扫描目标。"""
    value: str
    type: TargetType
    metadata: dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class Authorization:
    """授权信息。"""
    token: str
    user_id: str
    target: Target
    expires_at: datetime
    permissions: List[str]
    metadata: dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def is_expired(self) -> bool:
        """检查授权是否过期。"""
        return datetime.now() > self.expires_at

    def has_permission(self, permission: str) -> bool:
        """检查是否有特定权限。"""
        return permission in self.permissions


# 安全异常类
class SecurityException(Exception):
    """安全相关异常基类。"""
    pass


class UnauthorizedException(SecurityException):
    """未授权异常。"""
    pass


class OutOfScopeException(SecurityException):
    """超出范围异常。"""
    pass


class RateLimitException(SecurityException):
    """速率限制异常。"""
    pass


class BlacklistException(SecurityException):
    """黑名单异常。"""
    pass
