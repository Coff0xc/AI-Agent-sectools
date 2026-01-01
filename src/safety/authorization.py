"""授权验证模块。"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from .models import Authorization, Target, UnauthorizedException


class AuthorizationManager:
    """授权管理器。"""

    def __init__(self, token_expiration_hours: int = 24):
        self.token_expiration_hours = token_expiration_hours
        self._tokens: Dict[str, Authorization] = {}

    def generate_token(
        self,
        user_id: str,
        target: Target,
        permissions: List[str] = None
    ) -> str:
        """生成授权令牌。"""
        if permissions is None:
            permissions = ["scan", "report"]

        # 生成安全的随机令牌
        token = secrets.token_urlsafe(32)

        # 创建授权对象
        auth = Authorization(
            token=token,
            user_id=user_id,
            target=target,
            expires_at=datetime.now() + timedelta(hours=self.token_expiration_hours),
            permissions=permissions,
            metadata={
                "created_at": datetime.now().isoformat(),
                "ip_address": None  # 可以添加IP地址
            }
        )

        self._tokens[token] = auth
        return token

    async def validate_token(self, token: str) -> Authorization:
        """验证授权令牌。"""
        if not token:
            raise UnauthorizedException("授权令牌不能为空")

        auth = self._tokens.get(token)
        if not auth:
            raise UnauthorizedException("无效的授权令牌")

        if auth.is_expired():
            del self._tokens[token]
            raise UnauthorizedException("授权令牌已过期")

        return auth

    async def revoke_token(self, token: str) -> bool:
        """撤销授权令牌。"""
        if token in self._tokens:
            del self._tokens[token]
            return True
        return False

    async def check_permission(self, token: str, permission: str) -> bool:
        """检查权限。"""
        auth = await self.validate_token(token)
        return auth.has_permission(permission)

    def cleanup_expired(self) -> int:
        """清理过期令牌。"""
        expired = [
            token for token, auth in self._tokens.items()
            if auth.is_expired()
        ]
        for token in expired:
            del self._tokens[token]
        return len(expired)

    def get_active_tokens_count(self) -> int:
        """获取活跃令牌数量。"""
        return len(self._tokens)
