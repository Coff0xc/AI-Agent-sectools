"""集成的安全管理器。"""
from typing import Optional
from .models import Target, Authorization
from .authorization import AuthorizationManager
from .scope_validator import ScopeValidator
from .audit_logger import AuditLogger
from .rate_limiter import RateLimiter


class SecurityManager:
    """集成的安全管理器，协调所有安全组件。"""

    def __init__(
        self,
        auth_manager: Optional[AuthorizationManager] = None,
        scope_validator: Optional[ScopeValidator] = None,
        audit_logger: Optional[AuditLogger] = None,
        rate_limiter: Optional[RateLimiter] = None
    ):
        self.auth_manager = auth_manager or AuthorizationManager()
        self.scope_validator = scope_validator or ScopeValidator()
        self.audit_logger = audit_logger or AuditLogger()
        self.rate_limiter = rate_limiter or RateLimiter()

    async def validate_and_authorize(
        self,
        token: str,
        target: Target,
        action: str = "scan"
    ) -> Authorization:
        """
        执行完整的安全验证流程。

        1. 验证授权令牌
        2. 检查目标范围
        3. 检查速率限制
        4. 记录审计日志
        """
        try:
            # 1. 验证授权令牌
            auth = await self.auth_manager.validate_token(token)
            await self.audit_logger.log_auth_success(auth.user_id, target.value)

            # 2. 检查权限
            if not auth.has_permission(action):
                await self.audit_logger.log_auth_failure(
                    auth.user_id,
                    f"缺少权限: {action}"
                )
                raise PermissionError(f"用户没有 {action} 权限")

            # 3. 验证目标范围
            try:
                await self.scope_validator.validate(target)
            except Exception as e:
                await self.audit_logger.log_scope_violation(
                    auth.user_id,
                    target.value,
                    str(e)
                )
                raise

            # 4. 检查速率限制
            try:
                await self.rate_limiter.check_rate_limit(target.value, auth.user_id)
            except Exception as e:
                await self.audit_logger.log_rate_limit(auth.user_id, target.value)
                raise

            return auth

        except Exception as e:
            # 记录失败
            if hasattr(e, '__class__'):
                await self.audit_logger.log_auth_failure(
                    token[:8] + "...",
                    str(e)
                )
            raise

    async def start_scan(
        self,
        token: str,
        target: Target,
        scan_type: str,
        scan_id: str
    ) -> Authorization:
        """开始扫描（包含所有安全检查）。"""
        # 执行安全验证
        auth = await self.validate_and_authorize(token, target, "scan")

        # 检查并发扫描限制
        await self.rate_limiter.acquire_scan_slot(auth.user_id)

        # 记录扫描开始
        await self.audit_logger.log_scan_start(
            auth.user_id,
            target.value,
            scan_type,
            scan_id
        )

        return auth

    async def complete_scan(
        self,
        user_id: str,
        target: str,
        scan_id: str,
        findings_count: int
    ) -> None:
        """完成扫描。"""
        # 释放扫描槽位
        await self.rate_limiter.release_scan_slot(user_id)

        # 记录扫描完成
        await self.audit_logger.log_scan_complete(
            user_id,
            target,
            scan_id,
            findings_count
        )

    async def log_tool_execution(
        self,
        user_id: str,
        target: str,
        tool_name: str,
        command: str,
        result: str
    ) -> None:
        """记录工具执行。"""
        await self.audit_logger.log_tool_execution(
            user_id,
            target,
            tool_name,
            command,
            result
        )

    async def emergency_stop(self, user_id: str, reason: str) -> None:
        """紧急停止所有操作。"""
        # 重置用户的所有限制
        self.rate_limiter.reset_user_limits(user_id)

        # 记录紧急停止
        await self.audit_logger.log_emergency_stop(user_id, reason)
