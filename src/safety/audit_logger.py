"""审计日志系统。"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum


class AuditEventType(str, Enum):
    """审计事件类型。"""
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    SCAN_FAILED = "scan_failed"
    TOOL_EXECUTE = "tool_execute"
    SCOPE_VIOLATION = "scope_violation"
    RATE_LIMIT = "rate_limit"
    BLACKLIST_HIT = "blacklist_hit"
    EMERGENCY_STOP = "emergency_stop"


class AuditLogger:
    """审计日志记录器。"""

    def __init__(
        self,
        log_file: str = "logs/audit.log",
        log_level: str = "INFO",
        include_sensitive: bool = False
    ):
        self.log_file = Path(log_file)
        self.include_sensitive = include_sensitive

        # 创建日志目录
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # 配置日志记录器
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(getattr(logging, log_level.upper()))

        # 文件处理器
        file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
        file_handler.setLevel(logging.INFO)

        # 格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)

    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: str,
        target: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """记录审计事件。"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type.value,
            "user_id": user_id,
            "target": target,
            "action": action,
            "result": result,
            "metadata": metadata or {}
        }

        # 如果不包含敏感信息，移除某些字段
        if not self.include_sensitive:
            event = self._sanitize_event(event)

        # 记录到日志
        self.logger.info(json.dumps(event, ensure_ascii=False))

    async def log_auth_success(self, user_id: str, target: str) -> None:
        """记录授权成功。"""
        await self.log_event(
            AuditEventType.AUTH_SUCCESS,
            user_id=user_id,
            target=target,
            result="success"
        )

    async def log_auth_failure(self, user_id: str, reason: str) -> None:
        """记录授权失败。"""
        await self.log_event(
            AuditEventType.AUTH_FAILURE,
            user_id=user_id,
            result="failure",
            metadata={"reason": reason}
        )

    async def log_scan_start(
        self,
        user_id: str,
        target: str,
        scan_type: str,
        scan_id: str
    ) -> None:
        """记录扫描开始。"""
        await self.log_event(
            AuditEventType.SCAN_START,
            user_id=user_id,
            target=target,
            action=scan_type,
            metadata={"scan_id": scan_id}
        )

    async def log_scan_complete(
        self,
        user_id: str,
        target: str,
        scan_id: str,
        findings_count: int
    ) -> None:
        """记录扫描完成。"""
        await self.log_event(
            AuditEventType.SCAN_COMPLETE,
            user_id=user_id,
            target=target,
            result="success",
            metadata={
                "scan_id": scan_id,
                "findings_count": findings_count
            }
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
        await self.log_event(
            AuditEventType.TOOL_EXECUTE,
            user_id=user_id,
            target=target,
            action=tool_name,
            result=result,
            metadata={"command": command if self.include_sensitive else "[REDACTED]"}
        )

    async def log_scope_violation(
        self,
        user_id: str,
        target: str,
        reason: str
    ) -> None:
        """记录范围违规。"""
        await self.log_event(
            AuditEventType.SCOPE_VIOLATION,
            user_id=user_id,
            target=target,
            result="blocked",
            metadata={"reason": reason}
        )

    async def log_rate_limit(self, user_id: str, target: str) -> None:
        """记录速率限制。"""
        await self.log_event(
            AuditEventType.RATE_LIMIT,
            user_id=user_id,
            target=target,
            result="blocked"
        )

    async def log_emergency_stop(self, user_id: str, reason: str) -> None:
        """记录紧急停止。"""
        await self.log_event(
            AuditEventType.EMERGENCY_STOP,
            user_id=user_id,
            action="emergency_stop",
            result="stopped",
            metadata={"reason": reason}
        )

    def _sanitize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """清理敏感信息。"""
        # 移除或脱敏敏感字段
        if "metadata" in event and isinstance(event["metadata"], dict):
            sensitive_keys = ["password", "token", "api_key", "secret"]
            for key in sensitive_keys:
                if key in event["metadata"]:
                    event["metadata"][key] = "[REDACTED]"

        return event
