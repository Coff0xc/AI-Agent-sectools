"""速率限制器。"""
import time
from typing import Dict, Tuple
from collections import defaultdict
from .models import RateLimitException


class RateLimiter:
    """速率限制器（基于令牌桶算法）。"""

    def __init__(
        self,
        requests_per_minute: int = 60,
        max_concurrent_scans: int = 3
    ):
        self.requests_per_minute = requests_per_minute
        self.max_concurrent_scans = max_concurrent_scans

        # 存储每个目标的请求记录: {target: [(timestamp, count)]}
        self._request_history: Dict[str, list] = defaultdict(list)

        # 存储每个用户的并发扫描数: {user_id: count}
        self._concurrent_scans: Dict[str, int] = defaultdict(int)

    async def check_rate_limit(self, target: str, user_id: str) -> bool:
        """检查是否超过速率限制。"""
        current_time = time.time()
        key = f"{user_id}:{target}"

        # 清理过期的请求记录（超过1分钟）
        self._cleanup_old_requests(key, current_time)

        # 获取最近1分钟的请求数
        recent_requests = len(self._request_history[key])

        if recent_requests >= self.requests_per_minute:
            raise RateLimitException(
                f"超过速率限制: {recent_requests}/{self.requests_per_minute} 请求/分钟"
            )

        # 记录本次请求
        self._request_history[key].append(current_time)
        return True

    async def check_concurrent_scans(self, user_id: str) -> bool:
        """检查并发扫描数量。"""
        current_scans = self._concurrent_scans[user_id]

        if current_scans >= self.max_concurrent_scans:
            raise RateLimitException(
                f"超过并发扫描限制: {current_scans}/{self.max_concurrent_scans}"
            )

        return True

    async def acquire_scan_slot(self, user_id: str) -> None:
        """获取扫描槽位。"""
        await self.check_concurrent_scans(user_id)
        self._concurrent_scans[user_id] += 1

    async def release_scan_slot(self, user_id: str) -> None:
        """释放扫描槽位。"""
        if self._concurrent_scans[user_id] > 0:
            self._concurrent_scans[user_id] -= 1

    def _cleanup_old_requests(self, key: str, current_time: float) -> None:
        """清理超过1分钟的请求记录。"""
        cutoff_time = current_time - 60  # 1分钟前
        self._request_history[key] = [
            timestamp for timestamp in self._request_history[key]
            if timestamp > cutoff_time
        ]

    def get_remaining_requests(self, target: str, user_id: str) -> int:
        """获取剩余可用请求数。"""
        key = f"{user_id}:{target}"
        current_time = time.time()
        self._cleanup_old_requests(key, current_time)

        recent_requests = len(self._request_history[key])
        return max(0, self.requests_per_minute - recent_requests)

    def get_concurrent_scans(self, user_id: str) -> int:
        """获取当前并发扫描数。"""
        return self._concurrent_scans[user_id]

    def reset_user_limits(self, user_id: str) -> None:
        """重置用户的所有限制。"""
        # 清理该用户的所有请求记录
        keys_to_remove = [
            key for key in self._request_history.keys()
            if key.startswith(f"{user_id}:")
        ]
        for key in keys_to_remove:
            del self._request_history[key]

        # 重置并发扫描计数
        self._concurrent_scans[user_id] = 0
