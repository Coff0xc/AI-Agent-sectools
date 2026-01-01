"""目标范围验证器。"""
import re
import ipaddress
from typing import List, Set
from urllib.parse import urlparse
from .models import Target, TargetType, OutOfScopeException, BlacklistException


class ScopeValidator:
    """目标范围验证器。"""

    def __init__(
        self,
        allowed_ip_ranges: List[str] = None,
        allowed_domains: List[str] = None,
        blacklist: List[str] = None
    ):
        self.allowed_ip_ranges = allowed_ip_ranges or []
        self.allowed_domains = allowed_domains or []
        self.blacklist = blacklist or []

        # 预编译IP网络
        self._ip_networks = [
            ipaddress.ip_network(ip_range) for ip_range in self.allowed_ip_ranges
        ]

    async def validate(self, target: Target) -> bool:
        """验证目标是否在允许范围内。"""
        # 首先检查黑名单
        if await self._is_blacklisted(target):
            raise BlacklistException(f"目标在黑名单中: {target.value}")

        # 根据目标类型验证
        if target.type == TargetType.IP:
            return await self._validate_ip(target.value)
        elif target.type == TargetType.DOMAIN:
            return await self._validate_domain(target.value)
        elif target.type == TargetType.URL:
            return await self._validate_url(target.value)
        elif target.type == TargetType.CIDR:
            return await self._validate_cidr(target.value)

        raise OutOfScopeException(f"未知的目标类型: {target.type}")

    async def _is_blacklisted(self, target: Target) -> bool:
        """检查目标是否在黑名单中。"""
        value = target.value.lower()

        for pattern in self.blacklist:
            pattern = pattern.lower()
            # 支持通配符匹配
            if pattern.startswith("*."):
                domain_suffix = pattern[2:]
                if value.endswith(domain_suffix) or value == domain_suffix[1:]:
                    return True
            elif pattern in value:
                return True

        return False

    async def _validate_ip(self, ip: str) -> bool:
        """验证IP地址。"""
        try:
            ip_obj = ipaddress.ip_address(ip)

            # 如果没有配置允许的IP范围，拒绝所有
            if not self._ip_networks:
                raise OutOfScopeException("未配置允许的IP范围")

            # 检查IP是否在允许的范围内
            for network in self._ip_networks:
                if ip_obj in network:
                    return True

            raise OutOfScopeException(f"IP地址不在允许范围内: {ip}")

        except ValueError as e:
            raise OutOfScopeException(f"无效的IP地址: {ip}")

    async def _validate_domain(self, domain: str) -> bool:
        """验证域名。"""
        domain = domain.lower()

        # 如果没有配置允许的域名，拒绝所有
        if not self.allowed_domains:
            raise OutOfScopeException("未配置允许的域名")

        # 检查域名是否匹配
        for allowed in self.allowed_domains:
            allowed = allowed.lower()
            # 支持通配符匹配
            if allowed.startswith("*."):
                domain_suffix = allowed[2:]
                if domain.endswith(domain_suffix) or domain == domain_suffix:
                    return True
            elif domain == allowed:
                return True

        raise OutOfScopeException(f"域名不���允许范围内: {domain}")

    async def _validate_url(self, url: str) -> bool:
        """验证URL。"""
        parsed = urlparse(url)
        domain = parsed.netloc

        # 移除端口号
        if ":" in domain:
            domain = domain.split(":")[0]

        # 验证域名部分
        target = Target(value=domain, type=TargetType.DOMAIN)
        return await self.validate(target)

    async def _validate_cidr(self, cidr: str) -> bool:
        """验证CIDR网络。"""
        try:
            network = ipaddress.ip_network(cidr)

            # 如果没有配置允许的IP范围，拒绝所有
            if not self._ip_networks:
                raise OutOfScopeException("未配置允许的IP范围")

            # 检查CIDR是否在允许的范围内
            for allowed_network in self._ip_networks:
                if network.subnet_of(allowed_network):
                    return True

            raise OutOfScopeException(f"CIDR网络不在允许范围内: {cidr}")

        except ValueError as e:
            raise OutOfScopeException(f"无效的CIDR: {cidr}")

    def add_allowed_ip_range(self, ip_range: str) -> None:
        """添加允许的IP范围。"""
        self.allowed_ip_ranges.append(ip_range)
        self._ip_networks.append(ipaddress.ip_network(ip_range))

    def add_allowed_domain(self, domain: str) -> None:
        """添加允许的域名。"""
        self.allowed_domains.append(domain)

    def add_blacklist(self, pattern: str) -> None:
        """添加黑名单规则。"""
        self.blacklist.append(pattern)
