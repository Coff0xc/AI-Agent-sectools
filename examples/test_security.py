"""安全系统使用示例。"""
import asyncio
from datetime import datetime, timedelta
from src.safety import (
    SecurityManager,
    AuthorizationManager,
    ScopeValidator,
    AuditLogger,
    RateLimiter,
    Target,
    TargetType,
    UnauthorizedException,
    OutOfScopeException,
    RateLimitException
)


async def demo_authorization():
    """演示授权功能。"""
    print("=== 授权管理演示 ===")

    auth_manager = AuthorizationManager(token_expiration_hours=24)

    # 创建目标
    target = Target(value="example.com", type=TargetType.DOMAIN)

    # 生成授权令牌
    token = auth_manager.generate_token(
        user_id="user123",
        target=target,
        permissions=["scan", "report"]
    )
    print(f"生成的令牌: {token[:20]}...")

    # 验证令牌
    try:
        auth = await auth_manager.validate_token(token)
        print(f"✓ 令牌验证成功")
        print(f"  用户ID: {auth.user_id}")
        print(f"  目标: {auth.target.value}")
        print(f"  权限: {auth.permissions}")
        print(f"  过期时间: {auth.expires_at}")
    except UnauthorizedException as e:
        print(f"✗ 令牌验证失败: {e}")

    # 检查权限
    has_scan = await auth_manager.check_permission(token, "scan")
    print(f"✓ 有扫描权限: {has_scan}")

    has_admin = await auth_manager.check_permission(token, "admin")
    print(f"✗ 有管理员权限: {has_admin}")


async def demo_scope_validation():
    """演示范围验证功能。"""
    print("\n=== 范围验证演示 ===")

    # 配置允许的范围
    scope_validator = ScopeValidator(
        allowed_ip_ranges=["192.168.1.0/24", "10.0.0.0/8"],
        allowed_domains=["*.example.com", "testsite.local"],
        blacklist=["*.gov", "*.mil", "*.bank"]
    )

    # 测试合法目标
    test_cases = [
        (Target("192.168.1.100", TargetType.IP), True),
        (Target("test.example.com", TargetType.DOMAIN), True),
        (Target("192.168.2.100", TargetType.IP), False),
        (Target("evil.gov", TargetType.DOMAIN), False),
        (Target("https://api.example.com/test", TargetType.URL), True),
    ]

    for target, should_pass in test_cases:
        try:
            await scope_validator.validate(target)
            print(f"✓ {target.value} - 验证通过")
        except (OutOfScopeException, Exception) as e:
            if should_pass:
                print(f"✗ {target.value} - 意外失败: {e}")
            else:
                print(f"✓ {target.value} - 正确拒绝: {e}")


async def demo_rate_limiting():
    """演示速率限制功能。"""
    print("\n=== 速率限制演示 ===")

    rate_limiter = RateLimiter(
        requests_per_minute=5,
        max_concurrent_scans=2
    )

    user_id = "user123"
    target = "example.com"

    # 测试请求速率限制
    print(f"速率限制: 5 请求/分钟")
    for i in range(7):
        try:
            await rate_limiter.check_rate_limit(target, user_id)
            remaining = rate_limiter.get_remaining_requests(target, user_id)
            print(f"  请求 {i+1}: ✓ 通过 (剩余: {remaining})")
        except RateLimitException as e:
            print(f"  请求 {i+1}: ✗ 被限制 - {e}")

    # 测试并发扫描限制
    print(f"\n并发扫描限制: 2 个")
    for i in range(3):
        try:
            await rate_limiter.acquire_scan_slot(user_id)
            current = rate_limiter.get_concurrent_scans(user_id)
            print(f"  扫描 {i+1}: ✓ 获��槽位 (当前: {current})")
        except RateLimitException as e:
            print(f"  扫描 {i+1}: ✗ 无可用槽位 - {e}")


async def demo_audit_logging():
    """演示审计日志功能。"""
    print("\n=== 审计日志演示 ===")

    audit_logger = AuditLogger(
        log_file="logs/demo_audit.log",
        include_sensitive=False
    )

    # 记录各种事件
    await audit_logger.log_auth_success("user123", "example.com")
    print("✓ 记录授权成功")

    await audit_logger.log_scan_start("user123", "example.com", "web", "scan-001")
    print("✓ 记录扫描开始")

    await audit_logger.log_tool_execution(
        "user123",
        "example.com",
        "nmap",
        "nmap -sV example.com",
        "success"
    )
    print("✓ 记录工具执行")

    await audit_logger.log_scan_complete("user123", "example.com", "scan-001", 5)
    print("✓ 记录扫描完成")

    print(f"\n审计日志已保存到: {audit_logger.log_file}")


async def demo_integrated_security():
    """演示集成的安全管理器。"""
    print("\n=== 集成安全管理器演示 ===")

    # 创建安全管理器
    security_manager = SecurityManager(
        auth_manager=AuthorizationManager(),
        scope_validator=ScopeValidator(
            allowed_domains=["*.example.com"],
            blacklist=["*.gov"]
        ),
        audit_logger=AuditLogger(log_file="logs/integrated_audit.log"),
        rate_limiter=RateLimiter(requests_per_minute=10)
    )

    # 生成授权令牌
    target = Target("test.example.com", TargetType.DOMAIN)
    token = security_manager.auth_manager.generate_token(
        user_id="user123",
        target=target,
        permissions=["scan", "report"]
    )

    # 开始扫描（执行所有安全检查）
    try:
        auth = await security_manager.start_scan(
            token=token,
            target=target,
            scan_type="web",
            scan_id="scan-001"
        )
        print(f"✓ 扫描已授权并开始")
        print(f"  用户: {auth.user_id}")
        print(f"  目标: {target.value}")

        # 模拟工具执行
        await security_manager.log_tool_execution(
            auth.user_id,
            target.value,
            "nmap",
            "nmap -sV test.example.com",
            "success"
        )
        print(f"✓ 工具执行已记录")

        # 完成扫描
        await security_manager.complete_scan(
            auth.user_id,
            target.value,
            "scan-001",
            findings_count=3
        )
        print(f"✓ 扫描已完成")

    except Exception as e:
        print(f"✗ 安全检查失败: {e}")


async def main():
    """运行所有演示。"""
    await demo_authorization()
    await demo_scope_validation()
    await demo_rate_limiting()
    await demo_audit_logging()
    await demo_integrated_security()

    print("\n" + "="*50)
    print("所有演示完成！")
    print("="*50)


if __name__ == "__main__":
    asyncio.run(main())
