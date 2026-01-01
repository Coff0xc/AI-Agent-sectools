"""AI代理系统完整演示。"""
import asyncio
import os
from src.core.llm import LLMProvider, LLMConfig
from src.core.llm.registry import LLMRegistry
from src.core.agent import Orchestrator
from src.tools import ToolManager
from src.safety import SecurityManager, Target, TargetType


async def demo_ai_agent():
    """演示完整的AI代理扫描流程。"""
    print("="*60)
    print("AI自动化渗透测试代理演示")
    print("="*60)

    # 1. 初始化LLM提供商
    print("\n[初始化] 配置LLM提供商...")
    llm_config = LLMConfig(
        provider=LLMProvider.OPENAI,
        model="gpt-3.5-turbo",
        api_key=os.getenv("OPENAI_API_KEY", "your-api-key"),
        temperature=0.7,
        max_tokens=2000
    )
    llm_provider = LLMRegistry.get_provider(llm_config)

    # 2. 初始化工具管理器
    print("[初始化] 配置工具管理器...")
    tool_manager = ToolManager()

    # 3. 初始化安全管理器
    print("[初始化] 配置安全管理器...")
    security_manager = SecurityManager()

    # 配置允许的目标范围
    security_manager.scope_validator.add_allowed_domain("*.example.com")
    security_manager.scope_validator.add_allowed_domain("httpbin.org")

    # 4. 创建AI代理编排器
    print("[初始化] 创建AI代理编排器...")
    orchestrator = Orchestrator(
        llm_provider=llm_provider,
        tool_manager=tool_manager,
        security_manager=security_manager,
        max_iterations=5
    )

    # 5. 生成授权令牌
    print("\n[授权] 生成扫描授权令牌...")
    target = Target("httpbin.org", TargetType.DOMAIN)
    auth_token = security_manager.auth_manager.generate_token(
        user_id="demo_user",
        target=target,
        permissions=["scan", "report"]
    )
    print(f"[授权] 令牌生成成功: {auth_token[:20]}...")

    # 6. 运行AI驱动的扫描
    print("\n[扫描] 开始AI驱动的自动化扫描...")
    print("-"*60)

    try:
        context = await orchestrator.run_scan(
            target="https://httpbin.org",
            scan_type="web",
            auth_token=auth_token
        )

        # 7. 显示结果
        print("\n" + "="*60)
        print("扫描结果摘要")
        print("="*60)

        print(f"\n扫描ID: {context.scan_id}")
        print(f"目标: {context.target}")
        print(f"类型: {context.scan_type}")
        print(f"状态: {context.state.value}")
        print(f"执行动作数: {len(context.observations)}")
        print(f"发现问题数: {len(context.findings)}")

        # 显示计划
        if context.plan:
            print(f"\n执行计划:")
            print(f"  目标: {context.plan.goal}")
            print(f"  推理: {context.plan.reasoning}")
            print(f"  动作数: {len(context.plan.actions)}")

        # 显示发现
        if context.findings:
            print(f"\n安全发现:")
            severity_count = {}
            for finding in context.findings:
                severity = finding.get("severity", "unknown")
                severity_count[severity] = severity_count.get(severity, 0) + 1

            for severity, count in severity_count.items():
                print(f"  [{severity.upper()}]: {count} 个")

            print(f"\n详细发现（前5个）:")
            for i, finding in enumerate(context.findings[:5], 1):
                print(f"\n  {i}. [{finding.get('severity', 'unknown').upper()}] {finding.get('type', '')}")
                print(f"     {finding.get('description', '')}")

        # 显示分析
        if 'analysis' in context.metadata:
            analysis = context.metadata['analysis']
            print(f"\n风险分析:")
            print(f"  风险分数: {analysis['risk_score']}")
            print(f"  建议:")
            for rec in analysis.get('recommendations', []):
                print(f"    - {rec}")

    except Exception as e:
        print(f"\n[错误] 扫描失败: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "="*60)
    print("演示完成")
    print("="*60)


async def demo_without_llm():
    """演示不使用LLM的基础扫描（使用默认计划）。"""
    print("\n" + "="*60)
    print("基础扫描演示（无LLM）")
    print("="*60)

    # 使用模拟的LLM提供商（或者直接使用默认计划）
    tool_manager = ToolManager()
    security_manager = SecurityManager()

    # 配置允许的目标
    security_manager.scope_validator.add_allowed_domain("*.example.com")

    # 生成授权
    target = Target("example.com", TargetType.DOMAIN)
    auth_token = security_manager.auth_manager.generate_token(
        user_id="demo_user",
        target=target,
        permissions=["scan"]
    )

    # 直接执行工具（不使用AI代理）
    print("\n[扫描] 执行Web安全扫描...")
    result = await tool_manager.execute_tool(
        "web_scanner",
        Target("https://example.com", TargetType.URL)
    )

    print(f"状态: {result.status}")
    print(f"执行时间: {result.execution_time:.2f}秒")
    print(f"发现: {len(result.parsed_data.get('findings', []))} 个问题")

    if result.parsed_data.get('findings'):
        print("\n发现的问题:")
        for finding in result.parsed_data['findings']:
            print(f"  - [{finding['severity'].upper()}] {finding['description']}")


if __name__ == "__main__":
    print("选择演示模式:")
    print("1. 完整AI代理演示（需要OpenAI API密钥）")
    print("2. 基础扫描演示（无需LLM）")

    # 默认运行基础演示
    print("\n运行基础扫描演示...")
    asyncio.run(demo_without_llm())

    # 如果有API密钥，可以运行完整演示
    # asyncio.run(demo_ai_agent())
