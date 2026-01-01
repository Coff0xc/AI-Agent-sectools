"""工具执行框架使用示例。"""
import asyncio
from src.tools import ToolManager, ToolCategory
from src.safety import Target, TargetType


async def demo_nmap_scan():
    """演示Nmap扫描。"""
    print("=== Nmap网络扫描演示 ===")

    tool_manager = ToolManager()

    # 创建目标
    target = Target("scanme.nmap.org", TargetType.DOMAIN)

    # 执行Nmap扫描
    print(f"扫描目标: {target.value}")
    result = await tool_manager.execute_tool(
        "nmap",
        target,
        params={"args": ["-sV", "-p", "80,443"]}
    )

    print(f"状态: {result.status}")
    print(f"执行时间: {result.execution_time:.2f}秒")
    print(f"发现: {len(result.parsed_data.get('findings', []))} 个")

    # 显示开放端口
    open_ports = result.parsed_data.get("open_ports", [])
    if open_ports:
        print("\n开放端口:")
        for port_info in open_ports:
            print(f"  - {port_info['port']}/{port_info['protocol']}: {port_info['service']}")


async def demo_web_scanner():
    """演示Web扫描。"""
    print("\n=== Web应用扫描演示 ===")

    tool_manager = ToolManager()

    # 创建目标
    target = Target("https://example.com", TargetType.URL)

    # 执行Web扫描
    print(f"扫描目标: {target.value}")
    result = await tool_manager.execute_tool("web_scanner", target)

    print(f"状态: {result.status}")
    print(f"执行时间: {result.execution_time:.2f}秒")

    # 显示发现
    findings = result.parsed_data.get("findings", [])
    if findings:
        print(f"\n发现 {len(findings)} 个安全问题:")
        for finding in findings:
            severity = finding.get("severity", "unknown")
            description = finding.get("description", "")
            print(f"  [{severity.upper()}] {description}")


async def demo_api_tester():
    """演示API测试。"""
    print("\n=== API安全测试演示 ===")

    tool_manager = ToolManager()

    # 创建目标
    target = Target("https://api.example.com", TargetType.URL)

    # 执行API测试
    print(f"测试目标: {target.value}")
    result = await tool_manager.execute_tool("rest_tester", target)

    print(f"状态: {result.status}")
    print(f"执行时间: {result.execution_time:.2f}秒")

    # 显示发现
    findings = result.parsed_data.get("findings", [])
    if findings:
        print(f"\n发现 {len(findings)} 个API安全问题:")
        for finding in findings:
            severity = finding.get("severity", "unknown")
            ftype = finding.get("type", "")
            description = finding.get("description", "")
            print(f"  [{severity.upper()}] {ftype}: {description}")
    else:
        print("\n未发现明显的安全问题")


async def demo_tool_registry():
    """演示工具注册表。"""
    print("\n=== 工具注册表演示 ===")

    tool_manager = ToolManager()

    # 列出所有工具
    all_tools = tool_manager.list_available_tools()
    print(f"可用工具 ({len(all_tools)}):")
    for tool in all_tools:
        print(f"  - {tool}")

    # 按类别列出工具
    print("\n按类别分类:")
    for category in ToolCategory:
        tools = tool_manager.get_tools_by_category(category)
        if tools:
            print(f"  {category.value}: {', '.join(tools)}")


async def demo_parallel_execution():
    """演示并行执行多个工具。"""
    print("\n=== 并行执行演示 ===")

    tool_manager = ToolManager()

    # 创建目标
    target = Target("example.com", TargetType.DOMAIN)

    print(f"并行扫描目标: {target.value}")

    # 并行执行多个工具
    tasks = [
        tool_manager.execute_tool("web_scanner", Target(f"https://{target.value}", TargetType.URL)),
        tool_manager.execute_tool("rest_tester", Target(f"https://api.{target.value}", TargetType.URL)),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    print(f"\n完成 {len(results)} 个扫描:")
    for i, result in enumerate(results, 1):
        if isinstance(result, Exception):
            print(f"  扫描 {i}: 失败 - {result}")
        else:
            print(f"  扫描 {i}: {result.status} - {result.tool_name} ({result.execution_time:.2f}秒)")


async def main():
    """运行所有演示。"""
    # 注意：某些演示需要实际的网络连接和Docker环境

    # 演示工具注册表
    await demo_tool_registry()

    # 演示Web扫描（不需要Docker）
    try:
        await demo_web_scanner()
    except Exception as e:
        print(f"Web扫描演示失败: {e}")

    # 演示API测试（不需要Docker）
    try:
        await demo_api_tester()
    except Exception as e:
        print(f"API测试演示失败: {e}")

    # 演示Nmap扫描（需要Docker）
    # try:
    #     await demo_nmap_scan()
    # except Exception as e:
    #     print(f"Nmap扫描演示失败: {e}")

    # 演示并行执行
    try:
        await demo_parallel_execution()
    except Exception as e:
        print(f"并行执行演示失败: {e}")

    print("\n" + "="*50)
    print("所有演示完成！")
    print("="*50)


if __name__ == "__main__":
    asyncio.run(main())
