"""编排器 - 协调整个AI代理流程。"""
import uuid
from typing import Optional
from ..llm.base import BaseLLMProvider
from ...tools import ToolManager
from ...safety import SecurityManager, Target, TargetType
from .models import AgentState, AgentContext
from .memory import Memory
from .planner import Planner
from .executor import Executor
from .reflector import Reflector


class Orchestrator:
    """AI代理编排器 - 协调Planning→Execution→Reflection循环。"""

    def __init__(
        self,
        llm_provider: BaseLLMProvider,
        tool_manager: ToolManager,
        security_manager: SecurityManager,
        max_iterations: int = 10
    ):
        self.llm = llm_provider
        self.tool_manager = tool_manager
        self.security = security_manager
        self.max_iterations = max_iterations

        # 初始化各个模块
        self.memory = Memory()
        self.planner = Planner(llm_provider)
        self.executor = Executor(tool_manager)
        self.reflector = Reflector(llm_provider)

    async def run_scan(
        self,
        target: str,
        scan_type: str,
        auth_token: str
    ) -> AgentContext:
        """
        运行完整的AI驱动扫描。

        Args:
            target: 扫描目标
            scan_type: 扫描类型 (web/network/api)
            auth_token: 授权令牌

        Returns:
            AgentContext: 扫描上下文（包含所有结果）
        """
        # 生成扫描ID
        scan_id = str(uuid.uuid4())

        # 创建目标对象
        target_obj = self._create_target(target)

        # 安全验证
        auth = await self.security.start_scan(
            auth_token,
            target_obj,
            scan_type,
            scan_id
        )

        # 创建上下文
        context = self.memory.create_context(scan_id, target, scan_type)
        context.state = AgentState.PLANNING

        try:
            # 阶段1: 规划
            print(f"[规划] 为 {target} 创建扫描计划...")
            plan = await self.planner.create_plan(target, scan_type)
            context.plan = plan
            print(f"[规划] 计划创建完成，共 {len(plan.actions)} 个动作")

            # 阶段2: 执行循环
            context.state = AgentState.EXECUTING
            iteration = 0

            for action in plan.actions:
                if iteration >= self.max_iterations:
                    print(f"[执行] 达到最大迭代次数 ({self.max_iterations})")
                    break

                print(f"\n[执行] 动作 {iteration + 1}: {action.tool_name}")
                print(f"[执行] 推理: {action.reasoning}")

                # 执行动作
                observation = await self.executor.execute_action(action)

                # 记录观察
                self.memory.add_observation(scan_id, observation)

                # 记录到审计日志
                await self.security.log_tool_execution(
                    auth.user_id,
                    target,
                    action.tool_name,
                    f"{action.tool_name} {action.target}",
                    "success" if observation.success else "failed"
                )

                if observation.success:
                    findings_count = 0
                    if hasattr(observation.result, 'parsed_data'):
                        findings_count = len(observation.result.parsed_data.get('findings', []))
                    print(f"[执行] 成功 - 发现 {findings_count} 个问题")
                else:
                    print(f"[执行] 失败 - {observation.error}")

                iteration += 1

            # 阶段3: 反思
            context.state = AgentState.REFLECTING
            print(f"\n[反思] 分析执行结果...")

            reflection = await self.reflector.reflect(
                context.observations,
                self.memory.get_conversation_history(scan_id)
            )

            print(f"[反思] {reflection['summary']}")

            # 分析发现
            if context.findings:
                analysis = await self.reflector.analyze_findings(context.findings)
                context.metadata['analysis'] = analysis
                print(f"[分析] 风险分数: {analysis['risk_score']}")
                print(f"[分析] 发现分布: {analysis['severity_distribution']}")

            # 完成扫描
            context.state = AgentState.COMPLETED
            await self.security.complete_scan(
                auth.user_id,
                target,
                scan_id,
                len(context.findings)
            )

            print(f"\n[完成] 扫描完成，共发现 {len(context.findings)} 个问题")

            return context

        except Exception as e:
            context.state = AgentState.FAILED
            context.metadata['error'] = str(e)
            print(f"\n[错误] 扫描失败: {e}")
            raise

    def _create_target(self, target_value: str) -> Target:
        """创建Target对象。"""
        if target_value.startswith("http"):
            return Target(target_value, TargetType.URL)
        elif "/" in target_value:
            return Target(target_value, TargetType.CIDR)
        elif all(c.isdigit() or c == "." for c in target_value):
            return Target(target_value, TargetType.IP)
        else:
            return Target(target_value, TargetType.DOMAIN)

    def get_scan_result(self, scan_id: str) -> AgentContext:
        """获取扫描结果。"""
        return self.memory.get_context(scan_id)
