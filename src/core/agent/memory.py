"""记忆管理模块。"""
from typing import List, Dict, Any
from .models import AgentContext, Observation, Action


class Memory:
    """代理记忆管理器。"""

    def __init__(self, max_history: int = 10):
        self.max_history = max_history
        self.contexts: Dict[str, AgentContext] = {}

    def create_context(
        self,
        scan_id: str,
        target: str,
        scan_type: str
    ) -> AgentContext:
        """创建新的上下文。"""
        context = AgentContext(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type
        )
        self.contexts[scan_id] = context
        return context

    def get_context(self, scan_id: str) -> AgentContext:
        """获取上下文。"""
        if scan_id not in self.contexts:
            raise KeyError(f"未找到扫描上下文: {scan_id}")
        return self.contexts[scan_id]

    def add_observation(self, scan_id: str, observation: Observation) -> None:
        """添加观察结果。"""
        context = self.get_context(scan_id)
        context.add_observation(observation)

    def get_conversation_history(self, scan_id: str) -> str:
        """获取对话历史（用于LLM上下文）。"""
        context = self.get_context(scan_id)
        history = []

        # 添加目标和计划
        history.append(f"目标: {context.target}")
        history.append(f"扫描类型: {context.scan_type}")

        if context.plan:
            history.append(f"\n当前计划: {context.plan.goal}")
            history.append(f"计划推理: {context.plan.reasoning}")

        # 添加最近的观察
        recent_obs = context.get_recent_observations(self.max_history)
        if recent_obs:
            history.append("\n最近的执行历史:")
            for i, obs in enumerate(recent_obs, 1):
                history.append(f"\n{i}. 动作: {obs.action.tool_name}")
                history.append(f"   推理: {obs.action.reasoning}")
                if obs.success:
                    findings_count = 0
                    if hasattr(obs.result, 'parsed_data'):
                        findings_count = len(obs.result.parsed_data.get('findings', []))
                    history.append(f"   结果: 成功 (发现 {findings_count} 个问题)")
                else:
                    history.append(f"   结果: 失败 - {obs.error}")

        # 添加总结
        history.append(f"\n总计: 已执行 {len(context.observations)} 个动作，发现 {len(context.findings)} 个问题")

        return "\n".join(history)

    def get_findings_summary(self, scan_id: str) -> List[Dict[str, Any]]:
        """获取发现摘要。"""
        context = self.get_context(scan_id)
        return context.findings

    def clear_context(self, scan_id: str) -> None:
        """清除上下文。"""
        if scan_id in self.contexts:
            del self.contexts[scan_id]
