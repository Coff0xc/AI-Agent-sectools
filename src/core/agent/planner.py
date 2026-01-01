"""规划模块 - 将渗透测试目标分解为可执行步骤。"""
import json
from typing import List
from ..llm.base import BaseLLMProvider
from .models import Plan, Action, ActionType


class Planner:
    """AI规划器 - 使用LLM生成执行计划。"""

    def __init__(self, llm_provider: BaseLLMProvider):
        self.llm = llm_provider

    async def create_plan(
        self,
        target: str,
        scan_type: str,
        context: str = ""
    ) -> Plan:
        """创建执行计划。"""
        prompt = self._build_planning_prompt(target, scan_type, context)

        # 使用LLM生成结构化计划
        schema = {
            "type": "object",
            "properties": {
                "goal": {"type": "string"},
                "reasoning": {"type": "string"},
                "actions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},
                            "tool_name": {"type": "string"},
                            "target": {"type": "string"},
                            "params": {"type": "object"},
                            "reasoning": {"type": "string"},
                            "priority": {"type": "integer"}
                        }
                    }
                }
            }
        }

        try:
            result = await self.llm.generate_structured(prompt, schema)

            # 转换为Action对象
            actions = []
            for action_data in result.get("actions", []):
                action = Action(
                    type=ActionType(action_data.get("type", "scan")),
                    tool_name=action_data["tool_name"],
                    target=action_data["target"],
                    params=action_data.get("params", {}),
                    reasoning=action_data.get("reasoning", ""),
                    priority=action_data.get("priority", 1)
                )
                actions.append(action)

            # 按优先级排序
            actions.sort(key=lambda x: x.priority, reverse=True)

            return Plan(
                goal=result.get("goal", f"扫描 {target}"),
                actions=actions,
                reasoning=result.get("reasoning", "")
            )

        except Exception as e:
            # 如果LLM失败，返回默认计划
            return self._create_default_plan(target, scan_type)

    def _build_planning_prompt(
        self,
        target: str,
        scan_type: str,
        context: str
    ) -> str:
        """构建规划提示词。"""
        prompt = f"""你是一个专业的渗透测试AI代理。请为以下目标创建一个详细的扫描计划。

目标: {target}
扫描类型: {scan_type}

{context if context else ""}

可用工具:
1. nmap - 网络端口扫描和服务识别
2. web_scanner - Web应用安全扫描（检查安全头、信息泄露）
3. rest_tester - REST API安全测试（HTTP方法、认证、CORS）

请生成一个JSON格式的执行计划，包含:
- goal: 扫描目标的描述
- reasoning: 为什么选择这些步骤的推理
- actions: 要执行的动作列表，每个动作包含:
  - type: 动作类型 (scan/analyze/exploit/report)
  - tool_name: 使用的工具名称
  - target: 目标地址
  - params: 工具参数（可选）
  - reasoning: 执行此动作的原因
  - priority: 优先级 (1-10, 10最高)

注意:
- 从信息收集开始（如端口扫描）
- 根据扫描类型选择合适的工具
- 按照渗透测试的标准流程组织步骤
- 优先级高的动作会先执行
"""
        return prompt

    def _create_default_plan(self, target: str, scan_type: str) -> Plan:
        """创建默认计划（当LLM失败时）。"""
        actions = []

        if scan_type == "network":
            actions.append(Action(
                type=ActionType.SCAN,
                tool_name="nmap",
                target=target,
                params={"args": ["-sV", "-sC"]},
                reasoning="执行基础端口扫描和服务识别",
                priority=10
            ))
        elif scan_type == "web":
            actions.append(Action(
                type=ActionType.SCAN,
                tool_name="web_scanner",
                target=target,
                reasoning="检查Web应用安全配置",
                priority=10
            ))
        elif scan_type == "api":
            actions.append(Action(
                type=ActionType.SCAN,
                tool_name="rest_tester",
                target=target,
                reasoning="测试API安全性",
                priority=10
            ))

        return Plan(
            goal=f"对 {target} 执行 {scan_type} 扫描",
            actions=actions,
            reasoning="使用默认扫描策略"
        )
