"""反思模块 - 分析结果并调整策略。"""
from typing import List, Dict, Any
from ..llm.base import BaseLLMProvider
from .models import Observation, Action, ActionType


class Reflector:
    """AI反思器 - 分析执行结果并提供建议。"""

    def __init__(self, llm_provider: BaseLLMProvider):
        self.llm = llm_provider

    async def reflect(
        self,
        observations: List[Observation],
        context: str = ""
    ) -> Dict[str, Any]:
        """
        反思执行结果。

        Returns:
            Dict包含:
            - summary: 结果摘要
            - insights: 洞察和发现
            - next_actions: 建议的下一步动作
            - should_continue: 是否应该继续
        """
        prompt = self._build_reflection_prompt(observations, context)

        try:
            response = await self.llm.generate(prompt)

            # 解析LLM响应
            reflection = self._parse_reflection(response)
            return reflection

        except Exception as e:
            # 如果LLM失败，返回基础反思
            return self._create_basic_reflection(observations)

    def _build_reflection_prompt(
        self,
        observations: List[Observation],
        context: str
    ) -> str:
        """构建反思提示词。"""
        # 构建观察历史
        obs_text = []
        for i, obs in enumerate(observations, 1):
            obs_text.append(f"\n动作 {i}:")
            obs_text.append(f"  工具: {obs.action.tool_name}")
            obs_text.append(f"  目标: {obs.action.target}")
            obs_text.append(f"  推理: {obs.action.reasoning}")

            if obs.success:
                findings_count = 0
                if hasattr(obs.result, 'parsed_data'):
                    findings_count = len(obs.result.parsed_data.get('findings', []))
                obs_text.append(f"  结果: 成功 (发现 {findings_count} 个问题)")
            else:
                obs_text.append(f"  结果: 失败 - {obs.error}")

        prompt = f"""你是一个专业的渗透测试AI代理。请分析以下执行结果并提供反思。

{context}

执行历史:
{"".join(obs_text)}

请提供:
1. 结果摘要 - 简要总结执行情况
2. 关键洞察 - 从结果中发现的重要信息
3. 下一步建议 - 基于当前结果，建议接下来应该做什么
4. 是否继续 - 判断是否需要继续扫描

请用清晰、专业的语言回答。
"""
        return prompt

    def _parse_reflection(self, response: str) -> Dict[str, Any]:
        """解析LLM反思响应。"""
        # 简单解析（实际应用中可以使用更复杂的解析逻辑）
        return {
            "summary": response[:200] if len(response) > 200 else response,
            "insights": [response],
            "next_actions": [],
            "should_continue": "继续" in response or "下一步" in response
        }

    def _create_basic_reflection(
        self,
        observations: List[Observation]
    ) -> Dict[str, Any]:
        """创建基础反思（当LLM失败时）。"""
        success_count = sum(1 for obs in observations if obs.success)
        total_findings = 0

        for obs in observations:
            if obs.success and hasattr(obs.result, 'parsed_data'):
                total_findings += len(obs.result.parsed_data.get('findings', []))

        return {
            "summary": f"执行了 {len(observations)} 个动作，{success_count} 个成功，发现 {total_findings} 个问题",
            "insights": [
                f"成功率: {success_count}/{len(observations)}",
                f"总发现: {total_findings} 个安全问题"
            ],
            "next_actions": [],
            "should_continue": total_findings > 0
        }

    async def analyze_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """分析发现的安全问题。"""
        if not findings:
            return {
                "severity_distribution": {},
                "recommendations": ["未发现明显的安全问题"],
                "risk_score": 0
            }

        # 统计严重程度分布
        severity_dist = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            severity_dist[severity] = severity_dist.get(severity, 0) + 1

        # 计算风险分数
        risk_score = (
            severity_dist.get("high", 0) * 10 +
            severity_dist.get("medium", 0) * 5 +
            severity_dist.get("low", 0) * 1
        )

        return {
            "severity_distribution": severity_dist,
            "total_findings": len(findings),
            "risk_score": risk_score,
            "recommendations": self._generate_recommendations(findings)
        }

    def _generate_recommendations(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """生成修复建议。"""
        recommendations = []

        # 基于发现类型生成建议
        finding_types = set(f.get("type") for f in findings)

        if "missing_security_header" in finding_types:
            recommendations.append("添加缺失的安全响应头（X-Frame-Options, CSP等）")

        if "information_disclosure" in finding_types:
            recommendations.append("隐藏服务器版本信息，避免信息泄露")

        if "insecure_cors" in finding_types:
            recommendations.append("限制CORS配置，不要使用通配符'*'")

        if "dangerous_http_method" in finding_types:
            recommendations.append("禁用不必要的HTTP方法（PUT, DELETE等）")

        if not recommendations:
            recommendations.append("继续进行深入的安全测试")

        return recommendations
