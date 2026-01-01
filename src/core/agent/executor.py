"""执行模块 - 调用工具并解释结果。"""
from ...tools import ToolManager
from ...safety.models import Target, TargetType
from .models import Action, Observation


class Executor:
    """动作执行器。"""

    def __init__(self, tool_manager: ToolManager):
        self.tool_manager = tool_manager

    async def execute_action(self, action: Action) -> Observation:
        """执行单个动作。"""
        try:
            # 创建目标对象
            target = self._create_target(action.target)

            # 执行工具
            result = await self.tool_manager.execute_tool(
                action.tool_name,
                target,
                action.params
            )

            # 创建观察结果
            observation = Observation(
                action=action,
                result=result,
                success=result.is_success(),
                error=result.error if not result.is_success() else None
            )

            return observation

        except Exception as e:
            # 执行失败
            return Observation(
                action=action,
                result=None,
                success=False,
                error=str(e)
            )

    def _create_target(self, target_value: str) -> Target:
        """根据目标值创建Target对象。"""
        # 简单的类型推断
        if target_value.startswith("http"):
            return Target(target_value, TargetType.URL)
        elif "/" in target_value and any(c.isdigit() for c in target_value.split("/")[-1]):
            return Target(target_value, TargetType.CIDR)
        elif all(c.isdigit() or c == "." for c in target_value):
            return Target(target_value, TargetType.IP)
        else:
            return Target(target_value, TargetType.DOMAIN)
