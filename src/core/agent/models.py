"""AI代理数据模型。"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum


class AgentState(str, Enum):
    """代理状态。"""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    REFLECTING = "reflecting"
    COMPLETED = "completed"
    FAILED = "failed"


class ActionType(str, Enum):
    """动作类型。"""
    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    REPORT = "report"


@dataclass
class Action:
    """代理动作。"""
    type: ActionType
    tool_name: str
    target: str
    params: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    priority: int = 1


@dataclass
class Observation:
    """观察结果。"""
    action: Action
    result: Any
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    error: Optional[str] = None


@dataclass
class Plan:
    """执行计划。"""
    goal: str
    actions: List[Action] = field(default_factory=list)
    reasoning: str = ""
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class AgentContext:
    """代理上下文。"""
    scan_id: str
    target: str
    scan_type: str
    state: AgentState = AgentState.IDLE
    plan: Optional[Plan] = None
    observations: List[Observation] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def add_observation(self, observation: Observation) -> None:
        """添加观察结果。"""
        self.observations.append(observation)

        # 如果观察成功且有发现，添加到findings
        if observation.success and hasattr(observation.result, 'parsed_data'):
            result_findings = observation.result.parsed_data.get('findings', [])
            self.findings.extend(result_findings)

    def get_recent_observations(self, count: int = 5) -> List[Observation]:
        """获取最近的观察结果。"""
        return self.observations[-count:]

    def get_summary(self) -> str:
        """获取上下文摘要。"""
        return f"""
扫描ID: {self.scan_id}
目标: {self.target}
类型: {self.scan_type}
状态: {self.state.value}
已执行动作: {len(self.observations)}
发现问题: {len(self.findings)}
"""
