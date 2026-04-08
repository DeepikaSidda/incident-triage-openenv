"""Pydantic data models for the OpenEnv Incident Response Triage environment."""

from typing import Literal

from pydantic import BaseModel, Field


class Alert(BaseModel):
    """A notification indicating a potential security or operational issue."""

    id: str
    timestamp: str
    source: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    message: str


class LogEntry(BaseModel):
    """A timestamped record of system, network, or application activity."""

    timestamp: str
    source: str
    level: str
    content: str


class Observation(BaseModel):
    """The current visible state of an incident scenario returned by the environment."""

    task_description: str
    alerts: list[Alert]
    logs: list[LogEntry]
    system_status: dict[str, str]
    available_actions: list[str]
    step_count: int
    max_steps: int
    error_message: str | None = None


class Action(BaseModel):
    """An investigation or remediation step submitted by the agent."""

    action_type: Literal[
        "investigate", "classify", "correlate", "remediate", "escalate", "report"
    ]
    target: str
    parameters: dict = {}


class Reward(BaseModel):
    """A score representing the quality of the agent's most recent action."""

    score: float = Field(ge=0.0, le=1.0)

from dataclasses import dataclass, field


@dataclass
class GroundTruth:
    """Static ground-truth data for evaluating agent performance on a task."""

    severity: str
    malicious_ips: list[str]
    compromised_hosts: list[str]
    compromised_accounts: list[str]
    attack_method: str
    exfil_destination: str | None
    correlated_alert_groups: list[list[str]]
    correct_remediations: list[dict]
    incorrect_remediations: list[dict]
    report_required_fields: dict[str, str]


@dataclass
class TaskDefinition:
    """A complete incident scenario with initial state, ground truth, and grading rubric."""

    name: str
    difficulty: str
    max_steps: int
    description: str
    initial_alerts: list[Alert]
    initial_logs: list[LogEntry]
    system_status: dict[str, str]
    network_topology: dict[str, list[str]]
    valid_components: set[str]
    ground_truth: GroundTruth
    investigable_sources: dict[str, list[LogEntry]] = field(default_factory=dict)
    rubric_weights: dict[str, float] = field(default_factory=dict)
