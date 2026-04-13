"""OpenEnv-compliant server for the Incident Response Triage environment."""

from __future__ import annotations

import sys
import os
import uvicorn

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from openenv.core.env_server import (
    Environment,
    Observation as OpenEnvObservation,
    Action as OpenEnvAction,
    State as OpenEnvState,
    create_app,
)
from pydantic import Field
from typing import Any, Optional

from environment import IncidentTriageEnv
from models import Action as LocalAction
from tasks import TASK_REGISTRY

_MIN = 0.01
_MAX = 0.99

def _clamp(v):
    return max(_MIN, min(_MAX, float(v)))


class TriageAction(OpenEnvAction):
    action_type: str = "investigate"
    target: str = ""
    parameters: dict = Field(default_factory=dict)


class TriageObservation(OpenEnvObservation):
    task_description: str = ""
    alerts: list = Field(default_factory=list)
    logs: list = Field(default_factory=list)
    system_status: dict = Field(default_factory=dict)
    available_actions: list = Field(default_factory=list)
    step_count: int = 0
    max_steps: int = 0
    error_message: Optional[str] = None


class TriageEnvironment(Environment[TriageAction, TriageObservation, OpenEnvState]):

    def __init__(self):
        super().__init__()
        self._env = IncidentTriageEnv()

    def reset(self, seed=None, episode_id=None, **kwargs):
        task_name = kwargs.get("task_name", None)
        if task_name is None:
            task_name = next(iter(TASK_REGISTRY))
        obs = self._env.reset(task_name)
        return TriageObservation(
            task_description=obs.task_description,
            alerts=[a.model_dump() for a in obs.alerts],
            logs=[l.model_dump() for l in obs.logs],
            system_status=obs.system_status,
            available_actions=obs.available_actions,
            step_count=obs.step_count,
            max_steps=obs.max_steps,
            error_message=obs.error_message,
            done=False,
            reward=_clamp(0.5),
        )

    def step(self, action: TriageAction, timeout_s=None, **kwargs):
        try:
            local_action = LocalAction(
                action_type=action.action_type,
                target=action.target,
                parameters=action.parameters,
            )
        except Exception:
            comps = sorted(self._env._current_task.valid_components)
            local_action = LocalAction(
                action_type="escalate",
                target=comps[0],
                parameters={"reason": "invalid action"},
            )
        obs, reward, done, info = self._env.step(local_action)
        return TriageObservation(
            task_description=obs.task_description,
            alerts=[a.model_dump() for a in obs.alerts],
            logs=[l.model_dump() for l in obs.logs],
            system_status=obs.system_status,
            available_actions=obs.available_actions,
            step_count=obs.step_count,
            max_steps=obs.max_steps,
            error_message=obs.error_message,
            done=done,
            reward=_clamp(reward.score),
            metadata=info,
        )

    def state(self):
        s = self._env.state()
        return OpenEnvState(
            episode_id=s.get("task_name", "unknown"),
            step_count=s.get("step_count", 0),
        )


app = create_app(
    env=TriageEnvironment,
    action_cls=TriageAction,
    observation_cls=TriageObservation,
    env_name="incident-triage",
)


def main():
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
