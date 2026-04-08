"""FastAPI server exposing the OpenEnv Incident Response Triage environment.

Provides REST endpoints for the OpenEnv interface: reset, step, state, and
task listing. This keeps the HF Space running and accessible for evaluation.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Optional

from environment import IncidentTriageEnv
from models import Action
from tasks import TASK_REGISTRY

app = FastAPI(
    title="Incident Response Triage — OpenEnv",
    description="OpenEnv-compliant environment for IT/security incident response triage",
    version="1.0.0",
)

# Single shared environment instance
env = IncidentTriageEnv()


class ResetRequest(BaseModel):
    task_name: str | None = None


class StepRequest(BaseModel):
    action_type: str
    target: str
    parameters: dict = {}


class StepResponse(BaseModel):
    observation: dict
    reward: float
    done: bool
    info: dict


@app.get("/")
def root():
    """Health check and environment info."""
    return {
        "environment": "incident-triage",
        "version": "1.0.0",
        "tasks": list(TASK_REGISTRY.keys()),
        "status": "running",
    }


@app.get("/tasks")
def list_tasks():
    """List all available tasks with metadata."""
    return {
        name: {
            "difficulty": t.difficulty,
            "max_steps": t.max_steps,
            "description": t.description,
        }
        for name, t in TASK_REGISTRY.items()
    }


@app.post("/reset")
def reset(req: Optional[ResetRequest] = Body(default=None)):
    """Reset the environment to a task's initial state."""
    try:
        task_name = req.task_name if req else None
        obs = env.reset(task_name)
        return {"observation": obs.model_dump()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/step")
def step(req: StepRequest):
    """Submit an action and receive observation, reward, done, info."""
    try:
        action = Action(
            action_type=req.action_type,
            target=req.target,
            parameters=req.parameters,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid action: {e}")

    obs, reward, done, info = env.step(action)
    return StepResponse(
        observation=obs.model_dump(),
        reward=reward.score,
        done=done,
        info=info,
    )


@app.get("/state")
def state():
    """Return the current environment state."""
    return env.state()
