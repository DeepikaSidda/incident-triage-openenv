"""Baseline inference script for the OpenEnv Incident Response Triage environment.

Drives an LLM agent through all registered tasks using the OpenAI API client.
Outputs structured [START]/[STEP]/[END] lines to stdout for evaluation.

Usage:
    HF_TOKEN=<token> python inference.py
    HF_TOKEN=<token> MODEL_NAME=gpt-4.1-mini API_BASE_URL=https://api.openai.com/v1 python inference.py
"""

from __future__ import annotations

import json
import os
import sys
import time

from openai import OpenAI

from environment import IncidentTriageEnv
from models import Action
from tasks import TASK_REGISTRY

# ---------------------------------------------------------------------------
# 7.1 — Environment variables and OpenAI client
# ---------------------------------------------------------------------------

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4.1-mini")
HF_TOKEN = os.getenv("HF_TOKEN")

if HF_TOKEN is None:
    raise SystemExit(
        "ERROR: HF_TOKEN environment variable is required. "
        "Set it to your API key before running inference."
    )

client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_LLM_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 1.0

SYSTEM_PROMPT = (
    "You are an expert incident response agent. You are investigating a security "
    "incident and must take actions to triage, investigate, classify, correlate, "
    "remediate, and report on the incident.\n\n"
    "At each step you receive an observation describing the current state of the "
    "incident: alerts, logs, system status, and available actions.\n\n"
    "You MUST respond with a single JSON object (no markdown, no explanation) "
    "with exactly these keys:\n"
    '  {"action_type": "<type>", "target": "<component>", "parameters": {<params>}}\n\n'
    "Valid action_type values: investigate, classify, correlate, remediate, escalate, report\n\n"
    "Guidelines:\n"
    "- investigate: target a system component to reveal hidden logs. parameters can be empty.\n"
    "- classify: target any component, set parameters to {\"severity\": \"Critical|High|Medium|Low\"}\n"
    "- correlate: target any component, set parameters to {\"alert_ids\": [\"id1\", \"id2\", ...]}\n"
    "- remediate: target the component to act on, parameters describe the action "
    "(e.g. {\"action\": \"block_ip\", \"ip\": \"1.2.3.4\"})\n"
    "- escalate: target any component, parameters can include {\"reason\": \"...\"}\n"
    "- report: target any component, parameters should include summary fields like "
    "severity, root_cause, affected_systems, actions_taken, source_ip, etc.\n"
)


# ---------------------------------------------------------------------------
# 7.3 — Helper: call LLM with retry + exponential backoff
# ---------------------------------------------------------------------------


def call_llm(observation_json: str) -> str | None:
    """Send the observation to the LLM and return the raw response text.

    Retries up to MAX_LLM_RETRIES times with exponential backoff on API errors.
    Returns None if all retries are exhausted.
    """
    backoff = INITIAL_BACKOFF_SECONDS
    for attempt in range(1, MAX_LLM_RETRIES + 1):
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": observation_json},
                ],
                temperature=0.0,
            )
            return response.choices[0].message.content
        except Exception as exc:
            print(
                f"[stderr] LLM API error (attempt {attempt}/{MAX_LLM_RETRIES}): {exc}",
                file=sys.stderr,
            )
            if attempt < MAX_LLM_RETRIES:
                time.sleep(backoff)
                backoff *= 2
    return None


# ---------------------------------------------------------------------------
# 7.3 — Helper: parse LLM response into an Action
# ---------------------------------------------------------------------------


def parse_action(raw_text: str | None, valid_components: set[str]) -> Action:
    """Parse the LLM response text into an Action.

    On failure, returns a default investigate action targeting the first valid
    component.
    """
    fallback_target = sorted(valid_components)[0] if valid_components else "unknown"
    fallback = Action(action_type="investigate", target=fallback_target, parameters={})

    if raw_text is None:
        print("[stderr] LLM returned no response; using fallback action.", file=sys.stderr)
        return fallback

    # Strip markdown code fences if present
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last lines (fences)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"[stderr] Failed to parse LLM response as JSON: {exc}", file=sys.stderr)
        print(f"[stderr] Raw response: {raw_text[:200]}", file=sys.stderr)
        return fallback

    try:
        return Action(
            action_type=data.get("action_type", "investigate"),
            target=data.get("target", fallback_target),
            parameters=data.get("parameters", {}),
        )
    except Exception as exc:
        print(f"[stderr] Failed to construct Action from parsed JSON: {exc}", file=sys.stderr)
        return fallback


# ---------------------------------------------------------------------------
# 7.2 — Helper: format observation as a prompt string
# ---------------------------------------------------------------------------


def observation_to_prompt(obs) -> str:
    """Convert an Observation to a JSON string for the LLM prompt."""
    return json.dumps(
        {
            "task_description": obs.task_description,
            "alerts": [a.model_dump() for a in obs.alerts],
            "logs": [l.model_dump() for l in obs.logs],
            "system_status": obs.system_status,
            "available_actions": obs.available_actions,
            "step_count": obs.step_count,
            "max_steps": obs.max_steps,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# 7.2 — Main task iteration loop
# ---------------------------------------------------------------------------


def run_all_tasks() -> dict[str, float]:
    """Execute all registered tasks and return a mapping of task_name -> final_score."""
    env = IncidentTriageEnv()
    results: dict[str, float] = {}

    for task_name in TASK_REGISTRY:
        final_score = 0.0
        rewards: list[float] = []
        step_num = 0
        success = False

        print(f"[START] task={task_name} env=incident-triage model={MODEL_NAME}")

        try:
            obs = env.reset(task_name)
            task_def = TASK_REGISTRY[task_name]
            done = False

            while not done:
                # Build prompt and call LLM
                prompt_text = observation_to_prompt(obs)
                raw_response = call_llm(prompt_text)
                action = parse_action(raw_response, task_def.valid_components)

                # Step the environment
                obs, reward, done, info = env.step(action)
                step_num += 1
                rewards.append(reward.score)

                # Determine error string
                error_str = obs.error_message if obs.error_message else "null"

                # Format action as a readable string
                action_str = f"{action.action_type}('{action.target}')"

                print(
                    f"[STEP]  step={step_num} "
                    f"action={action_str} "
                    f"reward={reward.score:.2f} "
                    f"done={'true' if done else 'false'} "
                    f"error={error_str}"
                )

                if done:
                    final_score = info.get("final_score", 0.0)
                    success = True

        except Exception as exc:
            print(f"[stderr] Environment error on task '{task_name}': {exc}", file=sys.stderr)
            success = False
            final_score = 0.0

        # Always emit [END]
        rewards_str = ",".join(f"{r:.2f}" for r in rewards) if rewards else ""
        print(
            f"[END]   success={'true' if success else 'false'} "
            f"steps={step_num} "
            f"rewards={rewards_str}"
        )

        results[task_name] = final_score

    return results


# ---------------------------------------------------------------------------
# 7.2 — Summary table
# ---------------------------------------------------------------------------


def print_summary(results: dict[str, float]) -> None:
    """Print a summary table of all task scores."""
    print("\n" + "=" * 50)
    print("SUMMARY — Incident Triage Baseline Scores")
    print("=" * 50)
    print(f"{'Task':<30} {'Score':>8}")
    print("-" * 50)
    for task_name, score in results.items():
        print(f"{task_name:<30} {score:>8.4f}")
    print("-" * 50)
    if results:
        avg = sum(results.values()) / len(results)
        print(f"{'Average':<30} {avg:>8.4f}")
    print("=" * 50)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    task_results = run_all_tasks()
    print_summary(task_results)
