"""Core environment for the OpenEnv Incident Response Triage.

Implements the OpenEnv interface: reset(), step(), state().
"""

from __future__ import annotations

from pydantic import ValidationError

from grader import Grader
from models import Action, LogEntry, Observation, Reward, TaskDefinition
from tasks import TASK_REGISTRY

# Actions always available to the agent regardless of state.
AVAILABLE_ACTIONS: list[str] = [
    "investigate",
    "classify",
    "correlate",
    "remediate",
    "escalate",
    "report",
]


class IncidentTriageEnv:
    """OpenEnv-compliant incident response triage environment."""

    def __init__(self) -> None:
        self._grader = Grader()

        # Internal state — all initialised properly in reset()
        self._current_task: TaskDefinition | None = None
        self._step_count: int = 0
        self._done: bool = False
        self._action_history: list[dict] = []
        self._discovered_info: dict = {}
        self._score_accumulator: dict[str, float] = {}
        self._consecutive_repeat_count: int = 0
        self._last_action: dict | None = None
        self._revealed_logs: list[LogEntry] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def reset(self, task_name: str | None = None) -> Observation:
        """Load a task and return the initial observation.

        Parameters
        ----------
        task_name : str | None
            Name of the task to load.  Defaults to the first registered task.
        """
        if task_name is None:
            task_name = next(iter(TASK_REGISTRY))

        if task_name not in TASK_REGISTRY:
            raise ValueError(
                f"Unknown task '{task_name}'. "
                f"Available: {list(TASK_REGISTRY.keys())}"
            )

        task = TASK_REGISTRY[task_name]
        self._current_task = task
        self._step_count = 0
        self._done = False
        self._action_history = []
        self._discovered_info = {
            "investigated_sources": set(),
            "classified_severity": None,
            "correlated_groups": [],
            "remediations_taken": [],
            "report_submitted": False,
            "report_data": None,
        }
        self._score_accumulator = {k: 0.0 for k in task.rubric_weights}
        self._consecutive_repeat_count = 0
        self._last_action = None
        self._revealed_logs = []

        return self._build_observation()

    def step(
        self, action: Action
    ) -> tuple[Observation, Reward, bool, dict]:
        """Process an agent action and return (observation, reward, done, info).

        Parameters
        ----------
        action : Action
            The action submitted by the agent.
        """
        task = self._current_task
        assert task is not None, "Call reset() before step()"

        # If already done, return terminal observation immediately.
        if self._done:
            return self._terminal_response()

        # --- Validate action_type via Pydantic ---
        try:
            # Re-validate to catch raw dicts that bypass construction
            if not isinstance(action, Action):
                action = Action(**action)  # type: ignore[arg-type]
        except (ValidationError, TypeError) as exc:
            return self._error_step(
                f"Invalid action: {exc}"
            )

        # --- Validate target ---
        if action.target not in task.valid_components:
            return self._error_step(
                f"Invalid target '{action.target}'. "
                f"Valid components: {sorted(task.valid_components)}"
            )

        # --- Track consecutive repeats ---
        action_dict = action.model_dump()
        self._update_repeat_tracking(action_dict)

        # --- Delegate to action handler ---
        error_message: str | None = None
        handler = self._action_handlers().get(action.action_type)
        if handler is not None:
            error_message = handler(action)

        # --- Score the step via grader ---
        step_reward = self._grader.score_step(
            action, task, self._get_env_state_dict()
        )

        # --- Apply repeat penalty on third+ consecutive repeat ---
        if self._consecutive_repeat_count >= 3:
            step_reward -= 0.05
            warning = (
                "Warning: you have repeated the same action "
                f"{self._consecutive_repeat_count} times consecutively. "
                "Try a different approach."
            )
            if error_message:
                error_message = f"{error_message}; {warning}"
            else:
                error_message = warning

        # --- Update bookkeeping ---
        self._step_count += 1
        self._action_history.append(action_dict)

        # --- Check termination ---
        info: dict = {}
        if self._done:
            # Report action already set _done
            final_score, breakdown = self._grader.compute_final_score(
                task, self._get_env_state_dict()
            )
            info["final_score"] = final_score
            info["score_breakdown"] = breakdown
        elif self._step_count >= task.max_steps:
            self._done = True
            final_score, breakdown = self._grader.compute_final_score(
                task, self._get_env_state_dict()
            )
            info["final_score"] = final_score
            info["score_breakdown"] = breakdown

        # Clamp reward to [0, 1] for the Reward model
        clamped_reward = max(0.0, min(1.0, step_reward))
        obs = self._build_observation(error_message=error_message)
        return obs, Reward(score=clamped_reward), self._done, info

    def state(self) -> dict:
        """Return a serializable snapshot of all internal state."""
        return self._get_env_state_dict()

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _action_handlers(self) -> dict:
        """Map action_type strings to handler methods."""
        return {
            "investigate": self._handle_investigate,
            "classify": self._handle_classify,
            "correlate": self._handle_correlate,
            "remediate": self._handle_remediate,
            "escalate": self._handle_escalate,
            "report": self._handle_report,
        }

    def _handle_investigate(self, action: Action) -> str | None:
        """Reveal hidden logs for the targeted source."""
        task = self._current_task
        assert task is not None

        source = action.target
        if source in self._discovered_info["investigated_sources"]:
            # Redundant — no new info
            return None

        self._discovered_info["investigated_sources"].add(source)

        # Reveal hidden logs if the source has investigable data
        hidden_logs = task.investigable_sources.get(source, [])
        self._revealed_logs.extend(hidden_logs)
        return None

    def _handle_classify(self, action: Action) -> str | None:
        """Store the agent's severity classification."""
        severity = action.parameters.get("severity")
        if not severity:
            return "Missing required parameter 'severity' for classify action."
        self._discovered_info["classified_severity"] = severity
        return None

    def _handle_correlate(self, action: Action) -> str | None:
        """Store the agent's alert correlation group."""
        alert_ids = action.parameters.get("alert_ids")
        if not alert_ids or not isinstance(alert_ids, list):
            return "Missing or invalid parameter 'alert_ids' (expected list) for correlate action."
        self._discovered_info["correlated_groups"].append(alert_ids)
        return None

    def _handle_remediate(self, action: Action) -> str | None:
        """Store the remediation action taken."""
        self._discovered_info["remediations_taken"].append(
            {
                "target": action.target,
                "params": action.parameters,
            }
        )
        return None

    def _handle_escalate(self, action: Action) -> str | None:
        """Record an escalation (no special state change)."""
        # Escalation is noted in action_history; no extra state needed.
        return None

    def _handle_report(self, action: Action) -> str | None:
        """Store report data and trigger final scoring."""
        self._discovered_info["report_submitted"] = True
        self._discovered_info["report_data"] = action.parameters
        self._done = True
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_observation(
        self, *, error_message: str | None = None
    ) -> Observation:
        """Construct an Observation from current state."""
        task = self._current_task
        assert task is not None

        # Combine initial logs with any revealed logs
        all_logs = list(task.initial_logs) + list(self._revealed_logs)

        return Observation(
            task_description=task.description,
            alerts=list(task.initial_alerts),
            logs=all_logs,
            system_status=dict(task.system_status),
            available_actions=list(AVAILABLE_ACTIONS),
            step_count=self._step_count,
            max_steps=task.max_steps,
            error_message=error_message,
        )

    def _error_step(
        self, message: str
    ) -> tuple[Observation, Reward, bool, dict]:
        """Return an error response for an invalid action.

        Increments step count per Requirement 13.4.
        """
        self._step_count += 1

        # Check max-steps after incrementing
        info: dict = {}
        if self._step_count >= self._current_task.max_steps:  # type: ignore[union-attr]
            self._done = True
            final_score, breakdown = self._grader.compute_final_score(
                self._current_task, self._get_env_state_dict()  # type: ignore[arg-type]
            )
            info["final_score"] = final_score
            info["score_breakdown"] = breakdown

        obs = self._build_observation(error_message=message)
        return obs, Reward(score=0.0), self._done, info

    def _terminal_response(
        self,
    ) -> tuple[Observation, Reward, bool, dict]:
        """Return a terminal observation when the episode is already done."""
        obs = self._build_observation(
            error_message="Episode is already done. No further actions accepted."
        )
        return obs, Reward(score=0.0), True, {}

    def _update_repeat_tracking(self, action_dict: dict) -> None:
        """Update consecutive repeat counter."""
        if self._last_action is not None and self._actions_equal(
            action_dict, self._last_action
        ):
            self._consecutive_repeat_count += 1
        else:
            self._consecutive_repeat_count = 1
        self._last_action = action_dict

    @staticmethod
    def _actions_equal(a: dict, b: dict) -> bool:
        """Check if two action dicts are identical."""
        return (
            a.get("action_type") == b.get("action_type")
            and a.get("target") == b.get("target")
            and a.get("parameters") == b.get("parameters")
        )

    def _get_env_state_dict(self) -> dict:
        """Build a serializable dict of all internal state."""
        task = self._current_task
        # Convert set to sorted list for serialization
        investigated = sorted(self._discovered_info.get("investigated_sources", set()))
        return {
            "task_name": task.name if task else None,
            "step_count": self._step_count,
            "max_steps": task.max_steps if task else 0,
            "done": self._done,
            "action_history": list(self._action_history),
            "discovered_info": {
                "investigated_sources": investigated,
                "classified_severity": self._discovered_info.get("classified_severity"),
                "correlated_groups": list(self._discovered_info.get("correlated_groups", [])),
                "remediations_taken": list(self._discovered_info.get("remediations_taken", [])),
                "report_submitted": self._discovered_info.get("report_submitted", False),
                "report_data": self._discovered_info.get("report_data"),
            },
            "score_accumulator": dict(self._score_accumulator),
            "consecutive_repeat_count": self._consecutive_repeat_count,
            "revealed_logs_count": len(self._revealed_logs),
        }
