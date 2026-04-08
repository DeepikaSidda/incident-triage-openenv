"""Deterministic grader for the OpenEnv Incident Response Triage environment.

Evaluates agent actions and computes weighted partial-credit scores
against ground-truth data embedded in each task definition.
"""

from __future__ import annotations

from models import Action, TaskDefinition


class Grader:
    """Evaluates agent actions and computes scores against ground truth."""

    # ------------------------------------------------------------------
    # Step scoring
    # ------------------------------------------------------------------

    def score_step(
        self, action: Action, task: TaskDefinition, env_state: dict
    ) -> float:
        """Return a step reward for the given action.

        Parameters
        ----------
        action : Action
            The action the agent just took.
        task : TaskDefinition
            The current task scenario with ground truth.
        env_state : dict
            Snapshot of the environment's internal state.

        Returns
        -------
        float
            Step reward (may be negative for penalties).
        """
        handler = {
            "investigate": self._score_investigate,
            "classify": self._score_classify,
            "correlate": self._score_correlate,
            "remediate": self._score_remediate,
            "escalate": self._score_escalate,
            "report": self._score_report,
        }.get(action.action_type)

        if handler is None:
            return 0.0

        return handler(action, task, env_state)

    # --- per-action scoring helpers ---

    @staticmethod
    def _score_investigate(
        action: Action, task: TaskDefinition, env_state: dict
    ) -> float:
        # The handler has already added the source to investigated_sources
        # before score_step is called, but action_history has NOT yet been
        # updated.  So we check action_history for prior investigate actions
        # targeting the same source to detect redundancy.
        for prev in env_state["action_history"]:
            if (
                prev.get("action_type") == "investigate"
                and prev.get("target") == action.target
            ):
                return 0.0  # redundant
        return 0.10  # productive

    @staticmethod
    def _score_classify(
        action: Action, task: TaskDefinition, env_state: dict
    ) -> float:
        severity = action.parameters.get("severity")
        if severity == task.ground_truth.severity:
            return 0.15
        return 0.0

    @staticmethod
    def _score_correlate(
        action: Action, task: TaskDefinition, env_state: dict
    ) -> float:
        submitted_ids = action.parameters.get("alert_ids")
        if not submitted_ids:
            return 0.0
        submitted_set = set(submitted_ids)
        for group in task.ground_truth.correlated_alert_groups:
            if submitted_set == set(group):
                return 0.10
        return 0.0

    @staticmethod
    def _score_remediate(
        action: Action, task: TaskDefinition, env_state: dict
    ) -> float:
        gt = task.ground_truth
        # Check correct remediations
        for correct in gt.correct_remediations:
            if (
                action.target == correct["target"]
                and action.parameters == correct["params"]
            ):
                return 0.12
        # Check incorrect remediations (penalty)
        for incorrect in gt.incorrect_remediations:
            if (
                action.target == incorrect["target"]
                and action.parameters == incorrect["params"]
            ):
                return -0.10
        return 0.0

    @staticmethod
    def _score_escalate(
        action: Action, task: TaskDefinition, env_state: dict
    ) -> float:
        return 0.05

    @staticmethod
    def _score_report(
        action: Action, task: TaskDefinition, env_state: dict
    ) -> float:
        return 0.0

    # ------------------------------------------------------------------
    # Final score computation
    # ------------------------------------------------------------------

    def compute_final_score(
        self, task: TaskDefinition, env_state: dict
    ) -> tuple[float, dict]:
        """Compute the final weighted score at episode end.

        Parameters
        ----------
        task : TaskDefinition
            The current task scenario with rubric weights.
        env_state : dict
            Snapshot of the environment's internal state.

        Returns
        -------
        tuple[float, dict]
            (final_score in [0,1], breakdown dict mapping criterion -> score)
        """
        weights = task.rubric_weights
        breakdown: dict[str, float] = {}

        scorer = {
            "investigation": self._final_investigation,
            "classification": self._final_classification,
            "correlation": self._final_correlation,
            "remediation": self._final_remediation,
            "report": self._final_report,
            "precision": self._final_precision,
        }

        for criterion in weights:
            fn = scorer.get(criterion)
            if fn is not None:
                breakdown[criterion] = fn(task, env_state)
            else:
                breakdown[criterion] = 0.0

        total_weight = sum(weights.values())
        if total_weight == 0:
            return 0.01, breakdown

        weighted_sum = sum(
            breakdown[c] * weights[c] for c in weights
        )
        final_score = weighted_sum / total_weight
        # Clamp to strictly (0, 1) — never exactly 0.0 or 1.0
        final_score = max(0.01, min(0.99, final_score))

        return final_score, breakdown

    # --- per-criterion final scoring helpers ---

    @staticmethod
    def _final_investigation(
        task: TaskDefinition, env_state: dict
    ) -> float:
        investigated = env_state["discovered_info"]["investigated_sources"]
        total = len(task.investigable_sources)
        if total == 0:
            return 1.0
        return len(investigated) / total

    @staticmethod
    def _final_classification(
        task: TaskDefinition, env_state: dict
    ) -> float:
        classified = env_state["discovered_info"]["classified_severity"]
        if classified == task.ground_truth.severity:
            return 1.0
        return 0.0

    @staticmethod
    def _final_correlation(
        task: TaskDefinition, env_state: dict
    ) -> float:
        gt_groups = task.ground_truth.correlated_alert_groups
        if not gt_groups:
            return 1.0
        agent_groups = env_state["discovered_info"]["correlated_groups"]
        matched = 0
        for gt_group in gt_groups:
            gt_set = set(gt_group)
            for agent_group in agent_groups:
                if set(agent_group) == gt_set:
                    matched += 1
                    break
        return matched / len(gt_groups)

    @staticmethod
    def _final_remediation(
        task: TaskDefinition, env_state: dict
    ) -> float:
        correct_list = task.ground_truth.correct_remediations
        if not correct_list:
            return 1.0
        taken = env_state["discovered_info"]["remediations_taken"]
        matched = 0
        for correct in correct_list:
            for rem in taken:
                if (
                    rem["target"] == correct["target"]
                    and rem["params"] == correct["params"]
                ):
                    matched += 1
                    break
        return matched / len(correct_list)

    @staticmethod
    def _final_report(
        task: TaskDefinition, env_state: dict
    ) -> float:
        required = task.ground_truth.report_required_fields
        if not required:
            return 1.0
        report_data = env_state["discovered_info"].get("report_data")
        if not report_data:
            return 0.0
        matching = 0
        for field_name, expected_value in required.items():
            agent_value = report_data.get(field_name)
            if agent_value is not None:
                # Case-insensitive substring match
                if expected_value.lower() in str(agent_value).lower():
                    matching += 1
        return matching / len(required)

    @staticmethod
    def _final_precision(
        task: TaskDefinition, env_state: dict
    ) -> float:
        taken = env_state["discovered_info"]["remediations_taken"]
        incorrect_list = task.ground_truth.incorrect_remediations
        incorrect_count = 0
        for incorrect in incorrect_list:
            for rem in taken:
                if (
                    rem["target"] == incorrect["target"]
                    and rem["params"] == incorrect["params"]
                ):
                    incorrect_count += 1
                    break
        score = 1.0 - (incorrect_count * 0.1)
        return max(0.0, score)
