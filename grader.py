"""Deterministic grader for the OpenEnv Incident Response Triage environment.

Evaluates agent actions and computes weighted partial-credit scores
against ground-truth data embedded in each task definition.

IMPORTANT: All scores are strictly between 0 and 1 (never exactly 0.0 or 1.0).
"""

from __future__ import annotations

from models import Action, TaskDefinition

# Strict bounds — no score may ever be exactly 0.0 or 1.0
_MIN = 0.01
_MAX = 0.99


def _clamp(v: float) -> float:
    """Clamp a value to strictly (0, 1)."""
    return max(_MIN, min(_MAX, v))


class Grader:
    """Evaluates agent actions and computes scores against ground truth."""

    def score_step(
        self, action: Action, task: TaskDefinition, env_state: dict
    ) -> float:
        handler = {
            "investigate": self._score_investigate,
            "classify": self._score_classify,
            "correlate": self._score_correlate,
            "remediate": self._score_remediate,
            "escalate": self._score_escalate,
            "report": self._score_report,
        }.get(action.action_type)
        if handler is None:
            return _MIN
        return _clamp(handler(action, task, env_state))

    @staticmethod
    def _score_investigate(action, task, env_state):
        for prev in env_state["action_history"]:
            if prev.get("action_type") == "investigate" and prev.get("target") == action.target:
                return _MIN
        return 0.10

    @staticmethod
    def _score_classify(action, task, env_state):
        severity = action.parameters.get("severity")
        if severity == task.ground_truth.severity:
            return 0.15
        return _MIN

    @staticmethod
    def _score_correlate(action, task, env_state):
        submitted_ids = action.parameters.get("alert_ids")
        if not submitted_ids:
            return _MIN
        submitted_set = set(submitted_ids)
        for group in task.ground_truth.correlated_alert_groups:
            if submitted_set == set(group):
                return 0.10
        return _MIN

    @staticmethod
    def _score_remediate(action, task, env_state):
        gt = task.ground_truth
        for correct in gt.correct_remediations:
            if action.target == correct["target"] and action.parameters == correct["params"]:
                return 0.12
        for incorrect in gt.incorrect_remediations:
            if action.target == incorrect["target"] and action.parameters == incorrect["params"]:
                return _MIN  # penalty handled elsewhere
        return _MIN

    @staticmethod
    def _score_escalate(action, task, env_state):
        return 0.05

    @staticmethod
    def _score_report(action, task, env_state):
        return _MIN

    def compute_final_score(self, task, env_state):
        weights = task.rubric_weights
        breakdown = {}
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
                breakdown[criterion] = _clamp(fn(task, env_state))
            else:
                breakdown[criterion] = _MIN
        total_weight = sum(weights.values())
        if total_weight == 0:
            return _MIN, breakdown
        weighted_sum = sum(breakdown[c] * weights[c] for c in weights)
        final_score = _clamp(weighted_sum / total_weight)
        return final_score, breakdown

    @staticmethod
    def _final_investigation(task, env_state):
        investigated = env_state["discovered_info"]["investigated_sources"]
        total = len(task.investigable_sources)
        if total == 0:
            return _MAX
        return len(investigated) / total

    @staticmethod
    def _final_classification(task, env_state):
        classified = env_state["discovered_info"]["classified_severity"]
        if classified == task.ground_truth.severity:
            return _MAX
        return _MIN

    @staticmethod
    def _final_correlation(task, env_state):
        gt_groups = task.ground_truth.correlated_alert_groups
        if not gt_groups:
            return _MAX
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
    def _final_remediation(task, env_state):
        correct_list = task.ground_truth.correct_remediations
        if not correct_list:
            return _MAX
        taken = env_state["discovered_info"]["remediations_taken"]
        matched = 0
        for correct in correct_list:
            for rem in taken:
                if rem["target"] == correct["target"] and rem["params"] == correct["params"]:
                    matched += 1
                    break
        return matched / len(correct_list)

    @staticmethod
    def _final_report(task, env_state):
        required = task.ground_truth.report_required_fields
        if not required:
            return _MAX
        report_data = env_state["discovered_info"].get("report_data")
        if not report_data:
            return _MIN
        matching = 0
        for field_name, expected_value in required.items():
            agent_value = report_data.get(field_name)
            if agent_value is not None:
                if expected_value.lower() in str(agent_value).lower():
                    matching += 1
        return matching / len(required)

    @staticmethod
    def _final_precision(task, env_state):
        taken = env_state["discovered_info"]["remediations_taken"]
        incorrect_list = task.ground_truth.incorrect_remediations
        incorrect_count = 0
        for incorrect in incorrect_list:
            for rem in taken:
                if rem["target"] == incorrect["target"] and rem["params"] == incorrect["params"]:
                    incorrect_count += 1
                    break
        score = 1.0 - (incorrect_count * 0.1)
        return max(_MIN, score)
