"""Shared pytest fixtures for the OpenEnv Incident Response Triage test suite."""

import sys
import os

# Ensure the project root is on the Python path so imports work from tests/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from environment import IncidentTriageEnv
from grader import Grader
from models import Action
from tasks import TASK_REGISTRY


@pytest.fixture
def env():
    """Return a fresh IncidentTriageEnv instance."""
    return IncidentTriageEnv()


@pytest.fixture
def task_registry():
    """Return the TASK_REGISTRY dict."""
    return TASK_REGISTRY


@pytest.fixture
def brute_force_task():
    """Return the brute_force_login TaskDefinition."""
    return TASK_REGISTRY["brute_force_login"]


@pytest.fixture
def lateral_movement_task():
    """Return the lateral_movement TaskDefinition."""
    return TASK_REGISTRY["lateral_movement"]


@pytest.fixture
def insider_data_exfil_task():
    """Return the insider_data_exfil TaskDefinition."""
    return TASK_REGISTRY["insider_data_exfil"]


@pytest.fixture
def grader():
    """Return a fresh Grader instance."""
    return Grader()


@pytest.fixture
def sample_investigate_action():
    """Return an Action(action_type='investigate', target='ssh-monitor', parameters={})."""
    return Action(action_type="investigate", target="ssh-monitor", parameters={})


@pytest.fixture
def sample_classify_action():
    """Return an Action(action_type='classify', target='ssh-monitor', parameters={'severity': 'High'})."""
    return Action(
        action_type="classify",
        target="ssh-monitor",
        parameters={"severity": "High"},
    )


@pytest.fixture
def sample_report_action():
    """Return an Action(action_type='report', target='ssh-monitor', parameters={...})."""
    return Action(
        action_type="report",
        target="ssh-monitor",
        parameters={
            "severity": "High",
            "source_ip": "198.51.100.23",
            "attack_type": "ssh_brute_force",
            "remediation": "block_ip",
        },
    )
