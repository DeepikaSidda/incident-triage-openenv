---
title: Incident Triage OpenEnv
emoji: 🔒
colorFrom: red
colorTo: blue
sdk: docker
app_port: 7860
tags:
  - openenv
license: mit
---

# Incident Response Triage — OpenEnv Environment

![openenv](https://img.shields.io/badge/openenv-incident--triage-blue)
![python](https://img.shields.io/badge/python-3.11-green)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

## Overview

This is an [OpenEnv](https://github.com/meta-llama/open-env)-compliant environment that simulates **IT/security incident response triage** — a high-stakes, real-world domain where speed and accuracy directly impact organizational security posture.

AI agents are presented with realistic incident scenarios containing alerts, log entries, network topology, and system status. The agent must investigate the incident, classify its severity, correlate related evidence, execute remediation actions, and submit a final report. A deterministic grader evaluates the agent's performance on a 0.0–1.0 scale based on correctness, efficiency, and safety of actions taken.

**Why incident response triage?** Security operations centers (SOCs) process thousands of alerts daily. Effective triage requires multi-step reasoning, evidence correlation across disparate sources, and careful decision-making under ambiguity — exactly the capabilities we want to measure in AI agents. This environment tests whether agents can distinguish signal from noise, avoid collateral damage, and produce actionable incident reports.

## Observation Space

Each call to `step()` or `reset()` returns an `Observation` with the following fields:

| Field | Type | Description |
|---|---|---|
| `task_description` | `str` | Natural-language scenario description and objective |
| `alerts` | `list[Alert]` | Alert objects, each with `id`, `timestamp`, `source`, `severity` (Critical/High/Medium/Low), and `message` |
| `logs` | `list[LogEntry]` | Log entries, each with `timestamp`, `source`, `level`, and `content` |
| `system_status` | `dict[str, str]` | Component names mapped to their current operational status (e.g., `"operational"`, `"degraded"`) |
| `available_actions` | `list[str]` | Valid action type strings the agent may submit |
| `step_count` | `int` | Current step number (0 at reset, increments with each action) |
| `max_steps` | `int` | Maximum allowed steps for the current task |
| `error_message` | `str \| None` | Error description from invalid actions, or `None` |


## Action Space

Agents submit an `Action` with three fields:

| Field | Type | Description |
|---|---|---|
| `action_type` | `str` | One of the 6 valid action types listed below |
| `target` | `str` | The system component or source to act on (must be in the task's valid components) |
| `parameters` | `dict` | Action-specific parameters (e.g., severity level, alert IDs, remediation details) |

### Action Types

| Action Type | Description | Parameters |
|---|---|---|
| `investigate` | Query a system component to reveal hidden logs and additional evidence | `{}` (target specifies the source) |
| `classify` | Assign a severity level to the incident | `{"severity": "Critical\|High\|Medium\|Low"}` |
| `correlate` | Link related alerts by their IDs to establish an attack chain | `{"alert_ids": ["id1", "id2", ...]}` |
| `remediate` | Take a containment or mitigation action against a component | Action-specific (e.g., `{"action": "block_ip", "ip": "..."}`) |
| `escalate` | Flag the incident for human review with justification | `{"reason": "..."}` |
| `report` | Submit a final incident summary to conclude the episode | `{"severity": "...", "root_cause": "...", "affected_systems": "...", ...}` |

Invalid action types or targets return an error observation with a reward of 0.0. The step count still increments to prevent infinite retry loops.

## Tasks

The environment includes three incident scenarios of increasing difficulty:

### 1. `brute_force_login` — Easy (15 steps)

**Scenario:** An SSH brute-force attack targeting a single server. The agent observes repeated failed login attempts from a single malicious IP address, followed by a successful login.

**Objective:** Identify the malicious source IP, classify the severity as High, block the attacker, and submit a report.

**Rubric weights:** investigation (0.20), classification (0.20), remediation (0.30), report (0.30)

### 2. `lateral_movement` — Medium (25 steps)

**Scenario:** An attacker has compromised one host and is moving laterally across the network using stolen credentials. Alerts fire from multiple hosts showing suspicious authentication events, unusual process execution, and anomalous network flows.

**Objective:** Identify all compromised hosts, correlate alerts across the attack chain, classify severity as Critical, isolate compromised systems, and submit a comprehensive report.

**Rubric weights:** investigation (0.25), classification (0.15), correlation (0.20), remediation (0.20), report (0.20)

### 3. `insider_data_exfil` — Hard (35 steps)

**Scenario:** A compromised insider account is exfiltrating sensitive data. The alert stream contains both genuine false positives (routine large file transfers) and true positive indicators of data exfiltration, requiring the agent to distinguish signal from noise.

**Objective:** Identify the compromised insider account, determine the exfiltration method and destination, execute precise remediation without disrupting legitimate users, and submit a detailed report.

**Rubric weights:** investigation (0.20), classification (0.10), correlation (0.15), remediation (0.25), report (0.20), precision (0.10)

> The precision criterion penalizes incorrect remediation actions that disrupt legitimate users or services (−0.1 per incorrect action).


## Reward Function

The environment provides two levels of reward signal:

### Step Rewards

Each action receives an immediate step reward based on its type and correctness:

| Action Type | Positive Reward | Zero / Negative Reward |
|---|---|---|
| `investigate` | New relevant info discovered → **+0.10** | Redundant query → **0.00** |
| `classify` | Correct severity → **+0.15** | Wrong severity → **0.00** |
| `correlate` | Correct alert linkage → **+0.10** | Incorrect linkage → **0.00** |
| `remediate` | Correct action → **+0.12** | Wrong target (collateral) → **−0.10** |
| `escalate` | Appropriate escalation → **+0.05** | — |
| `report` | Triggers final scoring | — |

Additional penalties:
- **Consecutive repeat penalty:** Submitting the same action 3+ times consecutively incurs a −0.05 penalty per step.

### Final Score

When the episode ends (via `report` action or max steps exhausted), the grader computes a weighted final score:

```
final_score = Σ (criterion_score × criterion_weight) / Σ criterion_weight
```

Each criterion score is in [0.0, 1.0] and measures a specific aspect: investigation completeness, classification accuracy, correlation correctness, remediation effectiveness, report quality, and (for the hard task) precision.

## Setup and Usage

### Docker (Recommended)

Build and run the containerized environment:

```bash
docker build -t incident-triage .
docker run -e HF_TOKEN=<your-api-key> incident-triage
```

Optionally configure the model and API endpoint:

```bash
docker run \
  -e HF_TOKEN=<your-api-key> \
  -e API_BASE_URL=https://api.openai.com/v1 \
  -e MODEL_NAME=gpt-4.1-mini \
  incident-triage
```

### Local

```bash
pip install -r requirements.txt
HF_TOKEN=<your-api-key> python inference.py
```

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `HF_TOKEN` | **Yes** | — | API key for the LLM provider |
| `API_BASE_URL` | No | `https://api.openai.com/v1` | Base URL for the OpenAI-compatible API |
| `MODEL_NAME` | No | `gpt-4.1-mini` | Model identifier to use for inference |

## Baseline Performance Scores

| Task | Difficulty | Max Steps | Score |
|---|---|---|---|
| `brute_force_login` | Easy | 15 | TBD |
| `lateral_movement` | Medium | 25 | TBD |
| `insider_data_exfil` | Hard | 35 | TBD |
| **Average** | — | — | TBD |

> Scores will be populated after running the inference script with the baseline model.

## Project Structure

```
.
├── environment.py          # Core OpenEnv environment (reset/step/state)
├── grader.py               # Deterministic grader with weighted scoring
├── inference.py            # LLM agent driver script
├── models.py               # Pydantic data models (Observation, Action, Reward, etc.)
├── tasks/
│   ├── __init__.py         # Task registry
│   ├── brute_force_login.py    # Easy scenario — SSH brute-force
│   ├── lateral_movement.py     # Medium scenario — lateral movement
│   └── insider_data_exfil.py   # Hard scenario — insider data exfiltration
├── openenv.yaml            # OpenEnv manifest
├── Dockerfile              # Container build file
├── requirements.txt        # Python dependencies
└── README.md               # This file
```
