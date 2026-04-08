"""Task registry for the OpenEnv Incident Response Triage environment.

Exports TASK_REGISTRY: a mapping of task names to TaskDefinition instances.
Task modules are imported lazily so this package can be imported even before
all scenario modules are implemented.
"""

from models import TaskDefinition

TASK_REGISTRY: dict[str, TaskDefinition] = {}


def _load_registry() -> None:
    """Populate TASK_REGISTRY from available task modules."""
    _modules = [
        "tasks.brute_force_login",
        "tasks.lateral_movement",
        "tasks.insider_data_exfil",
    ]
    for module_name in _modules:
        try:
            import importlib

            mod = importlib.import_module(module_name)
            task: TaskDefinition = mod.TASK  # type: ignore[attr-defined]
            TASK_REGISTRY[task.name] = task
        except (ImportError, AttributeError):
            # Module not yet implemented — skip silently
            pass


_load_registry()
