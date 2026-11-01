from __future__ import annotations

from .schemas import TERMINAL_STATUSES, TaskStatus

ALLOWED_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.PENDING: {TaskStatus.READY, TaskStatus.SKIPPED},
    TaskStatus.READY: {TaskStatus.RUNNING, TaskStatus.SKIPPED},
    TaskStatus.RUNNING: {TaskStatus.DONE, TaskStatus.FAILED},
    TaskStatus.WAITING: {TaskStatus.READY, TaskStatus.SKIPPED, TaskStatus.FAILED},
    TaskStatus.DONE: set(),
    TaskStatus.FAILED: set(),
    TaskStatus.SKIPPED: set(),
}


def is_terminal(status: TaskStatus) -> bool:
    return status in TERMINAL_STATUSES


def validate_transition(current: TaskStatus, target: TaskStatus) -> None:
    if target not in ALLOWED_TRANSITIONS[current]:
        raise ValueError(f"invalid task transition: {current.value} -> {target.value}")
