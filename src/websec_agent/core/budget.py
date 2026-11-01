from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .schemas import Budget, RunBudget


@dataclass(frozen=True)
class BudgetSnapshot:
    tasks: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    replans: int = 0


class BudgetGuard:
    """Pre-flight checks against the run budget. 0 always means unlimited."""

    def __init__(self, budget: RunBudget, snapshot: Callable[[], BudgetSnapshot]) -> None:
        self._budget = budget
        self._snapshot = snapshot

    @property
    def budget(self) -> RunBudget:
        return self._budget

    def snapshot(self) -> BudgetSnapshot:
        return self._snapshot()

    def exhaustion_reason(self) -> str | None:
        snap = self._snapshot()
        b = self._budget
        if b.max_tasks > 0 and snap.tasks >= b.max_tasks:
            return f"max_tasks={b.max_tasks} reached"
        if b.max_total_tokens > 0 and snap.tokens >= b.max_total_tokens:
            return f"max_total_tokens={b.max_total_tokens} reached"
        if b.max_cost_usd > 0 and snap.cost_usd >= b.max_cost_usd:
            return f"max_cost_usd={b.max_cost_usd} reached"
        return None

    def replan_limit_reached(self, replans_used: int) -> bool:
        limit = self._budget.max_replans
        return limit > 0 and replans_used >= limit

    def output_token_cap(self, settings_cap: int, task_budget: Budget) -> int:
        cap = settings_cap
        if task_budget.max_tokens > 0:
            cap = min(cap, task_budget.max_tokens)
        remaining_tokens = 0
        if self._budget.max_total_tokens > 0:
            remaining_tokens = max(1, self._budget.max_total_tokens - self._snapshot().tokens)
            cap = min(cap, remaining_tokens)
        return max(1, cap)
