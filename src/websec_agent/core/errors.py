class WebSecError(Exception):
    """Base error for the harness."""


class ConfigError(WebSecError):
    """Invalid or incomplete configuration."""


class ScopeViolation(WebSecError):
    """An outbound action was attempted outside the authorized scope."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"scope violation for {target!r}: {reason}")


class ProtocolError(WebSecError):
    """Agent output did not satisfy the ws-result/v1 contract."""


class BudgetExceeded(WebSecError):
    """A run or task budget would be exceeded."""


class ConcurrentModification(WebSecError):
    """Optimistic-lock conflict on a task row."""


class ToolError(WebSecError):
    """Deterministic tool execution failed."""


class LLMError(WebSecError):
    """The model provider returned an error or an unusable response."""
