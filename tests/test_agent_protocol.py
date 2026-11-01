from __future__ import annotations

from websec_agent.agents.pentester import PentesterAgent
from websec_agent.core.schemas import Role, Task, TaskKind
from websec_agent.llm.gateway import LLMResponse


class StubCaller:
    def __init__(self, responses: list[str]) -> None:
        self.responses = responses
        self.calls = 0
        self.attempts: list[int] = []

    def call(self, messages, attempt=0, max_tokens=None, metadata=None):
        self.calls += 1
        self.attempts.append(attempt)
        text = self.responses[min(attempt, len(self.responses) - 1)]
        return LLMResponse(text=text, model="stub", provider="stub")


def test_agent_retries_once_on_invalid_protocol_output():
    valid = """
    {"summary": "checked", "findings": [], "tool_requests": [], "notes": ""}
    """
    caller = StubCaller(["this is not json", valid])
    task = Task(
        run_id="run-1",
        kind=TaskKind.ANALYZE,
        role=Role.PENTESTER,
        objective="check headers",
    )
    output = PentesterAgent().run(caller, task, {"evidence": []}, max_tokens=512)
    assert output.summary == "checked"
    assert caller.calls == 2
    assert caller.attempts == [0, 1]
