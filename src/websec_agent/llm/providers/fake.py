from __future__ import annotations

from typing import Callable

from ..gateway import LLMRequest, LLMResponse


class FakeGateway:
    """Deterministic gateway for tests; handler receives the full request."""

    provider = "fake"

    def __init__(self, handler: Callable[[LLMRequest], str] | None = None) -> None:
        self._handler = handler
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if self._handler is None:
            text = "{}"
        else:
            text = self._handler(request)
        tokens_in = max(1, sum(len(message.content) for message in request.messages) // 4)
        tokens_out = max(1, len(text) // 4)
        return LLMResponse(
            text=text,
            model=request.model,
            provider=self.provider,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=0,
        )


def scripted_gateway(*texts: str) -> FakeGateway:
    """Returns responses in order; repeats the last one afterwards."""
    queue = list(texts)
    calls = {"n": 0}

    def handler(_: LLMRequest) -> str:
        index = min(calls["n"], len(queue) - 1)
        calls["n"] += 1
        return queue[index]

    return FakeGateway(handler)


def json_messages(request: LLMRequest) -> dict:
    """Parse the JSON user payload used by the harness prompts."""
    import json

    for message in reversed(request.messages):
        if message.role == "user":
            try:
                return json.loads(message.content)
            except json.JSONDecodeError:
                continue
    return {}
