from __future__ import annotations

import json
import time
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from ..config import RoleModelConfig
from ..core.schemas import ChatMessage, LLMCallRecord, MessageRecord, Role, utcnow
from ..store.repos import LLMCallRepository, MessageRepository


class LLMRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role
    model: str
    messages: list[ChatMessage]
    temperature: float = 0.2
    max_tokens: int = 4096
    json_mode: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    model: str
    provider: str
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    raw: dict[str, Any] = Field(default_factory=dict)


class LLMGateway(Protocol):
    provider: str

    def complete(self, request: LLMRequest) -> LLMResponse: ...


class LLMCaller:
    """Single gateway facade per (run, task, role); records cost and messages."""

    def __init__(
        self,
        run_id: str,
        task_id: str,
        role: Role,
        settings: RoleModelConfig,
        gateway: LLMGateway,
        llm_calls: LLMCallRepository,
        messages: MessageRepository,
    ) -> None:
        self.run_id = run_id
        self.task_id = task_id
        self.role = role
        self.settings = settings
        self._gateway = gateway
        self._llm_calls = llm_calls
        self._messages = messages

    def call(
        self,
        messages: list[ChatMessage],
        attempt: int = 0,
        max_tokens: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> LLMResponse:
        request = LLMRequest(
            role=self.role,
            model=self.settings.model,
            messages=messages,
            temperature=self.settings.temperature,
            max_tokens=max_tokens or self.settings.max_output_tokens,
            json_mode=True,
            metadata=metadata or {},
        )
        started = time.perf_counter()
        response = self._gateway.complete(request)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        latency = response.latency_ms or elapsed_ms

        tokens_in = response.tokens_in
        tokens_out = response.tokens_out
        cost = (
            tokens_in / 1_000_000 * self.settings.input_cost_per_mtok
            + tokens_out / 1_000_000 * self.settings.output_cost_per_mtok
        )

        self._llm_calls.create(
            LLMCallRecord(
                run_id=self.run_id,
                task_id=self.task_id,
                role=self.role,
                provider=response.provider or self._gateway.provider,
                model=response.model or self.settings.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost,
                latency_ms=latency,
                created_at=utcnow(),
            )
        )

        self._messages.create(
            MessageRecord(
                run_id=self.run_id,
                task_id=self.task_id,
                role=self.role,
                direction="retry" if attempt else "prompt",
                content=json.dumps(
                    [m.model_dump() for m in messages], ensure_ascii=False, indent=2
                ),
            )
        )
        self._messages.create(
            MessageRecord(
                run_id=self.run_id,
                task_id=self.task_id,
                role=self.role,
                direction="response",
                content=response.text,
            )
        )
        return response
