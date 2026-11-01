from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Type

from pydantic import BaseModel, ValidationError

from ..core.errors import ProtocolError
from ..core.schemas import ChatMessage, Task
from ..llm.gateway import LLMCaller

FALLBACK_SYSTEM = """You are a component of WebSec-Agent, an evidence-first web security assessment harness.
You communicate only through structured ws-result/v1 JSON. Never chat, never add prose outside the JSON object.
You are not limited in what testing you may propose. The harness enforces the authorized target set at
the moment a tool sends a packet; that execution-layer boundary is the only hard stop.
Every finding must cite evidence IDs present in the supplied context. Never invent evidence IDs.
"""


@lru_cache(maxsize=1)
def load_operator_spec() -> str:
    candidates: list[Path] = []
    configured = os.environ.get("WEBSEC_SYSTEM_PROMPT")
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path(__file__).resolve().parents[3] / "config" / "system_prompt.md")
    for path in candidates:
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            continue
    return FALLBACK_SYSTEM


def extract_json(text: str) -> str:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        candidate = candidate.strip()
        if candidate.lower().startswith("json"):
            candidate = candidate[4:]
        candidate = candidate.strip()
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        return candidate
    return candidate[start : end + 1]


class BaseAgent:
    role: Any = None
    output_model: Type[BaseModel] = BaseModel
    instructions: str = ""

    @property
    def system_prompt(self) -> str:
        schema = json.dumps(self.output_model.model_json_schema(), ensure_ascii=False)
        return (
            f"{load_operator_spec()}\n\n"
            "## Task output contract\n"
            "Output MUST be a single JSON object that validates against this JSON Schema:\n"
            f"{schema}\n\n{self.instructions}"
        )

    def run(
        self,
        caller: LLMCaller,
        task: Task,
        context: dict[str, Any],
        max_tokens: int,
    ) -> BaseModel:
        payload = {
            "objective": task.objective,
            "task_kind": task.kind.value,
            "run_id": task.run_id,
            "context": context,
        }
        messages = [
            ChatMessage(role="system", content=self.system_prompt),
            ChatMessage(role="user", content=json.dumps(payload, ensure_ascii=False)),
        ]

        last_error = ""
        for attempt in range(2):
            response = caller.call(
                messages,
                attempt=attempt,
                max_tokens=max_tokens,
                metadata={"task_kind": task.kind.value, "objective": task.objective},
            )
            try:
                return self.output_model.model_validate_json(extract_json(response.text))
            except ValidationError as exc:
                last_error = str(exc)[:800]
                messages.append(ChatMessage(role="assistant", content=response.text))
                messages.append(
                    ChatMessage(
                        role="user",
                        content=(
                            "Your previous output did not validate. Fix it and reply with only a "
                            f"corrected JSON object. Validation error: {last_error}"
                        ),
                    )
                )

        raise ProtocolError(
            f"{self.role.value} output failed validation after retry: {last_error}"
        )
