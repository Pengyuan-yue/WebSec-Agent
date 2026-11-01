from __future__ import annotations

import time

import httpx

from ...core.errors import LLMError
from ..gateway import LLMRequest, LLMResponse

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = 2.0


class OpenAICompatibleGateway:
    """Azure/OpenAI-style /chat/completions client. No vendor SDK, no model names."""

    provider = "openai_compatible"

    def __init__(self, base_url: str, api_key: str, timeout: float = 240.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        if "openrouter.ai" in self._base_url:
            headers["HTTP-Referer"] = "http://localhost"
            headers["X-Title"] = "WebSec-Agent"
        return headers

    def _payload(self, request: LLMRequest) -> dict:
        payload = {
            "model": request.model,
            "messages": [message.model_dump() for message in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def complete(self, request: LLMRequest) -> LLMResponse:
        started = time.perf_counter()
        last_error: LLMError | None = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self._client.post(
                    f"{self._base_url}/chat/completions",
                    json=self._payload(request),
                    headers=self._headers(),
                )
            except httpx.HTTPError as exc:
                last_error = LLMError(f"model provider request failed: {exc}")
                if attempt + 1 < MAX_ATTEMPTS:
                    time.sleep(BACKOFF_SECONDS * (2**attempt))
                    continue
                raise last_error from exc

            if response.status_code >= 400:
                last_error = LLMError(
                    f"model provider returned HTTP {response.status_code}: "
                    f"{response.text[:500]}"
                )
                if (
                    response.status_code in RETRYABLE_STATUS
                    and attempt + 1 < MAX_ATTEMPTS
                ):
                    time.sleep(BACKOFF_SECONDS * (2**attempt))
                    continue
                raise last_error

            try:
                data = response.json()
                choice = data["choices"][0]
                text = choice["message"]["content"] or ""
                usage = data.get("usage") or {}
            except (KeyError, IndexError, ValueError, TypeError) as exc:
                last_error = LLMError(
                    f"unexpected provider response shape: {response.text[:300]}"
                )
                if attempt + 1 < MAX_ATTEMPTS:
                    time.sleep(BACKOFF_SECONDS * (2**attempt))
                    continue
                raise last_error from exc

            if not text:
                last_error = LLMError(
                    "model returned no final content (likely exhausted max_tokens on "
                    f"reasoning); finish_reason={choice.get('finish_reason')}"
                )
                if attempt + 1 < MAX_ATTEMPTS:
                    time.sleep(BACKOFF_SECONDS * (2**attempt))
                    continue
                raise last_error

            return LLMResponse(
                text=text,
                model=data.get("model") or request.model,
                provider=self.provider,
                tokens_in=int(usage.get("prompt_tokens") or 0),
                tokens_out=int(usage.get("completion_tokens") or 0),
                latency_ms=int((time.perf_counter() - started) * 1000),
                raw=data,
            )

        raise last_error or LLMError("model provider failed without a recorded error")

    def close(self) -> None:
        self._client.close()
