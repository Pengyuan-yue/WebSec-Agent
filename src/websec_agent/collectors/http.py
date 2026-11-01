from __future__ import annotations

import json
from typing import Any

import httpx

from ..core.errors import ToolError
from ..core.schemas import EvidenceKind
from .base import Collected

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
)

MAX_BODY_CHARS = 1_000_000


class HttpCollector:
    def __init__(self, client: httpx.Client, timeout: float = 15.0) -> None:
        self._client = client
        self._timeout = timeout

    def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        kind: EvidenceKind = EvidenceKind.HTTP_RESPONSE,
    ) -> Collected:
        method = method.upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}:
            raise ToolError(f"unsupported HTTP method: {method}")

        try:
            response = self._client.request(
                method,
                url,
                headers=headers or {},
                content=body,
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise ToolError(f"http request failed for {url}: {exc}") from exc

        raw_body = response.content
        text = raw_body.decode("utf-8", errors="replace")
        truncated = False
        if len(text) > MAX_BODY_CHARS:
            text = text[:MAX_BODY_CHARS]
            truncated = True

        header_map = {key.lower(): value for key, value in response.headers.items()}
        present_security = [name for name in SECURITY_HEADERS if name in header_map]
        payload: dict[str, Any] = {
            "request": {"method": method, "url": url, "headers": headers or {}, "body": body},
            "response": {
                "status_code": response.status_code,
                "headers": header_map,
                "body": text,
                "body_truncated": truncated,
                "body_bytes": len(raw_body),
            },
        }
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

        content_type = header_map.get("content-type", "-")
        security_note = ", ".join(present_security) if present_security else "none"
        signals = []
        if 300 <= response.status_code < 400:
            location = header_map.get("location", "-")
            signals.append(f"redirect-> {location}")
        if "set-cookie" in header_map:
            cookie_names = sorted(
                {part.split("=")[0].strip() for part in header_map["set-cookie"].split(",")}
            )
            signals.append(f"set-cookie={cookie_names}")
        if "www-authenticate" in header_map:
            signals.append(f"www-authenticate={header_map['www-authenticate'][:60]}")
        signal_note = f"; {', '.join(signals)}" if signals else ""
        summary = (
            f"{method} {url} -> {response.status_code} {content_type} "
            f"({len(raw_body)} B){signal_note}; security headers present: {security_note}"
        )
        return Collected(
            kind=kind,
            source_url=url,
            method=method,
            summary=summary,
            raw=raw,
        )

    def close(self) -> None:
        self._client.close()
