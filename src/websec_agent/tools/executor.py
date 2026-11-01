from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx

from ..collectors.base import Collected
from ..collectors.dns import DNSCollector, default_dns_lookup
from ..collectors.http import HttpCollector
from ..collectors.robots import RobotsCollector
from ..collectors.tls import TLSCollector, default_tls_probe
from ..config import ExternalToolSpec, ToolsConfig
from ..core.errors import ScopeViolation, ToolError
from ..core.schemas import Evidence, EvidenceKind, ToolName, ToolRequest, utcnow
from ..scope.guard import ScopeGuard
from ..store.repos import EvidenceRepository

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
MAX_TOOL_ARGS = 32
_PYTHON_NAMES = {"python", "python2", "python3", "python.exe"}


def resolve_program(path_str: str, base: Path) -> Path:
    """Resolve an executable across platforms.

    Handles the three OS-dependent cases in tools.yaml:
    - "python" -> the interpreter running the harness (venv on every OS)
    - "tools/bin/ffuf" -> "tools/bin/ffuf.exe" on Windows
    - "perl" -> whatever `perl` is on PATH (Strawberry Perl on Windows)
    """
    raw = Path(path_str)
    if os.name == "nt" and ".venv" in raw.parts and "bin" in raw.parts:
        # venv layout differs by platform: .venv/bin -> .venv/Scripts on Windows
        raw = Path(*["Scripts" if part == "bin" else part for part in raw.parts])
    candidate = raw if raw.is_absolute() else base / raw
    if raw.name.lower() in _PYTHON_NAMES:
        return Path(sys.executable)
    variants = [candidate]
    if os.name == "nt":
        variants.append(candidate.with_name(candidate.name + ".exe"))
    for variant in variants:
        if variant.exists():
            return variant
    found = shutil.which(candidate.name) or shutil.which(raw.name)
    return Path(found) if found else candidate



class ToolExecutor:
    """Deterministic tool layer. Every outbound action is scope-checked here."""

    def __init__(
        self,
        guard: ScopeGuard,
        evidence_repo: EvidenceRepository,
        artifacts_root: str | Path,
        http_client: httpx.Client | None = None,
        tls_probe=default_tls_probe,
        dns_lookup=default_dns_lookup,
        tools: ToolsConfig | None = None,
    ) -> None:
        self._guard = guard
        self._evidence_repo = evidence_repo
        self._artifacts_root = Path(artifacts_root)
        self._tools = tools or ToolsConfig()
        self._owns_client = http_client is None
        client = http_client or httpx.Client(
            follow_redirects=False,
            timeout=15.0,
            verify=False,
            headers={"User-Agent": "websec-agent/0.1"},
        )
        self._http = HttpCollector(client)
        self._robots = RobotsCollector(self._http)
        self._tls = TLSCollector(tls_probe)
        self._dns = DNSCollector(dns_lookup)

    @property
    def guard(self) -> ScopeGuard:
        return self._guard

    def execute(self, request: ToolRequest, run_id: str, task_id: str) -> Evidence:
        try:
            collected = self._dispatch(request)
            return self._persist(collected, run_id, task_id)
        except ScopeViolation:
            raise
        except ToolError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface any tool failure explicitly
            raise ToolError(f"{request.tool.value} failed: {exc}") from exc

    def _dispatch(self, request: ToolRequest) -> Collected:
        params = request.params
        if request.tool == ToolName.HTTP_REQUEST:
            url = _require_str(params, "url")
            self._guard.check_url(url)
            method = str(params.get("method", "GET"))
            headers = params.get("headers") or {}
            if not isinstance(headers, dict):
                raise ToolError("http_request.headers must be an object")
            body = params.get("body")
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False)
                headers = {str(k): str(v) for k, v in headers.items()}
                if "content-type" not in {key.lower() for key in headers}:
                    headers["Content-Type"] = "application/json"
            elif body is not None and not isinstance(body, str):
                raise ToolError("http_request.body must be a string or JSON object")
            headers = {str(k): str(v) for k, v in headers.items()}
            cookies_from = params.get("cookies_from")
            if cookies_from:
                cookie_header = self._cookie_header(str(cookies_from))
                if cookie_header:
                    headers["Cookie"] = cookie_header
            return self._http.fetch(url, method=method, headers=headers, body=body)

        if request.tool == ToolName.EVIDENCE_DIFF:
            return self._diff_evidence(
                _require_str(params, "evidence_a"), _require_str(params, "evidence_b")
            )

        if request.tool == ToolName.EXTERNAL_TOOL:
            return self._run_external(params)

        if request.tool == ToolName.BROWSER:
            return self._run_browser(params)

        if request.tool == ToolName.TLS_PROBE:
            host = _require_str(params, "host")
            port = int(params.get("port", 443))
            self._guard.check_host(host, port)
            return self._tls.collect(host, port)

        if request.tool == ToolName.DNS_LOOKUP:
            host = _require_str(params, "host")
            self._guard.check_host(host)
            return self._dns.collect(host)

        if request.tool == ToolName.ROBOTS:
            url = params.get("url")
            if url:
                url = str(url)
            else:
                host = _require_str(params, "host")
                port = int(params.get("port", 443))
                self._guard.check_host(host, port)
                url = f"https://{host}:{port}/robots.txt" if port != 443 else f"https://{host}/robots.txt"
            self._guard.check_url(url)
            return self._robots.collect(url)

        raise ToolError(f"unsupported tool: {request.tool}")

    def _run_external(self, params: dict[str, Any]) -> Collected:
        name = _require_str(params, "tool")
        spec = self._tools.tools.get(name)
        if spec is None:
            available = ", ".join(sorted(self._tools.tools)) or "none configured"
            raise ToolError(f"external tool not configured: {name} (available: {available})")
        base = self._artifacts_root.parent
        tool_path = resolve_program(spec.path, base)
        if not tool_path.exists() and not shutil.which(spec.path):
            raise ToolError(
                f"external tool not installed at {spec.path}: {name} "
                "(run tools/setup_tools.sh or tools/setup_tools.ps1)"
            )

        args = params.get("args")
        if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
            raise ToolError("external_tool.args must be a list of strings")
        if len(args) > MAX_TOOL_ARGS or any(len(item) > 500 for item in args):
            raise ToolError("external_tool.args exceeds size limits")

        joined = " ".join(args)
        for blocked in spec.blocked_args:
            if blocked and blocked in joined:
                raise ToolError(f"blocked argument pattern for {name}: {blocked}")

        urls = [match.rstrip(".,;)") for match in URL_RE.findall(joined)]
        bare_hosts = [arg for arg in args if HOST_RE.fullmatch(arg)]
        if spec.arg_scope == "url":
            if not urls and not bare_hosts:
                raise ToolError(f"{name}: args must include a target URL/host for scope validation")
            for url in urls:
                self._guard.check_url(url)
            for host in bare_hosts:
                self._guard.check_host(host)

        command = [str(tool_path)]
        for part in spec.pre_args:
            pre = Path(part)
            command.append(str(pre) if pre.is_absolute() else str(base / pre))
        command += args
        proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        if proxy and spec.proxy_args:
            bare = proxy.split("://", 1)[-1]
            command += [
                part.replace("{PROXY}", proxy).replace("{PROXY_BARE}", bare)
                for part in spec.proxy_args
            ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=spec.timeout_seconds,
                cwd=str(self._artifacts_root.parent),
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"{name} timed out after {spec.timeout_seconds}s") from exc
        except OSError as exc:
            raise ToolError(f"{name} failed to start: {exc}") from exc

        output = (completed.stdout or "") + ("\n[stderr]\n" + completed.stderr if completed.stderr else "")
        truncated = len(output.encode("utf-8", errors="replace")) > spec.max_output_bytes
        if truncated:
            keep = spec.max_output_bytes // 2
            head = output.encode("utf-8", errors="replace")[:keep].decode("utf-8", errors="replace")
            tail = output.encode("utf-8", errors="replace")[-keep:].decode("utf-8", errors="replace")
            output = f"{head}\n[...output truncated...]\n{tail}"

        head_line = " | ".join(
            line for line in output.splitlines() if line.strip()
        )[:160]
        summary = (
            f"$ {name} {joined[:120]} -> exit={completed.returncode} "
            f"({len(output)} B): {head_line}"
        )
        raw = json.dumps(
            {
                "tool": name,
                "command": command,
                "exit_code": completed.returncode,
                "urls": urls,
                "output": output,
            },
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        return Collected(
            kind=EvidenceKind.COMMAND_OUTPUT,
            source_url=urls[0] if urls else (f"http://{bare_hosts[0]}" if bare_hosts else ""),
            method="CMD",
            summary=summary,
            raw=raw,
            derived_from=[],
        )

    def _run_browser(self, params: dict[str, Any]) -> Collected:
        action = str(params.get("action", "get"))
        if action not in {"get", "click", "type", "flow"}:
            raise ToolError("browser.action must be one of: get, click, type, flow")
        url = _require_str(params, "url")
        self._guard.check_url(url)

        fill = params.get("fill") or {}
        if not isinstance(fill, dict):
            raise ToolError("browser.fill must be an object of selector -> value")
        snapshot = self._guard.snapshot()
        allowed_hosts = list(snapshot.get("allowed_hosts", []))
        if self._guard.target_host not in allowed_hosts:
            allowed_hosts.append(self._guard.target_host)
        spec: dict[str, Any] = {
            "action": action,
            "url": url,
            "allowed_hosts": allowed_hosts,
            "allow_private": bool(snapshot.get("allow_private", False)),
            "wait_ms": min(10000, int(params.get("wait_ms", 1500))),
        }
        if action in {"click", "type"}:
            spec["selector"] = str(params.get("selector", ""))
            if not spec["selector"]:
                raise ToolError(f"browser.action {action} requires 'selector'")
        if action == "type":
            spec["value"] = str(params.get("value", ""))
        if action == "flow":
            spec["fill"] = {str(key): str(value) for key, value in fill.items()}
            if params.get("click"):
                spec["click"] = str(params["click"])

        proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        if proxy:
            spec["proxy"] = proxy

        script = self._artifacts_root.parent / "tools" / "browser_probe.py"
        if not script.exists():
            raise ToolError(f"browser probe script missing: {script}")

        env = dict(os.environ)
        browsers = self._artifacts_root.parent / "tools" / "pw-browsers"
        if browsers.is_dir() and "PLAYWRIGHT_BROWSERS_PATH" not in env:
            env["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)

        try:
            completed = subprocess.run(
                [sys.executable, str(script), json.dumps(spec, ensure_ascii=False)],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=120,
                cwd=str(self._artifacts_root.parent),
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError("browser probe timed out after 120s") from exc
        except OSError as exc:
            raise ToolError(f"browser probe failed to start: {exc}") from exc

        stdout = (completed.stdout or "").strip()
        try:
            payload = json.loads(stdout or "{}")
        except ValueError as exc:
            raise ToolError(
                f"browser probe returned invalid json: {stdout[:200]} stderr={completed.stderr[:200]}"
            ) from exc
        if payload.get("error"):
            raise ToolError(f"browser probe: {payload['error']}")

        final_url = str(payload.get("final_url") or url)
        status = payload.get("status")
        title = str(payload.get("title", ""))[:120]
        dom_text = str(payload.get("dom_text", ""))[:4000]
        shot_kb = len(str(payload.get("screenshot_b64", ""))) // 1024
        summary = (
            f"browser {action} {url} -> status={status} final={final_url} "
            f"title={title!r} screenshot={shot_kb}KB dom_head={dom_text[:160]!r}"
        )
        raw = json.dumps(
            {"spec": {k: v for k, v in spec.items() if k != "proxy"}, "result": payload},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        return Collected(
            kind=EvidenceKind.BROWSER_SESSION,
            source_url=final_url,
            method=f"BRW_{action.upper()}",
            summary=summary,
            raw=raw,
            derived_from=[],
        )

    def _cookie_header(self, evidence_id: str) -> str:
        evidence = self._evidence_repo.get(evidence_id.strip())
        if evidence is None:
            raise ToolError(f"cookies_from: evidence {evidence_id} not found")
        try:
            payload = json.loads(
                (self._artifacts_root / evidence.raw_path).read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise ToolError(f"cookies_from: cannot read evidence {evidence_id}: {exc}") from exc
        raw_cookie = (payload.get("response") or {}).get("headers", {}).get("set-cookie", "")
        pairs: list[str] = []
        for part in raw_cookie.split(","):
            if "=" in part:
                name_value = part.strip().split(";", 1)[0]
                if name_value.count("=") == 1:
                    pairs.append(name_value)
        return "; ".join(pairs)

    def _diff_evidence(self, id_a: str, id_b: str) -> Collected:
        evidence_a = self._evidence_repo.get(id_a.strip())
        evidence_b = self._evidence_repo.get(id_b.strip())
        if evidence_a is None or evidence_b is None:
            missing = id_a if evidence_a is None else id_b
            raise ToolError(f"evidence_diff: evidence {missing} not found")

        def _body(evidence: Evidence) -> tuple[int, str]:
            try:
                payload = json.loads(
                    (self._artifacts_root / evidence.raw_path).read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as exc:
                raise ToolError(f"evidence_diff: cannot read {evidence.id}: {exc}") from exc
            response = payload.get("response") or {}
            status = response.get("status_code", "-")
            location = (response.get("headers") or {}).get("location", "-")
            body = response.get("body")
            body = body.strip() if isinstance(body, str) else ""
            return status, f"status={status} location={location}\n{body}"

        status_a, text_a = _body(evidence_a)
        status_b, text_b = _body(evidence_b)
        diff_lines = list(
            difflib.unified_diff(
                text_a.splitlines(), text_b.splitlines(),
                fromfile=f"A({evidence_a.source_url} {status_a})",
                tofile=f"B({evidence_b.source_url} {status_b})",
                lineterm="",
            )
        )
        removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
        added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
        identical = removed == 0 and added == 0 and text_a == text_b
        raw = json.dumps(
            {
                "a": {"evidence_id": evidence_a.id, "url": evidence_a.source_url},
                "b": {"evidence_id": evidence_b.id, "url": evidence_b.source_url},
                "unified_diff": "\n".join(diff_lines[:400]),
                "lines_removed": removed,
                "lines_added": added,
                "identical": identical,
            },
            indent=2,
            ensure_ascii=False,
        ).encode()
        summary = (
            f"diff A={evidence_a.source_url} ({status_a}) vs B={evidence_b.source_url} ({status_b}): "
            f"+{added}/-{removed} lines, identical={identical}"
        )
        return Collected(
            kind=EvidenceKind.EVIDENCE_DIFF,
            source_url=evidence_b.source_url,
            method=None,
            summary=summary,
            raw=raw,
            derived_from=[evidence_a.id, evidence_b.id],
        )

    def persist_collected(self, collected: Collected, run_id: str, task_id: str | None = None) -> Evidence:
        """Persist an externally produced result (e.g. OAST callbacks) as evidence."""
        return self._persist(collected, run_id, task_id)

    def _persist(self, collected: Collected, run_id: str, task_id: str) -> Evidence:
        content_hash = hashlib.sha256(collected.raw).hexdigest()
        extension = ".der" if collected.kind == EvidenceKind.TLS_CERT else ".json"
        directory = self._artifacts_root / "evidence" / run_id
        directory.mkdir(parents=True, exist_ok=True)
        filename = f"{content_hash}{extension}"
        path = directory / filename
        if not path.exists():
            path.write_bytes(collected.raw)

        evidence = Evidence(
            run_id=run_id,
            task_id=task_id,
            kind=collected.kind,
            source_url=collected.source_url,
            method=collected.method or "",
            collected_at=utcnow(),
            content_hash=content_hash,
            raw_path=str(path.relative_to(self._artifacts_root)),
            summary=collected.summary,
            derived_from=collected.derived_from,
            in_scope=True,
            size_bytes=len(collected.raw),
        )
        return self._evidence_repo.create(evidence)

    def close(self) -> None:
        if self._owns_client:
            self._http.close()


def _require_str(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"missing required string parameter: {key}")
    return value.strip()
