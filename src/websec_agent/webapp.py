"""Interactive web console for the websec-agent: chat with the AI operator,
launch scope-guarded runs, and watch tasks/findings/events live."""
from __future__ import annotations

import hashlib
import json
import re
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .agents.orchestrator import Orchestrator
from .agents.pentester import PentesterAgent
from .agents.planner import PlannerAgent
from .agents.reporter import ReporterAgent
from .agents.reviewer import ReviewerAgent
from .config import load_config, load_scope_policy, load_tools
from .config_overrides import apply_overrides, load_local, save_local
from .core.errors import ConfigError, ScopeViolation, WebSecError
from .core.schemas import ChatMessage, Role
from .llm.gateway import LLMRequest
from .llm.registry import ModelRegistry
from .scope.guard import ScopeGuard
from .store.db import Database
from .store.knowledge import KnowledgeStore
from .store.repos import Repositories
from .tools.executor import ToolExecutor

MAX_CHAT_HISTORY = 16


class ChatIn(BaseModel):
    message: str
    history: list[ChatMessage] = []


class RunIn(BaseModel):
    target: str
    use_memory: bool = True


class TranslateIn(BaseModel):
    kind: str = "text"  # "finding" (structured dict) | "report" (markdown)
    data: dict[str, Any] | None = None
    markdown: str | None = None


class BriefIn(BaseModel):
    run_id: str


FINDING_TRANSLATE_KEYS = ("title", "description", "impact", "reproduction", "remediation")

# Snapshot of factory prompt defaults, taken at import time (before overrides are
# applied) so the settings panel can always show and restore originals.
_AGENT_CLASSES = {
    Role.PLANNER: PlannerAgent,
    Role.PENTESTER: PentesterAgent,
    Role.REVIEWER: ReviewerAgent,
    Role.REPORTER: ReporterAgent,
}
DEFAULT_INSTRUCTIONS = {role.value: cls.instructions for role, cls in _AGENT_CLASSES.items()}


def _apply_instruction_overrides() -> None:
    """Hot-swap agent class prompts with user overrides from settings_local."""
    overrides = load_local().get("instructions") or {}
    if not isinstance(overrides, dict):
        return
    for role, cls in _AGENT_CLASSES.items():
        text = overrides.get(role.value)
        if isinstance(text, str) and text.strip():
            cls.instructions = text


class RunState:
    """Server-side single-flight run manager (one active run at a time)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active_run_id: str | None = None
        self.error: str | None = None

    def claim(self, run_id: str) -> bool:
        with self.lock:
            if self.active_run_id is not None:
                return False
            self.active_run_id = run_id
            self.error = None
            return True

    def release(self, error: str | None = None) -> None:
        with self.lock:
            self.active_run_id = None
            self.error = error


class Console:
    def __init__(
        self,
        config_path: str = "config/models.yaml",
        scope_path: str = "config/scope_policy.yaml",
        artifacts_root: str | Path | None = None,
        db_url: str | None = None,
        allow_private: bool = False,
        allow_hosts: list[str] | None = None,
    ) -> None:
        self.root = Path.cwd()
        self.config = load_config(config_path)
        apply_overrides(self.config)   # settings_local.json: model/run overrides
        _apply_instruction_overrides()  # settings_local.json: prompt overrides
        self.policy = load_scope_policy(scope_path)
        if allow_private:
            self.policy.allow_private = True
        self.allow_hosts = allow_hosts or []
        self.artifacts = Path(artifacts_root or self.config.artifacts_dir)
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.db_url = db_url or f"sqlite+pysqlite:///{self.artifacts / 'websec_webui.db'}"
        self.tools = load_tools(Path(config_path).resolve().parent / "tools.yaml")
        self.knowledge = KnowledgeStore(self.artifacts / "knowledge.json")
        self._translations_path = self.artifacts / "translations.json"
        self._translations = self._load_translations()
        self._translate_lock = threading.Lock()
        self.state = RunState()
        self._chat_lock = threading.Lock()

    # ------------------------------------------------------------ translations
    def _load_translations(self) -> dict[str, Any]:
        try:
            return json.loads(self._translations_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - cache is best-effort
            return {}

    def _save_translations(self) -> None:
        try:
            fd, tmp = tempfile.mkstemp(
                dir=str(self._translations_path.parent), suffix=".tmp"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._translations, fh, ensure_ascii=False)
            os.replace(tmp, self._translations_path)
        except Exception:  # noqa: BLE001 - cache is best-effort
            pass

    @staticmethod
    def _split_markdown(markdown: str, limit: int = 6000) -> list[str]:
        """Split markdown into translatable blocks: sections by heading, then
        overlong sections further by blank-line paragraph groups."""
        blocks: list[str] = []
        current: list[str] = []
        for line in markdown.splitlines():
            if line.lstrip().startswith("#") and current:
                blocks.append("\n".join(current))
                current = [line]
            else:
                current.append(line)
        if current:
            blocks.append("\n".join(current))

        out: list[str] = []
        for block in blocks:
            if len(block) <= limit:
                out.append(block)
                continue
            group: list[str] = []
            size = 0
            for para in block.split("\n\n"):
                if size + len(para) > limit and group:
                    out.append("\n\n".join(group))
                    group, size = [], 0
                group.append(para)
                size += len(para) + 2
            if group:
                out.append("\n\n".join(group))
        return [b for b in out if b.strip()]

    def translate(self, payload: TranslateIn) -> dict[str, Any]:
        if payload.kind == "finding":
            if not payload.data:
                raise HTTPException(status_code=400, detail="finding data required")
            content = json.dumps(
                {k: payload.data.get(k, "") for k in FINDING_TRANSLATE_KEYS},
                ensure_ascii=False,
            )
        elif payload.kind == "report":
            if not payload.markdown or not payload.markdown.strip():
                raise HTTPException(status_code=400, detail="markdown required")
            content = payload.markdown
        else:
            raise HTTPException(status_code=400, detail=f"unknown kind: {payload.kind}")

        key = hashlib.sha256(f"{payload.kind}|{content}".encode()).hexdigest()
        with self._translate_lock:
            cached = self._translations.get(key)
        if cached is not None:
            return {"cached": True, **cached}

        settings, gateway = ModelRegistry(self.config).resolve(Role.PENTESTER)
        try:
            if payload.kind == "finding":
                system = (
                    "You translate security assessment artifacts into Simplified "
                    "Chinese (简体中文). Translate every narrative value into natural, "
                    "fluent Chinese. Keep technical identifiers, endpoint paths, HTTP "
                    "parameters, product names, SQL, commands, code and URLs unchanged. "
                    "Return ONLY a JSON object with exactly the same keys as the input "
                    "and translated values."
                )
                request = LLMRequest(
                    role=Role.PENTESTER,
                    model=settings.model,
                    messages=[
                        ChatMessage(role="system", content=system),
                        ChatMessage(role="user", content=f"Translate:\n{content}"),
                    ],
                    temperature=0.1,
                    max_tokens=settings.max_output_tokens,
                    json_mode=True,
                    metadata={"source": "webui_translate_finding"},
                )
                response = gateway.complete(request)
                text = response.text.strip()
                if text.startswith("```"):
                    text = text.strip("` \n")
                    text = text[text.find("{") : text.rfind("}") + 1]
                try:
                    translation = json.loads(text)
                except Exception as exc:  # noqa: BLE001
                    raise HTTPException(
                        status_code=502, detail=f"translation parse failed: {exc}"
                    ) from exc
                if not isinstance(translation, dict):
                    raise HTTPException(status_code=502, detail="bad translation shape")
                result: dict[str, Any] = {"translation": translation}
            else:
                system = (
                    "You translate security assessment reports into Simplified Chinese "
                    "(简体中文). Preserve the markdown structure (headings, lists, "
                    "tables). Keep technical identifiers, endpoint paths, HTTP "
                    "parameters, SQL, commands, code blocks, URLs and evidence ids "
                    "unchanged. Translate ALL narrative text into natural Chinese. "
                    "Return ONLY the translated markdown for this excerpt; do not add "
                    "commentary."
                )
                blocks = self._split_markdown(content)
                translated: list[str] = []
                for idx, block in enumerate(blocks):
                    block_key = hashlib.sha256(
                        f"report_block|{block}".encode()
                    ).hexdigest()
                    with self._translate_lock:
                        cached_block = self._translations.get(block_key)
                    if cached_block is None:
                        request = LLMRequest(
                            role=Role.PENTESTER,
                            model=settings.model,
                            messages=[
                                ChatMessage(role="system", content=system),
                                ChatMessage(role="user", content=f"Translate:\n{block}"),
                            ],
                            temperature=0.1,
                            max_tokens=settings.max_output_tokens,
                            json_mode=False,
                            metadata={
                                "source": "webui_translate_report",
                                "block": idx,
                            },
                        )
                        response = gateway.complete(request)
                        cached_block = {"markdown": response.text.strip()}
                        with self._translate_lock:
                            self._translations[block_key] = cached_block
                            self._save_translations()
                    translated.append(cached_block["markdown"])
                result = {"markdown": "\n\n".join(translated)}
        finally:
            close = getattr(gateway, "close", None)
            if callable(close):
                close()

        with self._translate_lock:
            self._translations[key] = result
            self._save_translations()
        return {"cached": False, **result}

    # ------------------------------------------------------------- run launch
    def brief(self, run_id: str) -> dict[str, Any]:
        """Short Chinese vulnerability brief per finding: principle + POC."""
        db, repos = self.db_view()
        run = repos.runs.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        findings = repos.findings.list_by_run(run_id)
        if not findings:
            raise HTTPException(status_code=404, detail="no findings for this run")

        digest = ",".join(f"{f.id}:{f.updated_at.isoformat()}" for f in findings)
        key = hashlib.sha256(f"brief|{run_id}|{digest}".encode()).hexdigest()
        with self._translate_lock:
            cached = self._translations.get(key)
        if cached is not None:
            return {"cached": True, "items": cached["items"]}

        payload = [
            {
                "id": f.id[:8],
                "severity": f.severity,
                "title": f.title,
                "category": f.category,
                "description": f.description,
                "reproduction": f.reproduction,
            }
            for f in findings
        ]
        system = (
            "You are a penetration-test report writer. For each vulnerability in "
            "the input array produce a SHORT Chinese brief for the operator. "
            "Return ONLY a JSON object: {\"items\": [{\"id\", \"title\", "
            "\"principle\", \"poc\"}]}. Rules: id copied from input; title = "
            "concise Chinese title; principle = 1-2 sentences in Simplified "
            "Chinese explaining the root cause (漏洞原理); poc = a single "
            "copy-paste-ready command or HTTP request (curl / raw request) "
            "demonstrating exploitation, keep code/paths/params in English. "
            "Be terse: no methodology, no remediation, no filler."
        )
        settings, gateway = ModelRegistry(self.config).resolve(Role.PENTESTER)
        try:
            request = LLMRequest(
                role=Role.PENTESTER,
                model=settings.model,
                messages=[
                    ChatMessage(role="system", content=system),
                    ChatMessage(
                        role="user",
                        content=json.dumps(payload, ensure_ascii=False),
                    ),
                ],
                temperature=0.1,
                max_tokens=settings.max_output_tokens,
                json_mode=True,
                metadata={"source": "webui_brief"},
            )
            response = gateway.complete(request)
            text = response.text.strip()
            if text.startswith("```"):
                text = text.strip("` \n")
                start, end = text.find("{"), text.rfind("}")
                if start >= 0 and end > start:
                    text = text[start : end + 1]
            try:
                parsed = json.loads(text)
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(
                    status_code=502, detail=f"brief parse failed: {exc}"
                ) from exc
            items = parsed.get("items") if isinstance(parsed, dict) else None
            if not isinstance(items, list):
                raise HTTPException(status_code=502, detail="bad brief shape")
        finally:
            close = getattr(gateway, "close", None)
            if callable(close):
                close()

        with self._translate_lock:
            self._translations[key] = {"items": items}
            self._save_translations()
        return {"cached": False, "items": items}

    def start_run(self, target: str, use_memory: bool) -> dict[str, Any]:
        guard = ScopeGuard(self.policy, target)
        if self.allow_hosts:
            guard.expand(self.allow_hosts)

        registry = ModelRegistry(self.config)
        for role in (Role.PLANNER, Role.PENTESTER, Role.REVIEWER, Role.REPORTER):
            registry.resolve(role)

        db = Database(self.db_url)
        db.create_all()
        repos = Repositories.build(db)
        executor = ToolExecutor(guard, repos.evidence, self.artifacts, tools=self.tools)
        orchestrator = Orchestrator(
            db=db,
            target=target,
            executor=executor,
            registry=registry,
            run_budget=self.config.run,
            artifacts_root=self.artifacts,
            use_memory=use_memory,
        )

        run_holder: dict[str, Any] = {}

        def _worker() -> None:
            error: str | None = None
            try:
                finished = orchestrator.run()
                run_holder["id"] = finished.id
                run_holder["status"] = finished.status.value
            except WebSecError as exc:
                error = str(exc)
            finally:
                executor.close()
                registry.close()
                self.state.release(error)

        # claim AFTER validation but BEFORE the run row exists: use a placeholder
        if not self.state.claim("pending"):
            raise HTTPException(status_code=409, detail="a run is already active")
        known_ids = {r.id for r in repos.runs.list_all()}
        try:
            thread = threading.Thread(target=_worker, daemon=True, name="websec-run")
            thread.start()
        except Exception:
            self.state.release("failed to start worker thread")
            raise
        # the orchestrator creates the run row inside run(); poll for the NEW id
        run_id = self._await_new_run_row(db, known_ids, timeout=20)
        if run_id is None:
            self.state.release("run did not initialize")
            raise HTTPException(status_code=500, detail="run failed to initialize")
        with self.state.lock:
            self.state.active_run_id = run_id
        return {"run_id": run_id, "target": target, "use_memory": use_memory}

    def _await_new_run_row(
        self, db: Database, known_ids: set[str], timeout: float
    ) -> str | None:
        repos = Repositories.build(db)
        deadline = time.time() + timeout
        while time.time() < deadline:
            fresh = [r.id for r in repos.runs.list_all() if r.id not in known_ids]
            if fresh:
                return fresh[-1]
            time.sleep(0.3)
        return None

    # ----------------------------------------------------------------- queries
    def db_view(self) -> tuple[Database, Repositories]:
        db = Database(self.db_url)
        db.create_all()
        return db, Repositories.build(db)

    # -------------------------------------------------------------------- chat
    LAUNCH_RE = re.compile(r"^\[LAUNCH\s+(https?://[^\s\]]+)\]", re.IGNORECASE)

    def chat(self, payload: ChatIn) -> dict[str, Any]:
        history = payload.history[-MAX_CHAT_HISTORY:]
        if not payload.message.strip():
            raise HTTPException(status_code=400, detail="empty message")
        context = self._chat_context()

        system = (
            "You are the AI security operator of WebSec Agent, an interactive "
            "penetration-testing console. Answer the operator's questions about "
            "the assessment: runs, tasks, evidence, findings, tool usage, next "
            "steps. Be concrete and reference findings/evidence by id when "
            "useful. Reply in the operator's language (Chinese by default).\n\n"
            "LAUNCHING ASSESSMENTS: the operator starts a run by chatting. When "
            "the operator's message names a clear target URL and asks you to "
            "start testing (评估/测试/渗透/打一下), AND state.active_run_id is "
            "null, begin your reply with the marker [LAUNCH <url>] followed by "
            "a one-line Chinese confirmation (mention harmless read-only "
            "doctrine). The harness starts the run and shows it live. Do NOT "
            "output the marker when: a run is already active (active_run_id is "
            "set — tell the operator to wait), no clear absolute URL was given "
            "(ask for one), or the operator only asked a question. Never "
            "fabricate the marker for hosts other than what the operator "
            "named.\n\n"
            "Current console state (JSON):\n" + context
        )
        settings, gateway = ModelRegistry(self.config).resolve(Role.PENTESTER)
        messages = [ChatMessage(role="system", content=system)] + history + [
            ChatMessage(role="user", content=payload.message)
        ]
        request = LLMRequest(
            role=Role.PENTESTER,
            model=settings.model,
            messages=messages,
            temperature=0.4,
            max_tokens=settings.max_output_tokens,
            json_mode=False,
            metadata={"source": "webui_chat"},
        )
        with self._chat_lock:
            response = gateway.complete(request)
        close = getattr(gateway, "close", None)
        if callable(close):
            close()

        reply = response.text.strip()
        extra: dict[str, Any] = {}
        match = self.LAUNCH_RE.match(reply)
        if match:
            target = match.group(1).rstrip(".,;、。")
            reply = reply[match.end() :].strip()
            try:
                result = self.start_run(target, use_memory=True)
                extra = {"run_id": result["run_id"], "target": target}
                reply += (
                    f"\n\n⏺ 评估已启动（run {result['run_id'][:8]}），"
                    "中栏实时展示执行流程。Agent 全程执行无害只读验证。"
                )
            except HTTPException as exc:
                detail = str(exc.detail)
                reply += f"\n\n⏺ 发起失败：{detail}"
        return {"reply": reply, "model": response.model, **extra}

    def _chat_context(self) -> str:
        import json

        state: dict[str, Any] = {
            "active_run": self.state.active_run_id,
            "scope_allowed_hosts": sorted(self.policy.allowed_hosts or []),
            "tools": sorted(self.tools.tools),
        }
        knowledge = self.knowledge.entries_for_all()
        if knowledge:
            state["cross_run_knowledge"] = [
                {k: v for k, v in entry.items() if k in ("kind", "title", "url")}
                for entry in knowledge[-10:]
            ]
        try:
            db, repos = self.db_view()
            runs = repos.runs.list_all()
            if runs:
                run = runs[-1]
                state["latest_run"] = {
                    "id": run.id,
                    "target": run.target,
                    "status": run.status.value,
                    "stats": run.stats,
                }
                findings = repos.findings.list_by_run(run.id)
                state["findings"] = [
                    {
                        "severity": f.severity,
                        "status": f.status,
                        "title": f.title,
                        "category": f.category,
                    }
                    for f in findings
                ]
                events = repos.events.list_by_run(run.id)
                state["recent_events"] = [
                    {"type": e.type, "payload": e.payload} for e in events[-25:]
                ]
        except Exception as exc:  # noqa: BLE001 - context is best-effort
            state["context_error"] = str(exc)
        return json.dumps(state, ensure_ascii=False, default=str)[:20000]


def create_app(console: Console) -> FastAPI:
    app = FastAPI(title="WebSec Agent Console", docs_url=None, redoc_url=None)
    web_dir = console.root / "web"

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        html = (web_dir / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html, headers={"Cache-Control": "no-store"})

    @app.post("/api/runs")
    def launch_run(body: RunIn) -> JSONResponse:
        try:
            result = console.start_run(body.target, body.use_memory)
        except ScopeViolation as exc:
            raise HTTPException(status_code=400, detail=f"scope violation: {exc}") from exc
        except ConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(result)

    @app.get("/api/state")
    def state() -> dict[str, Any]:
        return {
            "active_run_id": console.state.active_run_id,
            "last_error": console.state.error,
            "allowed_hosts": sorted(console.policy.allowed_hosts or []),
            "allow_private": bool(console.policy.allow_private),
            "tools": sorted(console.tools.tools),
        }

    @app.get("/api/runs")
    def list_runs() -> dict[str, Any]:
        db, repos = console.db_view()
        runs = repos.runs.list_all()
        return {
            "runs": [
                {
                    "id": r.id,
                    "target": r.target,
                    "status": r.status.value,
                    "started_at": r.started_at.isoformat(),
                    "stats": r.stats,
                }
                for r in reversed(runs)
            ]
        }

    @app.get("/api/runs/{run_id}")
    def run_detail(run_id: str) -> dict[str, Any]:
        db, repos = console.db_view()
        run = repos.runs.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        tasks = repos.tasks.list_by_run(run_id)
        findings = repos.findings.list_by_run(run_id)
        evidence = repos.evidence.list_by_run(run_id)
        report_task = next(
            (t for t in tasks if t.kind == "report" and t.status.value == "done"), None
        )
        return {
            "run": {
                "id": run.id,
                "target": run.target,
                "status": run.status.value,
                "stats": run.stats,
                "started_at": run.started_at.isoformat(),
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            },
            "tasks": [
                {
                    "id": t.id,
                    "kind": t.kind,
                    "status": t.status.value,
                    "objective": t.objective,
                    "priority": t.priority,
                }
                for t in tasks
            ],
            "findings": [f.model_dump(mode="json") for f in findings],
            "evidence": [
                {
                    "id": e.id,
                    "kind": e.kind,
                    "method": e.method,
                    "source_url": e.source_url,
                    "summary": e.summary[:200],
                }
                for e in evidence
            ],
            "report_dir": (report_task.result or {}).get("report_dir")
            if report_task
            else None,
        }

    @app.get("/api/runs/{run_id}/events")
    def run_events(run_id: str, after: int = 0) -> dict[str, Any]:
        db, repos = console.db_view()
        events = repos.events.list_by_run(run_id)
        window = events[after:]
        return {
            "total": len(events),
            "events": [
                {
                    "type": e.type,
                    "payload": e.payload,
                    "task_id": e.task_id,
                    "created_at": e.created_at.isoformat(),
                }
                for e in window
            ],
        }

    @app.get("/api/runs/{run_id}/report")
    def run_report(run_id: str) -> dict[str, Any]:
        db, repos = console.db_view()
        tasks = repos.tasks.list_by_run(run_id)
        report_task = next((t for t in tasks if t.kind == "report"), None)
        report_dir = (report_task.result or {}).get("report_dir") if report_task else None
        path = console.root / str(report_dir) / "report.md" if report_dir else None
        if path is None or not path.exists():
            raise HTTPException(status_code=404, detail="no report for this run")
        return {"markdown": path.read_text(encoding="utf-8")}

    @app.post("/api/chat")
    def chat(body: ChatIn) -> dict[str, Any]:
        try:
            return console.chat(body)
        except ConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/translate")
    def translate(body: TranslateIn) -> dict[str, Any]:
        try:
            return console.translate(body)
        except ConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/brief")
    def brief(body: BriefIn) -> dict[str, Any]:
        try:
            return console.brief(body.run_id)
        except ConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/knowledge")
    def knowledge() -> dict[str, Any]:
        return {"entries": console.knowledge.entries_for_all()}

    # ------------------------------------------------------------ settings
    @app.get("/api/settings")
    def get_settings() -> dict[str, Any]:
        local = load_local()
        key = str(local.get("openrouter_key") or "")
        instructions = local.get("instructions") or {}
        return {
            "provider": "OpenRouter",
            "key_hint": f"…{key[-4:]}" if len(key) >= 8 else None,
            "key_set": bool(key),
            "models": {
                role.value: console.config.roles[role].model
                for role in _AGENT_CLASSES
            },
            "instructions": {
                role.value: (instructions.get(role.value) or DEFAULT_INSTRUCTIONS[role.value])
                for role in _AGENT_CLASSES
            },
            "instructions_default": DEFAULT_INSTRUCTIONS,
            "instructions_custom": {
                role.value: bool(isinstance(instructions.get(role.value), str) and instructions[role.value].strip())
                for role in _AGENT_CLASSES
            },
            "run": {
                "max_parallel": console.config.run.max_parallel,
                "max_tasks": console.config.run.max_tasks,
            },
            "theme": local.get("theme") or "light",
        }

    @app.post("/api/settings")
    def post_settings(payload: dict[str, Any]) -> dict[str, Any]:
        local = load_local()
        if isinstance(payload.get("openrouter_key"), str) and payload["openrouter_key"].strip():
            local["openrouter_key"] = payload["openrouter_key"].strip()
        if isinstance(payload.get("models"), dict):
            merged = local.get("models") or {}
            for role_value, model in payload["models"].items():
                if role_value in {role.value for role in _AGENT_CLASSES} and isinstance(model, str):
                    merged[role_value] = model.strip()
            local["models"] = merged
        if isinstance(payload.get("instructions"), dict):
            merged = local.get("instructions") or {}
            for role_value, text in payload["instructions"].items():
                if role_value not in DEFAULT_INSTRUCTIONS or not isinstance(text, str):
                    continue
                if not text.strip() or text.strip() == DEFAULT_INSTRUCTIONS[role_value].strip():
                    merged.pop(role_value, None)   # empty or identical to default -> drop
                else:
                    merged[role_value] = text
            local["instructions"] = merged
        if isinstance(payload.get("run"), dict):
            merged = local.get("run") or {}
            for name in ("max_parallel", "max_tasks"):
                value = payload["run"].get(name)
                if isinstance(value, int) and value >= 1:
                    merged[name] = value
            local["run"] = merged
        if payload.get("theme") in ("light", "dark"):
            local["theme"] = payload["theme"]
        try:
            save_local(local)
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"保存失败: {exc}") from exc
        apply_overrides(console.config)      # models/run take effect on next run
        _apply_instruction_overrides()       # prompts hot-swap immediately
        return {"ok": True, "theme": local.get("theme") or "light"}

    return app


def serve(argv: list[str] | None = None) -> int:
    """Entry point for the web console: ``websec-agent-web``."""
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(prog="websec-agent-web", description="WebSec Agent console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--config", default="config/models.yaml")
    parser.add_argument("--scope", default="config/scope_policy.yaml")
    parser.add_argument("--artifacts", default=None)
    parser.add_argument("--db-url", default=None)
    parser.add_argument("--allow-private", action="store_true")
    args = parser.parse_args(argv)

    console = Console(
        config_path=args.config,
        scope_path=args.scope,
        artifacts_root=args.artifacts,
        db_url=args.db_url,
        allow_private=args.allow_private,
    )
    uvicorn.run(create_app(console), host=args.host, port=args.port, log_level="warning")
    return 0
