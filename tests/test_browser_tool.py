from __future__ import annotations

import json
import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from websec_agent.config import ScopePolicy
from websec_agent.core.errors import ScopeViolation, ToolError
from websec_agent.core.schemas import (
    EvidenceKind,
    Run,
    ToolName,
    ToolRequest,
)
from websec_agent.scope.guard import ScopeGuard
from websec_agent.store.db import Database
from websec_agent.store.repos import Repositories
from websec_agent.tools.executor import ToolExecutor

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RENDER_PAGE = """<html><body><div id="x">static</div>
<script>setTimeout(function(){document.getElementById('x').innerText='JS-RENDERED-SECRET-42';},300)</script>
</body></html>"""

FORM_PAGE = """<html><body>
<form id="f"><input id="username"><input id="password" type="password">
<button id="submit" type="submit">Go</button></form>
<div id="out"></div>
<script>
document.getElementById('f').addEventListener('submit', function(e){
  e.preventDefault();
  fetch('/login', {method:'POST', body:'u=' + encodeURIComponent(document.getElementById('username').value) +
    '&p=' + encodeURIComponent(document.getElementById('password').value)})
    .then(function(r){return r.text();})
    .then(function(t){document.getElementById('out').innerText = t;});
});
</script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # silence
        pass

    def _send(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/render":
            self._send(200, RENDER_PAGE)
        elif self.path == "/form":
            self._send(200, FORM_PAGE)
        else:
            self._send(404, "not found")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        if form.get("u") == ["admin"] and form.get("p") == ["letmein"]:
            self._send(200, "after-login OK")
        else:
            self._send(403, "denied")


@pytest.fixture(scope="module")
def local_site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture()
def harness(tmp_path):
    # the probe subprocess must find the project's persistent browser install
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(PROJECT_ROOT / "tools" / "pw-browsers")
    db = Database(f"sqlite+pysqlite:///{tmp_path / 'browser.db'}")
    db.create_all()
    repos = Repositories.build(db)
    run = Run(target="http://127.0.0.1")
    repos.runs.create(run)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    shutil.copy(PROJECT_ROOT / "tools" / "browser_probe.py", tools_dir / "browser_probe.py")

    guard = ScopeGuard(
        ScopePolicy(allowed_hosts=["127.0.0.1"], allow_private=True),
        "http://127.0.0.1",
    )
    executor = ToolExecutor(guard, repos.evidence, artifacts)
    yield repos, run, executor, artifacts
    executor.close()
    os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)


def test_browser_get_captures_js_rendered_dom_and_screenshot(harness, local_site):
    repos, run, executor, artifacts = harness
    evidence = executor.execute(
        ToolRequest(
            tool=ToolName.BROWSER,
            params={"action": "get", "url": f"{local_site}/render", "wait_ms": 2000},
        ),
        run.id,
        "task-brw-1",
    )

    assert evidence.kind == EvidenceKind.BROWSER_SESSION
    assert evidence.method == "BRW_GET"
    payload = json.loads((artifacts / evidence.raw_path).read_text())
    result = payload["result"]
    assert result["status"] == 200
    assert "JS-RENDERED-SECRET-42" in result["dom_text"]
    assert len(result["screenshot_b64"]) > 1000
    assert result["final_url"] == f"{local_site}/render"
    assert repos.evidence.count_by_run(run.id) == 1


def test_browser_flow_fills_form_and_submits_login(harness, local_site):
    repos, run, executor, artifacts = harness
    evidence = executor.execute(
        ToolRequest(
            tool=ToolName.BROWSER,
            params={
                "action": "flow",
                "url": f"{local_site}/form",
                "fill": {"#username": "admin", "#password": "letmein"},
                "click": "#submit",
                "wait_ms": 2500,
            },
        ),
        run.id,
        "task-brw-2",
    )

    payload = json.loads((artifacts / evidence.raw_path).read_text())
    result = payload["result"]
    assert result["clicked"] == "#submit"
    assert result["filled"] == {"#username": "admin", "#password": "letmein"}
    assert "after-login OK" in result["dom_text"]


def test_browser_flow_with_wrong_credentials_shows_denied(harness, local_site):
    repos, run, executor, _ = harness
    executor.execute(
        ToolRequest(
            tool=ToolName.BROWSER,
            params={
                "action": "flow",
                "url": f"{local_site}/form",
                "fill": {"#username": "admin", "#password": "wrong"},
                "click": "#submit",
                "wait_ms": 2500,
            },
        ),
        run.id,
        "task-brw-3",
    )
    assert repos.evidence.count_by_run(run.id) == 1


def test_browser_rejects_url_out_of_scope(harness):
    _, run, executor, _ = harness
    with pytest.raises(ScopeViolation, match="not in scope"):
        executor.execute(
            ToolRequest(
                tool=ToolName.BROWSER,
                params={"action": "get", "url": "http://localhost:9999/render"},
            ),
            run.id,
            "task-brw-4",
        )


def test_browser_click_requires_selector(harness, local_site):
    _, run, executor, _ = harness
    with pytest.raises(ToolError, match="requires 'selector'"):
        executor.execute(
            ToolRequest(
                tool=ToolName.BROWSER,
                params={"action": "click", "url": f"{local_site}/form"},
            ),
            run.id,
            "task-brw-5",
        )


def test_browser_probe_itself_blocks_unauthorized_host():
    """The probe subprocess enforces scope independently of the executor."""
    import subprocess
    import sys

    spec = json.dumps(
        {
            "action": "get",
            "url": "http://public.example/render",
            "allowed_hosts": ["127.0.0.1"],
            "allow_private": True,
        }
    )
    completed = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "tools" / "browser_probe.py"), spec],
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload = json.loads(completed.stdout)
    assert "not authorized" in payload["error"]
