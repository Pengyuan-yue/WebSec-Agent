from __future__ import annotations

import stat

from websec_agent.config import ExternalToolSpec, ScopePolicy, ToolsConfig
from websec_agent.core.errors import ScopeViolation, ToolError
from websec_agent.core.schemas import EvidenceKind, Run, ToolName, ToolRequest
from websec_agent.scope.guard import ScopeGuard
from websec_agent.store.db import Database
from websec_agent.store.repos import Repositories
from websec_agent.tools.executor import ToolExecutor


def _fake_tool(tmp_path, name="faketool.sh"):
    path = tmp_path / name
    path.write_text('#!/bin/sh\necho "ran $@"\n')
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def _executor(tmp_path, spec: ExternalToolSpec):
    db = Database(f"sqlite+pysqlite:///{tmp_path / 'ext.db'}")
    db.create_all()
    repos = Repositories.build(db)
    run = Run(target="http://demo.testfire.net/")
    repos.runs.create(run)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    tools = ToolsConfig(tools={spec.name: spec})
    executor = ToolExecutor(
        ScopeGuard(ScopePolicy(allowed_hosts=["demo.testfire.net"]), "http://demo.testfire.net/"),
        repos.evidence,
        artifacts,
        tools=tools,
    )
    return repos, run, artifacts, executor


def test_external_tool_runs_and_persists_command_output(tmp_path):
    spec = ExternalToolSpec(
        name="faketool", path=str(_fake_tool(tmp_path)), arg_scope="url", description="test tool"
    )
    repos, run, artifacts, executor = _executor(tmp_path, spec)
    evidence = executor.execute(
        ToolRequest(
            tool=ToolName.EXTERNAL_TOOL,
            params={
                "tool": "faketool",
                "args": ["-u", "http://demo.testfire.net/login.jsp", "--flag"],
            },
        ),
        run.id,
        "task-1",
    )
    assert evidence.kind == EvidenceKind.COMMAND_OUTPUT
    assert evidence.method == "CMD"
    assert evidence.source_url == "http://demo.testfire.net/login.jsp"
    assert "exit=0" in evidence.summary
    assert "ran -u" in evidence.summary
    assert evidence.in_scope


def test_external_tool_blocks_out_of_scope_url_before_spawn(tmp_path):
    spec = ExternalToolSpec(
        name="faketool", path=str(_fake_tool(tmp_path, "never.sh")), arg_scope="url"
    )
    repos, run, artifacts, executor = _executor(tmp_path, spec)
    with __import__("pytest").raises(ScopeViolation):
        executor.execute(
            ToolRequest(
                tool=ToolName.EXTERNAL_TOOL,
                params={"tool": "faketool", "args": ["-u", "http://evil.example.org/x"]},
            ),
            run.id,
            "task-1",
        )
    assert repos.evidence.count_by_run(run.id) == 0


def test_external_tool_rejects_unknown_and_blocked_args(tmp_path):
    spec = ExternalToolSpec(
        name="faketool",
        path=str(_fake_tool(tmp_path)),
        arg_scope="url",
        blocked_args=["--os-shell"],
    )
    repos, run, artifacts, executor = _executor(tmp_path, spec)
    import pytest

    with pytest.raises(ToolError, match="not configured"):
        executor.execute(
            ToolRequest(
                tool=ToolName.EXTERNAL_TOOL,
                params={"tool": "nope", "args": ["-u", "http://demo.testfire.net/"]},
            ),
            run.id,
            "task-1",
        )
    with pytest.raises(ToolError, match="blocked argument"):
        executor.execute(
            ToolRequest(
                tool=ToolName.EXTERNAL_TOOL,
                params={
                    "tool": "faketool",
                    "args": ["-u", "http://demo.testfire.net/", "--os-shell"],
                },
            ),
            run.id,
            "task-1",
        )
    with pytest.raises(ToolError, match="target URL"):
        executor.execute(
            ToolRequest(
                tool=ToolName.EXTERNAL_TOOL,
                params={"tool": "faketool", "args": ["--no-target"]},
            ),
            run.id,
            "task-1",
        )


def test_tools_yaml_config_loads_installed_tools():
    from websec_agent.config import load_tools

    config = load_tools("config/tools.yaml")
    assert config.allow_destructive is False
    expected = ("ffuf", "nuclei", "sqlmap", "httpx", "katana", "gau", "dalfox", "commix", "arjun", "nikto", "wafw00f")
    for name in expected:
        assert name in config.tools, name
        assert config.tools[name].installed(), f"{name} not installed"
    blocked = config.tools["sqlmap"].blocked_args
    assert "--os-shell" in blocked


def test_external_tool_scope_checks_bare_host(tmp_path):
    spec = ExternalToolSpec(
        name="faketool", path=str(_fake_tool(tmp_path, "host.sh")), arg_scope="url"
    )
    repos, run, artifacts, executor = _executor(tmp_path, spec)
    import pytest

    with pytest.raises(ScopeViolation):
        executor.execute(
            ToolRequest(
                tool=ToolName.EXTERNAL_TOOL,
                params={"tool": "faketool", "args": ["evil.example.org"]},
            ),
            run.id,
            "task-1",
        )
    evidence = executor.execute(
        ToolRequest(
            tool=ToolName.EXTERNAL_TOOL,
            params={"tool": "faketool", "args": ["demo.testfire.net"]},
        ),
        run.id,
        "task-2",
    )
    assert evidence.source_url == "http://demo.testfire.net"
