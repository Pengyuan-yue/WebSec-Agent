from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agents.orchestrator import Orchestrator
from .config import load_config, load_scope_policy, load_tools
from .core.errors import ConfigError, ScopeViolation, WebSecError
from .core.schemas import Role, TaskKind, TaskStatus
from .llm.registry import ModelRegistry
from .scope.guard import ScopeGuard
from .store.db import Database
from .store.repos import Repositories
from .tools.executor import ToolExecutor


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websec-agent", description="Scope-guarded multi-agent web security harness"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="run an assessment against one authorized target")
    run.add_argument("--target", required=True, help="target URL, e.g. https://example.com")
    run.add_argument("--config", default="config/models.yaml", help="model routing config")
    run.add_argument("--scope", default="config/scope_policy.yaml", help="authorized scope policy")
    run.add_argument("--artifacts", default=None, help="artifacts directory override")
    run.add_argument("--db-url", default=None, help="database URL override")
    run.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="explicitly authorized extra host (repeatable); no automatic scope expansion",
    )
    run.add_argument(
        "--allow-private",
        action="store_true",
        help="allow private/loopback targets (local testing only)",
    )
    run.add_argument(
        "--no-memory",
        action="store_true",
        help="start from a clean slate: do not read or write cross-run knowledge",
    )

    serve = subparsers.add_parser("serve", help="launch the interactive web console")
    serve.add_argument("--host", default="127.0.0.1", help="bind address (local-only default)")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--config", default="config/models.yaml", help="model routing config")
    serve.add_argument("--scope", default="config/scope_policy.yaml", help="authorized scope policy")
    serve.add_argument("--artifacts", default=None, help="artifacts directory override")
    serve.add_argument("--db-url", default=None, help="database URL override")
    serve.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="explicitly authorized extra host (repeatable)",
    )
    serve.add_argument(
        "--allow-private",
        action="store_true",
        help="allow private/loopback targets (local testing only)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "run":
        return _run(args)
    if args.command == "serve":
        return _serve(args)
    return 2


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .webapp import Console, create_app

    try:
        console = Console(
            config_path=args.config,
            scope_path=args.scope,
            artifacts_root=args.artifacts,
            db_url=args.db_url,
            allow_private=args.allow_private,
            allow_hosts=args.allow_host,
        )
    except (ConfigError, ScopeViolation) as exc:
        print(f"startup error: {exc}", file=sys.stderr)
        return 2

    app = create_app(console)
    print(
        f"WebSec Agent console: http://{args.host}:{args.port} "
        f"(scope: {', '.join(sorted(console.policy.allowed_hosts)) or 'restricted by policy'})",
        file=sys.stderr,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def _run(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        policy = load_scope_policy(args.scope)
        if args.allow_private:
            policy.allow_private = True
        guard = ScopeGuard(policy, args.target)
        if args.allow_host:
            guard.expand(args.allow_host)

        registry = ModelRegistry(config)
        for role in (Role.PENTESTER,):
            registry.resolve(role)
    except (ConfigError, ScopeViolation) as exc:
        print(f"startup error: {exc}", file=sys.stderr)
        return 2

    database_url = args.db_url or config.database_url
    artifacts_root = Path(args.artifacts or config.artifacts_dir)
    artifacts_root.mkdir(parents=True, exist_ok=True)

    db = Database(database_url)
    db.create_all()
    repos = Repositories.build(db)
    tools_path = Path(args.config).resolve().parent / "tools.yaml"
    executor = ToolExecutor(
        guard, repos.evidence, artifacts_root, tools=load_tools(tools_path)
    )
    orchestrator = Orchestrator(
        db=db,
        target=args.target,
        executor=executor,
        registry=registry,
        run_budget=config.run,
        artifacts_root=artifacts_root,
        use_memory=not args.no_memory,
    )

    try:
        run = orchestrator.run()
    except WebSecError as exc:
        print(f"run failed: {exc}", file=sys.stderr)
        return 1
    finally:
        executor.close()
        registry.close()

    tasks = repos.tasks.list_by_run(run.id)
    report_task = next(
        (task for task in tasks if task.kind == TaskKind.REPORT and task.status == TaskStatus.DONE),
        None,
    )
    report_dir = (report_task.result or {}).get("report_dir") if report_task else None
    output = {
        "run_id": run.id,
        "status": run.status.value,
        "stats": run.stats,
        "report_dir": report_dir,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if run.status.value in {"completed", "completed_with_errors"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
