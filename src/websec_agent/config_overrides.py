"""Local user settings managed by the web console settings panel.

Stored in config/settings_local.json (plain JSON, never committed: contains the
OpenRouter key). Applies on top of config/models.yaml at console/CLI startup
and after every settings save:

  - openrouter_key: fallback API key when the api_key_env variable is unset
  - models: {role: model_name} overrides
  - run: {max_parallel, max_tasks} overrides
  - instructions: {role: prompt_text} overrides applied to agent classes
  - theme: "light" | "dark" (informational for the frontend)
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_PATH = Path("config") / "settings_local.json"

VALID_SETTINGS_KEYS = (
    "openrouter_key",
    "models",
    "instructions",
    "run",
    "theme",
)


def load_local(path: Path | None = None) -> dict[str, Any]:
    file = path or DEFAULT_PATH
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_local(settings: dict[str, Any], path: Path | None = None) -> None:
    file = path or DEFAULT_PATH
    file.parent.mkdir(parents=True, exist_ok=True)
    payload = {key: value for key, value in settings.items() if key in VALID_SETTINGS_KEYS}
    fd, tmp_name = tempfile.mkstemp(dir=str(file.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(tmp_name, file)
    except OSError:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def api_key_fallback() -> str:
    """Key from settings file; used only when the env variable is empty."""
    return str(load_local().get("openrouter_key") or "").strip()


def apply_overrides(config: Any) -> None:
    """Merge model names and run parameters from settings_local into AppConfig."""
    from .core.schemas import Role

    local = load_local()
    for role_str, model in (local.get("models") or {}).items():
        try:
            role = Role(str(role_str))
        except ValueError:
            continue
        if role in config.roles and isinstance(model, str) and model.strip():
            config.roles[role].model = model.strip()

    run = local.get("run") or {}
    if isinstance(run, dict):
        if isinstance(run.get("max_parallel"), int) and run["max_parallel"] >= 1:
            config.run.max_parallel = run["max_parallel"]
        if isinstance(run.get("max_tasks"), int) and run["max_tasks"] >= 1:
            config.run.max_tasks = run["max_tasks"]
