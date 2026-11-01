from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .core.errors import ConfigError
from .core.schemas import Role, RunBudget

REQUIRED_ROLES: tuple[Role, ...] = (Role.PENTESTER, Role.SUPERVISOR)


class RoleModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["openai_compatible", "fake"] = "openai_compatible"
    model: str = ""
    base_url: str = ""
    api_key_env: str = "WEBSEC_API_KEY"
    temperature: float = Field(default=0.2, ge=0, le=2)
    max_output_tokens: int = Field(default=4096, ge=1)
    context_window_tokens: int = Field(default=128000, ge=1024)
    input_cost_per_mtok: float = Field(default=0, ge=0)
    output_cost_per_mtok: float = Field(default=0, ge=0)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    database_url: str = "sqlite+pysqlite:///websec.db"
    artifacts_dir: str = "artifacts"
    run: RunBudget = Field(default_factory=RunBudget)
    roles: dict[Role, RoleModelConfig] = Field(default_factory=dict)


class ScopePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_hosts: list[str] = Field(default_factory=list)
    denied_hosts: list[str] = Field(default_factory=list)
    allow_private: bool = False
    allowed_ports: list[int] = Field(default_factory=list)

    def snapshot(self, target: str) -> dict:
        return {
            "allowed_hosts": list(self.allowed_hosts),
            "denied_hosts": list(self.denied_hosts),
            "allow_private": self.allow_private,
            "allowed_ports": list(self.allowed_ports),
            "target": target,
        }


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid yaml in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"config root must be a mapping: {path}")
    return data


def load_config(path: str | Path) -> AppConfig:
    raw = _read_yaml(Path(path))
    try:
        config = AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid models.yaml: {exc}") from exc
    validate_for_startup(config)
    return config


def validate_for_startup(config: AppConfig) -> None:
    """Fail fast instead of silently picking a default model."""
    missing = [role.value for role in REQUIRED_ROLES if role not in config.roles]
    if missing:
        raise ConfigError(f"missing role configuration: {', '.join(missing)}")

    invalid: list[str] = []
    for role in REQUIRED_ROLES:
        spec = config.roles[role]
        if not spec.model.strip():
            invalid.append(f"{role.value}: model is empty")
        if spec.provider == "openai_compatible" and not spec.base_url.strip():
            invalid.append(f"{role.value}: base_url is empty")
    if invalid:
        raise ConfigError(
            "model configuration is incomplete; fill these fields before starting:\n  "
            + "\n  ".join(invalid)
        )

    if config.run.max_parallel < 1:
        raise ConfigError("run.max_parallel must be >= 1")


class ExternalToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    path: str
    description: str = ""
    # "url": args must contain at least one URL and every URL must be in scope
    # "none": no target extraction (offline/utility tools)
    arg_scope: Literal["url", "none"] = "url"
    blocked_args: list[str] = Field(default_factory=list)
    # inserted between the executable and the agent-provided args
    pre_args: list[str] = Field(default_factory=list)
    # appended to args when HTTP_PROXY is set; "{PROXY}" is replaced by the proxy URL
    proxy_args: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=180, ge=1, le=900)
    max_output_bytes: int = Field(default=262144, ge=1024)

    def installed(self) -> bool:
        import os
        import shutil
        import sys

        raw = Path(self.path)
        if os.name == "nt" and ".venv" in raw.parts and "bin" in raw.parts:
            # venv layout differs by platform: .venv/bin -> .venv/Scripts on Windows
            raw = Path(*["Scripts" if part == "bin" else part for part in raw.parts])
        if raw.name.lower() in {"python", "python2", "python3", "python.exe"}:
            return Path(sys.executable).exists()
        if raw.exists():
            return True
        if os.name == "nt" and raw.with_name(raw.name + ".exe").exists():
            return True
        return bool(shutil.which(raw.name))


class ToolsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_destructive: bool = False
    tools: dict[str, ExternalToolSpec] = Field(default_factory=dict)


def load_tools(path: str | Path) -> ToolsConfig:
    file = Path(path)
    if not file.exists():
        return ToolsConfig()
    try:
        return ToolsConfig.model_validate(_read_yaml(file))
    except ValidationError as exc:
        raise ConfigError(f"invalid tools.yaml: {exc}") from exc


def load_scope_policy(path: str | Path) -> ScopePolicy:
    raw = _read_yaml(Path(path))
    try:
        return ScopePolicy.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid scope_policy.yaml: {exc}") from exc
