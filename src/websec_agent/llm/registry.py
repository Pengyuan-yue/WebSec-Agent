from __future__ import annotations

import os
from typing import Mapping, Protocol

from ..config import AppConfig, RoleModelConfig
from ..core.errors import ConfigError
from ..core.schemas import Role
from .gateway import LLMGateway
from .providers.openai_compatible import OpenAICompatibleGateway


class GatewayRegistry(Protocol):
    def resolve(self, role: Role) -> tuple[RoleModelConfig, LLMGateway]: ...


class ModelRegistry:
    def __init__(self, config: AppConfig, env: Mapping[str, str] | None = None) -> None:
        self._config = config
        self._env = env or os.environ
        self._gateways: dict[Role, LLMGateway] = {}

    def resolve(self, role: Role) -> tuple[RoleModelConfig, LLMGateway]:
        if role not in self._config.roles:
            raise ConfigError(f"no model configuration for role: {role.value}")
        settings = self._config.roles[role]
        if not settings.model.strip():
            raise ConfigError(f"role {role.value} has an empty model; fill config/models.yaml")

        gateway = self._gateways.get(role)
        if gateway is None:
            gateway = self._build(role, settings)
            self._gateways[role] = gateway
        return settings, gateway

    def _build(self, role: Role, settings: RoleModelConfig) -> LLMGateway:
        if settings.provider == "fake":
            raise ConfigError(
                f"role {role.value} uses provider 'fake'; inject a gateway in tests instead of CLI"
            )
        api_key = self._env.get(settings.api_key_env, "")
        if not api_key:
            from ..config_overrides import api_key_fallback

            api_key = api_key_fallback()
        if not api_key:
            raise ConfigError(
                f"environment variable {settings.api_key_env} is not set for role {role.value} "
                "(set it or save an OpenRouter key in the console settings panel)"
            )
        if not settings.base_url.strip():
            raise ConfigError(f"role {role.value} has an empty base_url")
        return OpenAICompatibleGateway(base_url=settings.base_url, api_key=api_key)

    def close(self) -> None:
        for gateway in self._gateways.values():
            close = getattr(gateway, "close", None)
            if callable(close):
                close()
