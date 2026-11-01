from __future__ import annotations

import yaml
import pytest

from websec_agent.config import load_config, load_scope_policy
from websec_agent.core.errors import ConfigError


def _write_config(tmp_path, **overrides):
    roles = {
        "pentester": {
            "provider": "openai_compatible",
            "model": "test-model",
            "base_url": "https://model.example/v1",
            "api_key_env": "TEST_KEY",
        }
    }
    roles.update(overrides)
    path = tmp_path / "models.yaml"
    path.write_text(
        yaml.safe_dump({"run": {"max_tasks": 10}, "roles": roles}),
        encoding="utf-8",
    )
    return path


def test_empty_pentester_model_is_rejected_at_startup(tmp_path):
    path = _write_config(
        tmp_path,
        pentester={
            "provider": "openai_compatible",
            "model": "",
            "base_url": "https://model.example/v1",
        },
    )
    with pytest.raises(ConfigError, match="pentester: model is empty"):
        load_config(path)


def test_valid_four_pentester_config_loads_one_shared_model(tmp_path):
    config = load_config(_write_config(tmp_path))
    assert list(config.roles) == ["pentester"]
    assert config.roles["pentester"].model == "test-model"
    assert config.run.max_tasks == 10


def test_missing_pentester_role_is_rejected(tmp_path):
    path = tmp_path / "models.yaml"
    path.write_text(yaml.safe_dump({"roles": {}}), encoding="utf-8")
    with pytest.raises(ConfigError, match="missing role configuration: pentester"):
        load_config(path)


def test_scope_policy_parsing(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(
        yaml.safe_dump({"allowed_hosts": ["*.example.com"], "allow_private": False}),
        encoding="utf-8",
    )
    policy = load_scope_policy(path)
    assert policy.allowed_hosts == ["*.example.com"]
    assert policy.allow_private is False
