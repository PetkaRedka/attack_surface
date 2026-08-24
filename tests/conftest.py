"""Общие pytest fixtures для attack_surface."""

import pytest


@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch):
    """Мокируем переменные окружения для тестов."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-12345")
    monkeypatch.setenv("OPENAI_MODEL_NAME", "gpt-4o-mini")
