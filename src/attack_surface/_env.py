"""Утилиты чтения переменных окружения."""

from __future__ import annotations

import os


def flag(name: str, default: bool) -> bool:
    """Логический флаг: истина, если значение не из списка отключения."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off", "")


def int_value(name: str, default: int) -> int:
    """Целое число из окружения (при невалидном значении — дефолт)."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default
