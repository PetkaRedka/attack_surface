"""Вспомогательные функции без внешнего ввода (не должны быть точками входа)."""


def calculate_hash(data: str) -> str:
    """Внутренняя функция — не точка входа."""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()


def validate_format(text: str) -> bool:
    """Внутренняя функция — не точка входа."""
    return len(text) > 0 and text.isalnum()


def internal_helper(x: int, y: int) -> int:
    """Внутренняя функция — не точка входа."""
    return x + y
