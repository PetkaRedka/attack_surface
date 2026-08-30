"""Модели данных для поверхности атаки."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Типы точек входа
# ---------------------------------------------------------------------------

class EntryPointType(str, Enum):
    """Классификация внешних интерфейсов."""

    ENVIRONMENT_VARIABLE = "environment_variable"
    COMMAND_LINE_ARGS = "command_line_args"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    WEBSOCKET = "websocket"
    SOCKET = "socket"
    USER_INPUT = "user_input"
    DATABASE_QUERY = "database_query"
    MESSAGE_QUEUE = "message_queue"
    EVENT_HANDLER = "event_handler"
    DESERIALIZATION = "deserialization"
    LAMBDA_HANDLER = "lambda_handler"
    AZURE_FUNCTION = "azure_function"
    MAIN_FUNCTION = "main_function"
    UNKNOWN = "unknown"


# Человекочитаемые названия (русский)
ENTRY_POINT_DISPLAY_NAMES: dict[str, str] = {
    "environment_variable": "Переменные окружения",
    "command_line_args": "Аргументы командной строки",
    "file_read": "Чтение из файла",
    "file_write": "Запись в файл",
    "http_request": "HTTP запрос",
    "http_response": "HTTP ответ",
    "websocket": "WebSocket",
    "socket": "Сокет",
    "user_input": "Пользовательский ввод",
    "database_query": "Запрос к базе данных",
    "message_queue": "Очередь сообщений",
    "event_handler": "Обработчик событий",
    "deserialization": "Десериализация",
    "lambda_handler": "AWS Lambda",
    "azure_function": "Azure Function",
    "main_function": "Главная функция",
    "unknown": "Неизвестный тип",
}


def display_name(entry_type: str) -> str:
    """Человекочитаемое имя для типа точки входа."""
    return ENTRY_POINT_DISPLAY_NAMES.get(entry_type, entry_type)


# ---------------------------------------------------------------------------
# Внешний источник данных
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExternalSource:
    """Вызов API/конструкция, получающая данные извне."""

    name: str
    line_number: int
    file_path: str
    entry_point_type: str = "unknown"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExternalSource":
        """Восстановить источник из JSON (см. ``to_dict``)."""
        return cls(
            name=str(data.get("name", "")),
            line_number=int(data.get("line_number", 0)),
            file_path=str(data.get("file", "")),
            entry_point_type=str(data.get("entry_point_type", "unknown")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "line_number": self.line_number,
            "file": self.file_path,
            "entry_point_type": self.entry_point_type,
        }


# ---------------------------------------------------------------------------
# Информация о точке входа
# ---------------------------------------------------------------------------

@dataclass
class EntryPointInfo:
    """Валидированная точка входа."""

    node_id: str
    function_name: str
    file_path: str
    start_line: int
    end_line: int
    entry_point_type: str = "unknown"
    external_data_description: str = ""
    external_sources: list[ExternalSource] = field(default_factory=list)
    confidence: str = "high"
    is_root_function: bool = False
    explanation: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EntryPointInfo":
        """Восстановить точку входа из JSON (см. ``to_dict``)."""
        return cls(
            node_id=str(data.get("node_id", "")),
            function_name=str(data.get("function_name", "")),
            file_path=str(data.get("file_path", "")),
            start_line=int(data.get("start_line", 0)),
            end_line=int(data.get("end_line", 0)),
            entry_point_type=str(data.get("entry_point_type", "unknown")),
            external_data_description=str(data.get("external_data_description", "")),
            external_sources=[
                ExternalSource.from_dict(s)
                for s in data.get("external_input_sources", [])
                if isinstance(s, dict)
            ],
            confidence=str(data.get("confidence", "high")),
            is_root_function=bool(data.get("is_root_function", False)),
            explanation=str(data.get("explanation", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "function_name": self.function_name,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "entry_point_type": self.entry_point_type,
            "external_data_description": self.external_data_description,
            "external_input_sources": [s.to_dict() for s in self.external_sources],
            "confidence": self.confidence,
            "is_root_function": self.is_root_function,
            "explanation": self.explanation,
        }


# ---------------------------------------------------------------------------
# Результат сканирования
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Агрегированный результат сканирования поверхности атаки."""

    project_name: str
    language: str
    entry_points: dict[str, EntryPointInfo] = field(default_factory=dict)
    root_function_count: int = 0
    external_input_function_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project_name,
            "language": self.language,
            "total_entry_points": len(self.entry_points),
            "entry_points": {
                k: v.to_dict() for k, v in self.entry_points.items()
            },
        }
