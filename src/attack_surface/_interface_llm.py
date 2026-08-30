"""LLM-анализ точек входа: валидация на принадлежность к поверхности атаки
и определение интерфейса для связи с другими репозиториями.

Каждая найденная статическим анализом точка входа проходит через LLM,
который (1) подтверждает или отклоняет её как реальную точку входа и
(2) определяет, является ли она интерфейсом для связи с другими
репозиториями, извлекая сигнатуру для последующего поиска в коде.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from attack_surface._llm import LLMTool, LLMToolInput, LLMToolOutput
from attack_surface._logger import Logger


# ---------------------------------------------------------------------------
# Дескриптор интерфейса
# ---------------------------------------------------------------------------

@dataclass
class InterfaceDescriptor:
    """Результат анализа точки входа: ПА-валидация + интерфейс связи."""

    is_entry_point: bool = True
    entry_point_confidence: str = "high"
    interface_role: str = "none"       # server | client | both | none
    interface_kind: str = "none"       # см. _INTERFACE_KINDS
    signature: str = ""
    signature_aliases: list[str] = field(default_factory=list)
    explanation: str = ""

    def is_server(self) -> bool:
        """Принимает ли интерфейс данные от других репозиториев/внешнего мира."""
        return self.interface_role in ("server", "both")

    def is_client(self) -> bool:
        """Обращается ли интерфейс к другим репозиториям."""
        return self.interface_role in ("client", "both")

    def has_interface(self) -> bool:
        """Имеет ли точка входа определяемый интерфейс связи."""
        return self.interface_kind not in ("", "none") and bool(self.signature)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InterfaceDescriptor":
        """Восстановить дескриптор из JSON (см. ``to_dict``)."""
        aliases = data.get("signature_aliases", [])
        if not isinstance(aliases, list):
            aliases = []
        return cls(
            is_entry_point=bool(data.get("is_entry_point", True)),
            entry_point_confidence=str(data.get("entry_point_confidence", "high")),
            interface_role=str(data.get("interface_role", "none")),
            interface_kind=str(data.get("interface_kind", "none")),
            signature=str(data.get("signature", "")),
            signature_aliases=[str(a) for a in aliases],
            explanation=str(data.get("explanation", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_entry_point": self.is_entry_point,
            "entry_point_confidence": self.entry_point_confidence,
            "interface_role": self.interface_role,
            "interface_kind": self.interface_kind,
            "signature": self.signature,
            "signature_aliases": self.signature_aliases,
            "explanation": self.explanation,
        }


# Фоллбэк: маппинг статического типа точки входа → (interface_kind, interface_role).
# Используется, когда LLM недоступен или не вернул результат.
_ENTRY_POINT_TO_INTERFACE: dict[str, tuple[str, str]] = {
    "http_request": ("http", "both"),
    "http_response": ("http", "both"),
    "websocket": ("websocket", "both"),
    "socket": ("rpc", "both"),
    "database_query": ("shared-db", "both"),
    "message_queue": ("message-queue", "both"),
    "lambda_handler": ("http", "server"),
    "azure_function": ("http", "server"),
    "event_handler": ("message-queue", "server"),
    "deserialization": ("file", "both"),
    "file_read": ("file", "both"),
    "file_write": ("file", "both"),
}


# Допустимые значения interface_kind: семьи взаимодействия, покрывающие
# все протоколы Threagile (см. _threagile.PROTOCOL_TO_LINK_TYPE).
_INTERFACE_KINDS: str = (
    "http | grpc | websocket | shared-db | ffi | pinvoke | message-queue | rpc | "
    "file | reverse-proxy | email | ssh | ftp | ldap | binary | text | ipc | "
    "container | nfs | none"
)


# ---------------------------------------------------------------------------
# Вход / выход
# ---------------------------------------------------------------------------

class InterfaceAnalyzerInput(LLMToolInput):
    """Вход для анализа точки входа."""

    def __init__(
        self,
        repo_name: str,
        repo_role: str,
        language: str,
        function_name: str,
        file_path: str,
        start_line: int,
        end_line: int,
        entry_point_type: str,
        code: str,
    ) -> None:
        self.repo_name = repo_name
        self.repo_role = repo_role
        self.language = language
        self.function_name = function_name
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.entry_point_type = entry_point_type
        self.code = code

    def __hash__(self) -> int:
        return hash(
            (
                self.repo_name,
                self.function_name,
                self.file_path,
                self.start_line,
                self.end_line,
                self.entry_point_type,
            )
        )

    def describe(self) -> str:
        return (
            f"функция {self.function_name} "
            f"({self.file_path}:{self.start_line}-{self.end_line})"
        )


class InterfaceAnalyzerOutput(LLMToolOutput):
    """Результат анализа точки входа."""

    def __init__(self, descriptor: InterfaceDescriptor) -> None:
        self.descriptor = descriptor


# ---------------------------------------------------------------------------
# LLM-инструмент
# ---------------------------------------------------------------------------

class InterfaceAnalyzerLLM(LLMTool):
    """Определяет интерфейс точки входа через LLM."""

    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
    ) -> None:
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self._load_prompts()

    # ------------------------------------------------------------------

    def _load_prompts(self) -> None:
        self._system_role = os.getenv(
            "INTERFACE_ANALYZER_SYSTEM_ROLE",
            "Вы — эксперт по архитектуре ПО и анализу безопасности. "
            "Вы классифицируете функции как точки входа и определяете, "
            "являются ли они интерфейсами связи между репозиториями.",
        )
        self._task = os.getenv(
            "INTERFACE_ANALYZER_TASK",
            "Проанализируйте функцию и определите, является ли она точкой входа "
            "и интерфейсом для связи с другими репозиториями.",
        )
        self._rules = os.getenv(
            "INTERFACE_ANALYZER_RULES",
            "interface_role: server — принимает запросы от других репозиториев "
            "или внешнего мира; client — сама вызывает другие репозитории; "
            "both; none — не является интерфейсом связи.\n"
            "interface_kind: " + _INTERFACE_KINDS + ".\n"
            "signature — точная строка, по которой интерфейс можно найти в коде "
            "другого репозитория (например 'POST /api/v1/orders', "
            "'orders.OrderService/Create', 'native_process', 'orders').\n"
            "signature_aliases — варианты записи сигнатуры (без HTTP-метода, "
            "без base_url, snake_case и т.п.).",
        )

    # ------------------------------------------------------------------

    def _get_prompt(self, inp: LLMToolInput) -> str:
        if not isinstance(inp, InterfaceAnalyzerInput):
            raise TypeError("Ожидается InterfaceAnalyzerInput")

        role = f" (роль: {inp.repo_role})" if inp.repo_role else ""
        parts: list[str] = [
            self._task,
            f"\nРепозиторий: {inp.repo_name}{role}, язык: {inp.language}",
            f"Файл: {inp.file_path}:{inp.start_line}-{inp.end_line}",
            f"Функция: {inp.function_name}",
            f"Тип по статическому анализу: {inp.entry_point_type}",
            f"\nКод функции:\n```\n{inp.code}\n```",
        ]

        if self._rules:
            parts.append(f"\nПравила:\n{self._rules}")

        parts.append(
            '\nОтветьте строго в формате JSON:\n'
            '{\n'
            '  "is_entry_point": true,\n'
            '  "entry_point_confidence": "high",\n'
            '  "interface_role": "server",\n'
            '  "interface_kind": "http",\n'
            '  "signature": "POST /api/v1/orders",\n'
            '  "signature_aliases": ["/api/v1/orders", "orders"],\n'
            '  "explanation": "HTTP POST эндпоинт создания заказа"\n'
            '}'
        )
        return "\n".join(parts)

    def _parse_response(
        self, response: str, inp: LLMToolInput | None = None
    ) -> LLMToolOutput | None:
        match = re.search(r'\{[\s\S]*"is_entry_point"[\s\S]*\}', response)
        if match:
            try:
                data = json.loads(match.group(0))
            except json.JSONDecodeError:
                return None

            role = str(data.get("interface_role", "none")).strip().lower()
            kind = str(data.get("interface_kind", "none")).strip().lower()
            aliases = data.get("signature_aliases", [])
            if not isinstance(aliases, list):
                aliases = []

            return InterfaceAnalyzerOutput(
                InterfaceDescriptor(
                    is_entry_point=bool(data.get("is_entry_point", True)),
                    entry_point_confidence=str(
                        data.get("entry_point_confidence", "high")
                    ),
                    interface_role=role if role in ("server", "client", "both", "none") else "none",
                    interface_kind=kind,
                    signature=str(data.get("signature", "")).strip(),
                    signature_aliases=[str(a) for a in aliases],
                    explanation=str(data.get("explanation", "")),
                )
            )

        # Фоллбэк: определение по статическому типу точки входа
        if isinstance(inp, InterfaceAnalyzerInput):
            return InterfaceAnalyzerOutput(
                fallback_descriptor(
                    inp.entry_point_type,
                    code=inp.code,
                    language=inp.language,
                    function_name=inp.function_name,
                )
            )
        return None


# ---------------------------------------------------------------------------
# Фоллбэк
# ---------------------------------------------------------------------------

# URL-подобные пути в строковых литералах: "/api/v1/orders", "/cabinet/auth/refresh"
_URL_PATH_RE = re.compile(r"""["'](/[A-Za-z0-9_\-./~?&=:{}%]+)["']""")


def extract_url_paths(code: str) -> list[str]:
    """Извлечь URL-подобные пути из строковых литералов кода."""
    seen: set[str] = set()
    result: list[str] = []
    for path in _URL_PATH_RE.findall(code or ""):
        if path not in seen:
            seen.add(path)
            result.append(path)
    return result


def fallback_descriptor(
    entry_point_type: str,
    code: str = "",
    language: str = "",
    function_name: str = "",
) -> InterfaceDescriptor:
    """Построить дескриптор по статическим признакам без обращения к LLM.

    Приоритет эвристик:
    1. Экспорты нативных функций (FFI / P/Invoke) по маркерам в коде;
    2. HTTP-интерфейсы по URL-литералам в коде функции;
    3. Маппинг по статическому типу точки входа.
    """
    code = code or ""

    # FFI / P/Invoke — экспортируемые нативные функции
    if function_name and language in ("c", "cpp") and (
        "extern" in code or "dllexport" in code
    ):
        return InterfaceDescriptor(
            is_entry_point=True,
            entry_point_confidence="medium",
            interface_role="server",
            interface_kind="ffi",
            signature=function_name,
            signature_aliases=[function_name],
            explanation="Экспорт нативной функции (статическая эвристика).",
        )
    if function_name and language == "c_sharp" and "DllImport" in code:
        return InterfaceDescriptor(
            is_entry_point=True,
            entry_point_confidence="medium",
            interface_role="both",
            interface_kind="pinvoke",
            signature=function_name,
            signature_aliases=[function_name],
            explanation="P/Invoke-импорт (статическая эвристика).",
        )

    # HTTP-интерфейсы по URL-литералам в коде функции
    paths = extract_url_paths(code)
    if paths:
        return InterfaceDescriptor(
            is_entry_point=True,
            entry_point_confidence="medium",
            interface_role="both",
            interface_kind="http",
            signature=paths[0],
            signature_aliases=paths[1:],
            explanation="HTTP-интерфейс по URL-литералам (статическая эвристика).",
        )

    kind, role = _ENTRY_POINT_TO_INTERFACE.get(entry_point_type, ("none", "none"))
    return InterfaceDescriptor(
        is_entry_point=True,
        entry_point_confidence="medium",
        interface_role=role,
        interface_kind=kind,
        signature="",
        signature_aliases=[],
        explanation="Определено по статическому типу (LLM недоступен).",
    )


# ---------------------------------------------------------------------------
# Батчевая валидация точек входа
# ---------------------------------------------------------------------------

class InterfaceBatchInput(LLMToolInput):
    """Вход для батчевого анализа нескольких точек входа одним запросом."""

    def __init__(
        self,
        repo_name: str,
        repo_role: str,
        language: str,
        items: list[dict[str, Any]],
    ) -> None:
        self.repo_name = repo_name
        self.repo_role = repo_role
        self.language = language
        self.items = items

    def __hash__(self) -> int:
        # Код не включаем в хеш: для статического сканирования достаточно
        # идентификаторов точек входа и их статических типов.
        keys = tuple(
            (item["node_id"], item["entry_point_type"]) for item in self.items
        )
        return hash((self.repo_name, keys))

    def describe(self) -> str:
        return f"батч из {len(self.items)} функций ({self.repo_name})"


class InterfaceBatchOutput(LLMToolOutput):
    """Результат батчевого анализа."""

    def __init__(self, descriptors: dict[str, InterfaceDescriptor]) -> None:
        # node_id → дескриптор
        self.descriptors = descriptors


class InterfaceBatchAnalyzerLLM(LLMTool):
    """Анализирует несколько точек входа одним LLM-запросом."""

    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
    ) -> None:
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self._load_prompts()

    # ------------------------------------------------------------------

    def _load_prompts(self) -> None:
        self._system_role = os.getenv(
            "INTERFACE_ANALYZER_SYSTEM_ROLE",
            "Вы — эксперт по архитектуре ПО и анализу безопасности. "
            "Вы классифицируете функции как точки входа и определяете, "
            "являются ли они интерфейсами связи между репозиториями.",
        )
        self._task = os.getenv(
            "INTERFACE_ANALYZER_TASK",
            "Проанализируйте список функций и для каждой определите, является ли "
            "она точкой входа и интерфейсом для связи с другими репозиториями.",
        )
        self._rules = os.getenv(
            "INTERFACE_ANALYZER_RULES",
            "interface_role: server — принимает запросы от других репозиториев "
            "или внешнего мира; client — сама вызывает другие репозитории; "
            "both; none — не является интерфейсом связи.\n"
            "interface_kind: " + _INTERFACE_KINDS + ".\n"
            "signature — точная строка, по которой интерфейс можно найти в коде "
            "другого репозитория (например 'POST /api/v1/orders', "
            "'orders.OrderService/Create', 'native_process', 'orders').\n"
            "signature_aliases — варианты записи сигнатуры (без HTTP-метода, "
            "без base_url, snake_case и т.п.).",
        )

    # ------------------------------------------------------------------

    def _get_prompt(self, inp: LLMToolInput) -> str:
        if not isinstance(inp, InterfaceBatchInput):
            raise TypeError("Ожидается InterfaceBatchInput")

        role = f" (роль: {inp.repo_role})" if inp.repo_role else ""
        parts: list[str] = [
            self._task,
            f"\nРепозиторий: {inp.repo_name}{role}, язык: {inp.language}",
        ]

        if self._rules:
            parts.append(f"\nПравила:\n{self._rules}")

        parts.append("\nФункции для анализа:")
        for index, item in enumerate(inp.items):
            parts.append(
                f"\n[{index}] {item['function_name']} "
                f"({item['file_path']}:{item['start_line']}-{item['end_line']}), "
                f"тип: {item['entry_point_type']}"
            )
            parts.append(f"```\n{item['code']}\n```")

        parts.append(
            '\nОтветьте строго в формате JSON (по одному элементу на каждую функцию):\n'
            '{\n'
            '  "results": [\n'
            '    {\n'
            '      "index": 0,\n'
            '      "is_entry_point": true,\n'
            '      "entry_point_confidence": "high",\n'
            '      "interface_role": "server",\n'
            '      "interface_kind": "http",\n'
            '      "signature": "POST /api/v1/orders",\n'
            '      "signature_aliases": ["/api/v1/orders", "orders"],\n'
            '      "explanation": "HTTP POST эндпоинт создания заказа"\n'
            '    }\n'
            '  ]\n'
            '}'
        )
        return "\n".join(parts)

    def _parse_response(
        self, response: str, inp: LLMToolInput | None = None
    ) -> LLMToolOutput | None:
        if not isinstance(inp, InterfaceBatchInput):
            return None
        descriptors = parse_batch_response(response, inp.items)
        if descriptors is None:
            return None
        return InterfaceBatchOutput(descriptors)


# ---------------------------------------------------------------------------
# Разбор батчевого ответа
# ---------------------------------------------------------------------------

def parse_batch_response(
    response: str, items: list[dict[str, Any]]
) -> dict[str, InterfaceDescriptor] | None:
    """Разобрать ответ LLM: JSON-объект с массивом результатов.

    :return: ``{node_id: InterfaceDescriptor}`` или ``None`` при неудачном разборе.
    """
    match = re.search(r'\{[\s\S]*"results"[\s\S]*\}', response)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

    results = data.get("results")
    if not isinstance(results, list):
        return None

    index_to_node: dict[int, str] = {}
    for index, item in enumerate(items):
        index_to_node[index] = item["node_id"]

    descriptors: dict[str, InterfaceDescriptor] = {}
    for result in results:
        if not isinstance(result, dict) or "index" not in result:
            continue
        node_id = index_to_node.get(result["index"])
        if node_id is None:
            continue
        descriptors[node_id] = _descriptor_from_data(result)
    return descriptors if descriptors else None


def _descriptor_from_data(data: dict[str, Any]) -> InterfaceDescriptor:
    """Построить дескриптор из JSON-объекта ответа LLM."""
    role = str(data.get("interface_role", "none")).strip().lower()
    kind = str(data.get("interface_kind", "none")).strip().lower()
    aliases = data.get("signature_aliases", [])
    if not isinstance(aliases, list):
        aliases = []
    return InterfaceDescriptor(
        is_entry_point=bool(data.get("is_entry_point", True)),
        entry_point_confidence=str(data.get("entry_point_confidence", "high")),
        interface_role=role if role in ("server", "client", "both", "none") else "none",
        interface_kind=kind,
        signature=str(data.get("signature", "")).strip(),
        signature_aliases=[str(a) for a in aliases],
        explanation=str(data.get("explanation", "")),
    )
