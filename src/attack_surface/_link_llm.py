"""LLM-подтверждение найденных кросс-репозиторных связей.

Кандидаты, найденные статическими эвристиками в ``_linker``, проверяются
LLM на предмет того, действительно ли найденный фрагмент кода обращается
к серверному эндпоинту другого репозитория.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from tqdm import tqdm

from attack_surface._llm import LLMTool, LLMToolInput, LLMToolOutput
from attack_surface._logger import Logger


# ---------------------------------------------------------------------------
# Вход / выход
# ---------------------------------------------------------------------------

class LinkValidatorInput(LLMToolInput):
    """Вход для подтверждения связи."""

    def __init__(
        self,
        link_type: str,
        server_repo: str,
        server_function_name: str,
        server_signature: str,
        client_repo: str,
        client_file: str,
        client_line: int,
        client_snippet: str,
    ) -> None:
        self.link_type = link_type
        self.server_repo = server_repo
        self.server_function_name = server_function_name
        self.server_signature = server_signature
        self.client_repo = client_repo
        self.client_file = client_file
        self.client_line = client_line
        self.client_snippet = client_snippet

    def __hash__(self) -> int:
        return hash(
            (
                self.link_type,
                self.server_repo,
                self.server_signature,
                self.client_file,
                self.client_line,
                self.client_snippet,
            )
        )

    def describe(self) -> str:
        return (
            f"связь {self.client_file}:{self.client_line} → "
            f"{self.server_function_name}"
        )


class LinkValidatorOutput(LLMToolOutput):
    """Результат подтверждения связи."""

    def __init__(
        self,
        is_match: bool,
        confidence: str,
        explanation: str,
    ) -> None:
        self.is_match = is_match
        self.confidence = confidence
        self.explanation = explanation


# ---------------------------------------------------------------------------
# LLM-инструмент
# ---------------------------------------------------------------------------

class LinkValidatorLLM(LLMTool):
    """Подтверждает кросс-репозиторную связь через LLM."""

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
            "LINK_VALIDATOR_SYSTEM_ROLE",
            "Вы — эксперт по анализу межсервисного взаимодействия. "
            "Вы определяете, действительно ли фрагмент кода обращается "
            "к указанному серверному эндпоинту.",
        )
        self._task = os.getenv(
            "LINK_VALIDATOR_TASK",
            "Определите, является ли найденный фрагмент кода обращением "
            "к указанному серверному эндпоинту.",
        )

    # ------------------------------------------------------------------

    def _get_prompt(self, inp: LLMToolInput) -> str:
        if not isinstance(inp, LinkValidatorInput):
            raise TypeError("Ожидается LinkValidatorInput")

        parts: list[str] = [
            self._task,
            f"\nТип связи: {inp.link_type}",
            f"\nСерверный эндпоинт:",
            f"  Репозиторий: {inp.server_repo}",
            f"  Функция: {inp.server_function_name}",
            f"  Сигнатура: {inp.server_signature}",
            f"\nКандидат-обращение в репозитории '{inp.client_repo}':",
            f"  Файл: {inp.client_file}:{inp.client_line}",
            f"  Строка: {inp.client_snippet}",
            (
                "\nОтветьте строго в формате JSON:\n"
                '{\n'
                '  "is_match": true,\n'
                '  "confidence": "high",\n'
                '  "explanation": "..."\n'
                '}'
            ),
        ]
        return "\n".join(parts)

    def _parse_response(
        self, response: str, inp: LLMToolInput | None = None
    ) -> LLMToolOutput | None:
        match = re.search(r'\{[\s\S]*"is_match"[\s\S]*\}', response)
        if match:
            try:
                data = json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
            confidence = str(data.get("confidence", "medium")).strip().lower()
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"
            return LinkValidatorOutput(
                is_match=bool(data.get("is_match", False)),
                confidence=confidence,
                explanation=str(data.get("explanation", "")),
            )
        return None


# ---------------------------------------------------------------------------
# Утилита
# ---------------------------------------------------------------------------

def confirm_edges(
    validator: LinkValidatorLLM,
    edges: list[Any],
) -> list[Any]:
    """Подтвердить список кандидатов, отфильтровав ложные срабатывания.

    Возвращает копию списка с обновлённым полем ``confidence``;
    не подтверждённые связи (``is_match=False``) исключаются.
    """
    confirmed: list[Any] = []
    for edge in tqdm(edges, desc="Подтверждение связей", unit="связь"):
        inp = LinkValidatorInput(
            link_type=edge.link.type,
            server_repo=edge.server_repo,
            server_function_name=edge.server_function_name,
            server_signature=edge.server_signature,
            client_repo=edge.client_repo,
            client_file=edge.client_file,
            client_line=edge.client_line,
            client_snippet=edge.client_snippet,
        )
        out = validator.invoke(inp, LinkValidatorOutput)
        if out is None:
            # LLM недоступен — сохраняем кандидата с прежней уверенностью
            confirmed.append(edge)
            continue
        if out.is_match:
            edge.confidence = out.confidence
            confirmed.append(edge)
    return confirmed


# ---------------------------------------------------------------------------
# Батчевое подтверждение связей
# ---------------------------------------------------------------------------

class LinkBatchInput(LLMToolInput):
    """Вход для батчевого подтверждения связей."""

    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items

    def __hash__(self) -> int:
        return hash(tuple(json.dumps(i, sort_keys=True) for i in self.items))

    def describe(self) -> str:
        return f"батч из {len(self.items)} связей"


class LinkBatchOutput(LLMToolOutput):
    """Результат батчевого подтверждения связей."""

    def __init__(self, results: dict[int, LinkValidatorOutput]) -> None:
        self.results = results


class LinkBatchValidatorLLM(LLMTool):
    """Подтверждает связи батчами, снижая число запросов к LLM."""

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
        # Те же переменные окружения, что и у LinkValidatorLLM
        self._system_role = os.getenv(
            "LINK_VALIDATOR_SYSTEM_ROLE",
            "Вы — эксперт по анализу межсервисного взаимодействия. "
            "Вы определяете, действительно ли фрагменты кода обращаются "
            "к указанным серверным эндпоинтам.",
        )
        self._task = os.getenv(
            "LINK_VALIDATOR_TASK",
            "Определите для каждого кандидата, является ли найденный фрагмент "
            "кода обращением к указанному серверному эндпоинту.",
        )

    # ------------------------------------------------------------------

    def _get_prompt(self, inp: LLMToolInput) -> str:
        if not isinstance(inp, LinkBatchInput):
            raise TypeError("Ожидается LinkBatchInput")

        parts: list[str] = [self._task, "\nКандидаты:"]
        for index, item in enumerate(inp.items):
            parts.append(
                f"\n[{index}] Тип связи: {item['link_type']}\n"
                f"  Сервер: {item['server_repo']}, функция: "
                f"{item['server_function_name']}, сигнатура: {item['server_signature']}\n"
                f"  Клиент: {item['client_repo']}, файл: {item['client_file']}:"
                f"{item['client_line']}\n"
                f"  Строка: {item['client_snippet']}"
            )

        parts.append(
            '\nОтветьте строго в формате JSON (по одному элементу на каждый кандидат):\n'
            '{\n'
            '  "results": [\n'
            '    {\n'
            '      "index": 0,\n'
            '      "is_match": true,\n'
            '      "confidence": "high",\n'
            '      "explanation": "..."\n'
            '    }\n'
            '  ]\n'
            '}'
        )
        return "\n".join(parts)

    def _parse_response(
        self, response: str, inp: LLMToolInput | None = None
    ) -> LLMToolOutput | None:
        results = parse_batch_response(response)
        if results is None:
            return None
        return LinkBatchOutput(results=results)


def parse_batch_response(
    response: str,
) -> dict[int, LinkValidatorOutput] | None:
    """Разобрать батчевый ответ LLM в ``{index: LinkValidatorOutput}``."""
    match = re.search(r'\{[\s\S]*"results"[\s\S]*\}', response)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

    results: dict[int, LinkValidatorOutput] = {}
    for item in data.get("results", []):
        if not isinstance(item, dict) or "index" not in item:
            continue
        try:
            index = int(item["index"])
        except (TypeError, ValueError):
            continue
        confidence = str(item.get("confidence", "medium")).strip().lower()
        if confidence not in ("high", "medium", "low"):
            confidence = "medium"
        results[index] = LinkValidatorOutput(
            is_match=bool(item.get("is_match", False)),
            confidence=confidence,
            explanation=str(item.get("explanation", "")),
        )
    if not results:
        return None
    return results


# Ключ группировки кандидатов: одна серверная сигнатура, вызываемая
# из одного файла клиента, — это одна связь, найденная в нескольких местах.
def _edge_group_key(edge: Any) -> tuple[str, str, str, str, str]:
    """Ключ, по которому кандидаты сворачиваются в одну связь."""
    return (
        edge.link.type,
        edge.server_repo,
        edge.server_signature,
        edge.client_repo,
        edge.client_file,
    )


def confirm_edges_batch(
    validator: LinkBatchValidatorLLM,
    edges: list[Any],
    batch_size: int,
) -> list[Any]:
    """Подтвердить связи батчами, сворачивая дубликаты в одну связь.

    Кандидаты группируются по ключу (тип, сервер, сигнатура, клиентский
    репозиторий и файл): на группу — один запрос к LLM, а его результат
    распространяется на все места вызова группы. Это сохраняет полноту
    графа (каждое место вызова остаётся ребром) и резко снижает число
    запросов.

    Не подтверждённые связи (``is_match=False``) исключаются.
    """
    if batch_size < 1:
        batch_size = 1

    # Группировка с сохранением порядка первого появления
    group_map: dict[tuple[str, str, str, str, str], list[Any]] = {}
    groups: list[list[Any]] = []
    for edge in edges:
        key = _edge_group_key(edge)
        if key not in group_map:
            group_map[key] = [edge]
            groups.append(group_map[key])
        else:
            group_map[key].append(edge)

    confirmed: list[Any] = []
    with tqdm(total=len(groups), desc="Подтверждение связей", unit="связь"):
        for start in range(0, len(groups), batch_size):
            chunk = groups[start : start + batch_size]
            inp = LinkBatchInput(items=[_edge_item(g[0]) for g in chunk])
            out = validator.invoke(inp, LinkBatchOutput)
            results = out.results if out is not None else {}

            for index, group in enumerate(chunk):
                result = results.get(index)
                if result is None:
                    # LLM не ответил по кандидату — сохраняем с прежней уверенностью
                    confirmed.extend(group)
                elif result.is_match:
                    for edge in group:
                        edge.confidence = result.confidence
                    confirmed.extend(group)
    return confirmed


def _edge_item(edge: Any) -> dict[str, Any]:
    """Представление кандидата для LLM-промпта."""
    return {
        "link_type": edge.link.type,
        "server_repo": edge.server_repo,
        "server_function_name": edge.server_function_name,
        "server_signature": edge.server_signature,
        "client_repo": edge.client_repo,
        "client_file": edge.client_file,
        "client_line": edge.client_line,
        "client_snippet": edge.client_snippet,
    }
