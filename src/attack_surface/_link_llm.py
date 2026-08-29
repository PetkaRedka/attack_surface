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
