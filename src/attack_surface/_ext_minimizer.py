"""LLM-минимизация внешних интерфейсов (EXT) в графе поверхности атаки.

Группирует схожие EXT-типы в один представительный EXT на модуль,
уменьшая визуальную избыточность графа.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from attack_surface._llm import LLMTool, LLMToolInput, LLMToolOutput
from attack_surface._logger import Logger


# ---------------------------------------------------------------------------
# Вход / выход
# ---------------------------------------------------------------------------


class EXTMinimizerInput(LLMToolInput):
    """Вход для минимизации EXT."""

    def __init__(
        self,
        module_name: str,
        ext_types: list[str],
        entry_points: list[dict[str, Any]],
    ) -> None:
        self.module_name = module_name
        self.ext_types = ext_types
        self.entry_points = entry_points

    def __hash__(self) -> int:
        return hash((self.module_name, tuple(sorted(self.ext_types))))

    def describe(self) -> str:
        return f"модуль {self.module_name}"


class EXTMinimizerOutput(LLMToolOutput):
    """Результат минимизации EXT."""

    def __init__(
        self,
        grouped_exts: list[dict[str, Any]],
        explanation: str,
    ) -> None:
        self.grouped_exts = grouped_exts
        self.explanation = explanation


# ---------------------------------------------------------------------------
# LLM-инструмент
# ---------------------------------------------------------------------------


class EXTMinimizer(LLMTool):
    """Минимизирует EXT-интерфейсы через LLM."""

    def __init__(
        self,
        model_name: str,
        temperature: float,
        max_query_num: int,
        logger: Logger,
    ) -> None:
        super().__init__(model_name, temperature, "Python", max_query_num, logger)
        self._load_prompts()

    # ------------------------------------------------------------------

    def _load_prompts(self) -> None:
        self._system_role = os.getenv(
            "EXT_MINIMIZER_SYSTEM_ROLE",
            "Вы — эксперт в архитектуре ПО и анализе безопасности.",
        )
        self._task = os.getenv(
            "EXT_MINIMIZER_TASK",
            "Проанализируйте внешние точки входа (EXT) модуля и сгруппируйте "
            "схожие интерфейсы в один представительный EXT.",
        )

        raw_rules = os.getenv("EXT_MINIMIZER_GROUPING_RULES", "")
        self._grouping_rules: list[str] = (
            raw_rules.split("\\n") if raw_rules else [
                "Группируйте EXT-интерфейсы, обрабатывающие схожие типы внешних данных.",
                "Группируйте EXT, выполняющие одну функциональную роль (например, все HTTP-эндпоинты).",
                "Оставляйте отдельными EXT с существенно разными рисками безопасности.",
                "Предпочитайте группировку по источнику данных, а не по имени функции.",
            ]
        )

    # ------------------------------------------------------------------

    def _get_prompt(self, inp: LLMToolInput) -> str:
        if not isinstance(inp, EXTMinimizerInput):
            raise TypeError("Ожидается EXTMinimizerInput")

        parts: list[str] = [self._task]

        parts.append("\nПравила группировки:")
        parts.extend(f"- {r}" for r in self._grouping_rules)

        parts.append(f"\nМодуль: {inp.module_name}")
        parts.append(f"\nНайденные EXT-типы: {', '.join(inp.ext_types)}")

        parts.append("\nТочки входа модуля:")
        for ep in inp.entry_points:
            parts.append(f"  - {ep.get('name', '?')}: {', '.join(ep.get('types', []))}")

        parts.append(
            '\nОтветьте в формате JSON:\n'
            '{\n'
            '  "grouped_exts": [\n'
            '    {\n'
            '      "representative_type": "http_request",\n'
            '      "grouped_types": ["http_request", "websocket"],\n'
            '      "interface_name": "EXT_HTTP"\n'
            '    }\n'
            '  ],\n'
            '  "explanation": "Краткое обоснование группировки"\n'
            '}'
        )
        return "\n".join(parts)

    def _parse_response(
        self, response: str, inp: LLMToolInput | None = None
    ) -> LLMToolOutput | None:
        match = re.search(r'\{[\s\S]*"grouped_exts"[\s\S]*\}', response)
        if match:
            try:
                data = json.loads(match.group(0))
                grouped = data.get("grouped_exts", [])
                if not isinstance(grouped, list):
                    return None
                for g in grouped:
                    if not isinstance(g, dict):
                        return None
                    if "representative_type" not in g or "grouped_types" not in g:
                        return None
                return EXTMinimizerOutput(grouped, data.get("explanation", ""))
            except json.JSONDecodeError:
                pass

        # Фоллбэк: каждый тип — отдельный EXT
        if isinstance(inp, EXTMinimizerInput):
            grouped = [
                {
                    "representative_type": t,
                    "grouped_types": [t],
                    "interface_name": f"EXT_{t.upper()}",
                }
                for t in inp.ext_types
            ]
            return EXTMinimizerOutput(
                grouped,
                "LLM не предложил группировку, все EXT оставлены отдельными.",
            )
        return None
