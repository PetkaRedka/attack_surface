"""Базовые утилиты для работы с LLM: клиент, абстрактный инструмент, кеш."""

from __future__ import annotations

import concurrent.futures
import json
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Optional, TypeVar, cast

import tiktoken
from openai import OpenAI

from attack_surface._logger import Logger

# ---------------------------------------------------------------------------
# LLM-клиент (поддержка OpenAI, DeepSeek, self-hosted)
# ---------------------------------------------------------------------------


class LLMClient:
    """Универсальный клиент для LLM-инференса через OpenAI-совместимый API."""

    def __init__(
        self,
        model_name: str,
        logger: Logger,
        temperature: float = 0.0,
        system_role: str = (
            "Вы — опытный программист, специализирующийся на анализе безопасности ПО."
        ),
        max_output_length: int = 4096,
        base_url: str | None = None,
    ) -> None:
        self.model_name = model_name
        self.logger = logger
        self.temperature = temperature
        self.system_role = system_role
        self.max_output_length = max_output_length
        self.base_url = base_url or os.environ.get("OPENAI_API_BASE")

        self._encoding = tiktoken.encoding_for_model("gpt-3.5-turbo-0125")

    # ------------------------------------------------------------------

    def infer(self, message: str, measure_cost: bool = False) -> tuple[str, int, int]:
        """Выполнить инференс и вернуть ``(ответ, input_tokens, output_tokens)``."""
        self.logger.print_log(f"Запуск модели {self.model_name}")

        output = self._call_api(message)

        input_tokens = (
            len(self._encoding.encode(self.system_role))
            + len(self._encoding.encode(message))
        ) if measure_cost else 0
        output_tokens = len(self._encoding.encode(output)) if measure_cost else 0

        return output, input_tokens, output_tokens

    # ------------------------------------------------------------------

    def _call_api(self, message: str) -> str:
        api_key = os.environ.get("OPENAI_API_KEY", "none")
        base_url = self.base_url

        model_name = self.model_name
        if model_name.startswith("local/"):
            model_name = model_name[6:]

        messages = [
            {"role": "system", "content": self.system_role},
            {"role": "user", "content": message},
        ]

        # Определяем base_url для DeepSeek
        if "deepseek" in self.model_name:
            api_key = os.environ.get("DEEPSEEK_API_KEY2", api_key)
            base_url = base_url or "https://api.deepseek.com"

        for attempt in range(1, 6):
            try:
                result = self._run_with_timeout(
                    lambda: self._openai_call(api_key, base_url, model_name, messages),
                    timeout=300,
                )
                if result:
                    return result
            except Exception as exc:
                self.logger.print_log(f"Ошибка API (попытка {attempt}/5): {exc}")
            time.sleep(2)

        return ""

    def _openai_call(
        self,
        api_key: str,
        base_url: str | None,
        model_name: str,
        messages: list[dict[str, str]],
    ) -> str:
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url

        client = OpenAI(**kwargs)
        response = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_output_length,
        )
        return response.choices[0].message.content or ""

    @staticmethod
    def _run_with_timeout(func: Any, timeout: int) -> str:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(func)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                return ""
            except Exception:
                return ""


# ---------------------------------------------------------------------------
# Абстрактный LLM-инструмент
# ---------------------------------------------------------------------------


class LLMToolInput(ABC):
    """Базовый вход для LLM-инструмента."""

    @abstractmethod
    def __hash__(self) -> int: ...

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LLMToolInput):
            return NotImplemented
        return hash(self) == hash(other)

    def describe(self) -> str:
        """Краткое описание входа для журналирования."""
        return ""


class LLMToolOutput(ABC):
    """Базовый выход LLM-инструмента."""


_T = TypeVar("_T", bound=LLMToolOutput)


class LLMTool(ABC):
    """Абстрактный LLM-инструмент с кешем и повторными запросами."""

    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
    ) -> None:
        self.model_name = model_name
        self.temperature = temperature
        self.language = language
        self.max_query_num = max_query_num
        self.logger = logger

        self._client = LLMClient(model_name, logger, temperature)
        self._cache: dict[LLMToolInput, LLMToolOutput] = {}

        self.input_token_cost = 0
        self.output_token_cost = 0
        self.total_query_num = 0

    # ------------------------------------------------------------------

    def invoke(self, inp: LLMToolInput, cls: type[_T]) -> _T | None:
        """Вызвать инструмент и вернуть типизированный результат."""
        output = self._invoke(inp)
        if output is None:
            return None
        if not isinstance(output, cls):
            raise TypeError(f"Ожидался {cls}, получен {type(output)}")
        return cast(_T, output)

    # ------------------------------------------------------------------

    def _invoke(self, inp: LLMToolInput) -> LLMToolOutput | None:
        name = type(self).__name__
        detail = f": {inp.describe()}" if inp.describe() else ""
        self.logger.debug(f"LLM-инструмент {name} вызван{detail}")

        if inp in self._cache:
            self.logger.print_log("Попадание в кеш.")
            return self._cache[inp]

        prompt = self._get_prompt(inp)
        self.logger.print_log("Промпт:\n", prompt)

        for attempt in range(1, self.max_query_num + 1):
            response, in_tok, out_tok = self._client.infer(prompt, measure_cost=True)
            self.logger.print_log("Ответ:\n", response)
            self.input_token_cost += in_tok
            self.output_token_cost += out_tok

            output = self._parse_response(response, inp)
            if output is not None:
                self._cache[inp] = output
                self.total_query_num += attempt
                return output

            self.logger.print_log(
                f"Не удалось разобрать ответ, повтор… ({attempt}/{self.max_query_num})"
            )

        self.total_query_num += self.max_query_num
        return None

    # ------------------------------------------------------------------

    @abstractmethod
    def _get_prompt(self, inp: LLMToolInput) -> str: ...

    @abstractmethod
    def _parse_response(
        self, response: str, inp: LLMToolInput | None = None
    ) -> LLMToolOutput | None: ...
