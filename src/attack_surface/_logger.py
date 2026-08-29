"""Потокобезопасный логгер с выводом в файл и консоль."""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path
from typing import Any


class Logger:
    """Потокобезопасный логгер: пишет в файл всегда, в консоль — по запросу."""

    def __init__(self, log_file_path: str, log_level: int = logging.INFO) -> None:
        self._lock = threading.Lock()
        self.log_file_path = Path(log_file_path)
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger(f"AttackSurface-{log_file_path}")
        self._logger.setLevel(log_level)
        self._logger.handlers.clear()

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        file_handler = logging.FileHandler(self.log_file_path, mode="a", encoding="utf-8")
        # Файл пишет всё, включая DEBUG
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)

        self._console_handler = logging.StreamHandler(sys.stdout)
        # В консоль — только сообщения уровня не ниже log_level
        self._console_handler.setLevel(log_level)
        self._console_handler.setFormatter(formatter)

    # ------------------------------------------------------------------
    # Публичные методы
    # ------------------------------------------------------------------

    def debug(self, *args: Any) -> None:
        """Запись только в файл на уровне DEBUG."""
        with self._lock:
            if self._console_handler in self._logger.handlers:
                self._logger.removeHandler(self._console_handler)
            self._logger.debug(" ".join(map(str, args)))

    def print_log(self, *args: Any) -> None:
        """Запись только в файл."""
        with self._lock:
            if self._console_handler in self._logger.handlers:
                self._logger.removeHandler(self._console_handler)
            self._logger.info(" ".join(map(str, args)))

    def print_console(self, *args: Any) -> None:
        """Запись в файл **и** вывод в консоль."""
        with self._lock:
            if self._console_handler not in self._logger.handlers:
                self._logger.addHandler(self._console_handler)
            self._logger.info(" ".join(map(str, args)))
            self._logger.removeHandler(self._console_handler)
