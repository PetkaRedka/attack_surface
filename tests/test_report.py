"""Функциональные тесты для генерации HTML-отчёта."""

import os
from pathlib import Path

import pytest

from attack_surface import generate_html_report


@pytest.fixture
def sample_entry_points():
    """Пример точек входа для отчёта."""
    return {
        "ep1": {
            "function_name": "parse_json",
            "file_path": "app/handlers.py",
            "start_line": 10,
            "entry_point_type": "http_request",
            "external_input_sources": [
                {"name": "request.get_json", "entry_point_type": "http_request", "line_number": 12}
            ],
        },
        "ep2": {
            "function_name": "read_config",
            "file_path": "app/config.py",
            "start_line": 5,
            "entry_point_type": "file_read",
            "external_input_sources": [
                {"name": "open", "entry_point_type": "file_read", "line_number": 7}
            ],
        },
        "ep3": {
            "function_name": "get_env",
            "file_path": "app/settings.py",
            "start_line": 3,
            "entry_point_type": "environment_variable",
            "external_input_sources": [
                {"name": "getenv", "entry_point_type": "environment_variable", "line_number": 4}
            ],
        },
    }


@pytest.fixture
def output_dir(tmp_path):
    """Временный каталог для выходных файлов."""
    return str(tmp_path / "report_output")


def test_generate_html_report(sample_entry_points, output_dir):
    """Тест: генерация HTML-отчёта."""
    html_path = generate_html_report(
        sample_entry_points,
        output_dir,
        "TestProject",
        "python",
    )
    
    assert os.path.exists(html_path), "HTML-файл должен быть создан"
    assert html_path.endswith(".html"), "Файл должен иметь расширение .html"
    
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "<!DOCTYPE html>" in content, "HTML должен содержать DOCTYPE"
    assert "TestProject" in content, "HTML должен содержать имя проекта"
    assert "parse_json" in content, "HTML должен содержать имена функций"
    assert "HTTP" in content or "http" in content, "HTML должен содержать типы интерфейсов"


def test_report_groups_by_type(sample_entry_points, output_dir):
    """Тест: отчёт группирует точки входа по типам."""
    html_path = generate_html_report(
        sample_entry_points,
        output_dir,
        "TestProject",
        "python",
    )
    
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Проверяем наличие разных типов интерфейсов
    assert "interface-type" in content, "HTML должен содержать блоки типов интерфейсов"
    
    # Должны быть упомянуты разные типы
    types_found = 0
    if "HTTP" in content or "запрос" in content.lower():
        types_found += 1
    if "файл" in content.lower() or "file" in content.lower():
        types_found += 1
    if "окружен" in content.lower() or "environment" in content.lower():
        types_found += 1
    
    assert types_found >= 2, "HTML должен содержать минимум 2 разных типа интерфейсов"


def test_report_handles_empty_entry_points(output_dir):
    """Тест: отчёт обрабатывает пустой список точек входа."""
    html_path = generate_html_report(
        {},
        output_dir,
        "EmptyProject",
        "python",
    )
    
    assert os.path.exists(html_path), "HTML должен быть создан даже для пустого списка"
    
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "EmptyProject" in content, "HTML должен содержать имя проекта"
