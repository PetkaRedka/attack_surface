"""Функциональные тесты для генерации графа поверхности атаки."""

import json
import os
from pathlib import Path

import pytest

from attack_surface import generate_attack_surface_graph
from attack_surface._logger import Logger


@pytest.fixture
def sample_entry_points():
    """Пример точек входа для генерации графа."""
    return {
        "ep1": {
            "function_name": "parse_json",
            "file_path": "app.py",
            "start_line": 10,
            "end_line": 20,
            "entry_point_type": "http_request",
            "external_input_sources": [
                {"name": "request.get_json", "entry_point_type": "http_request"}
            ],
        },
        "ep2": {
            "function_name": "read_file",
            "file_path": "utils.py",
            "start_line": 5,
            "end_line": 15,
            "entry_point_type": "file_read",
            "external_input_sources": [
                {"name": "open", "entry_point_type": "file_read"}
            ],
        },
    }


@pytest.fixture
def output_dir(tmp_path):
    """Временный каталог для выходных файлов."""
    return str(tmp_path / "graph_output")


@pytest.fixture
def logger(tmp_path):
    """Логгер для тестов."""
    log_path = str(tmp_path / "test.log")
    return Logger(log_path)


def test_generate_svg_graph(sample_entry_points, output_dir, logger):
    """Тест: генерация SVG-графа."""
    svg_path = generate_attack_surface_graph(
        sample_entry_points,
        output_dir,
        "TestProject",
        "python",
        output_format="svg",
        minimize_ext=False,
        logger=logger,
    )
    
    assert os.path.exists(svg_path), "SVG-файл должен быть создан"
    assert svg_path.endswith(".svg"), "Файл должен иметь расширение .svg"
    
    with open(svg_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert '<?xml version="1.0"' in content, "SVG должен содержать XML-декларацию"
    assert '<svg' in content, "SVG должен содержать тег svg"
    assert 'TestProject' in content, "SVG должен содержать имя проекта"


def test_generate_cert_graph(sample_entry_points, output_dir, logger):
    """Тест: генерация CERT JSON-графа."""
    json_path = generate_attack_surface_graph(
        sample_entry_points,
        output_dir,
        "TestProject",
        "python",
        output_format="cert",
        minimize_ext=False,
        logger=logger,
    )
    
    assert os.path.exists(json_path), "JSON-файл должен быть создан"
    assert json_path.endswith(".json"), "Файл должен иметь расширение .json"
    
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    assert "class" in data, "JSON должен содержать поле 'class'"
    assert data["class"] == "GraphLinksModel", "Должен быть GraphLinksModel"
    assert "nodeDataArray" in data, "JSON должен содержать nodeDataArray"
    assert "linkDataArray" in data, "JSON должен содержать linkDataArray"


def test_graph_handles_empty_entry_points(output_dir, logger):
    """Тест: обработка пустого списка точек входа."""
    svg_path = generate_attack_surface_graph(
        {},
        output_dir,
        "EmptyProject",
        "python",
        output_format="svg",
        minimize_ext=False,
        logger=logger,
    )
    
    assert os.path.exists(svg_path), "SVG должен быть создан даже для пустого списка"
    
    with open(svg_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "не найдены" in content.lower() or "no entry" in content.lower(), \
        "SVG должен содержать сообщение об отсутствии точек входа"
