"""Функциональные тесты для EntryPointExtractor."""

import json
import os
from pathlib import Path

import pytest
from trailmark import parse_directory

from attack_surface import EntryPointExtractor


@pytest.fixture
def test_project_path():
    """Путь к тестовому проекту."""
    return Path(__file__).parent / "test_project"


@pytest.fixture
def expected_entry_points():
    """Ожидаемые точки входа из fixtures."""
    fixture_path = Path(__file__).parent / "fixtures" / "expected_entry_points.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_extractor_finds_entry_points(test_project_path):
    """Тест: экстрактор находит точки входа в тестовом проекте."""
    graph = parse_directory(str(test_project_path), language="python")
    extractor = EntryPointExtractor(graph, "python")
    
    candidates = extractor.build_entry_points()
    
    assert len(candidates) >= 5, f"Должно быть найдено минимум 5 точек входа, найдено: {len(candidates)}"
    
    func_names = {ep.function_name for ep in candidates.values()}
    expected_funcs = {
        "parse_json_config",
        "process_file_upload",
        "get_environment_config",
        "process_user_input",
        "main",
    }
    
    assert expected_funcs.issubset(func_names), f"Не найдены ожидаемые функции: {expected_funcs - func_names}"


def test_extractor_identifies_external_sources(test_project_path):
    """Тест: экстрактор идентифицирует внешние источники данных."""
    graph = parse_directory(str(test_project_path), language="python")
    extractor = EntryPointExtractor(graph, "python")
    
    candidates = extractor.build_entry_points()
    
    # Проверяем, что у некоторых точек входа есть external_sources
    eps_with_sources = [ep for ep in candidates.values() if ep.external_sources]
    assert len(eps_with_sources) > 0, "Должны быть найдены точки входа с внешними источниками"
    
    # Проверяем типы источников
    source_types = {src.entry_point_type for ep in eps_with_sources for src in ep.external_sources}
    expected_types = {"deserialization", "file_read", "environment_variable", "user_input"}
    
    assert len(source_types & expected_types) > 0, f"Не найдены ожидаемые типы источников: {expected_types}"


def test_extractor_identifies_root_functions(test_project_path):
    """Тест: экстрактор идентифицирует корневые функции."""
    graph = parse_directory(str(test_project_path), language="python")
    extractor = EntryPointExtractor(graph, "python")
    
    roots = extractor.extract_root_functions()
    
    assert len(roots) > 0, "Должны быть найдены корневые функции"
    
    root_names = {node.name for node in roots}
    assert "main" in root_names, "main должна быть корневой функцией"


def test_extractor_excludes_internal_functions(test_project_path):
    """Тест: экстрактор не включает внутренние функции без внешнего ввода."""
    graph = parse_directory(str(test_project_path), language="python")
    extractor = EntryPointExtractor(graph, "python")
    
    candidates = extractor.build_entry_points()
    func_names = {ep.function_name for ep in candidates.values()}
    
    # Функции из utils.py не должны быть точками входа
    internal_funcs = {"calculate_hash", "validate_format", "internal_helper"}
    assert len(func_names & internal_funcs) == 0, f"Внутренние функции не должны быть точками входа: {func_names & internal_funcs}"


def test_extractor_output_format(test_project_path):
    """Тест: выходной формат соответствует ожидаемому."""
    graph = parse_directory(str(test_project_path), language="python")
    extractor = EntryPointExtractor(graph, "python")
    
    candidates = extractor.build_entry_points()
    
    for ep_id, ep in candidates.items():
        assert isinstance(ep_id, str), "ID точки входа должен быть строкой"
        assert ep.function_name, "Имя функции не должно быть пустым"
        assert ep.file_path, "Путь к файлу не должен быть пустым"
        assert ep.start_line > 0, "Начальная строка должна быть > 0"
        assert ep.entry_point_type, "Тип точки входа не должен быть пустым"
        
        ep_dict = ep.to_dict()
        assert "function_name" in ep_dict
        assert "file_path" in ep_dict
        assert "entry_point_type" in ep_dict
