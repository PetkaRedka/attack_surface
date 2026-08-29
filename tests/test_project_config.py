"""Тесты конфигурации мульти-репозиторного проекта."""

import json

import pytest

from attack_surface._project_config import (
    LinkType,
    load_project_config,
    normalize_language,
)


def _write_config(tmp_path, repos, links=None):
    data = {"project": "my-product", "repos": repos, "links": links or []}
    config_path = tmp_path / "project.json"
    config_path.write_text(json.dumps(data), encoding="utf-8")
    for repo in repos:
        (tmp_path / repo["path"]).mkdir(parents=True, exist_ok=True)
    return str(config_path)


def test_normalize_language():
    """Тест: нормализация имён языков."""
    assert normalize_language("csharp") == "c_sharp"
    assert normalize_language("C#") == "c_sharp"
    assert normalize_language("ts") == "typescript"
    assert normalize_language("python") == "python"


def test_load_basic_config(tmp_path):
    """Тест: загрузка валидной конфигурации."""
    config_path = _write_config(
        tmp_path,
        [
            {"name": "frontend", "path": "frontend", "language": "javascript", "role": "ui"},
            {"name": "backend", "path": "backend", "language": "csharp", "role": "api"},
        ],
        [{"from": "frontend", "to": "backend", "type": "http"}],
    )

    config = load_project_config(config_path)

    assert config.project == "my-product"
    assert len(config.repos) == 2
    assert config.repos[0].name == "frontend"
    assert config.repos[1].language == "c_sharp"
    assert config.links[0].type == LinkType.HTTP.value


def test_unknown_repo_in_link_raises(tmp_path):
    """Тест: ссылка на неизвестный репозиторий вызывает ошибку."""
    config_path = _write_config(
        tmp_path,
        [{"name": "a", "path": "a", "language": "python"}],
        [{"from": "a", "to": "b", "type": "http"}],
    )

    with pytest.raises(ValueError):
        load_project_config(config_path)


def test_missing_repo_dir_raises(tmp_path):
    """Тест: несуществующий каталог репозитория вызывает ошибку."""
    config_path = tmp_path / "project.json"
    config_path.write_text(
        json.dumps(
            {
                "project": "x",
                "repos": [{"name": "a", "path": "missing", "language": "python"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_project_config(str(config_path))


def test_duplicate_repo_raises(tmp_path):
    """Тест: дублирующееся имя репозитория вызывает ошибку."""
    config_path = _write_config(
        tmp_path,
        [
            {"name": "a", "path": "a", "language": "python"},
            {"name": "a", "path": "b", "language": "python"},
        ],
    )

    with pytest.raises(ValueError):
        load_project_config(config_path)


def test_invalid_link_type_raises(tmp_path):
    """Тест: неизвестный тип связи вызывает ошибку."""
    config_path = _write_config(
        tmp_path,
        [
            {"name": "a", "path": "a", "language": "python"},
            {"name": "b", "path": "b", "language": "go"},
        ],
        [{"from": "a", "to": "b", "type": "telepathy"}],
    )

    with pytest.raises(ValueError):
        load_project_config(config_path)
