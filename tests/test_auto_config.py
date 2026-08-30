"""Тесты автосоставления конфигурации мульти-репозиторного проекта."""

import json
import os

import yaml

from attack_surface._auto_config import (
    build_auto_config,
    detect_language,
    discover_repositories,
    save_auto_config,
)


def _write(tmp_path, rel_path, content=""):
    """Создать файл в tmp_path и вернуть его путь."""
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_detect_language_by_markers(tmp_path):
    """Тест: язык определяется по явным файлам-маркерам."""
    assert detect_language(str(_write(tmp_path, "go-app/go.mod").parent)) == "go"
    assert detect_language(str(_write(tmp_path, "ts-app/tsconfig.json").parent)) == "typescript"
    assert detect_language(str(_write(tmp_path, "py-app/main.py").parent)) == "python"
    assert detect_language(str(_write(tmp_path, "cpp-app/CMakeLists.txt").parent)) == "cpp"
    assert detect_language(str(_write(tmp_path, "cs-app/app.csproj").parent)) == "c_sharp"


def test_detect_language_tsconfig_over_package_json(tmp_path):
    """Тест: tsconfig.json важнее package.json."""
    repo = _write(tmp_path, "app/package.json").parent
    _write(tmp_path, "app/tsconfig.json")
    assert detect_language(str(repo)) == "typescript"


def test_detect_language_unknown(tmp_path):
    """Тест: без маркеров язык не определяется."""
    repo = _write(tmp_path, "docs/README.md").parent
    assert detect_language(str(repo)) == ""


def test_discover_repositories(tmp_path):
    """Тест: обнаруживаются только подкаталоги с определяемым языком."""
    _write(tmp_path, "backend/main.py")
    _write(tmp_path, "frontend/package.json")
    _write(tmp_path, "docs/README.md")

    repos = discover_repositories(str(tmp_path))

    assert {r.name for r in repos} == {"backend", "frontend"}
    by_name = {r.name: r for r in repos}
    assert by_name["backend"].language == "python"
    assert by_name["frontend"].language == "javascript"


def test_build_auto_config(tmp_path):
    """Тест: формирование ProjectConfig из корневого каталога."""
    _write(tmp_path, "backend/main.py")
    _write(tmp_path, "frontend/package.json")

    config = build_auto_config(str(tmp_path))

    assert config.project == tmp_path.name
    assert len(config.repos) == 2
    assert config.links == []
    assert config.links_authoritative is False


def test_build_auto_config_threagile(tmp_path):
    """Тест: в Threagile-режиме связи трактуются как доверенные."""
    _write(tmp_path, "backend/main.py")

    config = build_auto_config(str(tmp_path), threagile=True)

    assert config.links_authoritative is True


def test_build_auto_config_no_repos(tmp_path):
    """Тест: без репозиториев формирование конфига падает."""
    _write(tmp_path, "docs/README.md")

    try:
        build_auto_config(str(tmp_path))
        assert False, "ожидалась ошибка ValueError"
    except ValueError:
        pass


def test_save_auto_config_json(tmp_path):
    """Тест: авто-конфиг сохраняется в JSON."""
    _write(tmp_path, "backend/main.py")
    config = build_auto_config(str(tmp_path))

    path = save_auto_config(config, str(tmp_path / "out"), "json")

    assert path.endswith(".auto.json")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["project"] == tmp_path.name
    assert len(data["repos"]) == 1


def test_save_auto_config_threagile(tmp_path):
    """Тест: авто-конфиг сохраняется в архитектурный YAML Threagile."""
    _write(tmp_path, "backend/main.py")
    config = build_auto_config(str(tmp_path), threagile=True)

    path = save_auto_config(config, str(tmp_path / "out"), "threagile")

    assert path.endswith(".auto.yaml")
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert data["title"] == tmp_path.name
    assert data["technical_assets"][0]["id"] == "backend"
    assert data["technical_assets"][0]["technology"] == "python"
