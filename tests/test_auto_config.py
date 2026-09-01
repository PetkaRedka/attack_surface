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
    """Тест: при GIT_SUPPORT=false обнаруживаются подкаталоги с языком."""
    _write(tmp_path, "backend/main.py")
    _write(tmp_path, "frontend/package.json")
    _write(tmp_path, "docs/README.md")

    repos = discover_repositories(str(tmp_path), git_support=False)

    assert {r.name for r in repos} == {"backend", "frontend"}
    by_name = {r.name: r for r in repos}
    assert by_name["backend"].language == "python"
    assert by_name["frontend"].language == "javascript"


def _make_git_dir(tmp_path, name):
    """Создать каталог-репозиторий с маркером .git."""
    repo = tmp_path / name
    (repo / ".git").mkdir(parents=True, exist_ok=True)
    return repo


def test_discover_by_git(tmp_path):
    """Тест: репозиторием считается только каталог с .git."""
    _make_git_dir(tmp_path, "backend")
    _write(tmp_path, "frontend/package.json")  # код без .git — не репозиторий

    repos = discover_repositories(str(tmp_path), git_support=True)

    assert [r.name for r in repos] == ["backend"]


def test_discover_by_git_submodule_marker(tmp_path):
    """Тест: субмодуль (.git — файл-указатель) тоже репозиторий."""
    repo = tmp_path / "plugin"
    repo.mkdir()
    _write(tmp_path, "plugin/.git", content="gitdir: ../.git/modules/plugin\n")
    _write(tmp_path, "plugin/main.py")

    repos = discover_repositories(str(tmp_path), git_support=True)

    assert [r.name for r in repos] == ["plugin"]


def test_discover_by_git_depth(tmp_path):
    """Тест: глубина поиска .git ограничена GIT_DEPTH."""
    _make_git_dir(tmp_path, "group/service")

    assert discover_repositories(str(tmp_path), git_support=True, git_depth=1) == []
    assert [r.name for r in discover_repositories(
        str(tmp_path), git_support=True, git_depth=2
    )] == ["service"]


def test_discover_by_git_root_is_repo(tmp_path):
    """Тест: корень с .git считается единственным репозиторием."""
    _make_git_dir(tmp_path, "sub")  # вложенный репозиторий игнорируется
    (tmp_path / ".git").mkdir()

    repos = discover_repositories(str(tmp_path), git_support=True)

    assert len(repos) == 1
    assert repos[0].name == tmp_path.name
    assert repos[0].path == str(tmp_path)


def test_discover_modules(tmp_path):
    """Тест: git-поддиректории внутри репозитория становятся модулями."""
    _make_git_dir(tmp_path, "backend")
    _make_git_dir(tmp_path, "backend/core")
    _make_git_dir(tmp_path, "backend/plugins/plugin-a")
    _write(tmp_path, "backend/main.py")
    _write(tmp_path, "backend/core/main.py")
    _write(tmp_path, "backend/plugins/plugin-a/main.py")

    repos = discover_repositories(str(tmp_path), git_support=True)

    assert len(repos) == 1
    assert repos[0].name == "backend"
    assert set(repos[0].modules) == {"core", "plugins/plugin-a"}


def test_discover_modules_none(tmp_path):
    """Тест: репозиторий без вложенных git-директорий не имеет модулей."""
    _make_git_dir(tmp_path, "backend")
    _write(tmp_path, "backend/main.py")

    repos = discover_repositories(str(tmp_path), git_support=True)

    assert repos[0].modules == []


def test_discover_nested_modules(tmp_path):
    """Тест: git внутри git — вложенный модуль с путём от корня репозитория."""
    _make_git_dir(tmp_path, "backend")
    _make_git_dir(tmp_path, "backend/core")
    _make_git_dir(tmp_path, "backend/core/sub")
    _write(tmp_path, "backend/main.py")
    _write(tmp_path, "backend/core/main.py")
    _write(tmp_path, "backend/core/sub/main.py")

    repos = discover_repositories(str(tmp_path), git_support=True)

    assert len(repos) == 1
    assert set(repos[0].modules) == {"core", "core/sub"}


def test_discover_modules_depth(tmp_path):
    """Тест: глубина поиска модулей ограничена GIT_DEPTH."""
    _make_git_dir(tmp_path, "backend")
    _make_git_dir(tmp_path, "backend/a/b/c")

    repos = discover_repositories(str(tmp_path), git_support=True, git_depth=2)

    # a/b (глубина 2) и a (глубина 1) — каталоги без .git, обходятся;
    # a/b/c (глубина 3) — за пределами глубины
    assert repos[0].modules == []

    repos = discover_repositories(str(tmp_path), git_support=True, git_depth=3)
    assert "a/b/c" in repos[0].modules


def test_discover_git_support_env(tmp_path, monkeypatch):
    """Тест: флаг GIT_SUPPORT переключает режим обнаружения."""
    _make_git_dir(tmp_path, "backend")
    _write(tmp_path, "frontend/package.json")

    monkeypatch.setenv("GIT_SUPPORT", "false")
    assert {r.name for r in discover_repositories(str(tmp_path))} == {"frontend"}

    monkeypatch.setenv("GIT_SUPPORT", "true")
    assert [r.name for r in discover_repositories(str(tmp_path))] == ["backend"]


def test_build_auto_config(tmp_path):
    """Тест: формирование ProjectConfig из корневого каталога."""
    _write(tmp_path, "backend/main.py")
    _write(tmp_path, "frontend/package.json")

    config = build_auto_config(str(tmp_path), git_support=False)

    assert config.project == tmp_path.name
    assert len(config.repos) == 2
    assert config.links == []
    assert config.links_authoritative is False


def test_build_auto_config_threagile(tmp_path):
    """Тест: в Threagile-режиме связи трактуются как доверенные."""
    _write(tmp_path, "backend/main.py")

    config = build_auto_config(str(tmp_path), threagile=True, git_support=False)

    assert config.links_authoritative is True


def test_build_auto_config_no_repos(tmp_path):
    """Тест: без репозиториев формирование конфига падает."""
    _write(tmp_path, "docs/README.md")

    try:
        build_auto_config(str(tmp_path), git_support=False)
        assert False, "ожидалась ошибка ValueError"
    except ValueError:
        pass


def test_save_auto_config_json(tmp_path):
    """Тест: авто-конфиг сохраняется в JSON."""
    _write(tmp_path, "backend/main.py")
    config = build_auto_config(str(tmp_path), git_support=False)

    path = save_auto_config(config, str(tmp_path / "out"), "json")

    assert path.endswith(".auto.json")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["project"] == tmp_path.name
    assert len(data["repos"]) == 1


def test_save_auto_config_threagile(tmp_path):
    """Тест: авто-конфиг сохраняется в архитектурный YAML Threagile."""
    _write(tmp_path, "backend/main.py")
    config = build_auto_config(str(tmp_path), threagile=True, git_support=False)

    path = save_auto_config(config, str(tmp_path / "out"), "threagile")

    assert path.endswith(".auto.yaml")
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert data["title"] == tmp_path.name
    assert data["technical_assets"][0]["id"] == "backend"
    assert data["technical_assets"][0]["technology"] == "python"
