"""Тесты определения версии репозитория."""

import hashlib
import os

from attack_surface._versioning import (
    _file_list_hash,
    get_repo_version,
    read_git_commit,
)


def _make_git_repo(tmp_path, head="ref: refs/heads/master", refs=None):
    """Создать структуру .git с HEAD и (опционально) refs."""
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True, exist_ok=True)
    (git / "HEAD").write_text(head, encoding="utf-8")
    if refs:
        for name, value in refs.items():
            (git / "refs" / "heads" / name).write_text(value, encoding="utf-8")


def test_read_git_commit_branch(tmp_path):
    """Тест: коммит по ref из файла refs/heads/master."""
    _make_git_repo(tmp_path, refs={"master": "abc123" * 6})

    assert read_git_commit(str(tmp_path)) == "abc123" * 6


def test_read_git_commit_detached(tmp_path):
    """Тест: detached HEAD — коммит лежит прямо в HEAD."""
    _make_git_repo(tmp_path, head="def456" * 6)

    assert read_git_commit(str(tmp_path)) == "def456" * 6


def test_read_git_commit_packed_refs(tmp_path):
    """Тест: ref отсутствует в файле, но есть в packed-refs."""
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/master", encoding="utf-8")
    (git / "packed-refs").write_text(
        "# pack-refs with: peeled fully-peeled sorted\n"
        "1111111111111111111111111111111111111111 refs/heads/master\n",
        encoding="utf-8",
    )

    assert read_git_commit(str(tmp_path)) == "1" * 40


def test_read_git_commit_gitdir_file(tmp_path):
    """Тест: .git — файл-указатель (worktree/субмодуль)."""
    gitdir = tmp_path / "real-git"
    (gitdir / "refs" / "heads").mkdir(parents=True)
    (gitdir / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    (gitdir / "refs" / "heads" / "main").write_text("aabbcc" * 6, encoding="utf-8")
    (tmp_path / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")

    assert read_git_commit(str(tmp_path)) == "aabbcc" * 6


def test_read_git_commit_none(tmp_path):
    """Тест: без .git коммит не определяется."""
    assert read_git_commit(str(tmp_path)) is None


def _write(tmp_path, rel_path, content=""):
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_file_list_hash_changes_with_content_size(tmp_path):
    """Тест: изменение размера файла меняет хэш."""
    _write(tmp_path, "src/main.py", "print(1)")
    first = _file_list_hash(str(tmp_path))

    _write(tmp_path, "src/main.py", "print(1)\nprint(2)\n")
    second = _file_list_hash(str(tmp_path))

    assert first != second


def test_file_list_hash_changes_with_new_file(tmp_path):
    """Тест: новый файл меняет хэш."""
    _write(tmp_path, "src/main.py", "print(1)")
    first = _file_list_hash(str(tmp_path))

    _write(tmp_path, "src/extra.py", "print(2)")
    second = _file_list_hash(str(tmp_path))

    assert first != second


def test_file_list_hash_excludes_git(tmp_path):
    """Тест: содержимое .git не влияет на хэш списка файлов."""
    _write(tmp_path, "src/main.py", "print(1)")
    first = _file_list_hash(str(tmp_path))

    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/master", encoding="utf-8")

    assert _file_list_hash(str(tmp_path)) == first


def test_get_repo_version_prefers_git(tmp_path):
    """Тест: при наличии .git версия — коммит, иначе — хэш файлов."""
    _make_git_repo(tmp_path, refs={"master": "abc123" * 6})
    _write(tmp_path, "main.py", "x = 1")

    assert get_repo_version(str(tmp_path)) == "abc123" * 6

    plain = tmp_path / "plain"
    _write(plain, "main.py", "x = 1")
    version = get_repo_version(str(plain))
    assert version and len(version) == 64  # sha256 hex


def test_file_list_hash_deterministic(tmp_path):
    """Тест: хэш детерминирован для одинакового набора файлов."""
    _write(tmp_path, "b.py", "yy")
    _write(tmp_path, "a.py", "x")

    # В хэше участвуют относительные пути и размеры файлов
    expected = hashlib.sha256(b"a.py\x001\x00b.py\x002\x00").hexdigest()
    assert _file_list_hash(str(tmp_path)) == expected
