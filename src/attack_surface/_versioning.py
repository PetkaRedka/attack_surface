"""Определение версии репозитория для кэширования результатов.

Версия нужна, чтобы понять, изменился ли код репозитория с момента
предыдущего анализа. Приоритет:

1. **Git-коммит** — читается напрямую из каталога ``.git`` без вызова
   git CLI: ``HEAD`` → файл ref'а (или ``packed-refs``); учитываются
   worktree/субмодули, где ``.git`` — файл-указатель на gitdir;
2. **Хэш списка файлов** — для каталогов без ``.git``: SHA-256 от
   отсортированных пар ``(относительный путь, размер файла)``. Содержимое
   не читается, поэтому изменение внутри файла при том же размере не
   обнаруживается — приемлемо для «простенькой верификации».
"""

from __future__ import annotations

import hashlib
import os

from attack_surface._linker import _EXCLUDED_DIRS

#: Имена каталогов, которые не участвуют в хэше списка файлов
_HASH_EXCLUDED: frozenset[str] = _EXCLUDED_DIRS | frozenset({".git"})


# ---------------------------------------------------------------------------
# Git-коммит
# ---------------------------------------------------------------------------

def _git_dir(repo_path: str) -> str | None:
    """Путь к gitdir: каталог ``.git`` или gitdir из файла-указателя."""
    git = os.path.join(repo_path, ".git")
    if os.path.isdir(git):
        return git
    if os.path.isfile(git):
        try:
            with open(git, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("gitdir:"):
                        target = line.split(":", 1)[1].strip()
                        if os.path.isabs(target):
                            return target
                        return os.path.normpath(os.path.join(repo_path, target))
        except OSError:
            return None
    return None


def _resolve_ref(git_dir: str, ref: str) -> str | None:
    """Хэш коммита по имени ref (из файла refs/... или packed-refs)."""
    ref_path = os.path.join(git_dir, ref)
    if os.path.isfile(ref_path):
        try:
            with open(ref_path, encoding="utf-8", errors="ignore") as fh:
                value = fh.read().strip()
        except OSError:
            value = ""
        if value:
            return value
    # Полный ref не найден — ищем в packed-refs
    packed = os.path.join(git_dir, "packed-refs")
    if os.path.isfile(packed):
        try:
            with open(packed, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref:
                        return parts[0]
        except OSError:
            pass
    return None


def read_git_commit(repo_path: str) -> str | None:
    """Текущий коммит HEAD репозитория (или None, если это не git-репозиторий)."""
    git_dir = _git_dir(repo_path)
    if git_dir is None:
        return None
    try:
        with open(os.path.join(git_dir, "HEAD"), encoding="utf-8", errors="ignore") as fh:
            head = fh.read().strip()
    except OSError:
        return None
    if not head:
        return None
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        return _resolve_ref(git_dir, ref)
    # detached HEAD — в HEAD лежит сам хэш
    return head if len(head) >= 7 else None


# ---------------------------------------------------------------------------
# Хэш списка файлов
# ---------------------------------------------------------------------------

def _file_list_hash(root: str) -> str:
    """SHA-256 от отсортированного списка ``(относительный путь, размер)``."""
    entries: list[tuple[str, int]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _HASH_EXCLUDED]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            rel = os.path.relpath(full, root)
            entries.append((rel.replace("\\", "/"), size))
    entries.sort()
    digest = hashlib.sha256()
    for rel, size in entries:
        digest.update(f"{rel}\0{size}\0".encode("utf-8"))
    return digest.hexdigest()


def get_repo_version(repo_path: str) -> str:
    """Версия репозитория: git-коммит, либо хэш списка файлов.

    Для каталога без ``.git`` возвращается хэш; при отсутствии файлов
    возвращается фиксированная строка (кэш для такого репозитория
    будет «пустым»).
    """
    commit = read_git_commit(repo_path)
    if commit:
        return commit
    if not os.path.isdir(repo_path):
        return "no-files"
    return _file_list_hash(repo_path)
