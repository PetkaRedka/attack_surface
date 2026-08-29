"""Тесты пофайловой группировки батчей валидации."""

from attack_surface._models import EntryPointInfo
from attack_surface._project_pipeline import _group_batches_by_file


def _ep(node_id: str, file_path: str) -> EntryPointInfo:
    return EntryPointInfo(
        node_id=node_id,
        function_name=node_id,
        file_path=file_path,
        start_line=1,
        end_line=2,
    )


def test_batch_full_file_splits():
    """Тест: файл с 20 точками разбивается на 4 батча по 5."""
    entry_points = {f"n{i}": _ep(f"n{i}", "/x/a.py") for i in range(20)}

    batches = _group_batches_by_file(entry_points, 5)

    assert len(batches) == 4
    assert all(len(batch) == 5 for batch in batches)


def test_batch_tails_merge():
    """Тест: хвосты файлов с одной точкой добираются друг из друга."""
    entry_points = {f"n{i}": _ep(f"n{i}", f"/x/f{i}.py") for i in range(7)}

    batches = _group_batches_by_file(entry_points, 5)

    assert len(batches) == 2
    assert len(batches[0]) == 5
    assert len(batches[1]) == 2


def test_batch_mixed_files():
    """Тест: большой файл + хвосты маленьких файлов."""
    entry_points = {}
    for i in range(3):
        entry_points[f"a{i}"] = _ep(f"a{i}", "/x/a.py")
    entry_points["b0"] = _ep("b0", "/x/b.py")
    for i in range(6):
        entry_points[f"c{i}"] = _ep(f"c{i}", "/x/c.py")

    batches = _group_batches_by_file(entry_points, 5)

    # c: 5 полных + 1 в хвост; a(3) + b(1) + c-хвост(1) = 5 → один батч
    assert len(batches) == 2
    assert all(len(batch) == 5 for batch in batches)
