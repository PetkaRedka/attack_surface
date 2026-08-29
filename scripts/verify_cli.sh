#!/usr/bin/env bash
# Верификация всего доступного функционала attack-surface на тестовых проектах.
#
# Покрывает команды: scan, call-graph, graph-from-json, project (JSON и Threagile),
# export-threagile, а также проверку артефактов (включая CERT-граф для сертификации).
#
# Запуск (из любого каталога):
#   bash attack_surface/scripts/verify_cli.sh
#
# При наличии OPENAI_API_KEY можно убрать флаги --no-llm/--no-minimize-ext,
# чтобы проверить и LLM-функционал (минимизация EXT, подтверждение связей).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$WORKSPACE"

CLI="${CLI:-.cli-venv/Scripts/attack-surface.exe}"
PYTHON=".cli-venv/Scripts/python.exe"
OUT="test_projects/verification"
mkdir -p "$OUT"

echo "=== CLI: $CLI ==="
"$CLI" --help > /dev/null

run_scan() {
  local label="$1" path="$2" lang="$3"
  echo "--- scan $label (cert + svg + html) ---"
  "$CLI" scan --project-path "$path" --language "$lang" --output-dir "$OUT/$label/cert" \
      --html-report --graph --graph-format cert --no-minimize-ext
  "$CLI" scan --project-path "$path" --language "$lang" --output-dir "$OUT/$label/svg" \
      --html-report --graph --graph-format svg --no-minimize-ext
}

echo "=== 1. Одиночное сканирование репозиториев ==="
run_scan store-frontend   test_projects/store/frontend            javascript
run_scan store-backend    test_projects/store/backend             python
run_scan store-native     test_projects/store/native              cpp
run_scan multi-web        test_projects/multi-service/web         typescript
run_scan multi-api        test_projects/multi-service/api         go
run_scan bedolaga-bot     test_projects/Bedolaga/remnawave-bedolaga-telegram-bot python
run_scan bedolaga-cabinet test_projects/Bedolaga/bedolaga-cabinet typescript

echo "=== 2. Граф вызовов (call-graph) ==="
echo "--- call-graph stats ---"
"$CLI" call-graph --project-path test_projects/store/backend --language python \
    --output-dir "$OUT/call-graph-stats" --format stats
echo "--- call-graph cert ---"
"$CLI" call-graph --project-path test_projects/store/backend --language python \
    --output-dir "$OUT/call-graph-cert" --format cert
echo "--- call-graph filtered by attack surface ---"
"$CLI" call-graph --project-path test_projects/store/backend --language python \
    --output-dir "$OUT/call-graph-filtered" --format cert --filter-by-attack-surface

echo "=== 3. Граф из JSON (graph-from-json) ==="
"$CLI" graph-from-json \
    --entrypoints-json "$OUT/store-backend/cert/entry_points.json" \
    --output-dir "$OUT/graph-from-json" --project-name store-backend \
    --language python --graph-format cert --no-minimize-ext

echo "=== 4. Мульти-репозиторные проекты (project) ==="
echo "--- project store (JSON, svg) ---"
"$CLI" project --config test_projects/store/project.json \
    --output-dir "$OUT/project-store" --no-llm
echo "--- project store (JSON, cert) ---"
"$CLI" project --config test_projects/store/project.json \
    --output-dir "$OUT/project-store-cert" --no-llm --graph-format cert
echo "--- project multi-service (Threagile) ---"
"$CLI" project --config test_projects/multi-service/threagile.yaml \
    --output-dir "$OUT/project-multi" --no-llm
echo "--- project bedolaga (Threagile) ---"
"$CLI" project --config test_projects/Bedolaga/threagile.yaml \
    --output-dir "$OUT/project-bedolaga" --no-llm

echo "=== 5. Экспорт Threagile (export-threagile) ==="
"$CLI" export-threagile \
    --config test_projects/store/project.json \
    --output "$OUT/threagile-export.yaml"

echo "=== 6. Проверка артефактов ==="
"$PYTHON" attack_surface/scripts/verify_artifacts.py "$OUT"

echo
echo "Верификация завершена успешно."
