# attack-surface

Построение поверхности атаки проекта на базе [trailmark](../trailmark).

## Возможности

- **Извлечение точек входа** — анализ графа кода trailmark для обнаружения корневых функций и функций с внешним вводом (HTTP, файлы, сокеты, БД, CLI и т.д.)
- **Граф вызовов проекта** — построение полного графа вызовов всего проекта (обёртка над trailmark)
- **Фильтрация по поверхности атаки** — граф только с элементами связанными с точками входа (любой глубины)
- **Граф поверхности атаки** — визуализация в SVG или CERT JSON (GoJS GraphLinksModel)
- **HTML-отчёт** — интерактивный отчёт с группировкой по типам интерфейсов
- **LLM-минимизация EXT** — группировка схожих внешних интерфейсов через LLM
- **Поддержка языков** — Python, C/C++, Go, Java, TypeScript/JavaScript, C#

## Установка

```bash
uv add attack-surface
```

Или из локального каталога:

```bash
uv pip install -e ./attack_surface
```

## Использование

### CLI

```bash
# Сканировать проект и найти точки входа
attack-surface scan --project-path /path/to/project --html-report --graph

# Построить граф из существующего JSON
attack-surface graph-from-json --entrypoints-json entry_points.json --output-dir ./output

# Построить полный граф вызовов проекта
attack-surface call-graph --project-path /path/to/project --format svg

# Построить граф вызовов только с элементами связанными с поверхностью атаки
attack-surface call-graph --project-path /path/to/project --filter-by-attack-surface --format svg
```

### Как библиотека

```python
from trailmark import parse_directory
from attack_surface import (
    EntryPointExtractor, 
    CallGraphBuilder,
    generate_attack_surface_graph
)

# Построить граф кода
graph = parse_directory("/path/to/project")

# Извлечь точки входа
extractor = EntryPointExtractor(graph, language="python")
candidates = extractor.build_entry_points()

# Сгенерировать граф поверхности атаки
ep_dicts = {k: v.to_dict() for k, v in candidates.items()}
generate_attack_surface_graph(ep_dicts, "./output", "MyProject", "python")

# Работа с графом вызовов
builder = CallGraphBuilder(graph)

# Получить полный граф
full_graph = builder.get_full_graph()

# Отфильтровать по поверхности атаки
filtered_graph = builder.filter_by_attack_surface(candidates)

# Статистика
stats = builder.get_statistics(filtered_graph)
print(f"Узлов: {stats['total_nodes']}, функций: {stats['functions']}")
```

## Структура проекта

```
attack_surface/
├── pyproject.toml              # Конфигурация uv-проекта
├── README.md                   # Документация
├── src/attack_surface/
│   ├── __init__.py            # Публичный API модуля
│   ├── cli.py                 # CLI-интерфейс (scan/graph-from-json/call-graph)
│   ├── _models.py             # Модели данных
│   │   ├── EntryPointInfo     # Информация о точке входа
│   │   ├── ExternalSource     # Внешний источник данных
│   │   ├── ScanResult         # Результат сканирования
│   │   └── EntryPointType     # Enum типов точек входа
│   ├── _extractor.py          # Извлечение точек входа из CodeGraph
│   │   └── EntryPointExtractor # Основной класс-экстрактор
│   ├── _call_graph.py         # Построение и фильтрация графа вызовов
│   │   └── CallGraphBuilder   # Работа с графом вызовов проекта
│   ├── _languages.py          # API-маппинги для каждого языка
│   │   ├── PYTHON_API_MAP     # Python: input, open, getenv, loads, etc.
│   │   ├── CPP_API_MAP        # C/C++: fread, scanf, getenv, recv, etc.
│   │   ├── GO_API_MAP         # Go: ReadFile, Getenv, ListenAndServe, etc.
│   │   ├── JAVA_API_MAP       # Java: read, getenv, getParameter, etc.
│   │   ├── TYPESCRIPT_API_MAP # TS/JS: readFile, fetch, parse, etc.
│   │   └── CSHARP_API_MAP     # C#: ReadAllText, GetEnvironmentVariable, etc.
│   ├── _llm.py                # Базовые LLM-утилиты (общие для attack_surface и autofuzz)
│   │   ├── LLMClient          # Клиент для OpenAI-совместимых API
│   │   ├── LLMTool            # Абстрактный LLM-инструмент с кешем
│   │   ├── LLMToolInput       # Базовый класс входа
│   │   └── LLMToolOutput      # Базовый класс выхода
│   ├── _ext_minimizer.py      # LLM-минимизация внешних интерфейсов
│   │   ├── EXTMinimizer       # LLM-инструмент для группировки EXT
│   │   ├── EXTMinimizerInput  # Вход: модуль, типы EXT, точки входа
│   │   └── EXTMinimizerOutput # Выход: сгруппированные EXT
│   ├── _graph.py              # Генерация графа поверхности атаки
│   │   ├── generate_svg_graph # SVG-визуализация
│   │   ├── generate_cert_graph # CERT JSON (GoJS GraphLinksModel)
│   │   └── generate_attack_surface_graph # Единая точка входа
│   ├── _report.py             # HTML-отчёт
│   │   └── generate_html_report # Интерактивный HTML с группировкой
│   └── _logger.py             # Потокобезопасный логгер
│       └── Logger             # Логирование в файл + консоль
└── tests/
    ├── conftest.py            # Общие pytest fixtures
    ├── test_extractor.py      # Тесты EntryPointExtractor
    ├── test_graph.py          # Тесты генерации графа
    ├── test_report.py         # Тесты HTML-отчёта
    ├── test_project/          # Тестовый Python-проект
    │   ├── vulnerable_app.py  # Код с точками входа
    │   └── utils.py           # Внутренние функции
    └── fixtures/
        └── expected_entry_points.json # Ожидаемый результат
```

## Архитектура

### Процесс извлечения точек входа

1. **Построение графа** — trailmark парсит исходный код и строит `CodeGraph` (узлы = функции/классы, рёбра = вызовы/наследование)
2. **Анализ графа** — `EntryPointExtractor` анализирует граф:
   - Находит **корневые функции** (не имеют вызывающих в проекте)
   - Находит **функции с внешним вводом** (содержат вызовы API из `_languages.py`)
3. **Классификация** — каждая точка входа получает тип (`http_request`, `file_read`, `deserialization`, и т.д.)
4. **Выходной формат** — результат сохраняется в JSON с полной информацией о каждой точке входа

### LLM-минимизация EXT

Для упрощения графа схожие внешние интерфейсы группируются через LLM:
- **Вход**: список всех EXT-типов модуля
- **Промпт**: правила группировки (по источнику данных, функциональной роли, рискам)
- **Выход**: сгруппированные EXT с представительным типом

### Форматы графа

- **SVG** — статическая векторная визуализация (модули, подсистемы, EXT-интерфейсы, связи)
- **CERT JSON** — GoJS GraphLinksModel для интерактивных диаграмм (используется в CERT-инструментах)

## Зависимости

- `trailmark>=0.3` — построение графа кода
- `openai>=1.0` — LLM-инференс (для минимизации EXT)
- `tiktoken>=0.7` — подсчёт токенов
- `python-dotenv>=1.0` — загрузка переменных окружения
- `tqdm>=4.60` — прогресс-бары

## Тестирование

```bash
# Запустить все тесты
pytest tests/

# Запустить конкретный тест
pytest tests/test_extractor.py -v

# С покрытием
pytest tests/ --cov=attack_surface --cov-report=html
```

## Переменные окружения

- `OPENAI_API_KEY` — API-ключ OpenAI (обязательно для LLM-минимизации)
- `OPENAI_MODEL_NAME` — имя модели (по умолчанию: `gpt-4o-mini`)
- `OPENAI_API_BASE` — базовый URL для self-hosted моделей
- `EXT_MINIMIZER_SYSTEM_ROLE` — системный промпт для EXT-минимизатора
- `EXT_MINIMIZER_TASK` — задача для LLM
- `EXT_MINIMIZER_GROUPING_RULES` — правила группировки (разделитель: `\n`)
