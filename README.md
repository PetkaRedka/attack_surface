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

## Мульти-репозиторный анализ

Поддержка проектов, состоящих из нескольких репозиториев. Конфигурация
описывается в JSON-файле и включает репозитории, их роли и связи между ними.

Пример `project.json`:

```json
{
  "project": "my-product",
  "repos": [
    { "name": "frontend", "path": "./frontend", "language": "javascript", "role": "ui" },
    { "name": "backend", "path": "./backend", "language": "csharp", "role": "api" },
    { "name": "native", "path": "./native", "language": "cpp", "role": "core" }
  ],
  "links": [
    { "from": "frontend", "to": "backend", "type": "http" },
    { "from": "backend", "to": "native", "type": "pinvoke" }
  ]
}
```

Типы связей — семьи взаимодействия, покрывающие все протоколы Threagile:
`http`, `grpc`, `websocket`, `shared-db`, `ffi`, `pinvoke`, `message-queue`,
`rpc`, `file`, `reverse-proxy`, `email`, `ssh`, `ftp`, `ldap`, `binary`,
`text`, `ipc`, `container`, `nfs`. Пути репозиториев резолвятся относительно
каталога конфигурационного файла.

### CLI

```bash
# Полный анализ с LLM-валидацией (конфиг в нашем JSON)
attack-surface project --config project.json --output-dir ./out --graph-format cert

# Анализ на основе архитектурного файла Threagile (связи доверенные)
attack-surface project --config threagile.yaml --output-dir ./out

# Только статический анализ (без LLM)
attack-surface project --config project.json --no-llm

# Без конфига: автосоставление по корню проекта (JSON), связи ищутся перебором
attack-surface project --project-path ./my-product --output-dir ./out --no-llm

# Автосоставление в архитектурный YAML Threagile
attack-surface project --project-path ./my-product --config-format threagile --output-dir ./out --no-llm

# Искать связи перебором всех пар репозиториев, игнорируя links из конфига
attack-surface project --config project.json --auto-links --output-dir ./out --no-llm

# Пересобрать граф из уже проверенных точек входа (этап нахождения пропущен)
attack-surface project --config project.json --entrypoints-dir ./out/repos --output-dir ./out2 --no-llm

# Сразу CERT и SVG в одном прогоне
attack-surface project --config project.json --output-dir ./out --graph-format both

# Пересобрать CERT/SVG из готового project_scan.json (без сканирования и LLM)
attack-surface project --from-scan ./out/project_scan.json --output-dir ./out --graph-format cert

# Отрисовать CERT+SVG схему топологии из архитектурного файла Threagile (без анализа кода)
attack-surface render-threagile --config threagile.yaml --output-dir ./topology --graph-format both

# Сгенерировать архитектурный файл Threagile из JSON-конфига
attack-surface export-threagile --config project.json --output threagile.yaml
```

### Автосоставление конфигурации и авто-линковка

Если конфигурационного файла нет, можно запустить `project` с `--project-path`:
репозитории обнаруживаются в корневом каталоге, а конфигурация сохраняется
в `output-dir` как `<проект>.auto.json` или `<проект>.auto.yaml`
(`--config-format json|threagile`).

Режим обнаружения задаётся переменной окружения `GIT_SUPPORT`
(по умолчанию `true`):

- `GIT_SUPPORT=true` — репозиторием считается только каталог с маркером
  `.git` (включая субмодули, где `.git` — файл-указатель). Поиск ведётся
  от корня на глубину `GIT_DEPTH` (по умолчанию 3) без спуска внутрь
  найденных репозиториев; если `.git` есть в самом корне, корень считается
  единственным репозиторием;
- `GIT_SUPPORT=false` — прежнее поведение: подкаталоги первого уровня
  с определяемым языком (маркеры `go.mod`, `tsconfig.json`, `package.json`,
  `*.csproj`, `CMakeLists.txt`, `*.py` и т.п.); каталоги без кода (docs
  и т.п.) пропускаются.

Когда связи в конфиге отсутствуют (или задан флаг `--auto-links`), работает
авто-линковка: перебираются все пары репозиториев, для каждой пары сигнатуры
серверных эндпоинтов ищутся в коде другого репозитория (плюс обратный проход
при `CROSS_REPO_BIDIRECTIONAL=true`). Тип найденной связи выводится из
`interface_kind` эндпоинта, дубликаты совпадений отбрасываются.

Для конфига, заданного архитектором (Threagile с `data_flows`), связи
остаются доверенными и авто-линковка не применяется (кроме явного
`--auto-links`).

### Пересборка графа из проверенных точек входа

`project` сохраняет точки входа и их интерфейсы в `output-dir/repos/
<имя>_entry_points.json`. Флаг `--entrypoints-dir` позволяет пересобрать
кросс-репо граф из уже проверенных данных, пропустив этап нахождения
точек входа (сканирование и LLM-валидацию) внутри каждого репозитория:

```bash
attack-surface project --config project.json --entrypoints-dir ./out/repos --output-dir ./out2
```

Интерфейсы загружаются из JSON, исходный код репозиториев не читается —
пайплайн сразу переходит к этапу слияния графов: связи из `data_flows`
(если задан архитектурный файл Threagile) сопоставляются с эндпоинтами
как доверенные, при их отсутствии выполняется авто-линковка. Достижимость
и цепочки считаются по кросс-репо связям (внутрирепозиторные вызовы
в этом режиме не учитываются — для них нужен полный прогон).

### Пересборка графа из артефактов

- `project --from-scan <project_scan.json>` — пересобирает граф (CERT/SVG)
  из сохранённого `project_scan.json`: сканирование, LLM и линковка не
  выполняются, используются уже найденные точки входа, связи и
  поверхность атаки.
- `render-threagile --config threagile.yaml` — отрисовывает схему
  **топологии** (узлы — репозитории, рёбра — связи из `data_flows`)
  в CERT и/или SVG без анализа кода. Удобно для быстрой визуализации
  архитектурного файла, в том числе после того, как в него записаны
  найденные связи.
- `--graph-format both` у `project` и `render-threagile` генерирует
  CERT и SVG сразу.

### Промежуточные результаты (чекпойнты)

При обычном запуске `project` промежуточные результаты сохраняются на
каждом этапе, поэтому прерванный анализ можно продолжить:

1. **статически найденные точки входа** — `repos/<имя>_entry_points.json`
   пишется сразу после извлечения, до LLM-валидации (интерфейсы пустые);
2. **верифицированные точки входа и интерфейсы** — тот же файл
   перезаписывается после LLM-валидации каждого репозитория;
3. **верифицированные связи** — `cross_edges.json` после подтверждения
   линковки, до вычисления поверхности атаки.

Если процесс прерван (например, на этапе верификации связей), достаточно
перезапустить анализ с уже накопленными чекпойнтами:

```bash
attack-surface project --config <проект>.auto.json \
    --entrypoints-dir ./out/repos --output-dir ./out
```

Финальные артефакты (`project_graph.json`, `project_scan.json`, схема ПА)
появятся при успешном завершении.

### Найденные связи в архитектурном файле

Автосоставленный Threagile-файл создаётся до анализа с пустыми
`data_flows`. После завершения `project` найденные связи записываются
в него (`update_threagile_data_flows`): существующие потоки сохраняются,
дубликаты по паре `(source, target, protocol)` исключаются. Такой файл
можно передать архитектору или сразу отрисовать из него топологию
командой `render-threagile`.

### Кэш по версиям репозиториев

Чтобы не повторять LLM-валидацию при неизменном коде, результаты
кэшируются по версиям репозиториев (без БД):

- **Версия** — git-коммит (читается напрямую из `.git` без git CLI:
  `HEAD` → refs/packed-refs, учитываются worktree и субмодули) либо,
  для каталогов без `.git`, хэш списка файлов `(путь, размер)`;
- **Хранилище** — по умолчанию `<каталог проекта>/.attack_cache/<проект>/`,
  каталог переопределяется переменной `ATTACK_CACHE_DIR`:
  `current.json` (текущие версии), `repos/<имя>/<версия>.json`
  (точки входа, интерфейсы, проекция графа trailmark),
  `links/<хэш>.json` (подтверждённые связи);
- **Инкрементальность** — при изменении кода повторно верифицируются
  только **новые** точки входа (ключ — файл, функция, диапазон строк)
  и **новые** связи (ключ — тип, серверная сигнатура, место вызова);
  остальное переиспользуется из предыдущей версии. Ушедшие точки
  и завязанные на них связи исчезают из отчётов автоматически;
- **Управление** — `--no-cache` или `ATTACK_CACHE=false` отключает кэш;
  откат на старый коммит подхватывает его сохранённую верификацию.

### Подтверждение связей батчами

Кандидаты связей подтверждаются LLM батчами (размер — `LINK_BATCH_SIZE`,
по умолчанию 10; `LINK_BATCH_SIZE=1` — по одному запросу на связь, как
раньше). Перед отправкой кандидаты сворачиваются в связи: одна серверная
сигнатура, вызываемая из одного файла клиента, — это один запрос, а его
результат распространяется на все места вызова. Невалидные точки входа
(`is_entry_point=false`) отсекаются до процесса стыковки.

### Интеграция с Threagile

Поддерживается формат [Threagile](https://threagile.io) — инструмента
моделирования угроз. Архитектор описывает компоненты (`technical_assets`)
и взаимосвязи (`data_flows`) в YAML-файле.

При передаче `threagile.yaml` команде `project` связи из `data_flows`
считаются доверенными: вместо эвристического поиска и LLM-верификации они
лишь сопоставляются с найденными эндпоинтами (серверными в `target` и
клиентскими в `source`). `technical_assets[].id` соответствует имени
репозитория-каталога, лежащего рядом с файлом конфигурации.

Сопоставление типов связей. Словарь типов — это семьи взаимодействия,
покрывающие **все 48 допустимых значений** `protocol` файла архитектуры
Threagile (перечень выверен по `pkg/types/protocol.go`, ветка `master`):

| Threagile protocol | Тип связи |
|---|---|
| http, https | http |
| ws, wss | websocket |
| reverse-proxy-web-protocol, reverse-proxy-web-protocol-encrypted | reverse-proxy |
| jdbc, jdbc-encrypted, odbc, odbc-encrypted, sql-access-protocol, sql-access-protocol-encrypted, nosql-access-protocol, nosql-access-protocol-encrypted | shared-db |
| mqtt, jms | message-queue |
| binary, binary-encrypted | binary |
| text, text-encrypted, xmpp | text |
| ssh, ssh-tunnel, scp | ssh |
| sftp, ftp, ftps | ftp |
| smtp, smtp-encrypted, pop3, pop3-encrypted, imap, imap-encrypted | email |
| ldap, ldaps | ldap |
| nfs, smb, smb-encrypted | nfs |
| local-file-access | file |
| in-process-library-call | ffi |
| inter-process-communication | ipc |
| container-spawning | container |
| nrpe, iiop, iiop-encrypted, jrmp, jrmp-encrypted, unknown-protocol | rpc |

При генерации `threagile.yaml` каждый тип связи отображается в допустимый
протокол Threagile (для шифруемых протоколов по умолчанию берётся
шифрованный вариант: `http` → `https`, `ws` → `wss`, `ftp` → `ftps` и т.п.).
Исключения: `grpc` (в Threagile нет значения — отображается в `https`,
так как работает поверх HTTP/2), `rpc` (в `unknown-protocol`).

Как это работает

1. Каждый репозиторий сканируется через trailmark, извлекаются точки входа.
2. Каждая точка входа валидируется через LLM: подтверждается принадлежность
   к поверхности атаки и определяется интерфейс связи (серверный/клиентский,
   тип и сигнатура для поиска в других репозиториях).
3. Статические эвристики ищут обращения к серверным эндпоинтам в коде других
   репозиториев (прямой проход), а также обратный проход как средство
   дополнительной валидации (отключается через `CROSS_REPO_BIDIRECTIONAL`).
4. Найденные связи подтверждаются LLM (отключается через
   `CROSS_REPO_CONFIRM_LINKS` или `--no-llm`).
5. Строится кросс-репозиторный граф (`project_graph.json`, CERT/SVG), и
   относительно него вычисляется поверхность атаки: внешние источники плюс
   достижимые узлы и межрепозиторные цепочки атак.

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

### Тестовые проекты

В каталоге `test_projects/` находятся примеры мульти-репозиторных проектов
для проверки через CLI (без pytest):

- `store/` — витрина магазина: `frontend` (JavaScript) → `backend` (Python)
  → `native` (C++), конфиг в нашем JSON-формате (эвристический режим):
  ```bash
  attack-surface project --config test_projects/store/project.json --output-dir test_projects/store/output --no-llm
  ```
- `multi-service/` — сервисы `web` (TypeScript) → `api` (Go) → `worker` (C#),
  архитектурный файл Threagile (доверенные связи):
  ```bash
  attack-surface project --config test_projects/multi-service/threagile.yaml --output-dir test_projects/multi-service/output --no-llm
  ```
- `Bedolaga/` — реальные репозитории `remnawave-bedolaga-telegram-bot` (Python)
  и `bedolaga-cabinet` (TypeScript), архитектурный файл `Bedolaga/threagile.yaml`:
  ```bash
  attack-surface project --config test_projects/Bedolaga/threagile.yaml --output-dir test_projects/Bedolaga/output --no-llm
  ```

### Верификация всего функционала через CLI

Скрипт `attack_surface/scripts/verify_cli.sh` прогоняет все команды CLI на
тестовых проектах и проверяет артефакты (включая CERT-граф для сертификации):

```bash
bash attack_surface/scripts/verify_cli.sh
```

Покрытие: `scan` (HTML/SVG/CERT) для каждого репозитория, `call-graph`
(stats/cert/фильтрация по ПА), `graph-from-json`, `project` (JSON и Threagile),
`export-threagile`. Проверка артефактов — `attack_surface/scripts/verify_artifacts.py`
(валидность JSON, структура GoJS GraphLinksModel, HTML/SVG).

## Переменные окружения

- `OPENAI_API_KEY` — API-ключ OpenAI (обязательно для LLM-минимизации)
- `OPENAI_MODEL_NAME` — имя модели (по умолчанию: `gpt-4o-mini`)
- `OPENAI_API_BASE` — базовый URL для self-hosted моделей
- `EXT_MINIMIZER_SYSTEM_ROLE` — системный промпт для EXT-минимизатора
- `EXT_MINIMIZER_TASK` — задача для LLM
- `EXT_MINIMIZER_GROUPING_RULES` — правила группировки (разделитель: `\n`)

### Мульти-репозиторный анализ (кросс-репо)

- `INTERFACE_ANALYZER_SYSTEM_ROLE` — системный промпт анализатора интерфейсов
- `INTERFACE_ANALYZER_TASK` — задача для анализатора интерфейсов
- `INTERFACE_ANALYZER_RULES` — правила классификации интерфейсов
- `LINK_VALIDATOR_SYSTEM_ROLE` — системный промпт валидатора связей
- `LINK_VALIDATOR_TASK` — задача для валидатора связей
- `CROSS_REPO_BIDIRECTIONAL` — включить обратный проход связывания (`true`/`false`, по умолчанию `true`)
- `CROSS_REPO_CONFIRM_LINKS` — подтверждать найденные связи через LLM (`true`/`false`, по умолчанию `true`)

### Батчевая LLM-валидация точек входа

- `ENTRY_BATCH_SIZE` — размер батча при LLM-валидации точек входа (по умолчанию `5`). Батчи формируются пофайлово: файл с большим числом точек входа разбивается на чанки, а «хвосты» файлов с малым числом точек добираются друг из друга до полного батча.
