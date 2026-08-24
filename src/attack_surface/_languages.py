"""Конфигурации внешних API для каждого поддерживаемого языка.

Каждый словарь отображает имя API-вызова на тип точки входа
(:class:`str`, соответствует значениям ``EntryPointType``).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

PYTHON_API_MAP: dict[str, str] = {
    # Пользовательский ввод
    "input": "user_input",
    "raw_input": "user_input",
    # Файловые операции
    "open": "file_read",
    "read": "file_read",
    "readline": "file_read",
    "readlines": "file_read",
    # Переменные окружения
    "getenv": "environment_variable",
    "environ": "environment_variable",
    # stdin
    "stdin": "user_input",
    # Сетевые — сокеты
    "recv": "socket",
    "recvfrom": "socket",
    "recvmsg": "socket",
    "recvmsg_into": "socket",
    "recv_into": "socket",
    "accept": "socket",
    # Сетевые — HTTP (requests)
    "get": "http_request",
    "post": "http_request",
    "put": "http_request",
    "delete": "http_request",
    "patch": "http_request",
    "request": "http_request",
    # urllib
    "urlopen": "http_request",
    "urlretrieve": "http_request",
    # subprocess
    "check_output": "command_line_args",
    "communicate": "command_line_args",
    # Десериализация
    "load": "deserialization",
    "loads": "deserialization",
    # БД
    "fetchone": "database_query",
    "fetchall": "database_query",
    "fetchmany": "database_query",
    "execute": "database_query",
    # Flask / Django
    "get_json": "http_request",
    "get_data": "http_request",
    # argparse
    "parse_args": "command_line_args",
    "parse_known_args": "command_line_args",
}

# Дополнительные паттерны доступа к атрибутам (Python)
PYTHON_ATTRIBUTE_PATTERNS: dict[str, str] = {
    "os.environ": "environment_variable",
    "sys.argv": "command_line_args",
    "request.": "http_request",
}

# ---------------------------------------------------------------------------
# C / C++
# ---------------------------------------------------------------------------

CPP_API_MAP: dict[str, str] = {
    # Файловый ввод
    "fread": "file_read",
    "fgets": "file_read",
    "fgetc": "file_read",
    "fscanf": "file_read",
    "read": "file_read",
    "pread": "file_read",
    "fopen": "file_read",
    "freopen": "file_read",
    # Пользовательский ввод
    "scanf": "user_input",
    "gets": "user_input",
    "getchar": "user_input",
    "getline": "user_input",
    "cin": "user_input",
    # Переменные окружения
    "getenv": "environment_variable",
    "secure_getenv": "environment_variable",
    # Сетевой ввод
    "recv": "socket",
    "recvfrom": "socket",
    "recvmsg": "socket",
    "accept": "socket",
    # Десериализация
    "xmlParseMemory": "deserialization",
    "xmlParseFile": "deserialization",
    "json_parse": "deserialization",
    # Командная строка
    "getopt": "command_line_args",
    "getopt_long": "command_line_args",
}

# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

GO_API_MAP: dict[str, str] = {
    # Файловый ввод
    "ReadFile": "file_read",
    "ReadAll": "file_read",
    "Open": "file_read",
    "Read": "file_read",
    "Scanner": "file_read",
    # Пользовательский ввод
    "Scanf": "user_input",
    "Scan": "user_input",
    "Scanln": "user_input",
    "ReadString": "user_input",
    # Переменные окружения
    "Getenv": "environment_variable",
    "LookupEnv": "environment_variable",
    # Сетевой ввод
    "ListenAndServe": "http_request",
    "HandleFunc": "http_request",
    "Handle": "http_request",
    "Get": "http_request",
    "Post": "http_request",
    "Do": "http_request",
    # Десериализация
    "Unmarshal": "deserialization",
    "Decode": "deserialization",
    "NewDecoder": "deserialization",
    # Командная строка
    "Args": "command_line_args",
    "Parse": "command_line_args",
    # БД
    "Query": "database_query",
    "QueryRow": "database_query",
    "Exec": "database_query",
}

# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------

JAVA_API_MAP: dict[str, str] = {
    # Файловый ввод
    "read": "file_read",
    "readLine": "file_read",
    "readAllBytes": "file_read",
    "readAllLines": "file_read",
    "newInputStream": "file_read",
    # Пользовательский ввод
    "nextLine": "user_input",
    "next": "user_input",
    "nextInt": "user_input",
    "readLine": "user_input",
    # Переменные окружения
    "getenv": "environment_variable",
    "getProperty": "environment_variable",
    # Сетевой ввод
    "getInputStream": "socket",
    "accept": "socket",
    "getParameter": "http_request",
    "getHeader": "http_request",
    "getQueryString": "http_request",
    "getRequestURI": "http_request",
    # Десериализация
    "readObject": "deserialization",
    "fromJson": "deserialization",
    "readValue": "deserialization",
    "unmarshal": "deserialization",
    # БД
    "executeQuery": "database_query",
    "executeUpdate": "database_query",
    "prepareStatement": "database_query",
}

# ---------------------------------------------------------------------------
# TypeScript / JavaScript
# ---------------------------------------------------------------------------

TYPESCRIPT_API_MAP: dict[str, str] = {
    # Файловый ввод
    "readFile": "file_read",
    "readFileSync": "file_read",
    "createReadStream": "file_read",
    # Переменные окружения
    "env": "environment_variable",
    # Сетевой ввод
    "fetch": "http_request",
    "get": "http_request",
    "post": "http_request",
    "put": "http_request",
    "delete": "http_request",
    "request": "http_request",
    "listen": "http_request",
    # Десериализация
    "parse": "deserialization",
    # Пользовательский ввод
    "question": "user_input",
    "prompt": "user_input",
    # Командная строка
    "argv": "command_line_args",
    # БД
    "query": "database_query",
    "find": "database_query",
    "findOne": "database_query",
    # WebSocket
    "on": "websocket",
}

# ---------------------------------------------------------------------------
# C#
# ---------------------------------------------------------------------------

CSHARP_API_MAP: dict[str, str] = {
    # Файловый ввод
    "ReadAllText": "file_read",
    "ReadAllLines": "file_read",
    "ReadAllBytes": "file_read",
    "OpenRead": "file_read",
    "ReadLine": "user_input",
    "Read": "file_read",
    # Переменные окружения
    "GetEnvironmentVariable": "environment_variable",
    # Сетевой ввод
    "GetAsync": "http_request",
    "PostAsync": "http_request",
    "SendAsync": "http_request",
    "GetStringAsync": "http_request",
    "DownloadString": "http_request",
    # Десериализация
    "Deserialize": "deserialization",
    "DeserializeObject": "deserialization",
    "ReadObject": "deserialization",
    # Пользовательский ввод
    "ReadKey": "user_input",
    # Командная строка
    "GetCommandLineArgs": "command_line_args",
    # БД
    "ExecuteReader": "database_query",
    "ExecuteScalar": "database_query",
    "ExecuteNonQuery": "database_query",
}

# ---------------------------------------------------------------------------
# Маппинг: имя языка trailmark → словарь API
# ---------------------------------------------------------------------------

LANGUAGE_API_MAPS: dict[str, dict[str, str]] = {
    "python": PYTHON_API_MAP,
    "c": CPP_API_MAP,
    "cpp": CPP_API_MAP,
    "go": GO_API_MAP,
    "java": JAVA_API_MAP,
    "javascript": TYPESCRIPT_API_MAP,
    "typescript": TYPESCRIPT_API_MAP,
    "c_sharp": CSHARP_API_MAP,
}

# Маппинг имён языков RepoAudit → trailmark
REPOAUDIT_LANG_TO_TRAILMARK: dict[str, str] = {
    "Cpp": "cpp",
    "C": "c",
    "Go": "go",
    "Java": "java",
    "Python": "python",
    "TypeScript": "typescript",
    "JavaScript": "javascript",
    "TS": "typescript",
    "JS": "javascript",
    "CSharp": "c_sharp",
    "C#": "c_sharp",
}
