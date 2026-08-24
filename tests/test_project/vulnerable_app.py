"""
Тестовый Python-проект с уязвимостями для демонстрации attack_surface.
Содержит различные типы точек входа: HTTP, файлы, CLI, БД, десериализация.
"""

import json
import os
import sys
import pickle
from typing import Any


def parse_json_config(json_string: str) -> dict:
    """
    Парсинг JSON-конфигурации из внешнего источника.
    
    Точка входа: HTTP request body, file input
    Уязвимость: отсутствие валидации, KeyError
    """
    data = json.loads(json_string)
    
    if data["type"] == "admin":
        return {"role": data["role"], "permissions": data["permissions"]}
    
    return data


def process_file_upload(file_path: str) -> str:
    """
    Обработка загруженного файла.
    
    Точка входа: file_read
    Уязвимость: path traversal, отсутствие проверки размера
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    return content.upper()


def handle_cli_arguments(args: list[str]) -> dict:
    """
    Обработка аргументов командной строки.
    
    Точка входа: command_line_args
    Уязвимость: отсутствие валидации, injection
    """
    config = {}
    for arg in args:
        if '=' in arg:
            key, value = arg.split('=', 1)
            config[key] = value
    
    return config


def execute_database_query(query: str, params: tuple) -> list:
    """
    Выполнение SQL-запроса к БД.
    
    Точка входа: database_query
    Уязвимость: SQL injection (имитация)
    """
    # Имитация выполнения запроса
    result = []
    if "SELECT" in query.upper():
        result = [{"id": 1, "name": "test"}]
    
    return result


def deserialize_user_data(data: bytes) -> Any:
    """
    Десериализация пользовательских данных.
    
    Точка входа: deserialization
    Уязвимость: arbitrary code execution через pickle
    """
    obj = pickle.loads(data)
    return obj


def get_environment_config() -> dict:
    """
    Чтение конфигурации из переменных окружения.
    
    Точка входа: environment_variable
    Уязвимость: отсутствие валидации, injection
    """
    api_key = os.getenv("API_KEY", "")
    db_host = os.getenv("DB_HOST", "localhost")
    
    return {"api_key": api_key, "db_host": db_host}


def process_user_input() -> str:
    """
    Обработка пользовательского ввода из stdin.
    
    Точка входа: user_input
    Уязвимость: отсутствие санитизации
    """
    user_data = input("Enter data: ")
    return f"Processed: {user_data}"


def handle_http_request(request_body: str, headers: dict) -> dict:
    """
    Обработка HTTP-запроса.
    
    Точка входа: http_request
    Уязвимость: CSRF, XSS
    """
    data = json.loads(request_body)
    response = {
        "status": "ok",
        "data": data,
        "user_agent": headers.get("User-Agent", "")
    }
    return response


def main():
    """Главная функция — точка входа main_function."""
    if len(sys.argv) > 1:
        config = handle_cli_arguments(sys.argv[1:])
        print(f"Config: {config}")
    else:
        print("No arguments provided")


if __name__ == "__main__":
    main()
