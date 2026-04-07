import config
import pandas as pd
import sqlite3
import urllib.request
import os

# 1. Скачиваем файл
try:
    urllib.request.urlretrieve(config.URL, config.FILE_PATH)
    print(f"Файл скачан: {config.FILE_PATH}")
except Exception as e:
    print(f"Ошибка скачивания: {e}")
    print("Использую локальный файл (если есть)")
    if not os.path.exists(config.FILE_PATH):
        print("Локального файла тоже нет. Выход.")
        exit(1)
# 2. Читаем Excel
df = pd.read_excel(config.FILE_PATH)
# 3. Переименовываем колонки (твой код)
df = config.rename_columns(df)
# 4. Записываем в SQLite (таблица пересоздаётся)
config.bdu_con(df)

print("База данных обновлена")






