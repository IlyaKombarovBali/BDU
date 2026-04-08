import config
import pandas as pd
import sqlite3
import urllib.request
import os


# 1. Скачиваем файл
config.save_file()
# 2. Читаем Excel
df = pd.read_excel(config.FILE_PATH, header=2)
# 3. Переименовываем колонки 
df = config.rename_columns(df)
# 4. Записываем в SQLite (таблица пересоздаётся)
config.bdu_con(df)

print("База данных обновлена")






