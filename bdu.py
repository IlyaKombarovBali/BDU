import sqlite3
import zipfile
import xml.etree.ElementTree as ET

con = sqlite3.connect("bdu.db")
cursor = con.cursor()

# Путь к архиву и папка для распаковки
zip_path = 'vulxml.zip'

# Открытие и распаковка
with zipfile.ZipFile(zip_path, 'r') as zip_ref:
    zip_ref.extractall()
    print("Распаковка завершена")