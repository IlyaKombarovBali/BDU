import pandas as pd
import sqlite3
import urllib.request
import os

# 1. Скачиваем файл (если есть прямая ссылка)
url = "https://bdu.fstec.ru/files/documents/vullist.xlsx"  # проверь эту ссылку
file_path = "vullist.xlsx"

try:
    urllib.request.urlretrieve(url, file_path)
    print(f"Файл скачан: {file_path}")
except Exception as e:
    print(f"Ошибка скачивания: {e}")
    print("Использую локальный файл (если есть)")
    if not os.path.exists(file_path):
        print("Локального файла тоже нет. Выход.")
        exit(1)

# 2. Читаем Excel
df = pd.read_excel(file_path)

# 3. Переименовываем колонки (твой код)
df = df.rename(columns={
    'Идентификатор': 'bdu_id',
    'Наименование уязвимости': 'name',
    'Описание уязвимости': 'description',
    'Вендор ПО': 'vendor',
    'Название ПО': 'software_name',
    'Версия ПО': 'software_version',
    'Тип ПО': 'software_type',
    'Наименование ОС и тип аппаратной платформы': 'os_hardware',
    'Класс уязвимости': 'vul_class',
    'Дата выявления': 'detected_date',
    'CVSS 2.0': 'cvss_v2_score',
    'CVSS 3.0': 'cvss_v3_score',
    'CVSS 4.0': 'cvss_v4_score',
    'Уровень опасности уязвимости': 'severity',
    'Возможные меры по устранению': 'solution',
    'Статус уязвимости': 'vul_status',
    'Наличие эксплойта': 'exploit_status',
    'Информация об устранении': 'fix_status',
    'Ссылки на источники': 'sources',
    'Идентификаторы других систем описаний уязвимости': 'identifiers',
    'Прочая информация': 'other_info',
    'Связь с инцидентами ИБ': 'incident_relation',
    'Способ эксплуатации': 'exploit_method',
    'Способ устранения': 'vul_elimination',
    'Дата публикации': 'published_date',
    'Дата последнего обновления': 'last_updated',
    'Последствия эксплуатации уязвимости': 'impact',
    'Состояние уязвимости': 'vul_state',
    'Описание ошибки CWE': 'cwe_description',
    'Тип ошибки CWE': 'cwe_type',
    'Идентификатор': 'identifier',
    'Наименование': 'title'
})

# 4. Записываем в SQLite (таблица пересоздаётся)
con = sqlite3.connect("bdu.db")
df.to_sql("cve", con, if_exists="replace", index=False)

# 5. Добавляем поле published_date_iso для сортировки
con.execute("ALTER TABLE cve ADD COLUMN published_date_iso TEXT;")
con.execute("""
    UPDATE cve 
    SET published_date_iso = 
        substr(published_date, 7, 4) || '-' || 
        substr(published_date, 4, 2) || '-' || 
        substr(published_date, 1, 2) 
    WHERE published_date LIKE '__.__.____';
""")
con.commit()
con.close()

print("База данных обновлена")