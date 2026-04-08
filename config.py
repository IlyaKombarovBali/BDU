import config
import pandas as pd
import sqlite3
import urllib.request
import os
import ssl


#Скачиваем файл
URL = "https://bdu.fstec.ru/files/documents/vullist.xlsx"  
FILE_PATH = "vullist.xlsx"
BDU_PATH = "bdu.db"

def save_file():
    os.remove(FILE_PATH)
    print("Таблица BDU успешно удалена")
    os.remove(BDU_PATH)
    print("БД успешно удалена")
    con = sqlite3.connect("bdu.db")
    con.close()
    os.system(f"wget --no-check-certificate {URL} -O {FILE_PATH}")
    
    if not os.path.exists(FILE_PATH):
        print("Файл не скачался. Выход.")
        exit(1)
    
    print(f"Файл скачан: {FILE_PATH}")

#Переименовываем колонки
def rename_columns(df):
    return df.rename(columns={
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
#Подключаемся к БД
def get_db():
    con = sqlite3.connect("bdu.db") #Создайте файл в корне (bdu.db)
    con.row_factory = sqlite3.Row
    return con
#Получаем даные с БД по временной сортировки
def get_recent_vulns(limit=10):
    con = get_db()
    cursor = con.cursor()
    cursor.execute("SELECT identifier, name, severity, description, published_date FROM cve ORDER BY published_date_iso DESC LIMIT ?", (limit,))
    #cursor.execute("SELECT cve_id, name FROM cve LIMIT ?", (limit,))
    vulns = cursor.fetchall()
    con.close()
    return vulns


def get_vuln_by_identifier(identifier):
    con = get_db()
    cursor = con.cursor()
    cursor.execute("SELECT * FROM cve WHERE identifier = ?", (identifier,))
    vuln = cursor.fetchone()
    con.close()
    return vuln

def get_vulns_count():
    con = get_db()
    cursor = con.cursor()
    cursor.execute("SELECT COUNT(*) FROM cve")
    count = cursor.fetchone()[0]
    con.close()
    return count

def get_vulns_page(limit, offset):
    con = get_db()
    cursor = con.cursor()
    cursor.execute("""
        SELECT identifier, name, published_date 
        FROM cve 
        ORDER BY published_date_iso DESC 
        LIMIT ? OFFSET ?
    """, (limit, offset))
    vulns = cursor.fetchall()
    con.close()
    return vulns



# Записываем таблицу в БД и добавлляем дату по ISO для сортировки 
def bdu_con(df):
    con = get_db() 
    df.to_sql("cve", con, if_exists="replace", index=False)
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


