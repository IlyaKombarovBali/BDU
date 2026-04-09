import config
import pandas as pd
import sqlite3
import urllib.request
import os
import ssl
import pymorphy3
import re




#Скачиваем файл
URL = "https://bdu.fstec.ru/files/documents/vullist.xlsx"  
FILE_PATH = "vullist.xlsx"
BDU_PATH = "bdu.db"

def save_file():
    # Создаем контекст, который не проверяет SSL-сертификат (аналог --no-check-certificate)
    ssl_context = ssl._create_unverified_context()
    # Создаем "открывашку" (opener) с нашим контекстом и устанавливаем её по умолчанию
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))
    urllib.request.install_opener(opener)
    # -------------------------------------------------------
    if not os.path.exists(FILE_PATH):
        print(f"Скачиваю {FILE_PATH}...")
        urllib.request.urlretrieve(URL, FILE_PATH)
        print(f"Файл скачан: {FILE_PATH}")
    else:
        os.remove(FILE_PATH)
        print("Файл успешно удален")
        print(f"Скачиваю {FILE_PATH}...")
        urllib.request.urlretrieve(URL, FILE_PATH)
        print(f"Файл скачан: {FILE_PATH}")

    if not os.path.exists(BDU_PATH):
        con = sqlite3.connect("bdu.db")
        con.close()
    else:
        os.remove(BDU_PATH)
        print("БД успешно удалена")
        con = sqlite3.connect("bdu.db")
        con.close()

#Скачиваем словари, и делаем обработку словарей чтобы поиск был лучше

morph = pymorphy3.MorphAnalyzer()

def normalize_query(query):
    cleaned = re.sub(r'[^\w\s]', ' ', query)
    words = cleaned.lower().split()
    
    normalized = []
    for word in words:
        if len(word) < 3:
            normalized.append(word)
        else:
            # Лемматизация
            parsed = morph.parse(word)[0]
            base = parsed.normal_form
            # Берём первые 5-6 символов (корень)
            root = base[:6]
            normalized.append(root)
    
    return normalized


print("Идет создание БД....")

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
    con = sqlite3.connect("bdu.db")
    con.row_factory = sqlite3.Row
    return con

def get_norm_db():
    con = sqlite3.connect("site.db")
    con.row_factory = sqlite3.Row  # для удобного доступа по именам колонок
    return con


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

def search_vulns_by_identifier(query, limit, offset):
    con = get_db()
    cursor = con.cursor()
    cursor.execute("""
        SELECT identifier, name, published_date 
        FROM cve 
        WHERE identifier LIKE ? OR identifiers LIKE ? OR software_name LIKE ?
        ORDER BY published_date_iso DESC
        LIMIT ? OFFSET ?
    """, (f'%{query}%', f'%{query}%', f'%{query}%', limit, offset))
    results = cursor.fetchall()
    con.close()
    return results

def search_vulns_count(query):
    con = get_db()
    cursor = con.cursor()
    cursor.execute("""
        SELECT COUNT(*) 
        FROM cve 
        WHERE identifier LIKE ? OR identifiers LIKE ? OR software_name LIKE ?
    """, (f'%{query}%', f'%{query}%', f'%{query}%'))
    count = cursor.fetchone()[0]
    con.close()
    return count
#Фильтрация уязвимостей

def get_cve_count_by_filter(filter_type):
    con = get_db()
    cursor = con.cursor()
    
    if filter_type == 'critical':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE CAST(cvss_v3_score AS REAL) >= 9.0")
    elif filter_type == 'exploit_exists':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE exploit_status = 'Существует в открытом доступе'")
    elif filter_type == 'fix_available':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE fix_status = 'Уязвимость устранена'")
    elif filter_type == 'no_fix':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE fix_status = 'Информация об устранении отсутствует'")
    elif filter_type == 'code':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE vul_class = 'Уязвимость кода'")
    elif filter_type == 'arch':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE vul_class = 'Уязвимость архитектуры'")
    elif filter_type == 'confirmed':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE vul_status = 'Подтверждена производителем'")
    elif filter_type == 'year2026':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE published_date LIKE '2026%'")
    elif filter_type == 'year2025':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE published_date LIKE '2025%'")
    elif filter_type == 'recent':
        cursor.execute("SELECT COUNT(*) FROM cve WHERE julianday('now') - julianday(published_date_iso) <= 7")
    else:
        cursor.execute("SELECT COUNT(*) FROM cve")
    
    count = cursor.fetchone()[0]
    con.close()
    return count

def get_cve_page_by_filter(filter_type, limit, offset):
    con = get_db()
    cursor = con.cursor()
    
    if filter_type == 'critical':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE CAST(cvss_v3_score AS REAL) >= 9.0
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'exploit_exists':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE exploit_status = 'Существует в открытом доступе'
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'fix_available':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE fix_status = 'Уязвимость устранена'
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'no_fix':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE fix_status = 'Информация об устранении отсутствует'
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'code':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE vul_class = 'Уязвимость кода'
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'arch':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE vul_class = 'Уязвимость архитектуры'
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'confirmed':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE vul_status = 'Подтверждена производителем'
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'year2026':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE published_date LIKE '2026%'
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'year2025':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE published_date LIKE '2025%'
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    elif filter_type == 'recent':
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            WHERE julianday('now') - julianday(published_date_iso) <= 7
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    else:
        cursor.execute("""
            SELECT identifier, name, published_date, severity 
            FROM cve 
            ORDER BY published_date_iso DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
    
    results = cursor.fetchall()
    con.close()
    return results

#Получаем данные с таблицы norm

def get_all_norms():
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("SELECT groups, laws, title, description, link FROM norm")
    norms = cursor.fetchall()
    con.close()
    return norms
#Считает, сколько всего записей в таблице norm
def get_norms_count():
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("SELECT COUNT(*) FROM norm")
    count = cursor.fetchone()[0]
    con.close()
    return count
# Возвращает одну страницу записей из таблицы norm
def get_norms_page(limit, offset):
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("""
        SELECT rowid, groups, laws, title, description, link 
        FROM norm 
        LIMIT ? OFFSET ?
    """, (limit, offset))
    norms = cursor.fetchall()
    con.close()
    return norms
# узнаёшь, сколько всего законов в группе ПДн.
def get_norms_count_by_group(group):
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("SELECT COUNT(*) FROM norm WHERE groups = ?", (group.upper(),))
    count = cursor.fetchone()[0]
    con.close()
    return count
# получаешь законы только из этой группы.
def get_norms_page_by_group(group, limit, offset):
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("""
        SELECT rowid, groups, laws, title, description, link 
        FROM norm 
        WHERE groups = ?
        LIMIT ? OFFSET ?
    """, (group, limit, offset))
    norms = cursor.fetchall()
    con.close()
    return norms
# получаеv id для сортировки страниц
def get_law_by_id(law_id):
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("SELECT rowid, groups, laws, title, description, link FROM norm WHERE rowid = ?", (law_id,))
    law = cursor.fetchone()
    con.close()
    return law
#Поиск по законам
def search_norms_count(query):
    con = get_norm_db()
    cursor = con.cursor()
    
    # Получаем нормализованные слова
    words = normalize_query(query)
    if not words:
        return 0
    
    # Строим условие LIKE для каждого слова
    conditions = []
    params = []
    for word in words:
        conditions.append("search_text LIKE ?")
        params.append(f'%{word}%')
    
    sql = f"SELECT COUNT(*) FROM norm WHERE {' OR '.join(conditions)}"
    cursor.execute(sql, params)
    count = cursor.fetchone()[0]
    con.close()
    return count

def search_norms_page(query, limit, offset):
    con = get_norm_db()
    cursor = con.cursor()
    
    words = normalize_query(query)
    if not words:
        return []
    
    conditions = []
    params = []
    for word in words:
        conditions.append("search_text LIKE ?")
        params.append(f'%{word}%')
    
    # Добавляем LIMIT и OFFSET в конец параметров
    params.extend([limit, offset])
    
    sql = f"""
        SELECT rowid, groups, laws, title, description, link 
        FROM norm 
        WHERE {' OR '.join(conditions)}
        LIMIT ? OFFSET ?
    """
    cursor.execute(sql, params)
    norms = cursor.fetchall()
    con.close()
    return norms


#функции для страницы news 

def get_all_news():
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("""
        SELECT id, title, content, link, source, published_date 
        FROM news 
        ORDER BY published_date_iso DESC
    """)
    news = cursor.fetchall()
    con.close()
    return news

#Считает, сколько всего записей в таблице norm
def get_news_count():
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("SELECT COUNT(*) FROM news")
    count = cursor.fetchone()[0]
    con.close()
    return count
# Возвращает одну страницу записей из таблицы norm
def get_news_page(limit, offset):
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("""
        SELECT id, title, content, link, source, published_date  
        FROM news
        ORDER BY published_date_iso DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    news = cursor.fetchall()
    con.close()
    return news

def get_news_count_by_source(source):
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("SELECT COUNT(*) FROM news WHERE source = ?", (source,))
    count = cursor.fetchone()[0]
    con.close()
    return count

def get_news_page_by_source(source, limit, offset):
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("""
        SELECT id, title, content, link, source, published_date  
        FROM news
        WHERE source = ?
        ORDER BY published_date_iso DESC
        LIMIT ? OFFSET ?
    """, (source, limit, offset))
    news = cursor.fetchall()
    con.close()
    return news

def get_news_by_id(news_id):
    con = get_norm_db()
    cursor = con.cursor()
    cursor.execute("SELECT id, title, content, link, source, published_date FROM news WHERE id = ?", (news_id,))
    news = cursor.fetchone()
    con.close()
    return news

def search_news_count(query):
    con = get_norm_db()
    cursor = con.cursor()
    
    words = normalize_query(query)
    if not words:
        return 0
    
    conditions = []
    params = []
    for word in words:
        conditions.append("search_text LIKE ?")
        params.append(f'%{word}%')
    
    sql = f"SELECT COUNT(*) FROM news WHERE {' OR '.join(conditions)}"
    cursor.execute(sql, params)
    count = cursor.fetchone()[0]
    con.close()
    return count

def search_news_page(query, limit, offset):
    con = get_norm_db()
    cursor = con.cursor()
    
    words = normalize_query(query)
    if not words:
        return []
    
    conditions = []
    params = []
    for word in words:
        conditions.append("search_text LIKE ?")
        params.append(f'%{word}%')
    
    params.extend([limit, offset])
    
    sql = f"""
        SELECT id, title, content, link, source, published_date 
        FROM news 
        WHERE {' OR '.join(conditions)}
        ORDER BY published_date_iso DESC
        LIMIT ? OFFSET ?
    """
    cursor.execute(sql, params)
    news = cursor.fetchall()
    con.close()
    return news