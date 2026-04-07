import sqlite3
import zipfile
import xml.etree.ElementTree as ET

def get_db():
    con = sqlite3.connect("bdu.db")
    return con, con.cursor()

# Чтение из файла
tree = ET.parse('/home/kali/Desktop/BDU/export/vulxml.xml')
root = tree.getroot()



for vul in root.findall('.//vul'):
    # CVE из identifier
    identifier = vul.find('.//identifier')
    if identifier is not None:
        # Пытаемся взять CVE из атрибута link (самый надёжный способ)
        link = identifier.get('link')
        if link and 'CVE-' in link:
            # Извлекаем CVE ID из конца URL (например, .../CVE-2026-27951)
            cve_id = link.split('/')[-1]
        else:
            # Если ссылки нет, берём текст из тега
            cve_id = identifier.text or "Нет CVE"
        ident_type = identifier.get('type') or "Нет типа"
    else:
        cve_id = "Нет CVE"
        ident_type = "Нет типа"
    
    # Остальные поля
    vul_id = vul.findtext('vul_id') or "Нет ID"
    name = vul.findtext('name') or "Нет названия"
    description = vul.findtext('description') or "Нет описания"
    severity = vul.findtext('severity') or "Нет оценки"
    solution = vul.findtext('solution') or "Нет решения"
    vul_status = vul.findtext('vul_status') or "Нет статуса"
    exploit_status = vul.findtext('exploit_status') or "Нет данных"
    fix_status = vul.findtext('fix_status') or "Нет данных"
    vul_elimination = vul.findtext('vul_elimination') or "Не указано"
    vul_class = vul.findtext('vul_class') or "Не указан"
    sources = vul.findtext('sources') or "Нет ссылок"
    published_date = vul.findtext('published_date') or "Нет даты"
    
    # CVSS из severity (просто ищем число)
    cvss_v3_score = None
    if severity != "Нет оценки":
        import re
        # Ищем число, после которого идет запятая или точка (как в CVSS)
        # Ищем паттерн: цифра, точка, цифра (например, 7.5)
        match = re.search(r'([0-9]+\.[0-9]+)', severity)
        if match:
            cvss_v3_score = float(match.group(1))
    #Записываем в БД

    con, cursor = get_db()
    cursor.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,))
    records = cursor.fetchall()
    if not records:
        cursor.execute("INSERT INTO cve (vul_id, cve_id, name, description, severity, cvss_v3_score, solution, vul_status, exploit_status, fix_status, vul_elimination, vul_class, sources, identifiers, published_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (vul_id, cve_id, name, description, severity, cvss_v3_score, solution, vul_status, exploit_status, fix_status, vul_elimination, vul_class, sources, ident_type, published_date))
        con.commit()
    
con.close()






