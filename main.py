import sqlite3
import zipfile
import xml.etree.ElementTree as ET

# Чтение из файла
tree = ET.parse('/home/kali/Desktop/BDU/export/vulxml.xml')
root = tree.getroot()



for vul in root.findall('.//vul'):
    # CVE и тип из identifier
    identifier = vul.find('.//identifier')
    if identifier is not None:
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
    
    # CVSS из severity
    cvss_v3_score = None
    if severity != "Нет оценки":
        import re
        match = re.search(r'CVSS 3\.1 составляет ([0-9.]+)', severity)
        if match:
            cvss_v3_score = float(match.group(1))

    




