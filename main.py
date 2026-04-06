import sqlite3
import zipfile
import xml.etree.ElementTree as ET

# Чтение из файла
tree = ET.parse('/home/kali/Desktop/BDU/export/vulxml.xml')
root = tree.getroot()



for vul in root.findall('.//vul'):
    identifier = vul.find('.//identifier')
    if identifier is not None:
        cve_id = identifier.text
        ident_type = identifier.get('type')
    else:
        cve_id = "Нет CVE"
        ident_type = "Нет типа"

for vul in root.findall('.//vul'):
    name = vul.findtext('name') or "Нет названия"
    description = vul.findtext('description') or "Нет описания"

    




