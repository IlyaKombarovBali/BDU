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
    
    print(f"CVE ID: {cve_id}, Тип: {ident_type}")

for vul in root.findall('.//vul'):
    name_element = vul.find('name')
    if name_element is not None:
        name = name_element.text
    else:
        name = "Нет названия"
    
    print(f"Имя уязвимости: {name}")



