import sqlite3
import zipfile
import xml.etree.ElementTree as ET

# Чтение из файла
tree = ET.parse('/home/kali/Desktop/BDU/export')
root = tree.getroot()



# Поиск всех уязвимостей
for vul in root.findall('.//vul'):
    # Получаем cve_id (с проверкой, что тег существует)
    cve_element = vul.find('cve_id')
    cve_id = cve_element.text if cve_element is not None else "Нет CVE"
    
    # Получаем тип идентификатора
    identifiers_element = vul.find('identifiers')
    if identifiers_element is not None:
        identifier_element = identifiers_element.find('identifier')
        if identifier_element is not None:
            ident_type = identifier_element.get('type')
        else:
            ident_type = "Нет типа"
    else:
        ident_type = "Нет идентификаторов"
    
    print(f"CVE ID: {cve_id}, Тип: {ident_type}")



