import sqlite3
import zipfile
import xml.etree.ElementTree as ET

# Чтение из файла
tree = ET.parse('export/vulxml.xml')
root = tree.getroot()


# Чтение из файла
tree = ET.parse('export/vulxml.xml')
root = tree.getroot()

# Поиск всех уязвимостей
for vul in root.findall('.//vul'):
    # Ищем cve_id внутри identifiers/identifier
    identifiers_element = vul.find('identifiers')
    if identifiers_element is not None:
        identifier_element = identifiers_element.find('identifier')
        if identifier_element is not None:
            cve_id = identifier_element.text if identifier_element.text else "Нет CVE"
            ident_type = identifier_element.get('type')
        else:
            cve_id = "Нет CVE"
            ident_type = "Нет типа"
    else:
        cve_id = "Нет CVE"
        ident_type = "Нет идентификаторов"
    
    print(f"CVE ID: {cve_id}, Тип идентификатора: {ident_type}")



