-- Канонические имена как в config.get_tool_by_name (name_map) и в актуальной site.db.
-- Применять к копии прода, например: sqlite3 oldbd/site.db < scripts/rename_tools_prod_to_canonical.sql

UPDATE tools SET
  name = 'Мой IP Поиск Геолокации по IP-адресу',
  search_text = lower(trim('Мой IP Поиск Геолокации по IP-адресу' || ' ' || ifnull(description, '') || ' ' || ifnull(category, '')))
WHERE name = 'Геолокация IP';

UPDATE tools SET
  name = 'Проверка ссылки на вирусы (URL)',
  search_text = lower(trim('Проверка ссылки на вирусы (URL)' || ' ' || ifnull(description, '') || ' ' || ifnull(category, '')))
WHERE name = 'Проверка на вирусы (URL)';

UPDATE tools SET
  name = 'Проверка файла на вирусы (.docx, .exe, .pdf, .txt, .zip и др.)',
  search_text = lower(trim('Проверка файла на вирусы (.docx, .exe, .pdf, .txt, .zip и др.)' || ' ' || ifnull(description, '') || ' ' || ifnull(category, '')))
WHERE name = 'Проверка на вирусы (файл)';

UPDATE tools SET
  name = 'Поиск доменов организации по ИНН или названию',
  search_text = lower(trim('Поиск доменов организации по ИНН или названию' || ' ' || ifnull(description, '') || ' ' || ifnull(category, '')))
WHERE name = 'Поиск доменов организации';
