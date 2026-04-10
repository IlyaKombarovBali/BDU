import sqlite3

# Подключаемся к БД
con = sqlite3.connect("site.db")
cursor = con.cursor()

# Удаляем старую таблицу
cursor.execute("DROP TABLE IF EXISTS tools")

# Создаём таблицу заново
cursor.execute("""
CREATE TABLE tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    search_text TEXT
)
""")

# Данные для вставки (категория, название, описание)
tools = [
    # Криптография
    ('crypto', 'Генератор паролей', 'Создайте надёжные пароли любой сложности. Настройте длину и типы символов.'),
    ('crypto', 'Хэширование текста', 'Вычислите MD5, SHA-1, SHA-256 и SHA-512 хеш любой строки.'),
    ('crypto', 'Кодирование Base64', 'Преобразуйте текст в Base64 и обратно.'),
    ('crypto', 'Декодирование URL', 'Кодируйте и декодируйте URL-строки для передачи в веб-запросах.'),
    ('crypto', 'Анализ JWT токенов', 'Декодируйте JWT (JSON Web Token) и просмотрите его заголовок и полезную нагрузку.'),
    
    # Сетевые
    ('network', 'WHOIS', 'Получите информацию о домене: регистратор, даты регистрации, NS-серверы.'),
    ('network', 'Геолокация IP', 'Определите страну, город и провайдера по IP-адресу.'),
    ('network', 'Проверка SSL-сертификата', 'Проверьте срок действия и детали SSL-сертификата любого сайта.'),
    ('network', 'Анализ заголовков HTTP', 'Получите все HTTP-заголовки ответа веб-сервера.'),
    ('network', 'Проверка открытых портов', 'Проверьте, открыт ли определённый порт на удалённом сервере.'),
    ('network', 'Reverse DNS', 'Узнайте доменное имя (PTR-запись) по IP-адресу.'),
    ('network', 'DNS lookup', 'Получите A, AAAA, MX, TXT, NS, CNAME записи домена.'),
    
    # Репутация
    ('reputation', 'Проверка email в утечках', 'Проверьте, не был ли ваш email скомпрометирован в известных утечках баз данных.'),
    ('reputation', 'Проверка на вирусы (URL)', 'Проверьте ссылку на вредоносное ПО через VirusTotal API.'),
    ('reputation', 'Проверка на вирусы (файл)', 'Загрузите файл до 10 МБ и проверьте его на вирусы через VirusTotal.'),
    ('reputation', 'Поиск доменов организации', 'Найдите все домены, связанные с компанией по ИНН или названию.'),
    ('reputation', 'Анализатор доверия к сайту', 'Получите сводную оценку сайта: возраст домена, SSL, рейтинг безопасности.'),
    
    # Анализ данных
    ('analyze', 'Анализ метаданных файлов', 'Загрузите PDF, DOCX, JPG или PNG и извлеките скрытые метаданные.'),
    ('analyze', 'Анализатор логов', 'Загрузите текстовый лог-файл для поиска IP-адресов, email и ошибок.'),
    ('analyze', 'Анализатор PCAP', 'Загрузите файл pcap для базового анализа сетевого трафика.'),
    ('analyze', 'Статистический анализ кода', 'Загрузите файл с кодом для подсчёта строк, комментариев и функций.'),
    ('analyze', 'Анализ событий Windows (.evtx)', 'Загрузите .evtx файл для просмотра и поиска событий Windows.')
]

# Вставляем данные
for category, name, description in tools:
    cursor.execute("INSERT INTO tools (name, description, category) VALUES (?, ?, ?)", (name, description, category))

# Заполняем search_text
cursor.execute("SELECT id, name, description FROM tools")
rows = cursor.fetchall()
for tool_id, name, description in rows:
    search_text = f"{name} {description}".lower()
    cursor.execute("UPDATE tools SET search_text = ? WHERE id = ?", (search_text, tool_id))

con.commit()
con.close()

print("Таблица tools создана и заполнена")