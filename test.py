import sqlite3

con = sqlite3.connect("site.db")
cursor = con.cursor()

# Обновляем url для каждого инструмента по id
updates = [
    (1, '/tools/password-generator'),
    (2, '/tools/hash'),
    (3, '/tools/base64'),
    (4, '/tools/url-encode'),
    (5, '/tools/jwt'),
    (6, '/tools/whois'),
    (7, '/tools/ip-geo'),
    (8, '/tools/ssl-check'),
    (9, '/tools/http-headers'),
    (10, '/tools/port-check'),
    (11, '/tools/reverse-dns'),
    (12, '/tools/dns-lookup'),
    (13, '/tools/email-breach'),
    (14, '/tools/virus-url'),
    (15, '/tools/virus-file'),
    (16, '/tools/domain-search'),
    (17, '/tools/trust-score'),
    (18, '/tools/metadata'),
    (19, '/tools/log-analyzer'),
    (20, '/tools/pcap-analyzer'),
    (21, '/tools/code-stats'),
    (22, '/tools/evtx-analyzer')
]

for tool_id, url in updates:
    cursor.execute("UPDATE tools SET url = ? WHERE id = ?", (url, tool_id))

con.commit()
con.close()

print("URL добавлены")