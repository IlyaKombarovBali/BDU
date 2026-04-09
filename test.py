import sqlite3

con = sqlite3.connect("site.db")
cursor = con.cursor()

# Выбираем все записи
cursor.execute("SELECT rowid, title, laws, description, groups FROM norm")
rows = cursor.fetchall()

for row in rows:
    rowid, title, laws, description, groups = row
    # Приводим к нижнему регистру через Python (работает с кириллицей)
    search_text = ' '.join(filter(None, [
        title.lower() if title else '',
        laws.lower() if laws else '',
        description.lower() if description else '',
        groups.lower() if groups else ''
    ]))
    cursor.execute("UPDATE norm SET search_text = ? WHERE rowid = ?", (search_text, rowid))

con.commit()
con.close()
print("search_text обновлён")