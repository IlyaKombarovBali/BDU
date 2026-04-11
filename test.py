import sqlite3

con = sqlite3.connect("site.db")
cursor = con.cursor()
cursor.execute("UPDATE tools SET name = 'Кодировать и декодировать URL' WHERE id = 4")
con.commit()
con.close()
print("Название исправлено")