import pandas as pd
import sqlite3

# Читаем Excel, первая строка — заголовки
df = pd.read_excel('norm_1.xlsx', header=0)

# Создаём базу и таблицу
con = sqlite3.connect('site.db')
df.to_sql('norm', con, if_exists='replace', index=False)
con.close()