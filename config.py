import sqlite3

def get_db():
    con = sqlite3.connect("bdu.db")
    con.row_factory = sqlite3.Row
    return con

def get_recent_vulns(limit=10):
    con = get_db()
    cursor = con.cursor()
    cursor.execute("SELECT cve_id, name FROM cve LIMIT ?", (limit,))
    vulns = cursor.fetchall()
    con.close()
    return vulns




#cursor.execute('''
#    CREATE TABLE IF NOT EXISTS cve (
#        ID INTEGER PRIMARY KEY,
#        vul_id TEXT,
#        cve_id TEXT,
#        name TEXT,
#        description TEXT,
#        severity TEXT,
#        cvss_v3_score REAL,
#        solution TEXT,
#        vul_status TEXT,
#        exploit_status TEXT,
#        fix_status TEXT,
#        vul_elimination TEXT,
#        vul_class TEXT,
#        sources TEXT,
#        identifiers TEXT,
#        published_date TEXT
#        
#    )
#''')