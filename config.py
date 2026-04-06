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