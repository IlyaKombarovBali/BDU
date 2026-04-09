import feedparser
from lxml import html
import sqlite3
from datetime import datetime

url = {'xaker':'https://xakep.ru/category/news/feed/',
       'habr':'https://habr.com/ru/rss/hub/infosecurity/',
       'securitylab':'https://www.securitylab.ru/_services/export/rss/news.php',
       'rb':'https://rb.ru/feeds/tag/cybersecurity/',
       'anti':'https://www.anti-malware.ru/rss.xml'
      }

def get_norm_db():
    con = sqlite3.connect("site.db")
    con.row_factory = sqlite3.Row
    return con

for source, link in url.items():
    feed = feedparser.parse(link)
    for entry in feed.entries:  # убери [:1] когда нужно все новости
        title = entry.title
        if entry.description:
            content = html.fromstring(entry.description).text_content()
        else:
            content = ''
        news_link = entry.link
        
        # Оригинальная дата
        published_date = entry.get('published', '')
        
        # ISO для сортировки
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            published_date_iso = datetime(*entry.published_parsed[:6]).isoformat()
        else:
            published_date_iso = None
        
        con = get_norm_db()
        cursor = con.cursor()
        
        cursor.execute("SELECT 1 FROM news WHERE link = ?", (news_link,))
        exists = cursor.fetchone()
        
        if not exists:
            cursor.execute("""
                INSERT INTO news (title, content, link, source, published_date, published_date_iso) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (title, content, news_link, source, published_date, published_date_iso))
            con.commit()
        
        con.close()

