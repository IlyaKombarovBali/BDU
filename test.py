import feedparser


url = 'https://xakep.ru/category/news/feed/'
    feed = feedparser.parse(url)
    # Выводим заголовки последних новостей
    message_news = f"*Последние новости на {datetime.date.today()}:*\n\n"
    for entry in feed.entries[:5]:
        title = entry.title
        link = entry.link
        message_news += f"📌 *{title}*\n[Читать полностью]({link})\n\n"