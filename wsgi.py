import config
from flask import Flask, render_template
from flask import request
from flask import Flask, render_template, request, redirect
from urllib.parse import urlencode


app = Flask(__name__)

@app.route('/')
def index():
    # Перенаправляем на full_cve или показываем index.html
    #return redirect('/full_cve')
    
    # Или если хотите использовать существующий index.html:
    return render_template('index.html')

@app.route('/cve/<identifier>')
def cve_detail(identifier):
    # Получаем параметры для возврата
    back_page = request.args.get('page', 1, type=int)
    back_limit = request.args.get('limit', 20, type=int)
    back_query = request.args.get('q', '')
    
    if back_query:
        back_url = f"/search?q={back_query}&page={back_page}&limit={back_limit}"
    else:
        back_url = f"/full_cve?page={back_page}&limit={back_limit}"
    
    vuln = config.get_vuln_by_identifier(identifier)
    if vuln is None:
        return "Уязвимость не найдена", 404
    return render_template('cve.html', vuln=vuln, back_url=back_url, back_query=back_query, back_page=back_page, back_limit=back_limit)


@app.route('/full_cve')
def full_cve():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    filter_type = request.args.get('filter', 'all')
    
    offset = (page - 1) * limit
    
    total = config.get_cve_count_by_filter(filter_type)
    vulns = config.get_cve_page_by_filter(filter_type, limit, offset)
    
    total_pages = (total + limit - 1) // limit
    
    return render_template(
        'full_cve.html', 
        vulns=vulns, 
        page=page, 
        total_pages=total_pages, 
        limit=limit,
        filter=filter_type
    )

@app.route('/laws')
def laws():
    # Сначала получаем параметры из запроса
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    filter_type = request.args.get('filter', 'all')
    
    # Потом вычисляем offset
    offset = (page - 1) * limit
    
    # Потом используем их в запросах
    if filter_type != 'all':
        total = config.get_norms_count_by_group(filter_type)
        norms = config.get_norms_page_by_group(filter_type, limit, offset)
    else:
        total = config.get_norms_count()
        norms = config.get_norms_page(limit, offset)
    
    total_pages = (total + limit - 1) // limit
    
    return render_template(
        'laws.html', 
        norms=norms, 
        page=page, 
        total_pages=total_pages,
        limit=limit,
        filter=filter_type
    )

@app.route('/law/<int:law_id>')
def law_detail(law_id):
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    query = request.args.get('q', '')
    
    law = config.get_law_by_id(law_id)
    if law is None:
        return "Закон не найден", 404
    
    back_url = f"/laws?page={page}&limit={limit}"
    if query:
        back_url = f"/search_laws?q={query}&page={page}&limit={limit}"
    
    return render_template(
        'law_detail.html', 
        law=law, 
        back_url=back_url,
        back_page=page,
        back_limit=limit,
        back_query=query
    )



@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    
    if not query:
        return redirect('/full_cve')
    
    offset = (page - 1) * limit
    total = config.search_vulns_count(query)
    results = config.search_vulns_by_identifier(query, limit, offset)
    
    total_pages = (total + limit - 1) // limit
    
    return render_template(
        'search.html', 
        results=results, 
        query=query,
        page=page,
        total_pages=total_pages,
        limit=limit
    )


@app.route('/search_laws')
def search_laws():
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    offset = (page - 1) * limit
    
    if not query:
        return redirect('/laws')
    
    total = config.search_norms_count(query)
    norms = config.search_norms_page(query, limit, offset)
    total_pages = (total + limit - 1) // limit
    
    return render_template(
        'search_laws.html',
        norms=norms,
        query=query,
        page=page,
        total_pages=total_pages,
        limit=limit
    )



@app.route('/news')
def news():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    filter_source = request.args.get('source') or request.args.get('filter', 'all')
    
    offset = (page - 1) * limit
    
    if filter_source != 'all':
        total = config.get_news_count_by_source(filter_source)
        news = config.get_news_page_by_source(filter_source, limit, offset)
    else:
        total = config.get_news_count()
        news = config.get_news_page(limit, offset)
    
    total_pages = (total + limit - 1) // limit
    
    return render_template(
        'news.html', 
        news=news, 
        page=page, 
        total_pages=total_pages,
        limit=limit,
        filter_source=filter_source
    )

@app.route('/news/<int:news_id>')
def news_detail(news_id):
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    query = request.args.get('q', '')
    
    news = config.get_news_by_id(news_id)
    if news is None:
        return "Новость не найдена", 404
    
    back_url = f"/news?page={page}&limit={limit}"
    if query:
        back_url = f"/search_news?q={query}&page={page}&limit={limit}"
    
    return render_template('news_detail.html', news=news, back_url=back_url, back_page=page, back_limit=limit, back_query=query)

@app.route('/search_news')
def search_news():
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    offset = (page - 1) * limit
    
    if not query:
        return redirect('/news')
    
    total = config.search_news_count(query)
    news = config.search_news_page(query, limit, offset)
    total_pages = (total + limit - 1) // limit
    
    return render_template(
        'search_news.html',
        news=news,
        query=query,
        page=page,
        total_pages=total_pages,
        limit=limit
    )


@app.route('/donate')
def donate():
    return render_template('donate.html')
#

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    return render_template('feedback.html')


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)