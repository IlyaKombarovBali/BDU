import config
from flask import Flask, render_template
from flask import request
from flask import Flask, render_template, request, redirect

app = Flask(__name__)



@app.route('/cve/<identifier>')
def cve_detail(identifier):
    back_url = request.args.get('back', '/full_cve')
    vuln = config.get_vuln_by_identifier(identifier)
    if vuln is None:
        return "Уязвимость не найдена", 404
    return render_template('cve.html', vuln=vuln, back_url=back_url)


@app.route('/full_cve')
def full_cve():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    
    offset = (page - 1) * limit
    
    total = config.get_vulns_count()
    vulns = config.get_vulns_page(limit, offset)
    
    total_pages = (total + limit - 1) // limit
    
    return render_template(
        'full_cve.html', 
        vulns=vulns, 
        page=page, 
        total_pages=total_pages,
        limit=limit
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

if __name__ == '__main__':
    app.run(debug=True)