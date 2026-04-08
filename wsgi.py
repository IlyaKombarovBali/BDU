import config
from flask import Flask, render_template
from flask import request

app = Flask(__name__)



@app.route('/cve/<identifier>')
def cve_detail(identifier):
    vuln = config.get_vuln_by_identifier(identifier)
    if vuln is None:
        return "Уязвимость не найдена", 404
    return render_template('cve.html', vuln=vuln)


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


if __name__ == '__main__':
    app.run(debug=True)