import config
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/full_cve')
def full_cve():
    vuln = config.get_recent_vulns(10)
    return render_template('full_cve.html', vuln=vuln)

if __name__ == '__main__':
    app.run(debug=True)