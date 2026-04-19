import os
from pathlib import Path

from dotenv import load_dotenv

# Локальные секреты (Windows / dev): файл .env рядом с wsgi.py, не коммитится
load_dotenv(Path(__file__).resolve().parent / ".env")

import auth as auth_portal
import bookmark_meta
import config
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
)
from flask_wtf.csrf import CSRFProtect
from urllib.parse import quote, urlencode
from tools_logic import (
    get_whois,
    get_dns_records,
    get_ssl_info,
    get_ip_info,
    analyze_http_headers,
    get_reverse_dns,
    get_dns_lookup,
    scan_virustotal_url,
    scan_virustotal_file,
    search_org_domains,
    dadata_party_suggest,
    analyze_site_trust,
    analyze_file_metadata,
    TWOIP_CLIENT_GEO_URL,
)


app = Flask(__name__)
app.config["SECRET_KEY"] = (
    os.environ.get("FLASK_SECRET_KEY")
    or os.environ.get("SECRET_KEY")
    or "dev-only-set-FLASK_SECRET_KEY-for-production"
)
csrf = CSRFProtect(app)

auth_portal.init_auth_db()

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        app.static_folder,
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.context_processor
def inject_portal_profile():
    uid = session.get("user_id")
    user = auth_portal.get_user_by_id(uid) if uid else None
    fp = auth_portal.normalize_full_path(request.full_path or "/")
    bookmarkable = auth_portal.is_bookmarkable_path(fp)
    bookmarked = (
        bool(user and auth_portal.is_bookmarked(user["id"], fp)) if user else False
    )
    default_title = (
        auth_portal.default_title_for_path(fp) if bookmarkable else ""
    )
    show_star = bookmarkable and not (
        request.path.rstrip("/") == "/profile"
        or request.path.startswith("/static")
    )
    login_next = quote(fp, safe="/?:&=%+~#") if bookmarkable else ""
    return dict(
        portal_user=user,
        bookmark_target_path=fp,
        bookmark_target_title=default_title,
        show_bookmark_star=show_star,
        bookmark_already=bookmarked,
        bookmark_login_next=login_next,
    )


def _query_url(path: str, q: str, page: int, limit: int) -> str:
    return f"{path}?{urlencode({'q': q, 'page': page, 'limit': limit})}"


@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )
    return response


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
        back_url = _query_url("/search", back_query, back_page, back_limit)
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
        back_url = _query_url("/search_laws", query, page, limit)
    
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
        back_url = _query_url("/search_news", query, page, limit)
    
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


OWASP_DIR = Path(__file__).resolve().parent / "owasp"


def _owasp_cheatsheets_list():
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 20, type=int)
    filter_raw = request.args.get("filter") or request.args.get("source", "all")
    category = config.cheatsheet_category_by_filter(filter_raw)
    filter_param = None
    if category is not None:
        filter_param = str(config.CHEATSHEET_CATEGORY_ORDER.index(category))
    offset = (page - 1) * limit
    total = config.get_cheatsheets_count(category)
    cheatsheets = config.get_cheatsheets_page(limit, offset, category)
    total_pages = (total + limit - 1) // limit if total else 1
    if total_pages < 1:
        total_pages = 1
    return render_template(
        "owasp.html",
        cheatsheets=cheatsheets,
        page=page,
        total_pages=total_pages,
        limit=limit,
        filter_param=filter_param,
        cheat_categories=config.CHEATSHEET_CATEGORY_ORDER,
        category_icons=config.CHEATSHEET_CATEGORY_ICONS,
    )


@app.route("/owasp")
@app.route("/owasp/")
def owasp_cheatsheets():
    return _owasp_cheatsheets_list()


@app.route("/owasp/owasp.html")
def owasp_cheatsheets_html_alias():
    return _owasp_cheatsheets_list()


@app.route("/owasp/Abuse_Case_Cheat_Sheet.html")
@app.route("/owasp/abuse_case_cheat_sheet.html")
def owasp_abuse_case_cheat_sheet_alias():
    return redirect("/owasp/cheatsheets/Abuse_Case_Cheat_Sheet.html", code=302)


@app.route("/search_cheatsheets")
def search_cheatsheets():
    query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 20, type=int)
    offset = (page - 1) * limit
    if not query:
        return redirect("/owasp")
    total = config.search_cheatsheets_count(query)
    cheatsheets = config.search_cheatsheets_page(query, limit, offset)
    total_pages = (total + limit - 1) // limit if total else 1
    if total_pages < 1:
        total_pages = 1
    return render_template(
        "search_cheatsheets.html",
        cheatsheets=cheatsheets,
        query=query,
        page=page,
        total_pages=total_pages,
        limit=limit,
        total_count=total,
        category_icons=config.CHEATSHEET_CATEGORY_ICONS,
    )


@app.route("/owasp/assets/<path:fname>")
def owasp_assets_file(fname):
    return send_from_directory(OWASP_DIR / "assets", fname)


@app.route("/owasp/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html")
def owasp_xss_filter_evasion_cheat_sheet():
    return render_template("owasp_xss_filter_evasion.html")


@app.route("/owasp/cheatsheets/Abuse_Case_Cheat_Sheet.html")
def owasp_abuse_case_cheat_sheet():
    return render_template("owasp_abuse_case_cheat_sheet.html")


@app.route("/owasp/cheatsheets/<path:fname>")
def owasp_cheatsheet_file(fname):
    return send_from_directory(OWASP_DIR / "cheatsheets", fname)


@app.route('/tools', methods=['GET', 'POST'])
def tools():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    category = request.args.get('filter', 'all')
    search_query = request.args.get('q', '').strip()
    
    offset = (page - 1) * limit
    
    total = config.get_tools_count_by_filter(category, search_query)
    tools = config.get_tools_page_by_filter(category, search_query, limit, offset)
    tools = config.tools_rows_with_display_titles(tools)
    total_pages = (total + limit - 1) // limit
    
    return render_template(
        'tools.html',
        tools=tools,
        page=page,
        total_pages=total_pages,
        limit=limit,
        filter=category
    )


@app.route("/api/dadata/party-suggest", methods=["POST"])
def api_dadata_party_suggest():
    """Подсказки организаций (DaData); ключ только на сервере."""
    payload = request.get_json(silent=True) or {}
    q = (payload.get("q") or "").strip()
    return jsonify(dadata_party_suggest(q))


@app.route('/tools/<tool_name>', methods=['GET', 'POST'])
def tool_generic(tool_name):
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    filter_cat = request.args.get('filter', 'all')
    search_query = request.args.get('q', '')

    qs = {"page": page, "limit": limit}
    if filter_cat != "all":
        qs["filter"] = filter_cat
    if search_query:
        qs["q"] = search_query
    back_url = "/tools?" + urlencode(qs)

    tool = config.get_tool_by_name(tool_name)
    if not tool:
        return "Инструмент не найден", 404

    result = None
    ip_info = None
    ssl_info = None
    http_headers_result = None
    reverse_dns_result = None
    dns_lookup_result = None
    virus_url_result = None
    virus_file_result = None
    org_domain_result = None
    trust_score_result = None
    metadata_result = None

    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        ip = request.form.get('ip', '').strip()
        ssl_host = request.form.get('ssl_host', '').strip()
        http_url = request.form.get('http_url', '').strip()
        vt_url = request.form.get('vt_url', '').strip()
        org_query = request.form.get('org_query', '').strip()
        trust_url = request.form.get('trust_url', '').strip()
        if tool_name == "whois" and domain:
            result = get_whois(domain)
        elif tool_name == "dns-lookup" and domain:
            dns_lookup_result = get_dns_lookup(domain)
        elif tool_name == "ip-geo" and ip:
            ip_info = get_ip_info(ip)
        elif tool_name == "reverse-dns" and ip:
            reverse_dns_result = get_reverse_dns(ip)
        elif tool_name == "ssl-check" and ssl_host:
            ssl_info = get_ssl_info(ssl_host)
        elif tool_name == "http-headers" and http_url:
            http_headers_result = analyze_http_headers(http_url)
        elif tool_name == "virus-url" and vt_url:
            virus_url_result = scan_virustotal_url(vt_url)
        elif tool_name == "virus-file":
            vf = request.files.get("vt_file")
            if vf and vf.filename:
                virus_file_result = scan_virustotal_file(vf)
            else:
                virus_file_result = {"error": "Выберите файл для загрузки."}
        elif tool_name == "domain-search" and org_query:
            org_domain_result = search_org_domains(org_query)
        elif tool_name == "trust-score" and trust_url:
            trust_score_result = analyze_site_trust(trust_url)
        elif tool_name == "metadata":
            mf = request.files.get("metadata_file")
            if mf and mf.filename:
                metadata_result = analyze_file_metadata(mf)
            else:
                metadata_result = {"error": "Выберите файл для анализа."}

    return render_template(
        'tool_generic.html',
        result=result,
        tool=tool,
        tool_slug=tool_name,
        back_url=back_url,
        ip_info=ip_info,
        ssl_info=ssl_info,
        http_headers_result=http_headers_result,
        reverse_dns_result=reverse_dns_result,
        dns_lookup_result=dns_lookup_result,
        virus_url_result=virus_url_result,
        virus_file_result=virus_file_result,
        org_domain_result=org_domain_result,
        trust_score_result=trust_score_result,
        metadata_result=metadata_result,
        twoip_client_geo_url=TWOIP_CLIENT_GEO_URL if tool_name == "ip-geo" else None,
        page=page,
        limit=limit,
        filter_cat=filter_cat,
        search_query=search_query
    )




@app.route('/donate')
def donate():
    return render_template('donate.html')
#

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    return render_template('feedback.html')


@app.route("/legal")
def legal():
    return render_template("legal.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect("/profile")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        email = request.form.get("email", "").strip()
        err = auth_portal.validate_registration(username, password, password2, email)
        if err:
            flash(err, "error")
            return render_template("register.html", username=username, email=email)
        ok, uid, msg = auth_portal.create_user(username, password, email or None)
        if not ok:
            flash(msg or "Ошибка регистрации", "error")
            return render_template("register.html", username=username, email=email)
        session["user_id"] = uid
        flash("Добро пожаловать! Добавляйте страницы в «Изучение» через ★ в шапке.", "ok")
        return redirect("/profile")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect("/profile")
    next_raw = request.args.get("next") or ""
    if request.method == "POST":
        next_raw = request.form.get("next") or next_raw
        user = auth_portal.authenticate(
            request.form.get("username", "").strip(),
            request.form.get("password", ""),
        )
        if user:
            session["user_id"] = user["id"]
            dest = auth_portal.safe_relative_url(next_raw) or "/profile"
            return redirect(dest)
        flash("Неверный логин или пароль.", "error")
    safe_next = auth_portal.safe_relative_url(next_raw) or ""
    return render_template("login.html", next_url=safe_next)


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    flash("Вы вышли из аккаунта.", "ok")
    return redirect("/")


@app.route("/profile")
def profile():
    uid = session.get("user_id")
    if not uid:
        return redirect("/login?next=/profile")
    user = auth_portal.get_user_by_id(uid)
    if not user:
        session.pop("user_id", None)
        return redirect("/login")
    raw_bm = auth_portal.list_bookmarks(uid)
    bookmarks = bookmark_meta.enrich_bookmarks(raw_bm)
    smtp_ok = auth_portal.smtp_configured()

    limit = request.args.get("limit", 20, type=int)
    if limit not in (10, 20, 50, 100):
        limit = 20
    page = request.args.get("page", 1, type=int)
    total = len(bookmarks)
    total_pages = max(1, (total + limit - 1) // limit) if total else 1
    page = max(1, min(page, total_pages))
    offset = (page - 1) * limit
    bookmarks_page = bookmarks[offset : offset + limit]

    return render_template(
        "profile.html",
        bookmarks=bookmarks_page,
        bookmark_total=total,
        page=page,
        total_pages=total_pages,
        limit=limit,
        portal_user=user,
        smtp_configured=smtp_ok,
    )


@app.route("/profile/bookmarks/add", methods=["POST"])
def profile_bookmark_add():
    uid = session.get("user_id")
    path = request.form.get("path", "").strip()
    path_norm = auth_portal.normalize_full_path(path)
    if not uid:
        flash("Войдите, чтобы сохранять страницы.", "error")
        return redirect("/login?next=" + quote(path_norm, safe="/?:&=%+~#"))
    title = (request.form.get("title") or "").strip()
    if not auth_portal.is_bookmarkable_path(path_norm):
        flash("Эту страницу нельзя добавить в подборку.", "error")
        return redirect("/profile")
    ok, err = auth_portal.add_bookmark(uid, path_norm, title)
    if ok:
        flash("Страница добавлена в «К изучению».", "ok")
    else:
        flash(err or "Не удалось добавить.", "error")
    return redirect(path_norm)


@app.route("/profile/email", methods=["POST"])
def profile_update_email():
    uid = session.get("user_id")
    if not uid:
        return redirect("/login")
    email = request.form.get("email", "").strip()
    if email:
        err = auth_portal.validate_email_optional(email)
        if err:
            flash(err, "error")
            return redirect("/profile")
    ok, msg = auth_portal.update_user_email(uid, email)
    if ok:
        flash("Адрес почты обновлён.", "ok")
    else:
        flash(msg or "Не удалось сохранить email.", "error")
    return redirect("/profile")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if session.get("user_id"):
        return redirect("/profile")
    if request.method == "POST":
        if not auth_portal.smtp_configured():
            flash(
                "На сервере не настроена отправка писем. Напишите нам через «Обратная связь» "
                "или в Telegram-бота — поможем восстановить доступ.",
                "error",
            )
            return render_template("forgot_password.html")
        email = request.form.get("email", "").strip()
        if not email:
            flash("Введите email, указанный при регистрации.", "error")
            return render_template("forgot_password.html")
        user = auth_portal.get_user_by_email_normalized(email)
        if user and user.get("email"):
            if not auth_portal.create_password_reset_and_send(email):
                flash(
                    "Не удалось отправить письмо. Попробуйте позже или обратитесь в поддержку.",
                    "error",
                )
                return render_template("forgot_password.html")
        flash(
            "Если такой email зарегистрирован, на него отправлена ссылка для сброса пароля "
            f"(действует {auth_portal.RESET_TOKEN_HOURS} ч.). Проверьте папку «Спам».",
            "ok",
        )
        return redirect("/login")
    return render_template(
        "forgot_password.html",
        smtp_configured=auth_portal.smtp_configured(),
    )


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if session.get("user_id"):
        return redirect("/profile")
    token = (request.args.get("token") if request.method == "GET" else request.form.get("token")) or ""
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        p1 = request.form.get("password", "")
        p2 = request.form.get("password2", "")
        if p1 != p2:
            flash("Пароли не совпадают.", "error")
            return render_template("reset_password.html", token=token)
        ok, err = auth_portal.apply_password_reset(token, p1)
        if ok:
            flash("Пароль обновлён. Войдите с новым паролем.", "ok")
            return redirect("/login")
        flash(err or "Ссылка недействительна.", "error")
        return render_template("reset_password.html", token=token)
    if not token or not auth_portal.verify_reset_token(token):
        flash("Ссылка недействительна или устарела. Запросите новую на странице «Забыли пароль».", "error")
        return redirect("/forgot-password")
    return render_template("reset_password.html", token=token)


@app.route("/profile/bookmarks/remove", methods=["POST"])
def profile_bookmark_remove():
    uid = session.get("user_id")
    if not uid:
        return redirect("/login")
    bid = request.form.get("bookmark_id", type=int)
    if bid:
        auth_portal.remove_bookmark(uid, bid)
        flash("Удалено из подборки.", "ok")
    return redirect("/profile")


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)