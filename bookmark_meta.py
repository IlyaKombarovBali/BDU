"""Заголовок и краткое описание для закладок по данным БД портала."""
import re
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

import config

DESC_MAX = 240

LIST_SECTION_TITLE = {
    "/laws": "Законы и НПА",
    "/news": "Новости ИБ",
    "/owasp": "Статьи OWASP",
    "/full_cve": "База уязвимостей БДУ",
    "/search": "Поиск CVE",
    "/search_laws": "Поиск по законам",
    "/search_news": "Поиск по новостям",
    "/search_cheatsheets": "Поиск по статьям OWASP",
}

NEWS_FILTER_LABELS = {
    "xaker": "Xakep",
    "habr": "Habr",
    "securitylab": "SecurityLab",
    "rb": "RB.ru",
    "anti": "Anti-Malware",
}

CVE_FILTER_LABELS = {
    "recent": "Свежие (7 дней)",
    "exploit_exists": "Есть эксплойт",
    "fix_available": "Устранена",
    "no_fix": "Нет исправления",
    "code": "Уязвимость кода",
    "arch": "Уязвимость архитектуры",
    "confirmed": "Подтверждена",
}

NO_FILTER_TITLE = {
    "/laws": "Все тематики",
    "/news": "Все источники",
    "/owasp": "Все категории",
    "/full_cve": "Все уязвимости",
}

OWASP_CHEATSHEET_PAGE_TITLES = {
    "/owasp/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html": "Обход XSS-фильтров (OWASP Cheat Sheet)",
    "/owasp/cheatsheets/Abuse_Case_Cheat_Sheet.html": "Abuse Case — сценарии злоупотреблений (OWASP Cheat Sheet)",
}


def owasp_cheatsheet_bookmark_title(path_only: str) -> str:
    po = (path_only or "").split("?", 1)[0]
    if po in OWASP_CHEATSHEET_PAGE_TITLES:
        return OWASP_CHEATSHEET_PAGE_TITLES[po]
    base = po.rsplit("/", 1)[-1] if "/" in po else po
    if base.endswith(".html"):
        base = base[:-5]
    return f"OWASP: {base.replace('_', ' ')}"


def _snip(text, max_len=DESC_MAX):
    if not text:
        return ""
    s = " ".join(str(text).split())
    if len(s) <= max_len:
        return s
    return s[: max_len - 1].rstrip() + "…"


def path_without_query(full_path: str) -> str:
    return (full_path or "").split("?", 1)[0].rstrip("/") or "/"


def _qs(full_path: str):
    return parse_qs(urlparse(full_path).query, keep_blank_values=False)


def _filter_raw_list(path: str, po: str) -> Optional[str]:
    qs = _qs(path)
    if po == "/news":
        v = (qs.get("source") or qs.get("filter") or [None])[0]
    elif po == "/owasp":
        v = (qs.get("filter") or qs.get("source") or [None])[0]
    else:
        v = (qs.get("filter") or [None])[0]
    if v is None:
        return None
    v = unquote(str(v).strip())
    if not v or v.lower() == "all":
        return None
    return v


def filter_human_label(po: str, raw: str) -> str:
    if po == "/news":
        return NEWS_FILTER_LABELS.get(raw, raw)
    if po == "/owasp":
        return config.cheatsheet_filter_label(raw)
    if po == "/full_cve":
        return CVE_FILTER_LABELS.get(raw, raw)
    if po == "/laws":
        return raw
    return raw


def bookmark_title_from_path_normalized(fp: str) -> str:
    """
    Заголовок для сохранения закладки (учитывает filter / поисковый запрос).
    fp — уже нормализованный путь вида /laws?filter=ПДн&page=1
    """
    parsed = urlparse(fp)
    po = (parsed.path or "/").rstrip("/") or "/"

    if po.startswith("/cve/"):
        return f"Уязвимость {po[5:]}"
    if po.startswith("/law/"):
        return f"Закон №{po[5:]}"
    if po.startswith("/news/"):
        return f"Новость №{po[6:]}"
    if po.startswith("/tools/"):
        return f"Инструмент: {po[7:]}"

    qs = parse_qs(parsed.query, keep_blank_values=False)

    if po in LIST_SECTION_TITLE:
        section = LIST_SECTION_TITLE[po]
        if po in ("/search", "/search_laws", "/search_news", "/search_cheatsheets"):
            q = (qs.get("q") or [""])[0].strip()
            if q:
                return f"{section}: «{_snip(q, 100)}»"
            return section
        raw = _filter_raw_list(fp, po)
        if raw:
            return f"{section} — {filter_human_label(po, raw)}"
        return section

    if po.startswith("/owasp/cheatsheets/"):
        return owasp_cheatsheet_bookmark_title(po)

    labels = {
        "/": "Главная",
        "/tools": "Инструменты",
        "/donate": "Поддержка проекта",
        "/feedback": "Обратная связь",
    }
    return labels.get(po, po)


def enrich_bookmark(bookmark: dict) -> dict:
    """
    Добавляет: display_title, display_description, href, kind_label.
    href — полный сохранённый path (с query, если был).
    """
    b = dict(bookmark)
    path = b.get("path") or "/"
    po = path_without_query(path)
    stored_title = (b.get("title") or "").strip()
    b["href"] = path
    b["display_title"] = stored_title
    b["display_description"] = ""
    b["kind_label"] = "Раздел"

    m = re.match(r"^/law/(\d+)$", po)
    if m:
        law = config.get_law_by_id(int(m.group(1)))
        if law:
            t = law["title"] if law["title"] else stored_title
            b["display_title"] = t
            d = law["description"] if law["description"] else ""
            b["display_description"] = _snip(d)
            b["kind_label"] = "Закон"
        return b

    m = re.match(r"^/news/(\d+)$", po)
    if m:
        row = config.get_news_by_id(int(m.group(1)))
        if row:
            b["display_title"] = row["title"] or stored_title
            b["display_description"] = _snip(row["content"] or "")
            b["kind_label"] = "Новость"
        return b

    m = re.match(r"^/cve/([^/]+)$", po)
    if m:
        vuln = config.get_vuln_by_identifier(m.group(1))
        if vuln:
            b["display_title"] = vuln["name"] or stored_title
            b["display_description"] = _snip(vuln["description"] or "")
            b["kind_label"] = "Уязвимость"
        return b

    m = re.match(r"^/tools/([^/]+)$", po)
    if m:
        tool = config.get_tool_by_name(m.group(1))
        if tool:
            b["display_title"] = tool["name"] or stored_title
            b["display_description"] = _snip(tool["description"] or "")
            b["kind_label"] = "Инструмент"
        return b

    if po.startswith("/owasp/cheatsheets/"):
        b["kind_label"] = "Статья OWASP"
        if not stored_title or stored_title == path or stored_title == po:
            b["display_title"] = owasp_cheatsheet_bookmark_title(po)
        return b

    if po in LIST_SECTION_TITLE:
        b["kind_label"] = LIST_SECTION_TITLE[po]
        if po in ("/search", "/search_laws", "/search_news", "/search_cheatsheets"):
            q = (_qs(path).get("q") or [""])[0].strip()
            if q:
                b["display_title"] = f"Запрос: «{_snip(q, 96)}»"
            else:
                b["display_title"] = "Пустой поиск"
            return b
        raw = _filter_raw_list(path, po)
        if raw:
            b["display_title"] = filter_human_label(po, raw)
        else:
            b["display_title"] = NO_FILTER_TITLE.get(po, "Полный список")
        return b

    labels = {
        "/": "Главная",
        "/laws": "Законы и НПА",
        "/news": "Новости ИБ",
        "/full_cve": "База уязвимостей БДУ",
        "/search": "Поиск CVE",
        "/search_laws": "Поиск по законам",
        "/search_news": "Поиск по новостям",
        "/owasp": "Статьи OWASP",
        "/search_cheatsheets": "Поиск по статьям OWASP",
        "/tools": "Инструменты",
        "/donate": "Поддержка",
        "/feedback": "Обратная связь",
    }
    if po in labels:
        b["kind_label"] = "Раздел"
        if not b["display_title"] or b["display_title"] == po:
            b["display_title"] = labels[po]

    return b


def enrich_bookmarks(bookmarks: list) -> list:
    return [enrich_bookmark(x) for x in bookmarks]
