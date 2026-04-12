import hashlib
import io
import json
import os
import re
import time
import subprocess
import xml.etree.ElementTree as ET
import zipfile
import dns.reversename
import dns.resolver
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import requests
import vt
from vt.error import APIError
from werkzeug.utils import secure_filename

# Прозрачная идентификация клиента (не маскируемся под браузер пользователя)
HTTP_HEADERS_UA = "PRO-IB-Portal/1.0 (HTTP-headers-analyzer; educational use)"

# Ключ VirusTotal: только окружение, не хранить в коде и не коммитить
VIRUSTOTAL_API_KEY_ENV = "VIRUSTOTAL_API_KEY"
# Опционально: подсказки DaData для разрешения ИНН → наименование (https://dadata.ru/api/)
DADATA_API_KEY_ENV = "DADATA_API_KEY"

ORG_DOMAIN_UA = "PRO-IB-Portal/1.0 (org-domain-search; Certificate Transparency)"
ORG_EGRUL_TIMEOUT_SEC = 28
ORG_CRTSH_TIMEOUT_SEC = 90
ORG_CRTSH_MAX_ROWS = 4000
ORG_MAX_DOMAINS_RETURN = 200
ORG_MAX_CRT_QUERIES = 4

# Таймаут HTTP на один запрос к API (сек.); опрос анализа идёт отдельными запросами
VT_HTTP_TIMEOUT_SEC = 600

# Инструмент «файл»: имя в БД и config.name_map должно совпадать с VIRUS_FILE_TOOL_NAME
VIRUS_FILE_TOOL_NAME = (
    "Проверка файла на вирусы (.docx, .exe, .pdf, .txt, .zip и др.)"
)
VIRUS_FILE_TOOL_DESCRIPTION = (
    "Загрузите файл (не более 32 МБ). Результат формируют 90+ поставщиков "
    "решений в области безопасности."
)
VIRUS_FILE_MAX_BYTES = 32 * 1024 * 1024
# Расширение по MIME, если браузер не прислал имя с суффиксом (Chrome PDF и т.п.)
_VIRUS_FILE_CONTENT_TYPE_EXT = {
    "application/pdf": ".pdf",
    "application/x-pdf": ".pdf",
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/msword": ".doc",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/javascript": ".js",
    "text/plain": ".txt",
    "text/html": ".html",
    "application/x-msdownload": ".exe",
    "application/octet-stream": "",  # уточняем по сигнатуре
}

VIRUS_FILE_ALLOWED_EXTENSIONS = frozenset({
    ".7z",
    ".apk",
    ".bat",
    ".bin",
    ".cab",
    ".cmd",
    ".com",
    ".dll",
    ".doc",
    ".docx",
    ".exe",
    ".gadget",
    ".gz",
    ".hta",
    ".htm",
    ".html",
    ".iso",
    ".jar",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".msp",
    ".pdf",
    ".pps",
    ".ppt",
    ".pptx",
    ".ps1",
    ".py",
    ".rar",
    ".rtf",
    ".scr",
    ".sys",
    ".tar",
    ".tmp",
    ".txt",
    ".url",
    ".vbs",
    ".wsf",
    ".xls",
    ".xlsx",
    ".xml",
    ".zip",
})


def _virus_file_sniff_extension(data):
    """Сигнатура файла, если нет расширения в имени и MIME расплывчатый."""
    if not data or len(data) < 4:
        return ""
    if data[:4] == b"%PDF":
        return ".pdf"
    if data[:2] == b"PK":
        return ".zip"
    if data[:2] == b"MZ":
        return ".exe"
    if data[:2] == b"\x1f\x8b":
        return ".gz"
    return ""


def _sanitize_whois_domain(raw):
    """FQDN в punycode; без IP и служебных имён — один безопасный аргумент для whois."""
    s = (raw or "").strip()
    if not s:
        return None, "Укажите доменное имя"
    host = s
    if "://" in s or s.startswith("//"):
        p = urlparse(s if "://" in s else "https://" + s)
        host = p.hostname
        if not host:
            return None, "Не удалось извлечь имя хоста из URL"
    host = host.strip().lower().rstrip(".")
    if not host:
        return None, "Укажите доменное имя"
    try:
        ipaddress.ip_address(host)
        return None, "Для WHOIS укажите доменное имя, а не IP-адрес."
    except ValueError:
        pass
    if host == "localhost" or host.endswith(".local"):
        return None, "Такие имена не поддерживаются."
    if len(host) > 253:
        return None, "Слишком длинное доменное имя"
    for label in host.split("."):
        if not label or len(label) > 63:
            return None, "Некорректное доменное имя"
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None, "Некорректное доменное имя"
    return ascii_host, None


def get_whois(domain):
    d, err = _sanitize_whois_domain(domain)
    if err:
        return err
    try:
        # Полный путь к whois на сервере
        result = subprocess.run(
            ["/usr/bin/whois", d], capture_output=True, text=True, timeout=10
        )
        return result.stdout if result.returncode == 0 else f"Ошибка: {result.stderr}"
    except Exception as e:
        return f"Ошибка: {str(e)}"

def get_dns_records(domain, record_type='A'):
    """Возвращает DNS-записи указанного типа"""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception as e:
        return [f"Ошибка: {str(e)}"]


def get_reverse_dns(ip_input):
    """
    PTR (reverse DNS): доменное имя по публичному IPv4/IPv6.
    Запрос выполняется резолвером сервера (как у клиента dig -x).
    """
    raw = (ip_input or "").strip()
    if not raw:
        return {"error": "Укажите IP-адрес"}
    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        return {"error": "Некорректный IP-адрес"}
    ip_str = str(ip_obj)
    if not _is_public_ip(ip_str):
        return {
            "error": (
                "Допустимы только публичные адреса. "
                "Локальные и служебные сети недоступны (защита от сканирования внутренней инфраструктуры)."
            )
        }
    rev = dns.reversename.from_address(ip_str)
    arpa = rev.to_text(omit_final_dot=True)
    try:
        answers = dns.resolver.resolve(rev, "PTR", lifetime=12.0)
        names = [rdata.target.to_text(omit_final_dot=True) for rdata in answers]
        return {"ip": ip_str, "arpa": arpa, "ptr_records": names}
    except dns.resolver.NXDOMAIN:
        return {
            "ip": ip_str,
            "arpa": arpa,
            "ptr_records": [],
            "note": "Для этого адреса нет зоны обратного просмотра (NXDOMAIN).",
        }
    except dns.resolver.NoAnswer:
        return {
            "ip": ip_str,
            "arpa": arpa,
            "ptr_records": [],
            "note": "PTR-запись в DNS не найдена.",
        }
    except Exception as e:
        return {"error": str(e)}


def _normalize_dns_lookup_domain(raw):
    """Домен или URL → FQDN в ASCII (IDNA). Без IP и служебных имён."""
    s = (raw or "").strip()
    if not s:
        return None, "Укажите доменное имя"
    host = s
    if "://" in s or s.startswith("//"):
        p = urlparse(s if "://" in s else "https://" + s)
        host = p.hostname
        if not host:
            return None, "Не удалось извлечь имя хоста из URL"
    host = host.strip().lower().rstrip(".")
    if not host:
        return None, "Укажите доменное имя"
    try:
        ipaddress.ip_address(host)
        return None, "Укажите доменное имя, а не IP-адрес (для IP используйте Reverse DNS)."
    except ValueError:
        pass
    if host == "localhost" or host.endswith(".local"):
        return None, "Такие имена не поддерживаются."
    if len(host) > 253:
        return None, "Слишком длинное доменное имя"
    for label in host.split("."):
        if not label or len(label) > 63:
            return None, "Некорректное доменное имя"
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None, "Некорректное доменное имя"
    return ascii_host, None


def _dns_rdata_line(rdtype: str, rdata) -> str:
    if rdtype in ("A", "AAAA"):
        return rdata.to_text()
    if rdtype == "MX":
        exch = rdata.exchange.to_text(omit_final_dot=True)
        return f"{rdata.preference} {exch}"
    if rdtype in ("NS", "CNAME", "PTR"):
        return rdata.target.to_text(omit_final_dot=True)
    if rdtype == "TXT":
        return rdata.to_text()
    return str(rdata)


def _resolve_dns_section(qname: str, rdtype: str):
    last_timeout = False
    for use_tcp in (False, True):
        try:
            ans = dns.resolver.resolve(
                qname,
                rdtype,
                lifetime=20.0,
                tcp=use_tcp,
                search=False,
            )
            return [_dns_rdata_line(rdtype, r) for r in ans], None
        except dns.resolver.NXDOMAIN:
            return None, "NXDOMAIN"
        except dns.resolver.NoAnswer:
            return [], None
        except dns.exception.Timeout:
            last_timeout = True
            continue
        except Exception as e:
            return [], str(e)
    if last_timeout:
        return [], "Таймаут DNS"
    return [], "Таймаут DNS"


def get_dns_lookup(raw_input):
    """
    Справочный просмотр записей A, AAAA, MX, TXT, NS, CNAME для имени.
    Запросы выполняются резолвером сервера.
    """
    dname, err = _normalize_dns_lookup_domain(raw_input)
    if err:
        return {"error": err}

    order = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")
    by_type = {}
    for rdtype in order:
        lines, sec_err = _resolve_dns_section(dname, rdtype)
        if sec_err == "NXDOMAIN":
            return {
                "domain": dname,
                "error": "Доменное имя не найдено в DNS (NXDOMAIN).",
            }
        by_type[rdtype] = {"items": lines or [], "err": sec_err}

    return {"domain": dname, "by_type": by_type, "order": order}


def _vt_stats_as_ints(stats):
    if not stats:
        return {}
    out = {}
    for k in stats:
        try:
            out[k] = int(stats[k])
        except (TypeError, ValueError):
            continue
    return out


def _vt_stats_nonempty(stats_int):
    return sum(stats_int.values()) > 0


def _vt_verdict(stats_int):
    mal = stats_int.get("malicious", 0)
    sus = stats_int.get("suspicious", 0)
    if mal > 0:
        return (
            "bad",
            f"Часть поставщиков ({mal}) классифицировала ссылку как вредоносную. Смотрите таблицу ниже.",
        )
    if sus > 0:
        return (
            "warn",
            f"Есть подозрительные срабатывания ({sus}), вредоносных — {mal}. Оцените контекст и таблицу вердиктов.",
        )
    harmless = stats_int.get("harmless", 0)
    undet = stats_int.get("undetected", 0)
    if harmless + undet > 0:
        return (
            "ok",
            "В сводке нет детектов «вредоносный» / «подозрительный». Это не гарантия безопасности ссылки и контента по переходу.",
        )
    return ("muted", "Недостаточно данных в сводке (мало ответов).")


def _vt_api_error_response(exc: APIError):
    code = exc.code
    msg = exc.message or str(exc)
    if code in ("QuotaExceededError", "TooManyRequestsError"):
        return {
            "error": "Превышен лимит запросов к сервису проверки. Повторите позже.",
        }
    if code in ("AuthenticationFailedError", "WrongCredentialsError"):
        return {"error": "Отклонён"}
    return {"error": f"Сервис проверки: {msg} ({code})"}


_VT_CATEGORY_RU = {
    "malicious": "Вредоносный",
    "suspicious": "Подозрительный",
    "harmless": "Не вредоносный",
    "undetected": "Не обнаружено",
    "timeout": "Таймаут",
    "confirmed-timeout": "Таймаут",
    "failure": "Ошибка проверки",
    "type-unsupported": "Тип не поддерживается",
}


def _vt_category_ru(category):
    if not category:
        return "—"
    return _VT_CATEGORY_RU.get(category, category)


def _vt_engine_rows(url_obj):
    raw = url_obj.get("last_analysis_results")
    if not raw:
        return []
    rows = []
    for engine in raw:
        data = raw[engine]
        if hasattr(data, "get"):
            cat = data.get("category") or "undetected"
            detail = data.get("result")
        else:
            cat, detail = "undetected", None
        if isinstance(detail, str) and detail.strip():
            detail_out = detail.strip()
        else:
            detail_out = "—"
        rows.append(
            {
                "engine": engine,
                "category": cat,
                "category_label": _vt_category_ru(cat),
                "detail": detail_out,
            }
        )
    rows.sort(key=lambda x: (x.get("engine") or "").lower())
    return rows


def _vt_build_stats_rows(stats_int):
    # «timeout» в API VT — число движков без ответа, не секунды. Подписи явные; нули не показываем.
    labels = {
        "malicious": "Вредоносные",
        "suspicious": "Подозрительные",
        "harmless": "Чистые",
        "undetected": "Без вердикта",
        "timeout": "Движки без ответа (таймаут)",
        "confirmed-timeout": "Движки без ответа (подтв. таймаут)",
        "failure": "Ошибка сканера",
    }
    order = (
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "timeout",
        "confirmed-timeout",
        "failure",
    )
    stats_rows = []
    seen = set()
    for key in order:
        if key in stats_int:
            n = stats_int[key]
            if n > 0:
                stats_rows.append(
                    {"key": key, "label": labels.get(key, key), "count": n}
                )
            seen.add(key)
    for key in sorted(stats_int.keys()):
        if key not in seen:
            n = stats_int[key]
            if n > 0:
                stats_rows.append(
                    {"key": key, "label": labels.get(key, key), "count": n}
                )
    return stats_rows


def _vt_format_scan_duration(seconds, kind):
    """
    Человекочитаемое время операции на сервере портала.
    kind: 'cache' — только запрос готового отчёта; 'live' — ожидание новой проверки.
    """
    if seconds is None:
        return "—", ""
    if seconds < 90:
        disp = f"{seconds:.1f} с"
    else:
        m = int(seconds // 60)
        s = round(seconds - m * 60)
        if s >= 60:
            m += 1
            s = 0
        disp = f"{m} мин {s} с" if s else f"{m} мин"
    if kind == "cache":
        hint = "Время запроса готового отчёта у сервиса."
    else:
        hint = "Время ожидания завершения проверки на стороне сервиса (запрос с сервера портала)."
    return disp, hint


def _vt_format_url_report(
    url_submitted,
    url_obj,
    source_note,
    scan_duration_sec=None,
    scan_duration_kind=None,
):
    stats_int = _vt_stats_as_ints(url_obj.get("last_analysis_stats"))
    verdict_cls, verdict_text = _vt_verdict(stats_int)
    engines_total = sum(stats_int.values())
    stats_rows = _vt_build_stats_rows(stats_int)
    engine_rows = _vt_engine_rows(url_obj)
    last_final = url_obj.get("last_final_url")
    lad = url_obj.get("last_analysis_date")
    lad_iso = lad.isoformat() if lad is not None and hasattr(lad, "isoformat") else None
    dur_disp, dur_hint = _vt_format_scan_duration(
        scan_duration_sec,
        scan_duration_kind or "live",
    )

    return {
        "url": url_submitted,
        "engines_total": engines_total,
        "providers_count": len(engine_rows) if engine_rows else engines_total,
        "stats_rows": stats_rows,
        "engine_rows": engine_rows,
        "verdict_text": verdict_text,
        "verdict_class": verdict_cls,
        "last_final_url": last_final,
        "last_analysis_iso": lad_iso,
        "source_note": source_note,
        "scan_duration_sec": scan_duration_sec,
        "scan_duration_display": dur_disp,
        "scan_duration_hint": dur_hint,
    }


def scan_virustotal_url(url_input):
    """
    Проверка URL через VirusTotal (REST API v3, клиент vt-py).
    Ключ: переменная окружения VIRUSTOTAL_API_KEY.
    """
    api_key = (os.environ.get(VIRUSTOTAL_API_KEY_ENV) or "").strip()
    if not api_key:
        return {
            "error": (
                "Ключ проверки не задан. Создайте файл .env в корне проекта (рядом с wsgi.py) со строкой "
                "VIRUSTOTAL_API_KEY=ваш_ключ или задайте переменную окружения VIRUSTOTAL_API_KEY. "
                "Файл .env не должен попадать в git."
            )
        }

    clean, err = _normalize_http_headers_url(url_input)
    if err:
        return {"error": err}
    parsed = urlparse(clean)
    ok, msg = _http_headers_check_host_resolvable_public(parsed.hostname)
    if not ok:
        return {"error": msg}

    uid = vt.url_id(clean)
    try:
        with vt.Client(
            api_key,
            agent="PRO-IB-Portal/1.0",
            timeout=VT_HTTP_TIMEOUT_SEC,
        ) as client:
            t_fetch = time.perf_counter()
            url_obj = None
            try:
                url_obj = client.get_object(f"/urls/{uid}")
            except APIError as e:
                if e.code != "NotFoundError":
                    return _vt_api_error_response(e)
            fetch_elapsed = time.perf_counter() - t_fetch

            use_cache = False
            if url_obj is not None:
                st = _vt_stats_as_ints(url_obj.get("last_analysis_stats"))
                if _vt_stats_nonempty(st):
                    use_cache = True

            if use_cache:
                return _vt_format_url_report(
                    clean,
                    url_obj,
                    "Сводка из существующего отчёта (кэш).",
                    scan_duration_sec=fetch_elapsed,
                    scan_duration_kind="cache",
                )

            t_scan = time.perf_counter()
            client.scan_url(clean, wait_for_completion=True)
            url_obj = client.get_object(f"/urls/{uid}")
            scan_elapsed = time.perf_counter() - t_scan
            return _vt_format_url_report(
                clean,
                url_obj,
                "Выполнено новое сканирование.",
                scan_duration_sec=scan_elapsed,
                scan_duration_kind="live",
            )
    except APIError as e:
        return _vt_api_error_response(e)
    except Exception as e:
        return {"error": str(e)}


# Короткий таймаут для сводного инструмента (только чтение кэша VT, без live-scan)
VT_TRUST_CACHE_TIMEOUT_SEC = 45


def virustotal_url_reputation_cache_only(url_input):
    """
    Только готовый отчёт VirusTotal по URL (get_object), без scan_url.
    Если отчёта нет — возвращает mode=no_report (полная проверка — в инструменте «Проверка ссылки»).
    """
    api_key = (os.environ.get(VIRUSTOTAL_API_KEY_ENV) or "").strip()
    if not api_key:
        return {
            "mode": "absent",
            "note": "Ключ проверки не задан (VIRUSTOTAL_API_KEY) — сводка о вредоносном ПО не запрашивалась.",
        }

    clean, err = _normalize_http_headers_url(url_input)
    if err:
        return {"mode": "error", "error": err}
    parsed = urlparse(clean)
    ok, msg = _http_headers_check_host_resolvable_public(parsed.hostname)
    if not ok:
        return {"mode": "error", "error": msg}

    uid = vt.url_id(clean)
    try:
        with vt.Client(
            api_key,
            agent="PRO-IB-Portal/1.0",
            timeout=VT_TRUST_CACHE_TIMEOUT_SEC,
        ) as client:
            t_fetch = time.perf_counter()
            try:
                url_obj = client.get_object(f"/urls/{uid}")
            except APIError as e:
                if e.code == "NotFoundError":
                    return {
                        "mode": "no_report",
                        "note": (
                            "Готового отчёта о вредоносном ПО по этому URL в кэше нет. "
                            "Полную проверку со сканированием выполните в инструменте «Проверка ссылки на вирусы (URL)»."
                        ),
                    }
                err_body = _vt_api_error_response(e)
                return {"mode": "error", "error": err_body.get("error", str(e))}
            fetch_elapsed = time.perf_counter() - t_fetch
            st = _vt_stats_as_ints(url_obj.get("last_analysis_stats"))
            if not _vt_stats_nonempty(st):
                return {
                    "mode": "no_report",
                    "note": (
                        "Запись есть, но сводка о вредоносном ПО пуста. "
                        "Полную проверку выполните в инструменте «Проверка ссылки на вирусы (URL)»."
                    ),
                }
            rep = _vt_format_url_report(
                clean,
                url_obj,
                "Готовый отчёт о вредоносном ПО на сайте.",
                scan_duration_sec=fetch_elapsed,
                scan_duration_kind="cache",
            )
            return {"mode": "ok", **rep}
    except APIError as e:
        err_body = _vt_api_error_response(e)
        return {"mode": "error", "error": err_body.get("error", str(e))}
    except Exception as e:
        return {"mode": "error", "error": str(e)}


def _vt_format_file_report(
    filename,
    sha256_hex,
    file_obj,
    source_note,
    scan_duration_sec=None,
    scan_duration_kind=None,
):
    stats_int = _vt_stats_as_ints(file_obj.get("last_analysis_stats"))
    verdict_cls, verdict_text = _vt_verdict(stats_int)
    engines_total = sum(stats_int.values())
    stats_rows = _vt_build_stats_rows(stats_int)
    engine_rows = _vt_engine_rows(file_obj)
    lad = file_obj.get("last_analysis_date")
    lad_iso = lad.isoformat() if lad is not None and hasattr(lad, "isoformat") else None
    size_val = file_obj.get("size")
    dur_disp, dur_hint = _vt_format_scan_duration(
        scan_duration_sec,
        scan_duration_kind or "live",
    )

    return {
        "filename": filename,
        "sha256": sha256_hex,
        "size": size_val,
        "engines_total": engines_total,
        "providers_count": len(engine_rows) if engine_rows else engines_total,
        "stats_rows": stats_rows,
        "engine_rows": engine_rows,
        "verdict_text": verdict_text,
        "verdict_class": verdict_cls,
        "last_analysis_iso": lad_iso,
        "source_note": source_note,
        "scan_duration_sec": scan_duration_sec,
        "scan_duration_display": dur_disp,
        "scan_duration_hint": dur_hint,
    }


def scan_virustotal_file(file_storage):
    """
    Загрузка файла и проверка через VirusTotal (vt-py scan_file).
    """
    api_key = (os.environ.get(VIRUSTOTAL_API_KEY_ENV) or "").strip()
    if not api_key:
        return {
            "error": (
                "Ключ проверки не задан. Создайте файл .env с VIRUSTOTAL_API_KEY "
                "или переменную окружения."
            )
        }

    if file_storage is None or not getattr(file_storage, "filename", None):
        return {"error": "Выберите файл для загрузки."}

    raw_name = (file_storage.filename or "").strip()
    # Расширение — из исходного имени: secure_filename() выкидывает не-ASCII и может убрать .pdf
    ext = os.path.splitext(raw_name)[1].lower()

    data = file_storage.read()
    if not data:
        return {"error": "Пустой файл."}
    if len(data) > VIRUS_FILE_MAX_BYTES:
        return {
            "error": f"Файл слишком большой. Максимум {VIRUS_FILE_MAX_BYTES // (1024 * 1024)} МБ.",
        }

    if not ext:
        ct = (getattr(file_storage, "content_type", None) or "").split(";")[0].strip().lower()
        ext = _VIRUS_FILE_CONTENT_TYPE_EXT.get(ct, "")
    if not ext:
        ext = _virus_file_sniff_extension(data)
    if not ext:
        return {"error": "Не удалось определить тип файла (нет расширения в имени и неизвестный формат)."}

    if ext not in VIRUS_FILE_ALLOWED_EXTENSIONS:
        sample = ", ".join(sorted(VIRUS_FILE_ALLOWED_EXTENSIONS)[:12])
        return {
            "error": (
                f"Расширение «{ext}» не поддерживается. "
                f"Примеры допустимых: {sample} и др. (см. название инструмента)."
            )
        }

    stem = os.path.splitext(raw_name)[0]
    safe_stem = secure_filename(stem) or "upload"
    safe_name = f"{safe_stem}{ext}"

    sha256_hex = hashlib.sha256(data).hexdigest()

    try:
        with vt.Client(
            api_key,
            agent="PRO-IB-Portal/1.0",
            timeout=VT_HTTP_TIMEOUT_SEC,
        ) as client:
            t_fetch = time.perf_counter()
            file_obj = None
            try:
                file_obj = client.get_object(f"/files/{sha256_hex}")
            except APIError as e:
                if e.code != "NotFoundError":
                    return _vt_api_error_response(e)
            fetch_elapsed = time.perf_counter() - t_fetch

            use_cache = False
            if file_obj is not None:
                st = _vt_stats_as_ints(file_obj.get("last_analysis_stats"))
                if _vt_stats_nonempty(st):
                    use_cache = True

            if use_cache:
                return _vt_format_file_report(
                    safe_name,
                    sha256_hex,
                    file_obj,
                    "Сводка из существующего отчёта (кэш).",
                    scan_duration_sec=fetch_elapsed,
                    scan_duration_kind="cache",
                )

            bio = io.BytesIO(data)
            bio.name = safe_name
            t_scan = time.perf_counter()
            client.scan_file(bio, wait_for_completion=True)
            file_obj = client.get_object(f"/files/{sha256_hex}")
            scan_elapsed = time.perf_counter() - t_scan
            return _vt_format_file_report(
                safe_name,
                sha256_hex,
                file_obj,
                "Выполнено новое сканирование.",
                scan_duration_sec=scan_elapsed,
                scan_duration_kind="live",
            )
    except APIError as e:
        return _vt_api_error_response(e)
    except Exception as e:
        return {"error": str(e)}


# Инструмент «Анализ метаданных файлов»
METADATA_FILE_MAX_BYTES = 32 * 1024 * 1024
METADATA_ALLOWED_EXTENSIONS = frozenset({".pdf", ".docx", ".jpg", ".jpeg", ".png"})

_NS_DOCX_CORE_CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
_NS_DOCX_DC = "http://purl.org/dc/elements/1.1/"
_NS_DOCX_DCTERMS = "http://purl.org/dc/terms/"
_NS_DOCX_APP = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"


def _metadata_sniff_kind(data: bytes):
    if not data or len(data) < 8:
        return None
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = set(zf.namelist())
            if "word/document.xml" in names and "[Content_Types].xml" in names:
                return "docx"
        except zipfile.BadZipFile:
            return None
    return None


def _ext_to_kind(ext: str):
    e = ext.lower()
    if e == ".pdf":
        return "pdf"
    if e == ".docx":
        return "docx"
    if e in (".jpg", ".jpeg"):
        return "jpeg"
    if e == ".png":
        return "png"
    return None


def _pdf_meta_str(val):
    if val is None:
        return None
    s = str(val).strip()
    return s or None


def _extract_pdf_metadata(data: bytes):
    from pypdf import PdfReader

    sections = []
    warn = None
    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as e:
        return [], f"Не удалось разобрать PDF: {e}"

    if getattr(reader, "is_encrypted", False):
        try:
            if reader.decrypt("") == 0:
                return (
                    sections,
                    "PDF зашифрован: без пароля метаданные недоступны.",
                )
        except Exception:
            return (sections, "PDF зашифрован или повреждён — метаданные недоступны.")

    items = []
    meta = reader.metadata
    if meta:
        mapping = (
            ("Заголовок", lambda: _pdf_meta_str(getattr(meta, "title", None))),
            ("Автор", lambda: _pdf_meta_str(getattr(meta, "author", None))),
            ("Тема", lambda: _pdf_meta_str(getattr(meta, "subject", None))),
            ("Ключевые слова", lambda: _pdf_meta_str(getattr(meta, "keywords", None))),
            ("Создатель (ПО)", lambda: _pdf_meta_str(getattr(meta, "creator", None))),
            ("Производитель (ПО)", lambda: _pdf_meta_str(getattr(meta, "producer", None))),
            ("Дата создания", lambda: _pdf_meta_str(getattr(meta, "creation_date", None))),
            ("Дата изменения", lambda: _pdf_meta_str(getattr(meta, "modification_date", None))),
        )
        for label, fn in mapping:
            v = fn()
            if v:
                items.append({"label": label, "value": v})

    items.append(
        {
            "label": "Число страниц",
            "value": str(len(reader.pages)),
        }
    )
    ver = getattr(reader, "pdf_header", None)
    if ver:
        items.append({"label": "Заголовок PDF", "value": str(ver).strip()})

    if items:
        sections.append({"title": "Документ PDF", "items": items})
    return sections, warn


def _extract_docx_metadata(data: bytes):
    sections = []
    warn = None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            core_items = []
            if "docProps/core.xml" in names:
                root = ET.fromstring(zf.read("docProps/core.xml"))
                core_map = (
                    ("Название", "title", _NS_DOCX_DC),
                    ("Описание", "description", _NS_DOCX_DC),
                    ("Тема", "subject", _NS_DOCX_DC),
                    ("Автор", "creator", _NS_DOCX_DC),
                    ("Категория", "category", _NS_DOCX_CORE_CP),
                    ("Ключевые слова", "keywords", _NS_DOCX_CORE_CP),
                    ("Последний автор", "lastModifiedBy", _NS_DOCX_CORE_CP),
                    ("Редакция", "revision", _NS_DOCX_CORE_CP),
                )
                for label, local, ns_uri in core_map:
                    el = root.find(f"{{{ns_uri}}}{local}")
                    if el is not None and el.text and el.text.strip():
                        core_items.append({"label": label, "value": el.text.strip()})
                for tag, label in (
                    ("created", "Создано"),
                    ("modified", "Изменено"),
                ):
                    el = root.find(f"{{{_NS_DOCX_DCTERMS}}}{tag}")
                    if el is not None:
                        val = (el.text or "").strip()
                        if not val and el.attrib.get(
                            f"{{{_NS_DOCX_DCTERMS}}}W3CDTF"
                        ):
                            val = el.attrib.get(
                                f"{{{_NS_DOCX_DCTERMS}}}W3CDTF", ""
                            ).strip()
                        if val:
                            core_items.append({"label": label, "value": val})
            if core_items:
                sections.append({"title": "Свойства документа (OOXML)", "items": core_items})

            app_items = []
            if "docProps/app.xml" in names:
                aroot = ET.fromstring(zf.read("docProps/app.xml"))
                app_map = (
                    ("Приложение", "Application"),
                    ("Версия приложения", "AppVersion"),
                    ("Организация", "Company"),
                    ("Шаблон", "Template"),
                    ("Менеджер", "Manager"),
                    ("Страниц", "Pages"),
                    ("Слов", "Words"),
                    ("Символов с пробелами", "CharactersWithSpaces"),
                )
                for label, local in app_map:
                    el = aroot.find(f"{{{_NS_DOCX_APP}}}{local}")
                    if el is not None and el.text and el.text.strip():
                        app_items.append({"label": label, "value": el.text.strip()})
            if app_items:
                sections.append({"title": "Расширенные свойства (Office)", "items": app_items})
    except zipfile.BadZipFile:
        return [], "Файл не является корректным DOCX (ZIP)."
    except ET.ParseError as e:
        return [], f"Ошибка разбора XML в DOCX: {e}"

    if not sections:
        warn = "Встроенные свойства в файле не найдены (пустой блок метаданных)."
    return sections, warn


def _extract_image_metadata(data: bytes, kind: str):
    from PIL import Image
    from PIL.ExifTags import TAGS

    sections = []
    warn = None
    try:
        img = Image.open(io.BytesIO(data))
    except Exception as e:
        return [], f"Не удалось открыть изображение: {e}"

    base_items = [
        {"label": "Формат", "value": (img.format or kind).upper()},
        {"label": "Режим", "value": img.mode or "—"},
        {"label": "Размер (px)", "value": f"{img.width} × {img.height}"},
    ]
    sections.append({"title": "Изображение", "items": base_items})

    info_items = []
    for k, v in sorted((img.info or {}).items(), key=lambda x: str(x[0]).lower()):
        if k in ("exif",):
            continue
        vs = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
        if len(vs) > 2000:
            vs = vs[:2000] + "…"
        info_items.append({"label": str(k), "value": vs})
    if info_items:
        sections.append({"title": "Встроенные данные (chunks / info)", "items": info_items})

    exif = None
    try:
        exif = getattr(img, "getexif", lambda: None)()
    except (OSError, SyntaxError, ValueError, TypeError):
        exif = None
    if exif:
        ex_items = []
        for tag_id, val in exif.items():
            name = TAGS.get(tag_id, f"Tag {tag_id}")
            if tag_id == 34665:
                continue
            sval = val
            if isinstance(sval, bytes):
                sval = sval.decode("utf-8", errors="replace")
            else:
                sval = str(sval)
            if len(sval) > 800:
                sval = sval[:800] + "…"
            ex_items.append({"label": str(name), "value": sval})
        if ex_items:
            ex_items.sort(key=lambda x: x["label"].lower())
            sections.append({"title": "EXIF", "items": ex_items})
    elif kind == "jpeg":
        warn = "EXIF в файле не обнаружен."

    return sections, warn


def analyze_file_metadata(file_storage):
    """
    Извлечение метаданных из PDF, DOCX, JPEG, PNG (только в памяти, без записи на диск).
    """
    if file_storage is None or not getattr(file_storage, "filename", None):
        return {"error": "Выберите файл для анализа."}

    raw_name = (file_storage.filename or "").strip()
    ext = os.path.splitext(raw_name)[1].lower()
    if ext not in METADATA_ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(METADATA_ALLOWED_EXTENSIONS))
        return {
            "error": f"Допустимые типы: {allowed}.",
        }

    data = file_storage.read()
    if not data:
        return {"error": "Пустой файл."}
    if len(data) > METADATA_FILE_MAX_BYTES:
        mb = METADATA_FILE_MAX_BYTES // (1024 * 1024)
        return {"error": f"Файл слишком большой. Максимум {mb} МБ."}

    kind_expected = _ext_to_kind(ext)
    kind_sniff = _metadata_sniff_kind(data)
    if kind_sniff != kind_expected:
        return {
            "error": (
                "Содержимое файла не совпадает с расширением "
                f"(ожидался тип «{kind_expected}», получено «{kind_sniff or 'неизвестно'}»). "
                "Возможно, файл повреждён или переименован."
            ),
        }

    stem = os.path.splitext(raw_name)[0]
    safe_stem = secure_filename(stem) or "upload"
    safe_name = f"{safe_stem}{ext}"

    sections = []
    notes = []

    if kind_expected == "pdf":
        sec, w = _extract_pdf_metadata(data)
        sections.extend(sec)
        if w:
            notes.append(w)
    elif kind_expected == "docx":
        sec, w = _extract_docx_metadata(data)
        sections.extend(sec)
        if w:
            notes.append(w)
    elif kind_expected in ("jpeg", "png"):
        sec, w = _extract_image_metadata(data, kind_expected)
        sections.extend(sec)
        if w:
            notes.append(w)

    return {
        "filename": safe_name,
        "size_bytes": len(data),
        "format_label": {"pdf": "PDF", "docx": "DOCX", "jpeg": "JPEG", "png": "PNG"}.get(
            kind_expected, kind_expected
        ),
        "sections": sections,
        "notes": notes,
    }


def _parse_ssl_host_port(raw):
    """Домен, URL или host:port → (hostname, port)."""
    raw = (raw or "").strip()
    if not raw:
        return None, None
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    host = p.hostname
    port = p.port or 443
    if not host:
        return None, None
    return host, int(port)


def _x509_name_to_dict(name_tuple):
    if not name_tuple:
        return {}
    out = {}
    for rdn in name_tuple:
        for k, v in rdn:
            out[k] = v
    return out


def _parse_asn1_time(s):
    """Формат OpenSSL: 'Jan 15 12:00:00 2024 GMT'"""
    dt = datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
    return dt.replace(tzinfo=timezone.utc)


def _ssl_fetch_peer_cert(host, port, verify):
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ipaddress.ip_address(host)
        sni = None
    except ValueError:
        sni = host
    with socket.create_connection((host, port), timeout=12) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
            cert = ssock.getpeercert()
            tls_ver = ssock.version()
            ciph = ssock.cipher()
            cipher_name = ciph[0] if ciph else None
            return cert, tls_ver, cipher_name


def get_ssl_info(host_input):
    """
    TLS-сертификат с удалённого хоста: срок, издатель, SAN, шифр.
    При ошибке проверки цепочки повторяет запрос без verify (для аудита самоподписанных и т.п.).
    """
    host, port = _parse_ssl_host_port(host_input)
    if not host:
        return {"error": "Укажите домен или URL, например yandex.ru или https://example.com:443"}

    cert = None
    tls_ver = None
    cipher_name = None
    verified = True
    trust_warning = None

    try:
        cert, tls_ver, cipher_name = _ssl_fetch_peer_cert(host, port, True)
    except ssl.SSLCertVerificationError:
        try:
            cert, tls_ver, cipher_name = _ssl_fetch_peer_cert(host, port, False)
            verified = False
            trust_warning = (
                "Цепочка доверия или имя хоста не прошли стандартную проверку. "
                "Сертификат показан для анализа (как в openssl s_client -verify_return_error off)."
            )
        except Exception as e:
            return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

    if not cert:
        return {"error": "Сертификат не получен (пустой ответ)."}

    subj = _x509_name_to_dict(cert.get("subject", ()))
    iss = _x509_name_to_dict(cert.get("issuer", ()))
    san_list = []
    for pair in cert.get("subjectAltName", ()) or ():
        if len(pair) >= 2:
            san_list.append(f"{pair[0]}:{pair[1]}")

    nb_raw = cert.get("notBefore")
    na_raw = cert.get("notAfter")
    try:
        not_before = _parse_asn1_time(nb_raw) if nb_raw else None
        not_after = _parse_asn1_time(na_raw) if na_raw else None
    except (ValueError, TypeError):
        not_before = not_after = None

    days_left = None
    status = "unknown"
    now = datetime.now(timezone.utc)
    if not_after:
        days_left = (not_after - now).days
        if days_left < 0:
            status = "expired"
        elif days_left <= 7:
            status = "expiring"
        else:
            status = "ok"
    if not_before and now < not_before:
        status = "not_yet_valid"

    return {
        "host": host,
        "port": port,
        "verified": verified,
        "trust_warning": trust_warning,
        "subject": subj,
        "issuer": iss,
        "san": san_list,
        "not_before": nb_raw,
        "not_after": na_raw,
        "not_before_iso": not_before.isoformat() if not_before else None,
        "not_after_iso": not_after.isoformat() if not_after else None,
        "days_left": days_left,
        "status": status,
        "serial": cert.get("serialNumber"),
        "version": cert.get("version"),
        "tls_version": tls_ver,
        "cipher": cipher_name,
    }

# Токен и URL «мой IP» в браузере (запрос с клиента — как при открытии ссылки в вкладке)
TWOIP_API_TOKEN = "np34wtt2fgt28ove"
TWOIP_CLIENT_GEO_URL = f"https://api.2ip.io/?token={TWOIP_API_TOKEN}&lang=ru"


def get_ip_info(ip):
    url = f"https://api.2ip.io/{ip}?token={TWOIP_API_TOKEN}&lang=ru"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        resolved_ip = data.get("ip")
        city = data.get("city")
        region = data.get("region")
        country = data.get("country")
        code = data.get("code")
        emoji = data.get("emoji")
        lat = data.get("lat")
        lon = data.get("lon")
        timezone = data.get("timezone")
        asn = data.get("asn") or {}
        asn_id = asn.get("id")
        asn_name = asn.get("name")
        asn_hosting = asn.get("hosting")
        return {
            "ip": resolved_ip,
            "city": city,
            "region": region,
            "country": country,
            "code": code,
            "emoji": emoji,
            "lat": lat,
            "lon": lon,
            "timezone": timezone,
            "asn": {
                "id": asn_id,
                "name": asn_name,
                "hosting": asn_hosting,
            },
        }
    except Exception as e:
        return {"error": str(e)}


def _is_public_ip(addr_str):
    """Защита SSRF: только публичные адреса (не RFC1918, loopback, link-local и т.д.)."""
    try:
        ip_obj = ipaddress.ip_address(addr_str)
    except ValueError:
        return False
    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
        return False
    if ip_obj.is_multicast or ip_obj.is_reserved:
        return False
    if ip_obj.version == 6 and getattr(ip_obj, "is_site_local", False):
        return False
    return True


def _http_headers_check_host_resolvable_public(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"Не удалось разрешить имя хоста: {e}"
    if not infos:
        return False, "Нет адресов для хоста"
    for info in infos:
        addr = info[4][0]
        if not _is_public_ip(addr):
            return (
                False,
                "Запросы к локальным, служебным и внутренним адресам запрещены (защита от SSRF). "
                "Разрешены только публичные адреса.",
            )
    return True, None


def _normalize_http_headers_url(raw):
    raw = (raw or "").strip()
    if not raw:
        return None, "Укажите URL (например https://example.ru)"
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        return None, "Допустимы только протоколы http и https"
    if not p.hostname:
        return None, "Некорректный URL"
    if p.username or p.password:
        return None, "URL с логином и паролем не поддерживается"
    path = p.path if p.path else "/"
    clean = urlunparse((p.scheme, p.netloc, path, p.params, p.query, p.fragment))
    return clean, None


def _security_header_hints(header_names_lower):
    """Краткие заметки для ИБ (наличие типовых заголовков, не полноценный аудит)."""
    h = header_names_lower
    notes = []
    if "strict-transport-security" in h:
        notes.append("Обнаружен Strict-Transport-Security (HSTS)")
    else:
        notes.append("Нет HSTS — при ответе по HTTPS имеет смысл оценить политику")

    if "content-security-policy" in h or "content-security-policy-report-only" in h:
        notes.append("Задана Content-Security-Policy (или report-only)")
    else:
        notes.append("CSP в ответе не найден")

    if "x-frame-options" in h:
        notes.append("Есть X-Frame-Options (защита от clickjacking)")
    else:
        notes.append("X-Frame-Options не найден — проверьте модель встраивания в iframe")

    if "x-content-type-options" in h:
        notes.append("Есть X-Content-Type-Options")
    if "referrer-policy" in h:
        notes.append("Указан Referrer-Policy")
    if "permissions-policy" in h or "feature-policy" in h:
        notes.append("Есть Permissions-Policy / Feature-Policy")
    return notes


def analyze_http_headers(url_input):
    """
    Одиночный HEAD или GET (если HEAD недоступен) к указанному URL.
    Только публичные адреса после DNS; прозрачный User-Agent.
    """
    url, err = _normalize_http_headers_url(url_input)
    if err:
        return {"error": err}

    p = urlparse(url)
    ok, msg = _http_headers_check_host_resolvable_public(p.hostname)
    if not ok:
        return {"error": msg}

    req_headers = {
        "User-Agent": HTTP_HEADERS_UA,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.5",
    }

    sess = requests.Session()
    sess.max_redirects = 8

    try:
        r = sess.head(
            url,
            timeout=15,
            allow_redirects=True,
            headers=req_headers,
        )
        method = "HEAD"
        if r.status_code == 405:
            r.close()
            r = sess.get(
                url,
                timeout=15,
                allow_redirects=True,
                headers=req_headers,
                stream=True,
            )
            method = "GET"
            try:
                for _ in r.iter_content(chunk_size=8192):
                    break
            finally:
                r.close()
    except requests.exceptions.TooManyRedirects:
        return {"error": "Слишком много перенаправлений"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    hdr_items = sorted(r.headers.items(), key=lambda x: x[0].lower())
    names_lower = {k.lower() for k in r.headers.keys()}
    hints = _security_header_hints(names_lower)

    redirect_chain = []
    for h in r.history:
        redirect_chain.append({"url": h.url, "status": h.status_code})
    redirect_chain.append({"url": r.url, "status": r.status_code})

    return {
        "requested_url": url,
        "final_url": r.url,
        "status_code": r.status_code,
        "method": method,
        "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
        "redirect_count": len(r.history),
        "redirect_chain": redirect_chain,
        "headers": hdr_items,
        "security_hints": hints,
    }


def _org_normalize_ct_hostname(line):
    s = (line or "").strip().lower()
    if s.startswith("*."):
        s = s[2:]
    if s.startswith("www."):
        s = s[4:]
    return s.rstrip(".")


_org_tld_extract = None


def _org_get_tld_extract():
    global _org_tld_extract
    if _org_tld_extract is None:
        import tldextract

        _org_tld_extract = tldextract.TLDExtract()
    return _org_tld_extract


def _org_registered_domain(hostname):
    """Регистрируемый домен без поддомена (например mail.shop.lenta.ru → lenta.ru)."""
    h = _org_normalize_ct_hostname(hostname)
    if not h or "." not in h:
        return None
    try:
        ext = _org_get_tld_extract()(h)
    except Exception:
        return None
    rd = (ext.registered_domain or "").strip().lower().rstrip(".")
    if not rd or "." not in rd:
        return None
    return rd


RDAP_DOMAIN_BOOTSTRAP = "https://rdap-bootstrap.arin.net/bootstrap/domain/{domain}"


def _parse_rdap_datetime(val):
    if not val or not isinstance(val, str):
        return None
    s = val.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _rdap_registrar_name(entities):
    for ent in entities or []:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrar" not in roles:
            continue
        vc = ent.get("vcardArray")
        if not isinstance(vc, list) or len(vc) < 2:
            continue
        for prop in vc[1]:
            if (
                isinstance(prop, list)
                and len(prop) >= 4
                and str(prop[0]).lower() == "fn"
            ):
                fn = prop[3]
                if isinstance(fn, str) and fn.strip():
                    return fn.strip()
    return None


def get_domain_registration_meta(domain_ascii: str):
    """
    Даты регистрации/истечения и регистратор через открытый RDAP (IANA bootstrap → сервер зоны).
    Для части ccTLD (например .ru) единый bootstrap может не находить сервер — тогда возраст недоступен.
    """
    d = (domain_ascii or "").strip().lower().rstrip(".")
    if not d:
        return {"error": "Пустое доменное имя"}
    url = RDAP_DOMAIN_BOOTSTRAP.format(domain=d)
    try:
        r = requests.get(
            url,
            timeout=22,
            allow_redirects=True,
            headers={
                "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.8",
                "User-Agent": "PRO-IB-Portal/1.0 (site-trust; RDAP)",
            },
        )
        ctype = (r.headers.get("Content-Type") or "").lower()
        if r.status_code == 404:
            msg = (
                "RDAP: для этой зоны единый bootstrap не вернул данные "
                "(часто для ccTLD вроде .ru); возраст домена здесь не определён."
            )
            try:
                errj = r.json()
                desc = errj.get("description")
                if isinstance(desc, list) and desc and isinstance(desc[0], str):
                    raw = desc[0]
                    if "not here" in raw.lower():
                        msg = (
                            "RDAP: для этой зоны общий bootstrap не находит сервер "
                            "или домен не найден; даты регистрации недоступны."
                        )
                    else:
                        msg = raw
            except (ValueError, TypeError):
                pass
            return {"error": msg, "domain": d}
        if r.status_code != 200:
            return {
                "error": f"RDAP: HTTP {r.status_code}",
                "domain": d,
            }
        if "json" not in ctype:
            return {"error": "RDAP: ожидался JSON.", "domain": d}
        data = r.json()
    except requests.RequestException as e:
        return {"error": f"RDAP: {e}", "domain": d}
    except ValueError:
        return {"error": "RDAP: некорректный JSON.", "domain": d}

    reg_dt = exp_dt = None
    for ev in data.get("events") or []:
        action = (ev.get("eventAction") or "").lower()
        edt = _parse_rdap_datetime(ev.get("eventDate"))
        if not edt:
            continue
        if action == "registration":
            reg_dt = edt
        elif action == "expiration":
            exp_dt = edt

    registrar = _rdap_registrar_name(data.get("entities"))
    age_days = None
    if reg_dt:
        age_days = max(0, (datetime.now(timezone.utc) - reg_dt).days)

    return {
        "domain": d,
        "registrar": registrar,
        "creation_date_iso": reg_dt.isoformat() if reg_dt else None,
        "expiration_date_iso": exp_dt.isoformat() if exp_dt else None,
        "age_days": age_days,
    }


def _build_trust_summary(host, ssl_block, http_block, whois_block, dns_block, vt_block):
    score = 55
    factors = []

    if ssl_block.get("error"):
        score -= 12
        factors.append("TLS/SSL: не удалось получить сертификат с хоста.")
    else:
        st = ssl_block.get("status")
        if ssl_block.get("verified") and st == "ok":
            score += 12
            factors.append("TLS: доверенная цепочка, срок сертификата в порядке.")
        elif st == "expired":
            score -= 25
            factors.append("TLS: сертификат истёк.")
        elif st in ("expiring", "not_yet_valid"):
            score -= 5
            factors.append("TLS: обратите внимание на срок действия сертификата.")
        if not ssl_block.get("verified"):
            score -= 8
            factors.append("TLS: цепочка или имя не прошли стандартную проверку браузера.")
        tv = ssl_block.get("tls_version") or ""
        if tv.startswith("TLSv1.0") or tv.startswith("TLSv1.1"):
            score -= 5
            factors.append("TLS: устаревшая версия протокола (рекомендуют TLS 1.2+).")

    if http_block.get("error"):
        score -= 5
        factors.append("HTTP(S): ответ по URL не получен — оценка заголовков ограничена.")
    else:
        fu = (http_block.get("final_url") or "").lower()
        if fu.startswith("https:"):
            score += 5
            factors.append("Итоговый ответ отдаётся по HTTPS.")
        sc = http_block.get("status_code") or 0
        if 200 <= sc < 400:
            score += 3
        hints = " ".join(http_block.get("security_hints") or []).lower()
        if "strict-transport-security" in hints or "hsts" in hints:
            score += 6
            factors.append("В ответе есть HSTS.")
        if "content-security-policy" in hints:
            score += 3
        if "x-frame-options" in hints:
            score += 2

    if whois_block.get("skipped"):
        pass
    elif whois_block.get("error"):
        factors.append(
            "RDAP: даты регистрации не получены (часть ccTLD не обслуживается единым bootstrap или домен не найден)."
        )
    else:
        ad = whois_block.get("age_days")
        if ad is not None:
            if ad >= 365 * 5:
                score += 12
                factors.append("Возраст домена: около пяти лет и более.")
            elif ad >= 365:
                score += 8
                factors.append("Возраст домена: больше года.")
            elif ad >= 90:
                score += 4
                factors.append("Возраст домена: от нескольких месяцев.")
            else:
                score -= 2
                factors.append("Домен зарегистрирован недавно — осторожность уместна, но это не вердикт.")

    if dns_block.get("skipped"):
        pass
    elif dns_block.get("error"):
        score -= 15
        factors.append("DNS: ошибка или домен не найден в DNS.")
    else:
        score += 3
        factors.append("DNS: зона регистрируемого домена отвечает (сводка записей ниже).")

    mode = (vt_block or {}).get("mode")
    if mode == "ok":
        vc = vt_block.get("verdict_class")
        if vc == "bad":
            score = min(score, 22)
            factors.append("VirusTotal: есть отметки «вредоносный».")
        elif vc == "warn":
            score -= 18
            factors.append("VirusTotal: есть «подозрительный».")
        elif vc == "ok":
            score += 8
            factors.append("VirusTotal: в сводке нет вредоносных/подозрительных вердиктов.")
        else:
            factors.append("VirusTotal: недостаточно данных в сводке.")
    elif mode == "absent":
        factors.append("VirusTotal: ключ не задан — репутация по VT не учитывалась.")
    elif mode == "no_report":
        factors.append("VirusTotal: готового отчёта нет (без запуска сканирования).")
    elif mode == "error":
        factors.append(f"VirusTotal: {(vt_block or {}).get('error', 'ошибка')}")

    score = max(0, min(100, int(round(score))))
    if score >= 75:
        label = "В целом благоприятные признаки"
    elif score >= 50:
        label = "Смешанная картина"
    elif score >= 30:
        label = "Заметные риски"
    else:
        label = "Серьёзные красные флаги"

    return {
        "score": score,
        "label": label,
        "factors": factors,
        "disclaimer": (
            "Индекс носит учебно-справочный характер. Он не заменяет аудит безопасности, "
            "юридическую оценку и осмотрительность при вводе данных на сайте."
        ),
    }


def analyze_site_trust(url_input):
    """
    Сводка для страницы «Анализатор доверия»: TLS, HTTP-заголовки, даты домена (RDAP), DNS по регистрируемому домену,
    при наличии ключа — готовый отчёт о вредоносном ПО (без нового сканирования).
    """
    clean, err = _normalize_http_headers_url(url_input)
    if err:
        return {"error": err}
    p = urlparse(clean)
    host = p.hostname
    if not host:
        return {"error": "Некорректный URL"}
    ok, msg = _http_headers_check_host_resolvable_public(host)
    if not ok:
        return {"error": msg}

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    reg_domain = None
    if is_ip:
        whois_block = {
            "skipped": True,
            "note": "Для IP-адреса сведения о регистрации домена не применяются.",
        }
        dns_block = {
            "skipped": True,
            "note": "Для IP-адреса сводка DNS по домену не выполнялась.",
        }
    else:
        reg_domain = _org_registered_domain(host)
        if not reg_domain:
            whois_block = {
                "error": "Не удалось определить регистрируемый домен для WHOIS (проверьте написание хоста).",
            }
            dns_block = {
                "error": "Не удалось определить регистрируемый домен для DNS.",
            }
        else:
            whois_block = get_domain_registration_meta(reg_domain)
            dns_block = get_dns_lookup(reg_domain)

    ssl_block = get_ssl_info(f"https://{host}")
    http_block = analyze_http_headers(clean)
    vt_block = virustotal_url_reputation_cache_only(clean)

    summary = _build_trust_summary(
        host, ssl_block, http_block, whois_block, dns_block, vt_block
    )

    return {
        "input_url": clean,
        "host": host,
        "registered_domain": reg_domain,
        "whois": whois_block,
        "ssl": ssl_block,
        "http": http_block,
        "dns": dns_block,
        "virustotal": vt_block,
        "summary": summary,
    }


_ORG_LONG_PREFIX = re.compile(
    r"^(?:"
    r"общество\s+с\s+ограниченной\s+ответственностью|"
    r"некоммерческое\s+акционерное\s+общество|"
    r"публичное\s+акционерное\s+общество|"
    r"закрытое\s+акционерное\s+общество|"
    r"открытое\s+акционерное\s+общество|"
    r"акционерное\s+общество|"
    r"индивидуальный\s+предприниматель|"
    r"товарищество\s+на\s+вере|"
    r"товарищество\s+с\s+ограниченной\s+ответственностью|"
    r"производственный\s+кооператив|"
    r"хозяйственное\s+партнерство|"
    r"хозяйственное\s+товарищество|"
    r"унитарное\s+предприятие|"
    r"государственное\s+унитарное\s+предприятие"
    r")\s+",
    re.I | re.UNICODE,
)
_ORG_ABBREV_PREFIX = re.compile(
    r"^(?:ооо|оао|зао|пао|ао|нао|ип|тоо|муп|гуп|фгуп|ано|нп|нко|оод|гау|фгу|буз)\b[.\s,:;]*\s*",
    re.I | re.UNICODE,
)
_ORG_ABBREV_SUFFIX = re.compile(
    r"\s+(?:ооо|оао|зао|пао|ао|нао|ип|тоо)\s*$",
    re.I | re.UNICODE,
)

_ORG_CYR_TO_LAT = {
    "а": "a",
    "б": "b",
    "в": "v",
    "г": "g",
    "д": "d",
    "е": "e",
    "ё": "e",
    "ж": "zh",
    "з": "z",
    "и": "i",
    "й": "y",
    "к": "k",
    "л": "l",
    "м": "m",
    "н": "n",
    "о": "o",
    "п": "p",
    "р": "r",
    "с": "s",
    "т": "t",
    "у": "u",
    "ф": "f",
    "х": "h",
    "ц": "ts",
    "ч": "ch",
    "ш": "sh",
    "щ": "sch",
    "ъ": "",
    "ы": "y",
    "ь": "",
    "э": "e",
    "ю": "yu",
    "я": "ya",
}


def _org_strip_legal_form(name):
    """Убирает типовые формы (ООО, АО, ПАО и длинные наименования ОПФ)."""
    s = (name or "").strip()
    s = re.sub(r'[«»"\'„“]', " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        return ""
    for _ in range(24):
        t = s
        s = _ORG_LONG_PREFIX.sub("", s).strip()
        m = _ORG_ABBREV_PREFIX.match(s)
        if m:
            s = s[m.end() :].strip()
        s = _ORG_ABBREV_SUFFIX.sub("", s).strip()
        if s == t:
            break
    return s.strip()


def _org_transliterate_to_latin_token(core_name):
    """
    Транслитерация для поиска в crt.sh: одна слитная латинская строка в нижнем регистре.
    Латиница и цифры сохраняются; остальное отбрасывается.
    """
    s = (core_name or "").strip().lower()
    if not s:
        return ""
    parts = []
    for ch in s:
        if ch.isascii() and ch.isalnum():
            parts.append(ch.lower())
        elif ch in _ORG_CYR_TO_LAT:
            parts.append(_ORG_CYR_TO_LAT[ch])
        elif ch in " \t\n\r._-+":
            continue
    token = "".join(parts)
    return token[:72] if token else ""


def _dadata_party_from_item(item, inn_fallback=""):
    """Разбор элемента ответа suggest/find_by_id DaData (party)."""
    if not item or not isinstance(item, dict):
        return None
    d = item.get("data") or {}
    nm = d.get("name") or {}
    full_n = (nm.get("full_with_opf") or "").strip()
    short_n = (nm.get("short_with_opf") or "").strip()
    inn = str(d.get("inn") or inn_fallback or "").strip()
    val = (item.get("value") or "").strip()
    display_name = full_n or short_n or val
    if not display_name and not inn:
        return None
    label = display_name
    if inn:
        label = f"{display_name} — ИНН {inn}" if display_name else f"ИНН {inn}"
    return {
        "label": label,
        "value": val or display_name,
        "inn": inn or None,
        "name": display_name,
        "name_full": full_n or None,
        "name_short": short_n or None,
        "ogrn": str(d.get("ogrn") or "").strip() or None,
        "source": "DaData",
    }


def _dadata_party_by_inn(inn):
    key = (os.environ.get(DADATA_API_KEY_ENV) or "").strip()
    if not key:
        return None
    try:
        from dadata import Dadata

        with Dadata(key) as client:
            rows = client.find_by_id("party", inn)
    except Exception:
        return None
    if not rows:
        return None
    item = rows[0]
    parsed = _dadata_party_from_item(item, inn_fallback=inn)
    if not parsed:
        return None
    return {
        "inn": parsed["inn"] or str(inn).strip(),
        "name": parsed["name"] or (parsed["value"] or ""),
        "ogrn": parsed["ogrn"] or "",
        "source": "DaData",
        "name_full": (parsed.get("name_full") or "") or "",
        "name_short": (parsed.get("name_short") or "") or "",
    }


def dadata_party_suggest(query: str):
    """
    Подсказки по организациям (Suggest API «party»), для автодополнения в UI.
    Требуется DADATA_API_KEY; ключ не уходит в браузер — только ответ через бэкенд.
    """
    key = (os.environ.get(DADATA_API_KEY_ENV) or "").strip()
    if not key:
        return {"suggestions": [], "configured": False, "error": None}
    q = (query or "").strip()
    if len(q) < 2:
        return {"suggestions": [], "configured": True, "error": None}
    if len(q) > 100:
        q = q[:100]
    try:
        from dadata import Dadata

        with Dadata(key) as client:
            rows = client.suggest("party", q, count=12)
    except Exception:
        return {
            "suggestions": [],
            "configured": True,
            "error": "Не удалось получить подсказки. Проверьте ключ или повторите позже.",
        }
    out = []
    for item in rows or []:
        row = _dadata_party_from_item(item)
        if row:
            out.append(row)
    return {"suggestions": out, "configured": True, "error": None}


def _egrul_collect_orgs(obj, acc):
    if isinstance(obj, dict):
        inn = obj.get("inn") or obj.get("i")
        name = (
            obj.get("n")
            or obj.get("name")
            or obj.get("nm")
            or obj.get("Наименование")
        )
        if inn and name and str(name).strip():
            acc.append(
                {
                    "inn": str(inn).strip(),
                    "name": str(name).strip(),
                    "ogrn": str(
                        obj.get("ogrn") or obj.get("o") or obj.get("ОГРН") or ""
                    ).strip(),
                    "source": "ФНС (egrul.nalog.ru)",
                }
            )
        for k, v in obj.items():
            if k == "rows" and isinstance(v, str):
                try:
                    _egrul_collect_orgs(json.loads(v), acc)
                except (json.JSONDecodeError, TypeError):
                    pass
            else:
                _egrul_collect_orgs(v, acc)
    elif isinstance(obj, list):
        for el in obj:
            _egrul_collect_orgs(el, acc)


def _egrul_search_query(query, name_eq_on):
    sess = requests.Session()
    sess.headers["User-Agent"] = ORG_DOMAIN_UA
    sess.get("https://egrul.nalog.ru/", timeout=ORG_EGRUL_TIMEOUT_SEC)
    payload = {
        "vyp3CaptchaToken": "",
        "page": "",
        "query": query,
        "nameEq": "on" if name_eq_on else "",
        "region": "",
        "PreventChromeAutocomplete": "",
    }
    r = sess.post(
        "https://egrul.nalog.ru/",
        data=payload,
        timeout=ORG_EGRUL_TIMEOUT_SEC,
    )
    r.raise_for_status()
    token = (r.json() or {}).get("t")
    if not token:
        return None
    ts = int(time.time() * 1000)
    r2 = sess.get(
        f"https://egrul.nalog.ru/search-result/{token}",
        params={"r": ts, "_": ts},
        timeout=ORG_EGRUL_TIMEOUT_SEC,
    )
    r2.raise_for_status()
    return r2.json()


def _crt_sh_domains_for_phrase(phrase, session):
    clean = phrase.strip().replace("%", "")[:140]
    if not clean:
        return set(), "Пустая строка для поиска в crt.sh."
    q = f"%{clean}%"
    try:
        r = session.get(
            "https://crt.sh/",
            params={"q": q, "output": "json", "exclude": "expired"},
            timeout=ORG_CRTSH_TIMEOUT_SEC,
        )
        if r.status_code != 200:
            return set(), f"crt.sh вернул код {r.status_code}."
        text = (r.text or "").strip()
        if not text:
            return set(), None
        try:
            rows = json.loads(text)
        except json.JSONDecodeError:
            return (
                set(),
                "Не удалось разобрать ответ crt.sh (часто при перегрузке сервиса). Повторите запрос позже.",
            )
        if not isinstance(rows, list):
            return set(), "Неожиданный формат ответа crt.sh."
    except requests.RequestException as e:
        return set(), str(e)

    doms = set()
    for row in rows[:ORG_CRTSH_MAX_ROWS]:
        nv = row.get("name_value") or ""
        if isinstance(nv, str):
            for line in nv.splitlines():
                h = _org_normalize_ct_hostname(line)
                rd = _org_registered_domain(h)
                if rd:
                    doms.add(rd)
        if len(doms) >= ORG_MAX_DOMAINS_RETURN * 4:
            break
    return doms, None


def _dedupe_preserve(seq):
    seen = set()
    out = []
    for x in seq:
        k = x.strip().lower()
        if not k or k in seen:
            continue
        seen.add(k)
        out.append(x.strip())
    return out


def _org_build_crt_queries(name_variants):
    """
    Из сырых наименований: убрать ОПФ → транслитерация → уникальные латинские токены для crt.sh.
    Возвращает (список токенов, метаданные для отображения).
    """
    queries = []
    seen_tok = set()
    for raw in name_variants:
        raw = (raw or "").strip()
        if not raw:
            continue
        stripped = _org_strip_legal_form(raw) or raw
        token = _org_transliterate_to_latin_token(stripped)
        if not token:
            token = _org_transliterate_to_latin_token(raw)
        if len(token) < 2:
            continue
        if token in seen_tok:
            continue
        seen_tok.add(token)
        queries.append(
            {
                "token": token,
                "name_raw": raw,
                "name_stripped": stripped,
            }
        )
    tokens = [q["token"] for q in queries]
    return tokens, queries


def search_org_domains(query_raw):
    """
    Наименование компании (ИНН/DaData/ФНС или ввод пользователя) → удаление ОПФ →
    транслитерация → поиск в crt.sh; в результате только регистрируемые домены (без поддоменов).
    """
    q = (query_raw or "").strip()
    if not q:
        return {
            "error": (
                "Введите ИНН юридического лица (10 цифр), ИП (12 цифр) "
                "или фрагмент наименования организации."
            ),
        }
    if len(q) > 256:
        return {"error": "Строка запроса слишком длинная."}

    is_inn = bool(re.fullmatch(r"\d{10}|\d{12}", q))
    org_rows = []
    name_candidates = []

    if is_inn:
        dd = _dadata_party_by_inn(q)
        if dd:
            org_rows.append(
                {
                    "inn": dd["inn"],
                    "name": dd["name"],
                    "ogrn": dd["ogrn"],
                    "source": dd["source"],
                }
            )
            if dd.get("name_short"):
                name_candidates.append(dd["name_short"])
            if dd.get("name_full") and dd["name_full"] != dd.get("name_short"):
                name_candidates.append(dd["name_full"])

        try:
            data = _egrul_search_query(q, name_eq_on=True)
            if data:
                found = []
                _egrul_collect_orgs(data, found)
                for rec in found:
                    if rec["inn"] != q:
                        continue
                    org_rows.append(rec)
                    if rec.get("name"):
                        name_candidates.append(rec["name"])
        except requests.RequestException:
            pass

        seen_org = set()
        uniq_orgs = []
        for r in org_rows:
            key = (r.get("inn", ""), r.get("name", ""))
            if key in seen_org:
                continue
            seen_org.add(key)
            uniq_orgs.append(r)
        org_rows = uniq_orgs
        name_candidates = _dedupe_preserve(name_candidates)

        if not name_candidates:
            return {
                "error": (
                    "Не удалось получить наименование по ИНН: сервис ФНС (egrul.nalog.ru) "
                    "недоступен с сервера или вернул пустой ответ. Укажите "
                    "DADATA_API_KEY в .env (см. dadata.ru) или введите наименование "
                    "организации вручную."
                ),
                "orgs": org_rows,
            }
    else:
        if len(q) < 2:
            return {
                "error": "Для поиска по названию введите не менее 2 символов.",
            }
        org_rows = [
            {"inn": "", "name": q, "ogrn": "", "source": "Запрос пользователя"},
        ]
        name_candidates = [q]

    crt_tokens, _ = _org_build_crt_queries(name_candidates)
    crt_tokens = crt_tokens[:ORG_MAX_CRT_QUERIES]

    if not crt_tokens:
        return {
            "error": (
                "Не удалось построить латинский запрос для crt.sh после удаления формы "
                "собственности (ООО, АО и т.д.) и транслитерации. Введите более полное "
                "наименование или используйте ИНН с DaData."
            ),
            "orgs": org_rows,
        }

    session = requests.Session()
    session.headers["User-Agent"] = ORG_DOMAIN_UA

    all_domains = set()
    side_errors = []
    for token in crt_tokens:
        doms, err = _crt_sh_domains_for_phrase(token, session)
        all_domains |= doms
        if err:
            side_errors.append(err)

    sorted_domains = sorted(all_domains, key=lambda x: x.lower())
    total_found = len(sorted_domains)
    truncated = total_found > ORG_MAX_DOMAINS_RETURN
    sorted_domains = sorted_domains[:ORG_MAX_DOMAINS_RETURN]

    if not sorted_domains:
        msg = (
            "По запросу не найдено имён хостов в открытых данных о TLS-сертификатах (crt.sh). "
            "Попробуйте другую формулировку наименования или повторите позже."
        )
        if side_errors:
            msg = side_errors[0]
        return {
            "error": msg,
            "orgs": org_rows,
            "partial_errors": side_errors,
        }

    return {
        "query": q,
        "orgs": org_rows,
        "domains": sorted_domains,
        "domains_total": total_found,
        "domains_truncated": truncated,
        "partial_errors": side_errors,
    }
