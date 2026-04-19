"""Translate navigable text in REST Security cheat sheet HTML fragment to Russian."""
from __future__ import annotations

import re
import time
from pathlib import Path

from bs4 import BeautifulSoup, NavigableString, Comment
from deep_translator import GoogleTranslator

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "templates" / "_owasp_rest_article_extracted.html"
OUT = ROOT / "templates" / "owasp_rest_security_article.html"

SKIP_PARENTS = frozenset({"code", "pre", "script", "style"})
SEP = "\n\u241e\u241eSEP\u241e\u241e\n"
MAX_CHUNK = 4200


def eligible_string(node: NavigableString) -> bool:
    if isinstance(node, Comment):
        return False
    parent = getattr(node, "parent", None)
    if parent is None:
        return False
    chain = []
    while parent is not None and parent.name not in (None, "[document]"):
        chain.append(parent.name)
        parent = parent.parent
    if any(n in SKIP_PARENTS for n in chain):
        return False
    if "cheatsheet-code-window" in chain:
        return False
    t = str(node)
    if not t.strip():
        return False
    if re.fullmatch(r"[\s\d\W]+", t):
        return False
    return True


def translate_batches(strings: list[str], translator: GoogleTranslator) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    cur = 0

    def flush_buf() -> None:
        nonlocal buf, cur, out
        if not buf:
            return
        payload = SEP.join(buf)
        try:
            tr = translator.translate(payload)
        except Exception as e:  # noqa: BLE001
            print("translate error", e, "retrying single...")
            tr = SEP.join(translator.translate(s) for s in buf)
        parts = tr.split(SEP)
        if len(parts) != len(buf):
            print("split mismatch", len(parts), len(buf), "fallback per string")
            parts = [translator.translate(s) for s in buf]
        out.extend(parts)
        buf = []
        cur = 0
        time.sleep(0.35)

    for s in strings:
        piece = s
        if len(piece) > MAX_CHUNK:
            flush_buf()
            out.append(translator.translate(piece))
            time.sleep(0.35)
            continue
        if cur + len(piece) + len(SEP) * len(buf) > MAX_CHUNK:
            flush_buf()
        buf.append(piece)
        cur += len(piece)
    flush_buf()
    return out


def postprocess_ru_spacing(s: str) -> str:
    s = re.sub(r"([\w\u0400-\u04FF\)\]\>])(<a\s)", r"\1 \2", s)
    s = re.sub(r"(</a>)([\w\u0400-\u04FF\(])", r"\1 \2", s)
    s = re.sub(r"([\w\u0400-\u04FF])(<code)", r"\1 \2", s)
    s = re.sub(r"(</code>)([\w\u0400-\u04FF\(])", r"\1 \2", s)
    s = re.sub(r"(>)([а-яёА-ЯЁ])", r"\1 \2", s)
    return s


def postprocess_rest_acronyms(s: str) -> str:
    """Undo common wrong translations of the REST acronym and expansion."""
    s = re.sub(r">\s*ОТДЫХ\s*</a>", ">REST</a>", s)
    s = s.replace(">ОТДЫХ<", ">REST<")
    s = re.sub(
        r"\(или\s*<strong>\s*РЭ\s*</strong>\s*презентационный\s*<strong>\s*С\s*</strong>\s*Тейт\s*<strong>\s*Т\s*</strong>\s*рансфер\)",
        "(или <strong>RE</strong>presentational <strong>S</strong>tate <strong>T</strong>ransfer)",
        s,
        flags=re.I,
    )
    s = s.replace(
        "стандартных HTTP-команд и кодов ошибок при поиске или устранении ненужных различий",
        "стандартных HTTP-глаголов и кодов ошибок в целях устранения лишних расхождений",
    )
    return s


def main() -> None:
    html = SRC.read_text(encoding="utf-8")
    html = html.replace("{% raw %}", "<!--JINJA_RAW_OPEN-->").replace(
        "{% endraw %}",
        "<!--JINJA_RAW_CLOSE-->",
    )
    soup = BeautifulSoup(html, "html.parser")
    nodes: list[NavigableString] = []
    for el in soup.find_all(string=True):
        if isinstance(el, NavigableString) and eligible_string(el):
            nodes.append(el)
    originals = [str(n) for n in nodes]
    print("strings", len(originals), "chars", sum(len(s) for s in originals))
    translator = GoogleTranslator(source="en", target="ru")
    translated = translate_batches(originals, translator)
    for n, t in zip(nodes, translated, strict=True):
        n.replace_with(t)
    html_out = str(soup)
    html_out = html_out.replace("<!--JINJA_RAW_OPEN-->", "{% raw %}").replace(
        "<!--JINJA_RAW_CLOSE-->",
        "{% endraw %}",
    )
    html_out = postprocess_ru_spacing(html_out)
    html_out = postprocess_rest_acronyms(html_out)
    OUT.write_text(html_out, encoding="utf-8")
    print("Wrote", OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
