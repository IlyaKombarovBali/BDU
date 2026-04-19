"""Extract OWASP Node.js Security cheat sheet article body and emit a Jinja-friendly HTML fragment."""
from __future__ import annotations

import html as html_lib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "owasp" / "cheatsheets" / "Nodejs_Security_Cheat_Sheet.html"
OUT = ROOT / "templates" / "_owasp_nodejs_article_extracted.html"


def strip_spans(s: str) -> str:
    s = re.sub(r"<span[^>]*>", "", s)
    s = re.sub(r"</span>", "", s)
    return s


def fix_cheatsheet_links(s: str) -> str:
    def rep(m: re.Match[str]) -> str:
        href = m.group(1)
        if href.startswith(("http://", "https://", "#", "mailto:")):
            return m.group(0)
        if "/" in href or href.startswith(".."):
            return m.group(0)
        return f'href="/owasp/cheatsheets/{href}"'

    return re.sub(r'href="([^"]+)"', rep, s)


def detect_lang(code: str) -> str:
    c = code.lstrip()
    if re.search(r"^apiVersion:", c, re.M):
        return "language-yaml"
    if c.startswith("{") and ('"dependencies"' in c or '"scripts"' in c or '"name"' in c[:120]):
        return "language-json"
    if re.search(r"^FROM\s+", c, re.M | re.I):
        return "language-dockerfile"
    if re.search(r"<\?xml|<!DOCTYPE\s+html|<web-app", c, re.I):
        return "language-xml"
    if "{%" in code or "{{" in code:
        return "language-markup"
    return "language-javascript"


def escape_code_for_html(code: str) -> str:
    return code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def repl_highlight(m: re.Match[str]) -> str:
    inner = m.group(1)
    stripped = strip_spans(inner)
    cm = re.search(r"<code>(.*?)</code>", stripped, re.DOTALL)
    code = cm.group(1).strip() if cm else stripped.strip()
    code = html_lib.unescape(code)
    lang = detect_lang(code)
    code_html = escape_code_for_html(code)
    if lang == "language-markup":
        return (
            '<div class="cheatsheet-code-window">{% raw %}<pre><code class="language-markup">'
            + code_html
            + "</code></pre>{% endraw %}</div>"
        )
    return (
        f'<div class="cheatsheet-code-window"><pre><code class="{lang}">'
        + code_html
        + "</code></pre></div>"
    )


def main() -> None:
    lines = SRC.read_text(encoding="utf-8").splitlines()
    body = "\n".join(lines[3616:4135])
    body = re.sub(
        r'<a class="headerlink"[^>]*>.*?</a>',
        "",
        body,
        flags=re.DOTALL,
    )
    body = fix_cheatsheet_links(body)
    body = re.sub(
        r'<div class="highlight"><pre><span></span><code>(.*?)</code></pre></div>',
        repl_highlight,
        body,
        flags=re.DOTALL,
    )
    OUT.write_text(body, encoding="utf-8")
    print("Wrote", OUT.relative_to(ROOT), len(body), "chars")


if __name__ == "__main__":
    main()
