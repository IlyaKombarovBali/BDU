"""Set hljs language-xml on code blocks that are clearly XML (escaped in HTML)."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "templates" / "owasp_dotnet_security_cheat_sheet_article.html"

XML_HINT = re.compile(
    r"&lt;(\?xml|configuration|system\.web|system\.webServer|httpCookies|authentication|compilation|trace|add\s|rewrite)",
    re.I,
)


def main() -> None:
    s = P.read_text(encoding="utf-8")

    def sub(m: re.Match[str]) -> str:
        pre, cls, mid, code, end = m.groups()
        if cls != "language-csharp":
            return m.group(0)
        if XML_HINT.search(code):
            cls = "language-xml"
        return f"{pre}{cls}{mid}{code}{end}"

    s2 = re.sub(
        r'(<pre><code class=")(language-csharp)(">)([\s\S]*?)(</code></pre>)',
        sub,
        s,
    )
    P.write_text(s2, encoding="utf-8")
    print("patched", P.name)


if __name__ == "__main__":
    main()
