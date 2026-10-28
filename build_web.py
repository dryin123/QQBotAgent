#!/usr/bin/env python3
"""把 web/index.html 注入 main.py，保持单文件可分发。

开发时改 web/index.html，跑这个脚本把内容写回 main.py。
main.py 里 HTML_TEMPLATE 那段是生成物，不要手改，下次构建会覆盖。
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
START = ROOT / "main.py"
WEB = ROOT / "web" / "index.html"
PATTERN = re.compile(r'HTML_TEMPLATE = """(.*?)"""\n', re.S)


def main() -> int:
    if not WEB.exists():
        print(f"找不到 {WEB}", file=sys.stderr)
        return 1
    html = WEB.read_text(encoding="utf-8")
    if '"""' in html:
        print("web/index.html 含三引号，无法安全注入", file=sys.stderr)
        return 1
    src = START.read_text(encoding="utf-8")
    if not PATTERN.search(src):
        print("main.py 里找不到 HTML_TEMPLATE 块", file=sys.stderr)
        return 1

    new = PATTERN.sub(lambda m: 'HTML_TEMPLATE = """' + html + '"""\n', src, count=1)
    START.write_text(new, encoding="utf-8")
    print(f"已注入 {len(html.splitlines())} 行 / {len(html)} 字符到 main.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
