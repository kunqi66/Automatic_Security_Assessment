"""Jinja2 渲染：一份 `ReportData` → HTML / Markdown（B6 设计 §4.1）。

## 一套数据三格式的实现方式

```
{REPORT_ROOT}/reports/{id}/report.html   ← templates/report.html.j2  + partials/*.j2
{REPORT_ROOT}/reports/{id}/report.md     ← templates/report.md.j2    + partials/md_*.j2
{REPORT_ROOT}/reports/{id}/report.pdf    ← 上面前者的 HTML 交给 Chromium（pdf.py）
```

HTML 是**主模板**，Markdown 复用同一套章节顺序与字段（设计 §7.2），
只是把呈现语法从标签换成 Markdown 语法。**格式特有内容在模板层解决，不新增数据字段。**

## ⚠️ 两个 Environment，autoescape 的差别是有意的

`report.html.j2` 里渲染的是**被评估项目的源码片段、LLM 输出、项目名**
—— 全都是**不可信数据**。默认的 `select_autoescape` 按**文件名后缀**判断，
而我们的模板叫 `report.html.j2`，后缀是 `.j2`，**不会被自动转义**。
所以这里显式 `autoescape=True`，而不是写 `select_autoescape(["html"])` 然后
以为它生效了 —— 那个写法会让报告直接变成存储型 XSS 的投递平台。

Markdown 用 `autoescape=False`（它本来就是纯文本格式），改用下面三个过滤器
在**该防的地方**防：表格单元格走 `md_cell`，代码/补丁走 `md_code`（围栏代码块），
正文散文走 `md_text`。Markdown 的注入面比 HTML 小得多（react-markdown 默认
不渲染裸 HTML），但「小得多」不是「没有」，尤其是表格 —— 一个含 `|` 的标题
就能把整张表的列错位，读者看到的是**错误的数字对应关系**。
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from markupsafe import Markup

from app.report import charts
from app.report.types import GRADE_LABEL, SEVERITY_LABEL, STATUS_LABEL, ReportData

TEMPLATES_DIR = Path(__file__).parent / "templates"

#: `<` 紧跟字母、`/`、`!` 时才当标签处理。
#: 这样 `a < b` 这种比较不会被误伤，而 `<script>` / `</div>` / `<!--` 全被中和。
_TAG_LIKE = re.compile(r"<(?=[A-Za-z/!])")


# ---------------------------------------------------------------------------
# Markdown 过滤器
# ---------------------------------------------------------------------------


def md_cell(value: object) -> str:
    """表格单元格：管道符、换行、裸 HTML 全部处理掉。

    换行必须换成空格 —— Markdown 表格里出现换行会把一行拆成两行，
    后面所有行的列都会错位。**列错位不会报错，只会给出错误的对应关系**，
    这比渲染失败危险得多。
    """
    text = "" if value is None else str(value)
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return _TAG_LIKE.sub("&lt;", text.replace("|", r"\|"))


def md_text(value: object) -> str:
    """正文散文（描述、叙事、建议）：只中和裸 HTML 标签，保留换行。"""
    text = "" if value is None else str(value)
    return _TAG_LIKE.sub("&lt;", text)


def md_code(value: object, language: str = "") -> str:
    """围栏代码块。

    围栏本身也要防：内容里若出现三个反引号，就能提前闭合围栏、把后面的内容
    变成正文。用四个反引号起步并在内容里升级到「比内容最长反引号串多一个」
    是标准做法，这里按内容动态取围栏长度。
    """
    text = "" if value is None else str(value).rstrip("\n")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{text}\n{fence}"


#: 两个 Environment 共用的一组全局量。
#:
#: **抽成一份而不是各写一遍**：HTML 与 Markdown 的章节顺序、字段、术语必须
#: 逐字一致（设计 §7.2「一套数据三格式」），而「两个 env 的 globals 漂移」
#: 是那种只在某一份格式上出现的错 —— 另一份读起来完全正常，没人会去比对。
#:
#: 术语映射表放在这里而不是写在模板里，是因为模板里出现「critical → 严重」
#: 这样的映射就等于把术语定义搬进了呈现层，而术语规范（PRD §6）是数据层的约定。
_GLOBALS: dict[str, object] = {
    "GRADE_LABEL": GRADE_LABEL,
    "SEVERITY_LABEL": SEVERITY_LABEL,
    "STATUS_LABEL": STATUS_LABEL,
    # `md_*` 既注册成 filter 也注册成 global：模板里两种写法都有用 ——
    # `{{ x | md_cell }}` 在表达式里更顺手，`{{ md_code(payload) }}` 在
    # 需要传第二个参数（语言名）时更清楚。注册两次的成本是零。
    "md_cell": md_cell,
    "md_text": md_text,
    "md_code": md_code,
}


@lru_cache(maxsize=1)
def _html_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR, encoding="utf-8"),
        # ★ 见模块文档：显式 True，不依赖后缀嗅探
        autoescape=True,
        # 变量缺失即报错：模板里 `{{ vuln.typo_field }}` 静默渲染成空串
        # 会让报告少一个字段而没有任何人发现
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals.update(
        severity_bar_chart=charts.severity_bar_chart,
        type_donut=charts.type_donut,
        type_legend=charts.type_legend,
        score_ring=charts.score_ring,
        **_GLOBALS,
    )
    return env


@lru_cache(maxsize=1)
def _md_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR, encoding="utf-8"),
        # 见模块文档：Markdown 是纯文本格式，HTML 实体会原样出现在报告里。
        # 注入面由 `md_cell` / `md_text` / `md_code` 三个过滤器负责，而不是 autoescape
        autoescape=False,  # noqa: S701
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(md_cell=md_cell, md_text=md_text, md_code=md_code)
    env.globals.update(**_GLOBALS)
    return env


@lru_cache(maxsize=1)
def _inline_css() -> Markup:
    """把 CSS 读进内存供 HTML 内联。

    报告 HTML 要能整段塞进 iframe（B6 设计 §3.1 preview）且**零外部资源**
    —— 外链 CSS 在 iframe 里会因为源不同而加载失败，报告会变成一坨无样式的文字。
    """
    css = (TEMPLATES_DIR / "assets" / "report.css").read_text(encoding="utf-8")
    # 这段 CSS 是本仓库里的静态资产，不是任何运行时输入；
    # 转义它反而会让 `>` 选择器变成 `&gt;` 而失效
    return Markup(f"<style>\n{css}\n</style>")  # noqa: S704


def render_html(data: ReportData) -> str:
    """HTML（内联 CSS + 内联 SVG，零外部资源）。"""
    return _html_env().get_template("report.html.j2").render(d=data, inline_css=_inline_css())


def render_markdown(data: ReportData) -> str:
    """Markdown（图表降级为表格，见 `report.md.j2`）。"""
    return _md_env().get_template("report.md.j2").render(d=data)


__all__ = ["md_cell", "md_code", "md_text", "render_html", "render_markdown"]
