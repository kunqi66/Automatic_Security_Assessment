"""Source 规格表（设计文档 §2 的 sources）—— **纯数据 + 匹配函数，零算法**。

设计原则（设计文档 §2）：**规格与算法分离**。这张表是「用户输入从哪些符号进来」
的唯一答案，新增一个框架或一条输入通道只改表，不改传播代码。

**符号用点分后缀匹配，不绑定模块前缀**，原因是同一个入口有三种写法且都常见：

```python
from flask import request;  request.args.get("id")      # flask.request.args.get
import flask;               flask.request.args.get("id") # 带模块前缀
```

三种写法在语义上是同一个 source，规则库里写成三条只会让表越来越长。
匹配按**段边界**做（`_matches`），所以 `myrequest.args.get` 不会被误判成
`request.args.get` —— 「前缀相同就当同一个」那类实现会在这种地方静默误报。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """一条 source 规则。

    - `kind="call"`：`symbol` 是**函数名**（`request.args.get`），在调用点匹配。
    - `kind="value"`：`symbol` 是**对象/属性名**（`request.json`、`sys.argv`），
      在属性读取与下标取值处匹配（`request.json["k"]`、`sys.argv[1]`）。

    区分这两者不是洁癖：`request.json` 只在**读属性**时是 source，
    而 `request.args.get` 只在**被调用**时才是 —— 把两者混成一类，
    `request.json` 出现在 `request.json.get(...)` 的接收者位置时会被重复计污点，
    `origin` 也会指错行。
    """

    symbol: str
    framework: str  # flask | fastapi | django | generic
    channel: str  # http_param | http_body | cookie | header | env | argv | stdin | db_read
    kind: str  # call | value
    #: 是否**只允许精确相等**。默认 False（点分后缀匹配，吸收模块前缀差异）。
    #: 单段符号必须设 True：`input` 用后缀匹配会把 `parser.input()` 这种
    #: 与 stdin 毫无关系的方法调用判成 source，而这类误报在报告里
    #: 与真漏洞长得一模一样，只能靠人逐个复核 —— 代价远高于漏掉一个变异写法。
    exact_name: bool = False
    #: 该入口的数据是否**默认**来自攻击者。恒为 True 的今天留着这个字段，
    #: 是为了让「哪些入口需要显式配置才可信」这类判断有地方落。
    tainted_by_default: bool = True


#: 输入通道取值（B4 设计 §3.3 冻结的集合）。
CHANNELS: frozenset[str] = frozenset(
    {"http_param", "http_body", "cookie", "header", "env", "argv", "stdin", "db_read"}
)


SOURCES: tuple[SourceSpec, ...] = (
    # ---------- Flask（PRD §7.1 ③）----------
    SourceSpec("request.args.get", "flask", "http_param", "call"),
    SourceSpec("request.args", "flask", "http_param", "value"),
    SourceSpec("request.form.get", "flask", "http_body", "call"),
    SourceSpec("request.form", "flask", "http_body", "value"),
    SourceSpec("request.values.get", "flask", "http_param", "call"),
    SourceSpec("request.values", "flask", "http_param", "value"),
    SourceSpec("request.json", "flask", "http_body", "value"),
    SourceSpec("request.get_json", "flask", "http_body", "call"),
    SourceSpec("request.data", "flask", "http_body", "value"),
    SourceSpec("request.cookies.get", "flask", "cookie", "call"),
    SourceSpec("request.cookies", "flask", "cookie", "value"),
    SourceSpec("request.headers.get", "flask", "header", "call"),
    SourceSpec("request.headers", "flask", "header", "value"),
    SourceSpec("request.view_args", "flask", "http_param", "value"),
    SourceSpec("request.files", "flask", "http_body", "value"),
    SourceSpec("request.full_path", "flask", "http_param", "value"),
    SourceSpec("request.path", "flask", "http_param", "value"),
    SourceSpec("request.url", "flask", "http_param", "value"),
    SourceSpec("request.get_data", "flask", "http_body", "call"),
    # ---------- FastAPI（显式从 Request 对象取值的写法）----------
    SourceSpec("request.query_params", "fastapi", "http_param", "value"),
    SourceSpec("request.path_params", "fastapi", "http_param", "value"),
    SourceSpec("request.headers", "fastapi", "header", "value"),
    SourceSpec("request.cookies", "fastapi", "cookie", "value"),
    SourceSpec("request.json", "fastapi", "http_body", "call"),
    SourceSpec("request.body", "fastapi", "http_body", "call"),
    SourceSpec("request.form", "fastapi", "http_body", "call"),
    # ---------- Django（同类框架，表驱动即可覆盖）----------
    SourceSpec("request.GET.get", "django", "http_param", "call"),
    SourceSpec("request.GET", "django", "http_param", "value"),
    SourceSpec("request.POST.get", "django", "http_body", "call"),
    SourceSpec("request.POST", "django", "http_body", "value"),
    SourceSpec("request.COOKIES", "django", "cookie", "value"),
    SourceSpec("request.META", "django", "header", "value"),
    # ---------- 通用（PRD §7.1 ③ 的「通用」一组）----------
    SourceSpec("input", "generic", "stdin", "call", exact_name=True),
    SourceSpec("sys.argv", "generic", "argv", "value"),
    SourceSpec("os.environ", "generic", "env", "value"),
    SourceSpec("os.environ.get", "generic", "env", "call"),
    SourceSpec("os.getenv", "generic", "env", "call"),
    SourceSpec("sys.stdin.read", "generic", "stdin", "call"),
    SourceSpec("sys.stdin.readline", "generic", "stdin", "call"),
    # ---------- 二阶注入：从库里读出来的数据也是不可信输入 ----------
    # 例：`row = cursor.fetchone(); cursor.execute("... id=" + row[0])` —— 二阶 SQL 注入。
    # 列进表里意味着「库里存过的用户数据再回流到 sink」能被追上，代价是
    # 纯内部报表类代码可能因此被报（有 sanitizer 与人工复核兜底）。
    SourceSpec("cursor.fetchone", "generic", "db_read", "call"),
    SourceSpec("cursor.fetchall", "generic", "db_read", "call"),
)

#: 调用索引：点分名 → 规则。同一符号可能同时存在 call / value 两条规则
#: （`request.cookies.get` 与 `request.cookies`），所以用元组不用单值。
_CALL_INDEX: dict[str, tuple[SourceSpec, ...]] = {}
_VALUE_INDEX: dict[str, tuple[SourceSpec, ...]] = {}
for _spec in SOURCES:
    _target = _CALL_INDEX if _spec.kind == "call" else _VALUE_INDEX
    _target[_spec.symbol] = (*_target.get(_spec.symbol, ()), _spec)


def _matches(dotted: str, symbol: str, *, exact: bool = False) -> bool:
    """**段边界感知**的匹配：完全相等，或以 `.` 结尾的符号为后缀。

    `flask.request.args.get` 命中 `request.args.get`；
    `myrequest.args.get` **不**命中（它在 `.` 边界上不成立）。
    `exact=True` 时只接受完全相等（见 `SourceSpec.exact_name`）。
    """
    if exact:
        return dotted == symbol
    return dotted == symbol or dotted.endswith("." + symbol)


def match_call_source(dotted: str) -> SourceSpec | None:
    """按被调函数名匹配 source；无匹配返回 None。"""
    if not dotted:
        return None
    for symbol, specs in _CALL_INDEX.items():
        if _matches(dotted, symbol, exact=specs[0].exact_name):
            return specs[0]
    return None


def match_object_source(dotted: str) -> SourceSpec | None:
    """按属性链匹配 value 型 source（`request.args` / `sys.argv` / `request.json`）。"""
    if not dotted:
        return None
    for symbol, specs in _VALUE_INDEX.items():
        if _matches(dotted, symbol, exact=specs[0].exact_name):
            return specs[0]
    return None


#: FastAPI「Depends 注入参数」的默认值函数名（PRD §7.1 ③ 的 FastAPI 一行）。
#:
#: FastAPI 的路由参数不是通过 `request.args` 进来的，而是**由框架按签名注入** ——
#: 只看符号表的话，`def get_user(uid: str = Query(...))` 里的 `uid` 与普通局部变量
#: 长得一模一样，整类漏洞会全漏。识别它有两个互补特征，缺一不可：
#: ① 默认值是这几个标注函数的调用；② 参数名出现在路由路径模板里（见 taint.py）。
PARAM_SOURCE_DEFAULTS: frozenset[str] = frozenset(
    {"Query", "Path", "Body", "Form", "Header", "Cookie", "Depends", "File", "UploadFile"}
)

#: 注解为这几个类型的参数本身即「请求对象」，其属性是 source。
REQUEST_TYPES: frozenset[str] = frozenset({"Request", "starlette.requests.Request"})
