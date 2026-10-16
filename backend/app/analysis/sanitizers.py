"""Sanitizer 规格表 + 净化强度判定（设计文档 §2 的 sanitizers）。

**这个文件直接决定误报数**（设计文档 §4.4 末尾：靶场误报主要来源就在这里）。
两个判定函数是重点：

- `is_parametric_sql()` —— `cursor.execute(sql, params)` 里 `params` 是绑定值
  而非 SQL 文本。没有它，`(uid,)` 这个元组的污点会被当成注入载荷报出来，
  而参数化查询恰恰是**修好了**的代码。这是最丢人的一类误报。
- `is_whitelist_guard()` —— 反向守卫 `if x not in ALLOWED: return`。
  识别不了它，所有「先白名单校验再使用」的正确代码都会被报成漏洞。

**净化判定为什么不在传播阶段做**（设计文档 §4.4）：因为「完全净化」永远是
相对于**某一条 source→sink 路径**、**某个具体 vuln_type** 而言的。
`os.path.basename()` 对路径穿越有效、对 SQL 注入完全无效 —— 同一个值在
传播时无法判断它「算不算干净」，只有到了 sink 才知道要对谁干净。
所以传播阶段只**累积**已命中的 sanitizer，判定推迟到 sink 匹配阶段。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.analysis.parser import call_args, call_keyword_args, dotted_name, snippet_of
from app.analysis.types import VulnType

# ---------------------------------------------------------------------------
# 规格表
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SanitizerSpec:
    """一条净化规则。

    - `neutralizes`：能中和的 vuln_type 集合。**空集合**只对 `strength="partial"`
      的弱净化成立 —— 语义是「降级信号，不改变报不报」。
    - `strength="full"`：命中即**不可能**携带该类型的注入载荷 → 该路径不报。
    - `strength="partial"`：只改变表示形态 → 仍报，但 `confidence ×0.6`
      且 `guard_blocked=True`（对应 ORM 的 `partially_sanitized` 语义）。
    """

    symbol: str
    category: str  # int | filename | shell | sql_param | whitelist | escape | orm | weak
    neutralizes: tuple[VulnType, ...] = ()
    strength: str = "full"
    exact_name: bool = False


SANITIZERS: tuple[SanitizerSpec, ...] = (
    # ---------------- 整型化：转换成功即不可能携带注入载荷 ----------------
    # `int("1; drop table")` 直接抛异常，能走到 sink 的一定是纯数字
    SanitizerSpec(
        "int",
        "int",
        (VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION, VulnType.PATH_TRAVERSAL),
        "full",
        exact_name=True,
    ),
    SanitizerSpec(
        "float",
        "int",
        (VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION, VulnType.PATH_TRAVERSAL),
        "full",
        exact_name=True,
    ),
    # ---------------- 文件名：剥掉目录成分，路径穿越不再成立 ----------------
    SanitizerSpec("secure_filename", "filename", (VulnType.PATH_TRAVERSAL, VulnType.FILE_UPLOAD)),
    # `os.path.basename` 只对**路径穿越**有效：`../../etc/passwd` → `passwd`，
    # 目录上跳失效。但它对 SQL 注入、命令注入**完全无效** ——
    # `basename("1; rm -rf /")` 原样返回。把它的 neutralizes 写成「全部」
    # 是这个文件里最容易犯的错，也是「净化必须按 vuln_type 判定」的最好例子。
    SanitizerSpec("os.path.basename", "filename", (VulnType.PATH_TRAVERSAL,)),
    SanitizerSpec("basename", "filename", (VulnType.PATH_TRAVERSAL,)),
    # ---------------- 命令：shell 转义 / 分词后列表传参 ----------------
    SanitizerSpec("shlex.quote", "shell", (VulnType.COMMAND_INJECTION,)),
    # `shlex.split` 把字符串拆成列表，配合 `shell=False` 时参数不过 shell ——
    # 真正的安全条件是两者同时成立，`requires_shell` 那一侧会把 shell=True 的情况拦回来
    SanitizerSpec("shlex.split", "shell", (VulnType.COMMAND_INJECTION,)),
    # ---------------- 转义：XSS ----------------
    SanitizerSpec("escape", "escape", (VulnType.XSS,)),
    SanitizerSpec("html.escape", "escape", (VulnType.XSS,)),
    SanitizerSpec("markupsafe.escape", "escape", (VulnType.XSS,)),
    # ---------------- 弱净化：只改表示形态，不消除语义（partial） ----------------
    # 这几个**不改变「报不报」**，只把置信度打 ×0.6 并在路径上留一个
    # sanitize 步骤，告诉复核者「这里被人动过手，但仍然危险」。
    SanitizerSpec("str", "weak", (), "partial", exact_name=True),
    SanitizerSpec("repr", "weak", (), "partial", exact_name=True),
    SanitizerSpec("json.dumps", "weak", (), "partial"),
    SanitizerSpec("strip", "weak", (), "partial"),
    SanitizerSpec("lstrip", "weak", (), "partial"),
    SanitizerSpec("rstrip", "weak", (), "partial"),
)

# 说明：设计文档 §4.4 的 `sql_param` / `whitelist` 两类**没有符号名**，
# 它们是**结构性**判定（看调用/条件语句的形状），由下面的
# `is_parametric_sql()` / `is_whitelist_guard()` 实现；
# 而 `orm` 类（`filter_by` / `filter` 列名来自常量）在本版本里是
# **结构性满足**的：这两个调用根本不在 SINKS 表里，所以参数化 ORM 查询
# 天然不会产出 Finding —— 不需要额外写一个永不被触发的 sanitizer。
# 详见 `docs`（本包 README 的「已知精度边界」一节）与交付说明。

_SORTED_SANITIZERS: tuple[SanitizerSpec, ...] = tuple(
    sorted(SANITIZERS, key=lambda s: (len(s.symbol), s.symbol), reverse=True)
)

#: category → 中文说明。前端「净化点」气泡与报告要展示，避免前端自己写映射表。
CATEGORY_LABEL: dict[str, str] = {
    "int": "整型化",
    "filename": "文件名规整",
    "shell": "Shell 转义",
    "sql_param": "参数化查询",
    "whitelist": "白名单校验",
    "escape": "输出转义",
    "orm": "ORM 参数化",
    "weak": "弱净化（仅改表示形态）",
}


def match_sanitizer(dotted: str) -> SanitizerSpec | None:
    """按被调函数名匹配净化规则；无匹配返回 None。"""
    if not dotted:
        return None
    for spec in _SORTED_SANITIZERS:
        if spec.exact_name:
            if dotted == spec.symbol:
                return spec
        elif dotted == spec.symbol or dotted.endswith("." + spec.symbol):
            return spec
    return None


# ---------------------------------------------------------------------------
# 结构性判定：参数化 SQL
# ---------------------------------------------------------------------------

#: SQL 占位符形态。四种都收：`%s`（DB-API）、`%(name)s`（DB-API 命名）、
#: `?`（sqlite3 / MySQLdb）、`:name`（SQLAlchemy text()）。
_PLACEHOLDER = re.compile(r"%s|%\([A-Za-z_]\w*\)s|\?|:[A-Za-z_]\w*")

#: 包装原始 SQL 的构造函数（SQLAlchemy 2.0 的 `text()`）。
#: 不剥掉它，`execute(text("... :n"), {"n": uid})` 的 arg0 会被当成
#: 「未知调用 → 干净」，看似没事 —— 但真正的问题是它让 arg1 落进了
#: 「任一实参」的危险位，于是绑定值被报成注入。
_SQL_WRAPPERS = ("text", "sqlalchemy.text", "sa.text")


def constant_string_value(node: object, const_table: dict[str, object]) -> str | None:
    """把节点解析成**常量字符串的字面文本**，解析不到返回 None。

    「常量」的判定刻意只认两种情况：字符串字面量本身、以及模块级名字
    绑定的字符串字面量（`SQL = "select ..."`）。**不追**函数返回值、
    不追 f-string、不追拼接结果 —— 那是传播分析的事，放进这里会让
    「这个 SQL 是不是常量」变成一个需要到底层才能回答的问题，
    而这一个判断就能同时制造漏报和误报。
    """
    if node is None:
        return None
    node_type = node.type  # type: ignore[attr-defined]
    if node_type == "string":
        # f-string 不是常量：`f"... {uid}"` 的文本随输入变化
        if any(child.type == "interpolation" for child in node.named_children):  # type: ignore[attr-defined]
            return None
        return snippet_of(node)
    if node_type == "identifier":
        bound = const_table.get(node.text.decode("utf-8", errors="replace"))  # type: ignore[attr-defined]
        if bound is None:
            return None
        return constant_string_value(bound, {})  # 只跟一层，避免常量链循环
    if node_type == "call":
        function = node.child_by_field_name("function")  # type: ignore[attr-defined]
        if function is None:
            return None
        name = dotted_name(function)
        if not any(name == w or name.endswith("." + w) for w in _SQL_WRAPPERS):
            return None
        args = call_args(node)
        return constant_string_value(args[0], const_table) if args else None
    return None


def is_constant_value(node: object, const_table: dict[str, object]) -> bool:
    """节点是否是编译期常量（标量字面量，或全字面量的集合/列表/元组/字典）。

    白名单守卫的另一半：`if x not in ALLOWED` 只有当 `ALLOWED` 是常量集合时
    才是守卫。`if x not in get_allowed()` 不是 —— 那个集合可能随请求变化。
    """
    if node is None:
        return False
    node_type = node.type  # type: ignore[attr-defined]
    if node_type in ("integer", "float", "true", "false", "none"):
        return True
    if node_type == "string":
        return not any(child.type == "interpolation" for child in node.named_children)  # type: ignore[attr-defined]
    if node_type in ("set", "list", "tuple", "dictionary"):
        return all(is_constant_value(child, const_table) for child in node.named_children)  # type: ignore[attr-defined]
    if node_type == "pair":
        return is_constant_value(node.child_by_field_name("value"), const_table)  # type: ignore[attr-defined]
    if node_type == "identifier":
        bound = const_table.get(node.text.decode("utf-8", errors="replace"))  # type: ignore[attr-defined]
        return bound is not None and is_constant_value(bound, {})
    return False


def is_parametric_sql(call_node: object, const_table: dict[str, object]) -> bool:
    """`execute(sql, params)` 是否是**参数化查询**（sql 为常量 + 参数独立传参）。

    三个条件同时成立才算：

    1. 至少两个实参 —— 只有一个实参的 `execute(sql)` 没有「独立传参」可言；
    2. 第 0 个实参是**常量 SQL 文本**（含 `text()` 包装内的常量）；
    3. 该常量里含占位符。

    第 3 条不是形式主义：`execute("select 1", (uid,))` 里的 `uid` 是
    返回值/审计参数，不该被当作注入载荷；把它报出来是纯噪声。
    """
    args = call_args(call_node)
    if len(args) < 2:
        return False
    literal = constant_string_value(args[0], const_table)
    if literal is None:
        return False
    return _PLACEHOLDER.search(literal) is not None


def has_safe_loader(call_node: object) -> bool:
    """`yaml.load(x, Loader=yaml.SafeLoader)` —— 带安全 Loader 时不算 sink。

    只认 `SafeLoader` / `CSafeLoader`。`FullLoader` **不认**：
    它是「默认更安全」而不是「保证安全」，把它当作等价于 SafeLoader
    会让一条真实的 RCE 路径被静默放过 —— 这类「差不多安全」的判断
    在安全工具里是最不该出现的。
    """
    keywords = call_keyword_args(call_node)
    candidates: list[object] = []
    if "Loader" in keywords:
        candidates.append(keywords["Loader"])
    args = call_args(call_node)
    if len(args) > 1:
        candidates.append(args[1])
    for node in candidates:
        name = (
            dotted_name(node)
            if node.type != "identifier"  # type: ignore[attr-defined]
            else node.text.decode("utf-8", "replace")  # type: ignore[attr-defined]
        )
        if name.rsplit(".", 1)[-1] in ("SafeLoader", "CSafeLoader"):
            return True
    return False


# ---------------------------------------------------------------------------
# 结构性判定：白名单守卫
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WhitelistGuard:
    """一次白名单比较。

    `positive=True` 表示「比较成立即安全」（`x in ALLOWED` / `x == "1"`），
    因此**分支体内**被净化；`positive=False` 表示「比较不成立即安全」
    （`x not in ALLOWED` / `x != "1"`），因此**分支之外**（且分支终止）才被净化。
    这两种形状的本体与替身正好相反，用一个布尔值显式区分，
    比在两个地方各写一遍 `if` 更难写错。
    """

    sanitized: tuple[str, ...]  # 被约束住的访问路径
    positive: bool
    operator: str


#: 可作守卫的比较运算符。
_GUARD_OPERATORS = frozenset({"in", "not in", "==", "!="})


def comparison_operands(node: object) -> tuple[object, object, str] | None:
    """把 `comparison_operator` 拆成 (左, 右, 运算符文本)。

    tree-sitter-python 里比较运算符是**没有字段名的子节点**（`in` / `not in` /
    `==` …），操作数是其余子节点。只看 `named_children` 会把 `in`
    当成操作数之一，于是 `x in ALLOWED` 变成三元比较 —— 这是本文件里
    最容易踩的坑，所以单独抽一个函数并只在一处实现。
    """
    if node.type != "comparison_operator":  # type: ignore[attr-defined]
        return None
    operands: list[object] = []
    operator = ""
    for index, child in enumerate(node.children):  # type: ignore[attr-defined]
        field = node.field_name_for_child(index)  # type: ignore[attr-defined]
        if field == "operators":
            operator = child.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
        else:
            operands.append(child)
    if len(operands) != 2:
        # 链式比较（`a < b < c`）不当作守卫：它的约束是区间而不是集合，
        # 而区间对注入防护的意义完全不同（`0 < x < 10` 确实也安全，
        # 但那属于「数值域约束」，本版本不建模）
        return None
    return operands[0], operands[1], operator


def is_whitelist_guard(
    condition: object,
    tainted_paths: frozenset[str],
    const_table: dict[str, object],
) -> WhitelistGuard | None:
    """判断 if 条件是否是白名单守卫；是则返回被约束的访问路径。

    只处理**单条**比较：`if x not in A and y not in B` 不识别（返回 None）。
    这是刻意收窄的 —— 布尔组合要正确处理得先有短路语义，
    而漏识别一条守卫只会多报一条（可复核），错识别一条会漏报（不可见）。
    在污点工具里这两种错的代价不对称，规则一律往「宁可多报」的方向偏。
    """
    from app.analysis.parser import access_path  # 局部导入：避免与包导入顺序耦合

    parts = comparison_operands(condition)
    if parts is None:
        return None
    left, right, operator = parts
    if operator not in _GUARD_OPERATORS:
        return None

    left_path = access_path(left)
    right_path = access_path(right)
    left_tainted = left_path is not None and _is_tainted_path(left_path, tainted_paths)
    right_tainted = right_path is not None and _is_tainted_path(right_path, tainted_paths)

    if left_tainted and is_constant_value(right, const_table):
        sanitized = (left_path,)
    elif right_tainted and is_constant_value(left, const_table):
        sanitized = (right_path,)
    else:
        return None

    return WhitelistGuard(
        sanitized=tuple(p for p in sanitized if p is not None),
        positive=operator in ("in", "=="),
        operator=operator,
    )


def _is_tainted_path(path: str, tainted_paths: frozenset[str]) -> bool:
    """精确命中，或该路径的**基对象**在污点集合里。

    `x.y in ALLOWED` 是对 `x.y` 的约束，`x` 整体是否污点无关紧要；
    但 `x["k"]` 被约束时，它的基 `x` 仍然是污点。所以只往**下**看一层基对象，
    不做前缀匹配（前缀匹配会把 `x` 的约束错误地应用到 `x.y` 上，
    方向反了 —— 那是漏报）。
    """
    if path in tainted_paths:
        return True
    base = path.rsplit(".", 1)[0] if "." in path else path.split("[", 1)[0]
    return base in tainted_paths


# ---------------------------------------------------------------------------
# 传播器：返回值继承实参/接收者的污点
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PropagatorSpec:
    """一个「返回值由入参决定」的调用。

    `mode` 三选一：
    - `args`：结果是所有实参的并集（`os.path.join(base, uid)`）；
    - `receiver`：结果是**接收者**的污点（`uid.strip()` 里的 `uid`）；
    - `all`：接收者与实参的并集（`sep.join(lst)`、`Markup(uid)`）。
    """

    symbol: str
    mode: str  # args | receiver | all
    exact_name: bool = False


PROPAGATORS: tuple[PropagatorSpec, ...] = (
    # 路径拼接族。**`os.path.join` 是污点传播器而不是 sink**：
    # 它把 `base` 与 `uid` 拼起来，危险的是拼完之后落盘/读盘那一步。
    PropagatorSpec("os.path.join", "args"),
    PropagatorSpec("os.path.abspath", "args"),
    PropagatorSpec("os.path.realpath", "args"),
    PropagatorSpec("os.path.normpath", "args"),
    PropagatorSpec("os.path.dirname", "args"),
    PropagatorSpec("os.path.expanduser", "args"),
    PropagatorSpec("os.path.expandvars", "args"),
    PropagatorSpec("join", "all"),
    PropagatorSpec("format", "all"),
    PropagatorSpec("format_map", "all"),
    # 字符串方法：结果仍是同一个字符串的变形
    PropagatorSpec("strip", "receiver"),
    PropagatorSpec("lstrip", "receiver"),
    PropagatorSpec("rstrip", "receiver"),
    PropagatorSpec("replace", "all"),
    PropagatorSpec("lower", "receiver"),
    PropagatorSpec("upper", "receiver"),
    PropagatorSpec("casefold", "receiver"),
    PropagatorSpec("encode", "receiver"),
    PropagatorSpec("decode", "receiver"),
    PropagatorSpec("split", "all"),
    PropagatorSpec("rsplit", "all"),
    PropagatorSpec("removeprefix", "receiver"),
    PropagatorSpec("removesuffix", "receiver"),
    # 反序列化族：结果是从入参还原出来的对象，污点跟着走
    # （`data = pickle.loads(uid); os.system(data["cmd"])` 这条链要能接上）
    PropagatorSpec("pickle.loads", "args"),
    PropagatorSpec("yaml.load", "args"),
    PropagatorSpec("yaml.safe_load", "args"),
    PropagatorSpec("json.loads", "args"),
    PropagatorSpec("marshal.loads", "args"),
    PropagatorSpec("b64decode", "args"),
    PropagatorSpec("b64encode", "args"),
    PropagatorSpec("unquote", "args"),
    PropagatorSpec("quote", "args"),
    # 包装器：`Markup(x)` / `mark_safe(x)` 同时是 XSS sink 与传播器
    PropagatorSpec("Markup", "all"),
    PropagatorSpec("mark_safe", "all"),
)

_SORTED_PROPAGATORS: tuple[PropagatorSpec, ...] = tuple(
    sorted(PROPAGATORS, key=lambda s: (len(s.symbol), s.symbol), reverse=True)
)


def match_propagator(dotted: str) -> PropagatorSpec | None:
    if not dotted:
        return None
    for spec in _SORTED_PROPAGATORS:
        if spec.exact_name:
            if dotted == spec.symbol:
                return spec
        elif dotted == spec.symbol or dotted.endswith("." + spec.symbol):
            return spec
    return None
