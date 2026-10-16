"""注入点的**语法上下文**：这个载荷在这个位置上语法成立吗？

## 为什么必须有这一层

路由绑定（`routes.py`）把探针送到 finding 自己的端点之后，一个**新的**假阴性
立刻冒出来 —— 这是端到端跑之前看不出来的：

    端点            拼出来的 SQL                                          载荷
    /search         WHERE id = " + q                                      "1 AND 1=1"
    /admin/login    WHERE username = '" + username + "' AND password …    "1 AND 1=1"

同一个 `1 AND 1=1`，落在 `/search` 里是**有效的注入**（`WHERE id = 1 AND 1=1`，
返回不同的行）；落在 `/admin/login` 里被拼成 `username = '1 AND 1=1'` ——
**它也是一条合法 SQL**，只是匹配不到任何用户，于是登录失败、真假分支响应一致、
布尔差分如实报告"无差异"、`rejected` 如实落库。

**每步都对，结论是错的** —— 与当初那条假 `rejected` 是同一个病：
把「载荷根本没进入语法位置」读成了「注入不存在」。

## 判据：数引号，多数一列

不看 SQL 方言、不做解析，只做两件**可证伪的机械计数**：

* **单引号奇偶**：把注入点之前的所有字符串字面量按源码顺序接起来，
  数其中的 `'`。奇数 = 此刻正处在**一个没闭合的字符串里**（string 上下文），
  偶数 = 处在语句层（numeric 上下文）。

      /search        "… WHERE id = "                    → 0 个 ' → numeric
      /admin/login   "… username = '" + "' AND … = '"  → 1 个 ' → string

* **SELECT 与 FROM 之间的逗号数 + 1**：UNION 的列数必须与被注入的 SELECT 一致，
  否则数据库报 `SELECTs … do not have the same number of result columns`，
  而不是命中。列数不对的 UNION 载荷**天然没有证明力**。

## 这一层产出的是「能不能证伪」，不是「能不能命中」

`payload_fits_context()` 返回 False 时，探针**照样发出去**（万一命中了，那是真证据），
但它的**未命中不再有否证力**（见 `fingerprints._is_conclusive`）。
理由是上面那两段：载荷语法不成立时的"无差异"，与注入不存在时的"无差异"
在响应里长得一模一样，而只有前者我们知道原因。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.analysis.parser import ParsedFile, call_args
from app.verify.types import Technique

#: Python 字符串字面量前缀（`"..."` / `'...'` / `r"..."`）。
_STRING_PREFIX = ('r"""', "r'''", '"""', "'''", 'r"', "r'", '"', "'")


class SqlContext(StrEnum):
    """注入点所处的语法层。"""

    NUMERIC = "numeric"
    STRING = "string"
    UNKNOWN = "unknown"
    """没能读出上下文（找不到 SQL 语句、污点路径缺失等）。
    **它不是"无所谓"** —— 见 `payload_fits_context`：UNKNOWN 一律按"不适配"处理，
    因为"我不知道载荷能不能进语法位置"与"我知道它进不去"在证伪力上等价。"""


@dataclass(frozen=True, slots=True)
class SinkContext:
    """注入点上下文。`columns` 为 None 表示列数读不出来。"""

    kind: SqlContext
    columns: int | None = None
    sql_prefix: str = ""
    """注入点之前的 SQL 前缀，仅用于报告与排错 —— 它让"为什么这条不适配"
    可以被人工核对，而不是只能相信一个布尔值。"""

    @property
    def is_string(self) -> bool:
        return self.kind is SqlContext.STRING


def _unquote(text: str) -> str:
    stripped = text.strip()
    for prefix in _STRING_PREFIX:
        closer = prefix[-1]
        if stripped.startswith(prefix) and stripped.endswith(closer):
            return stripped[len(prefix) : -len(closer)]
    return stripped


def _flatten_concat(node: Any) -> list[Any]:
    """把 `a + b + c` 摊平成 `[a, b, c]`，**从左到右保持源码顺序**。

    ## 这里为什么用 AST 而不用正则（第一版就是正则，错的）

    先是写成 `(['"])(?:\\\\.|(?!\\1).)*\\1\\s*\\+\\s*(\\w+)`。带 `re.S` 之后
    `.` 能跨行，于是这个正则**贪婪地吞掉整个调用表达式再去回溯**：
    `/api/order/query` 上前缀被算成了
    `…'T id, product_id, amount FROM orders WHERE id = " + order_id…` ——
    连开引号都被吃进去了，引号计数直接失去意义。而 `username` 那条更干脆：
    回溯到一个空的 `''`，于是**把 string 上下文读成了 numeric** ——
    正是这一层要防的那个错误，被这一层自己犯了一遍。

    正则在这里没有出路：拼接链是**语法结构**，就该按语法结构走。
    """
    if node is not None and node.type == "binary_operator":
        op = node.child_by_field_name("operator")
        if op is not None and op.text.decode("utf-8", errors="replace").strip() == "+":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            return _flatten_concat(left) + _flatten_concat(right)
    return [node] if node is not None else []


def _enclosing_sink_call(parsed: ParsedFile, line: int) -> Any | None:
    """`line` 所在的最内层**实参里含 SQL 的调用节点**。

    取整个调用表达式而不是单行，是必需的：靶场的拼接跨了 5 行

        cursor.execute(
            "SELECT role FROM users WHERE username = '"
            + username
            + "' AND password = '"
            ...
        )

    只看 `line` 那一行的话，字面量和变量根本不在同一行上 —— 什么都读不出来。
    """
    best: Any = None
    best_span: int | None = None
    stack = [parsed.root]
    while stack:
        node = stack.pop()
        if node.end_point[0] + 1 < line or node.start_point[0] + 1 > line:
            continue
        if node.type == "call":
            span = node.end_point[0] - node.start_point[0]
            if best_span is None or span < best_span:
                if "SELECT" in node.text.decode("utf-8", errors="replace").upper():
                    best, best_span = node, span
        stack.extend(node.children)
    return best


def infer_sink_context(parsed: ParsedFile, line: int, local_var: str | None) -> SinkContext:
    """读出 `line` 处注入点的 SQL 上下文。读不出就返回 `UNKNOWN`。

    `local_var` 是**局部变量名**（`order_id`），不是 HTTP 参数名（`id`）——
    拼接链上写的是前者。见 `routes.RouteBinding.local_var`。
    """
    call = _enclosing_sink_call(parsed, line)
    if call is None or not local_var:
        return SinkContext(kind=SqlContext.UNKNOWN)

    args = call_args(call)
    if not args:
        return SinkContext(kind=SqlContext.UNKNOWN)
    operands = _flatten_concat(args[0])

    # 注入点 = 拼接链上那个**名字等于局部变量**的操作数。取第一个 ——
    # 同一个变量在一条语句里可能拼多次，第一次就是它的入口。
    cut: int | None = None
    for index, operand in enumerate(operands):
        if (
            operand.type == "identifier"
            and operand.text.decode("utf-8", errors="replace") == local_var
        ):
            cut = index
            break
    if cut is None:
        return SinkContext(
            kind=SqlContext.UNKNOWN,
            sql_prefix=" + ".join(o.text.decode("utf-8", errors="replace") for o in operands)[:200],
        )

    # 前缀 = 注入点之前的字符串字面量按源码顺序拼起来。
    # ⚠️ 必须把**前面所有字面量**接起来再数，不能只看紧邻的那一个：
    # `password` 紧邻的字面量是 `' AND password = '`（两个引号 → 偶数 → 会被误判成
    # numeric），接上前面的 `… username = '` 之后是 3 个引号 → 奇数 → string。**对了。**
    prefix = "".join(
        _unquote(o.text.decode("utf-8", errors="replace"))
        for o in operands[:cut]
        if o.type == "string"
    )
    kind = SqlContext.STRING if prefix.count("'") % 2 else SqlContext.NUMERIC

    return SinkContext(kind=kind, columns=_column_count(prefix), sql_prefix=prefix[-200:])


#: 选择列表是「星号」—— 裸 `*` 或限定 `t.*`。列数**不可知**，见 `_column_count`。
_SELECT_STAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*\.\s*\*$|^\*$")


def _column_count(prefix: str) -> int | None:
    """`SELECT` 与 `FROM` 之间的顶层逗号数 + 1。读不出返回 None。"""
    upper = prefix.upper()
    start = upper.find("SELECT")
    end = upper.find("FROM")
    if start < 0 or end < 0 or end <= start:
        return None
    between = prefix[start + len("SELECT") : end]
    # ⚠️ `SELECT *` / `SELECT t.*` 的列数是**不知道**，不是 1。
    #
    # 这里返回 1 曾经是安全的 —— 那时载荷恒为两列，`1 != 2` 于是
    # `payload_fits_context` 判"不适配"，未命中不构成证伪，歪打正着。
    # 载荷改成按 `ctx.columns` 构造之后，1 就**真的会去构造一个一列的载荷**，
    # 于是 `1 == 1` 判成适配 —— 一张五列的表上打了单列 UNION，必然不命中，
    # 而这次未命中被当成**证伪**，真注入被写成 `rejected`。
    #
    # 这个类别的错误是这个模块最不该犯的（见文件头：宁可漏报不可误拒），
    # 所以遇到星号必须显式退回"不知道"。
    if _SELECT_STAR_RE.match(between.strip()):
        return None
    # 顶层逗号：不在引号里的那些。`name || ' :: ' || description` 里的 `' :: '`
    # 不含逗号，但真实 SQL 的选择列表里可能有（`'a,b'`），所以要做引号深度。
    depth = 0
    commas = 0
    for ch in between:
        if ch == "'":
            depth ^= 1
        elif ch == "," and depth == 0:
            commas += 1
    return commas + 1


def payload_fits_context(technique: Technique, payload: str, ctx: SinkContext | None) -> bool:
    """这个载荷在这个上下文里**语法上成立**吗？用于决定"未命中能否证伪"。

    只管两种技术 —— 它们的载荷形态对上下文**敏感**：

    * `UNION_EXTRACT`：numeric 上下文 ∧ 列数正好等于载荷里的列数。
      载荷的列数由 `probe._build_union_payload` 按 `ctx.columns` 构造，
      所以正常情况下这一步必然相等 —— 它是**兜底**，不是主要机制。
    * `BOOLEAN_BLIND`：必须 numeric。string 上下文里 `1 AND 1=1` 会被整个包进引号，
      成为一条**合法但恒假**的字符串比较。

    其余技术（命令注入、路径穿越、上传、反序列化、IDOR、未授权）的载荷不依赖
    SQL 语法位置，一律返回 True —— **这个函数刻意只对它能判断的东西表态**。
    """
    if ctx is None:
        # 没有上下文 = 老路径（模板固定路由，未绑定）。此时**不新增限制**：
        # `param_is_canonical` 那道闸门已经在管这件事了，两处都收紧会让
        # 未绑定场景下的证伪能力凭空消失，那是另一个方向的失真。
        return True
    if technique is Technique.UNION_EXTRACT:
        if ctx.kind is not SqlContext.NUMERIC:
            return False
        # 载荷自己的列数**从载荷里数出来**，不写死 2 —— 这样它和
        # `_build_union_payload` 的构造逻辑互为独立的两条路径：
        # 构造写错了（比如补列数时算错），这里会判"不适配"而不是发出一个错载荷。
        # 两边都写死同一个常量就得不到这个交叉校验。
        wanted = _payload_columns(payload)
        return wanted is not None and ctx.columns == wanted
    if technique is Technique.BOOLEAN_BLIND:
        return ctx.kind is SqlContext.NUMERIC
    return True


def _payload_columns(payload: str) -> int | None:
    """UNION 载荷的选择列表列数。`1 UNION SELECT 'a','b' -- ` → 2。"""
    upper = payload.upper()
    start = upper.find("SELECT")
    if start < 0:
        return None
    tail = payload[start + len("SELECT") :]
    tail = re.split(r"--", tail, maxsplit=1)[0]
    depth = 0
    commas = 0
    for ch in tail:
        if ch == "'":
            depth ^= 1
        elif ch == "," and depth == 0:
            commas += 1
    return commas + 1


def infer_context_for(reader: Any, finding: Any, binding: Any) -> SinkContext:
    """按 finding 的**污点路径 sink 步**反查上下文。

    绑定给了「端点在哪、参数叫什么」；上下文要的是「载荷落在什么语法位置」——
    后者只有 sink 那一步（`cursor.execute(...)`）说得清，所以单独走一趟。

    sink 文件与 source 文件常常不是同一个（`admin_login.py` 的 sink 在辅助函数里、
    路由在 `app.py`），所以这里要按 sink 步自己的 `file_path` 去读。
    """
    from app.analysis.parser import parse_file  # 局部导入：避免和 routes 的循环

    sink_steps: list[Any] = []
    for step in getattr(finding, "taint_path", ()) or ():
        kind = getattr(step, "step_kind", "")
        kind = str(getattr(kind, "value", kind) or "")
        if "sink" in kind.lower():
            sink_steps.append(step)
    if not sink_steps:
        return SinkContext(kind=SqlContext.UNKNOWN)

    step = sink_steps[-1]
    rel = str(getattr(step, "file_path", "") or "").replace("\\", "/").split("/")[-1]
    try:
        source = reader(rel)
        parsed = parse_file(rel, source)
    except Exception:  # noqa: BLE001 —— 读不到就不给上下文，按 UNKNOWN 处理
        return SinkContext(kind=SqlContext.UNKNOWN)
    return infer_sink_context(parsed, int(getattr(step, "line", 0) or 0), binding.local_var)


__all__ = [
    "SinkContext",
    "SqlContext",
    "infer_context_for",
    "infer_sink_context",
    "payload_fits_context",
]
