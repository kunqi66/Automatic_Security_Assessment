"""污点传播引擎（设计文档 §2 的 taint、§4.2 函数内、§4.3 跨函数）。

这是 B4 的技术核心，也是最容易「看起来对、实际不对」的一段。三条实现原则：

**一、按 AST 的后序遍历求值，不是按语句顺序扫一遍。**
设计文档 §4.2 规则 1 点名的坑是 `b = a; a = taint`：语句顺序扫描会把 `b`
判成干净。真正的判据是**求值顺序** —— 赋值语句必须「先求右值、再把结果写进
左值」。本文件里所有赋值/运算都是 `_eval(右)` → `_assign(左)` 这个顺序，
由 `_handle_assignment` 单点保证。

**二、分支合并取并集，且净化集合取交集。**
`if c: q = sanitize(x) else: q = x` 之后 `q` 的污点状态：级别取**脏的那一支**
（并集），净化集合取**两支的交集** —— 因为「只有一支被净化」等于没被净化。
方向反了（并集净化）会让过滤器绕过直接消失，是这个模块最危险的错误。

**三、未知一律按「污点穿过」处理。**
不在三张规则表里的调用（`quote(x)` / `self.repo.load(uid)`）默认返回值继承
实参污点。这是**故意选宽**的：选窄会让漏洞静默消失（不可见），选宽只是多报
（可复核）。全模块的误报主要来自这一条，所以它必须写在最显眼的注释里。

**已知精度边界**（面试必问，逐条写在对应实现处，汇总见包 docstring）：
只做一层跨函数、不建模闭包/类属性/别名/类型推断、未知调用传播、返回值的
形参来源不区分。
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import IntEnum
from pathlib import Path, PurePosixPath

from app.analysis.errors import SourceUnreadable
from app.analysis.finding import dedupe, make_finding
from app.analysis.parser import (
    ParsedFile,
    access_path,
    call_args,
    call_function_node,
    call_keyword_args,
    count_loc,
    dotted_name,
    is_terminating,
    iter_py_files,
    make_fs_reader,
    node_column,
    node_end_line,
    node_line,
    parse_file,
    read_text_file,
    snippet_of,
)
from app.analysis.patterns import (
    is_secret_literal,
    make_secret_finding,
    name_looks_like_secret,
    run_pattern_rules,
)
from app.analysis.sanitizers import (
    SanitizerSpec,
    has_safe_loader,
    is_parametric_sql,
    is_whitelist_guard,
    match_propagator,
    match_sanitizer,
)
from app.analysis.sinks import SinkSpec, match_sink
from app.analysis.sources import (
    PARAM_SOURCE_DEFAULTS,
    REQUEST_TYPES,
    SourceSpec,
    match_call_source,
    match_object_source,
)
from app.analysis.summary import (
    FunctionRunResult,
    Seed,
    SinkHit,
    SummaryTable,
    build_summary_table,
    match_call_site,
)
from app.analysis.symbols import (
    FunctionDef,
    SymbolTable,
    build_symbol_table,
    const_table_of,
)
from app.analysis.types import AnalysisResult, Finding, SkipRecord, TaintStep, VulnType
from app.core.logging import get_logger
from app.models.enums import DetectionMethod, TaintStepType

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# 上限（设计文档 §4.6 / §6 的全部闸门）
# ---------------------------------------------------------------------------

#: 分析文件数上限。**注意**：`app/core/config.py` 里**没有**这两个设置项
#: （只有 `max_source_file_bytes`），所以本期用模块常量兜底，
#: 并允许 B3 通过参数显式传入。见交付报告的「上游 TODO」。
DEFAULT_MAX_FILES = 2000
#: 墙钟预算（秒）
DEFAULT_MAX_SECONDS = 60.0
#: 单文件字节上限，与 `settings.max_source_file_bytes` 的当前取值一致（2 MB）
DEFAULT_MAX_FILE_BYTES = 2_000_000

#: 扩展名 → 引擎内部语言标识。**这是 B4 自己的词汇表。**
#:
#: 🔴 **判「能不能分析」必须看扩展名，不能看 manifest 里的 `language`。**
#:
#: B1 的 `LANGUAGE_BY_EXT` 把 `.py` 映射成 **`"Python"`（显示名，首字母大写）**，
#: 那是给 LOC 统计和前端展示用的；而引擎的注册表
#: （`parser._LANGUAGE_FACTORIES`）键是 **`"python"`（标识符，全小写）**。
#: 两套词汇表长得几乎一样，混用的后果没有任何报错：
#:
#:     实测（2026-10-16）：`analyze()` 对 `app.py` 产出
#:     SkipRecord「暂不支持的语言：Python」，files_scanned=0，findings=0
#:     —— **一个 Python 项目被判成「不支持 Python」**。
#:
#: 而这正是本系统最坏的失败模式：报告输出「0 个漏洞」，
#: 用户读到的是「这个项目很干净」，实际上一行代码都没扫。
#: `analyze_sources()` 不走这条路（它的 `language` 是函数参数），
#: 所以单测全绿 —— 只有真的经 `analyze()` 跑一遍才会露出来。
#:
#: B1 那边已经把这个区分写清楚了（`projects/types.py`：`ANALYZABLE_EXTS`
#: 与 `LANGUAGE_BY_EXT` 是「能不能分析」与「有多少代码」两个问题，
#: 注释里明说「别把它们合并成一个集合」）。这里只是把同一个原则
#: 落到 B4 侧：**引擎不该依赖别人给它的语言叫法。**
#: 扩展点是 `parser._LANGUAGE_FACTORIES`（三张规则表 + 一行注册）。
_EXT_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
}

#: 循环回边的不动点迭代轮数（设计文档 §4.2 规则 6「路径敏感分析上限 5 轮」）
MAX_LOOP_ROUNDS = 5

#: 单条污点路径的最大步数。防的是病态链（`a=x;b=a;c=b;...` 循环一千次）：
#: 路径超过 24 跳时，报告里的「跳转链」已经比代码本身还长，
#: 人工复核的收益是负的，截断反而更好用。
MAX_PATH_STEPS = 24

#: 单个函数内最多记录多少条 sink 命中。超限后**只记 WARN 并丢弃后续命中**，
#: 不假装完整 —— 一个函数打到几百个 sink 通常是规则表配错（比如某个
#: `save` 名字太常见），把它全量报出来会淹掉真正的漏洞。
MAX_HITS_PER_FUNCTION = 200


class Level(IntEnum):
    """污点格（设计文档 §4.2 引入的 3 值格）。

    `CLEAN` 的值不出现在 `TaintMap` 里（不存在即干净），保留它是为了让
    `max()` 合并与日志输出能用一个类型表达「没有污点」。
    """

    CLEAN = 0
    PARTIAL = 1  # 有污点，但路径上有弱净化 → 仍然报，置信度 ×0.6
    TAINTED = 2


def _level_of(partial: bool) -> Level:
    """`partial` 与 `level` 是同一件事的两种表示，只在**一个地方**互相派生。

    两处各写一遍 `if` 迟早会不一致，而不一致的表现是「同一批 Finding 的
    `guard_blocked` 与置信度对不上」，很难定位。
    """
    return Level.PARTIAL if partial else Level.TAINTED


@dataclass(frozen=True, slots=True)
class TaintValue:
    """一个访问路径当前的污点状态。

    `origin` 是**首跳**（真实 source 或形参入口），它必须一直带着 ——
    设计文档 §2.4 的行级锚点（`source_file`/`source_line`）就是它的行号，
    而「补丁后这条路径还在不在」正是靠这个锚点复验的。
    """

    origin: TaintStep
    origin_path: str
    origin_channel: str
    current_path: str
    level: Level = Level.TAINTED
    #: 路径上经过的弱净化（`str()` / `.strip()` …）
    partial: bool = False
    #: 已被**完全**中和的漏洞类型（强度 full 且覆盖该类型）
    sanitized_types: frozenset[VulnType] = frozenset()
    #: 中间步骤：净化点、跨函数调用点、形参入口
    via_steps: tuple[TaintStep, ...] = ()
    #: 是否经过跨函数调用（一层）
    inter_procedural: bool = False
    #: 是否经过**未展开**的调用（摘要缺失/递归/更深一层）
    unexpanded: bool = False

    @property
    def dirty(self) -> bool:
        return self.level != Level.CLEAN


@dataclass(slots=True)
class _Context:
    """一次函数分析的上下文。

    `hits` / `guarded` 是**收集器**（可变），其余是只读引用。
    刻意不做成全局状态：同一份输入并发分析两个文件时，
    全局收集器会互相污染 —— 而那种 bug 只在并发下出现。
    """

    parsed: ParsedFile
    function: FunctionDef
    table: SymbolTable
    summaries: SummaryTable | None
    expand_inter: bool
    const_table: dict[str, object]
    aliases: dict[str, str]
    hits: list[SinkHit]
    guarded: set[str]
    uses_project_call: bool = False
    calls_self: bool = False
    returns_tainted: bool = False
    hit_limit_warned: bool = False


# ---------------------------------------------------------------------------
# 路径与查找
# ---------------------------------------------------------------------------


def _canonical(path: str, aliases: Mapping[str, str]) -> str:
    """把 `req.query_params` 规范成 `request.query_params`（Request 形参别名）。

    FastAPI 的 Request 对象常常不叫 `request`（`def f(req: Request)`）。
    不建这个别名，`req.query_params["uid"]` 整类漏报 —— 而这类写法
    在新项目里几乎是主流。
    """
    if not aliases:
        return path
    head, sep, rest = path.partition(".")
    if not sep:
        head, sep, rest = path.partition("[")
    target = aliases.get(head)
    if target is None:
        return path
    return f"{target}{sep}{rest}" if sep else target


def _prefixes(path: str) -> list[str]:
    """`a[0].b` → `['a[0].b', 'a[0]', 'a']`，由具体到宽泛。"""
    result = [path]
    current = path
    while True:
        if current.endswith("]"):
            index = current.rfind("[")
            if index <= 0:
                break
            current = current[:index]
        else:
            index = current.rfind(".")
            if index <= 0:
                break
            current = current[:index]
        result.append(current)
    return result


def _lookup(
    path: str, env: Mapping[str, TaintValue], aliases: Mapping[str, str]
) -> TaintValue | None:
    """按访问路径取污点：精确命中，或**基对象**命中（保守上溯）。

    `tainted["k"]` 能查到时用精确的；查不到就退到 `tainted`：
    `uid = request.args.get("id")` 之后 `uid["x"]` / `uid.upper()` 都应当继承。
    刻意只上溯（不看子路径）：下钻（`x` 脏 → `x.a` 脏）与上溯
    （`x.a` 脏 → `x` 脏）**都做**，因为两者都能造成漏报，
    而多报的那一点由 sanitizer 与人工复核兜住。
    """
    canonical = _canonical(path, aliases)
    for candidate in _prefixes(canonical):
        value = env.get(candidate)
        if value is not None:
            return value
    return None


def _symbol_of(node: object, fallback: str) -> str:
    path = access_path(node)
    return path if path is not None else fallback


def _source_step(spec: SourceSpec, node: object, parsed: ParsedFile, symbol: str) -> TaintStep:
    return TaintStep(
        step_index=0,
        file_path=parsed.rel_path,
        line=node_line(node),
        column=node_column(node),
        symbol=symbol or spec.symbol,
        step_kind=TaintStepType.SOURCE,
        snippet=snippet_of(node, limit=120),
    )


def _make_source_value(spec: SourceSpec, node: object, ctx: _Context, symbol: str) -> TaintValue:
    name = symbol or spec.symbol
    return TaintValue(
        origin=_source_step(spec, node, ctx.parsed, name),
        origin_path=name,
        origin_channel=spec.channel,
        current_path=name,
    )


def _mid_step(
    parsed: ParsedFile,
    node: object,
    symbol: str,
    kind: TaintStepType = TaintStepType.PROPAGATE,
) -> TaintStep:
    return TaintStep(
        step_index=0,  # 真正的下标由 finding.make_finding 统一重排
        file_path=parsed.rel_path,
        line=node_line(node),
        column=node_column(node),
        symbol=symbol,
        step_kind=kind,
        snippet=snippet_of(node, limit=120),
    )


def _append_step(value: TaintValue, step: TaintStep) -> tuple[TaintStep, ...]:
    """追加中间步骤，超过 `MAX_PATH_STEPS` 时**丢弃新步骤但保留路径有效性**。

    丢尾而不是丢头：首跳（source）是补丁复验的锚点，永远不能丢；
    末跳（sink）由调用方另行拼接，也不经过这里。
    """
    steps = value.via_steps
    if len(steps) >= MAX_PATH_STEPS:
        return steps
    return (*steps, step)


# ---------------------------------------------------------------------------
# 合并（分支 / 多操作数）
# ---------------------------------------------------------------------------


def _merge_values(values: Sequence[TaintValue | None]) -> TaintValue | None:
    """多个污点值合并（设计文档 §4.2 规则 4/5：并集 + 净化交集）。

    - **存在性**：任一为污点则结果为污点；
    - **代表值**：取级别最高的那个（同级取更早的 source，保证确定性）；
    - **净化集合**：取**交集**（只有所有来源都被净化才算净化）；
    - **partial**：取**并集**（只要有一条路径被弱净化，就不能宣称确定）。
    """
    live = [value for value in values if value is not None and value.dirty]
    if not live:
        return None
    best = max(
        live,
        key=lambda v: (
            int(v.level),
            -v.origin.line,
            v.origin_path,
        ),
    )
    sanitized = frozenset.intersection(*(value.sanitized_types for value in live))
    partial = any(value.partial for value in live)
    return replace(
        best,
        level=_level_of(partial),
        partial=partial,
        sanitized_types=sanitized,
        via_steps=_longest_steps(live),
        unexpanded=any(value.unexpanded for value in live),
    )


def _longest_steps(live: Sequence[TaintValue]) -> tuple[TaintStep, ...]:
    """选一条步骤链作为合并结果的路径：先取最长，再取「路径键」最小。

    「取最长」是为了让报告里的路径尽量完整；后一个条件保证**平局时也确定** ——
    直接取 `max` 在平局时会返回先出现的那个，那取决于外层列表的构造顺序，
    不是一个可复现的承诺。
    """
    return max(live, key=lambda v: (len(v.via_steps), _path_key(v))).via_steps


def _path_key(value: TaintValue) -> tuple:
    return (value.origin.line, value.origin_path, value.current_path)


# ---------------------------------------------------------------------------
# 求值
# ---------------------------------------------------------------------------

#: 不做传播的表达式（设计文档 §4.2 明确列出）：比较/取非/算术的结果
#: 是「关于污点的结论」而不是「污点本身」。`if uid == "1"` 之后的 `True`
#: 不带污点 —— 传播它等于把每个 if 都变成传播点，误报会翻倍。
#:
#: `boolean_operator`（`and` / `or`）**不在**这张表里，它的结果是操作数本身。
_NO_PROPAGATION = frozenset(
    {
        "comparison_operator",
        "not_operator",
        "lambda",
        "function_definition",
        "class_definition",
        "generator_expression",
        "await",
        "yield",
    }
)


def _eval(node: object | None, env: dict[str, TaintValue], ctx: _Context) -> TaintValue | None:
    """求一个表达式节点的污点值；干净返回 None。

    **这个函数会记录 sink 命中**（副作用）。理由：命中只能在这里被发现 ——
    实参的污点状态是求值过程的产物，出了函数就只剩一个 `TaintValue`，
    再想知道「它是不是经过了危险函数」就得把求值重做一遍。
    副作用被限制在 `ctx` 内部，且 `_eval` 本身不做任何 IO。
    """
    if node is None:
        return None
    node_type = node.type  # type: ignore[attr-defined]

    if node_type in _NO_PROPAGATION:
        return None

    if node_type in ("identifier", "attribute", "subscript"):
        path = access_path(node)
        if path is not None:
            found = _lookup(path, env, ctx.aliases)
            if found is not None and found.dirty:
                return found
        if node_type == "subscript":
            value_node = node.child_by_field_name("value")  # type: ignore[attr-defined]
            index_node = node.child_by_field_name("subscript")  # type: ignore[attr-defined]
            _eval(index_node, env, ctx)  # 下标里的 sink 也要记录
            return _eval(value_node, env, ctx)
        if node_type == "attribute":
            dotted = _canonical(dotted_name(node), ctx.aliases)
            spec = match_object_source(dotted)
            if spec is not None:
                return _make_source_value(spec, node, ctx, _symbol_of(node, dotted))
        return None

    if node_type == "call":
        return _eval_call(node, env, ctx)

    if node_type == "string":
        # f-string：`f"select {uid}"` —— 插值表达式全部参与合并。
        # `interpolation` 只是 f-string 的子节点，普通字符串一个都没有，
        # 所以这一条同时覆盖了普通字符串（返回 None，干净）。
        return _merge_values(
            [_eval_interpolation(child, env, ctx) for child in node.named_children]  # type: ignore[attr-defined]
        )

    if node_type == "interpolation":
        return _eval_interpolation(node, env, ctx)

    if node_type == "binary_operator":
        left = node.child_by_field_name("left")  # type: ignore[attr-defined]
        right = node.child_by_field_name("right")  # type: ignore[attr-defined]
        return _merge_values([_eval(left, env, ctx), _eval(right, env, ctx)])

    if node_type == "boolean_operator":
        # `uid or "default"` 的**结果**就是其中一个操作数，污点必须跟着走。
        # 这与「比较运算不传播」不冲突：比较的结果是一个布尔值，
        # 而 `or` 的结果是操作数本身（设计文档 §4.2 的不传播清单里只有比较与算术）。
        return _merge_values(
            [_eval(child, env, ctx) for child in node.named_children]  # type: ignore[attr-defined]
        )

    if node_type in ("list", "tuple", "set", "expression_list", "pattern_list"):
        return _merge_values([_eval(child, env, ctx) for child in node.named_children])  # type: ignore[attr-defined]

    if node_type == "dictionary":
        values: list[TaintValue | None] = []
        for child in node.named_children:  # type: ignore[attr-defined]
            if child.type == "pair":
                values.append(_eval(child.child_by_field_name("value"), env, ctx))  # type: ignore[attr-defined]
            else:
                values.append(_eval(child, env, ctx))
        return _merge_values(values)

    if node_type == "pair":
        return _eval(node.child_by_field_name("value"), env, ctx)  # type: ignore[attr-defined]

    if node_type == "conditional_expression":
        return _merge_values(
            [
                _eval(node.child_by_field_name("body"), env, ctx),  # type: ignore[attr-defined]
                _eval(node.child_by_field_name("alternative"), env, ctx),  # type: ignore[attr-defined]
            ]
        )

    if node_type in ("list_comprehension", "set_comprehension", "dictionary_comprehension"):
        # 推导式：结果集合的元素来自被迭代对象 → 保守地取整个表达式的污点
        return _merge_values([_eval(child, env, ctx) for child in node.named_children])  # type: ignore[attr-defined]

    if node_type == "as_pattern":
        return _eval(node.child_by_field_name("value"), env, ctx)  # type: ignore[attr-defined]

    # 其余节点类型（数字/布尔/None/参数列表…）不携带污点。
    # **注意这里是白名单式的保守**：新出现的表达式类型默认「不传播」，
    # 表现为漏报而不是误报 —— 但每次升级 tree-sitter 语法都要回来核对一遍。
    return None


def _eval_interpolation(
    node: object, env: dict[str, TaintValue], ctx: _Context
) -> TaintValue | None:
    """f-string 的 `{...}`：求值方括号里的表达式。"""
    expression = node.child_by_field_name("expression")  # type: ignore[attr-defined]
    if expression is None:
        children = node.named_children  # type: ignore[attr-defined]
        expression = children[0] if children else None
    return _eval(expression, env, ctx)


def _tail_name(function_node: object | None) -> str:
    """调用目标属性链的**末段名**（`conn.cursor().execute` → `execute`）。

    这是对 `parser.dotted_name` 那条「解析不出接收者就返回空串」的
    受限例外，只用于 sink/sanitizer/propagator 三张表 —— 它们本来就是
    按名字后缀匹配的（`match_sink` 内部就用 `endswith`），
    接收者是谁不影响结果，所以兜底**不扩大误报面**。
    反之 source 与项目内函数解析**必须**用完整点分名：那里的身份就在接收者上，
    退到末段名会让 `obj.get_json()` 被误判成 `request.get_json`。
    """
    if function_node is None or function_node.type != "attribute":  # type: ignore[attr-defined]
        return ""
    attribute = function_node.child_by_field_name("attribute")  # type: ignore[attr-defined]
    if attribute is None:
        return ""
    return attribute.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]


def _eval_call(node: object, env: dict[str, TaintValue], ctx: _Context) -> TaintValue | None:
    """调用表达式的求值：source → 净化 → sink → 传播器 → 跨函数 → 未知穿过。

    顺序是**语义顺序**，不是随便排的：
    `int(request.args["id"])` 必须先命中净化器（否则会被当成未知调用而穿透），
    `cursor.execute(q)` 必须命中 sink（否则 `execute` 会被当成未知调用）。
    """
    function_node = call_function_node(node)
    dotted = dotted_name(function_node) if function_node is not None else ""
    dotted = _canonical(dotted, ctx.aliases) if dotted else ""
    receiver_node = (
        function_node.child_by_field_name("object")  # type: ignore[attr-defined]
        if function_node is not None and function_node.type == "attribute"  # type: ignore[attr-defined]
        else None
    )

    # 实参**只求值一次**：多次求值会重复记录 sink 命中（同一行两条一样的 Finding）
    positional_nodes = call_args(node)
    positional: list[tuple[object, TaintValue | None]] = [
        (item, _eval(item, env, ctx)) for item in positional_nodes
    ]
    keyword_nodes = call_keyword_args(node)
    keywords: dict[str, tuple[object, TaintValue | None]] = {
        name: (item, _eval(item, env, ctx)) for name, item in keyword_nodes.items()
    }
    receiver = _eval(receiver_node, env, ctx) if receiver_node is not None else None
    arg_values = [value for _, value in positional] + [value for _, value in keywords.values()]
    # 链式调用的兜底名（见 `_tail_name`）：`conn.cursor().execute(q)` 的
    # `dotted_name` 是空串（接收者是调用结果，解析不出类型），
    # 但 sink **只看方法名**，所以这里退到 `.execute` 的末段名。
    # 这条兜底**不用于 source 与项目内调用解析** —— 那两处的身份恰恰在接收者上。
    rule_name = dotted or _tail_name(function_node)

    spec = match_call_source(dotted) if dotted else None
    if spec is not None:
        # `request.args.get("id", "默认值")` 的默认值是干净的，但整条链
        # 只要有一个分支来自请求就不可信 —— 直接按 source 处理
        return _make_source_value(spec, node, ctx, dotted)

    sanitizer = match_sanitizer(rule_name)
    if sanitizer is not None:
        return _apply_sanitizer(
            _merge_values([receiver, *arg_values]), sanitizer, node, ctx, rule_name
        )

    sink = match_sink(rule_name)
    if sink is not None:
        return _handle_sink(node, sink, rule_name, receiver, positional, keywords, env, ctx)

    propagator = match_propagator(rule_name)
    if propagator is not None:
        if propagator.mode == "receiver":
            return receiver
        if propagator.mode == "args":
            return _merge_values(arg_values)
        return _merge_values([receiver, *arg_values])

    if dotted and ctx.table.candidates(dotted, ctx.parsed.rel_path, ctx.function.enclosing_class):
        return _handle_project_call(node, dotted, receiver, positional, keywords, env, ctx)

    # 未知调用：**污点穿过**（见模块 docstring 第三条）。
    return _merge_values([receiver, *arg_values])


def _apply_sanitizer(
    incoming: TaintValue | None,
    spec: SanitizerSpec,
    node: object,
    ctx: _Context,
    dotted: str,
) -> TaintValue | None:
    """按净化规则修饰流入值。

    - `strength="full"` 且 `neutralizes` 覆盖某漏洞类型 → 该类型加入
      `sanitized_types`（到 sink 时**不产出**该类型的 Finding）；
    - `strength="partial"` → 级别降为 `PARTIAL`：仍然报，但
      `guard_blocked=True`、置信度 ×0.6（设计文档 §4.4 的弱净化）。

    净化的输入是**接收者与实参的并集**：`uid.strip()` 的污点来自接收者，
    `escape(uid)` 的来自实参。写成「只看实参」会让所有方法形态的净化失效，
    写成「只看接收者」会让所有函数形态的净化失效 —— 只有并集两边都覆盖。
    """
    if incoming is None or not incoming.dirty:
        return incoming
    step = _mid_step(ctx.parsed, node, dotted, TaintStepType.SANITIZE)
    if spec.strength == "partial":
        return replace(
            incoming,
            level=Level.PARTIAL,
            partial=True,
            via_steps=_append_step(incoming, step),
        )
    return replace(
        incoming,
        level=_level_of(incoming.partial),
        sanitized_types=incoming.sanitized_types | frozenset(spec.neutralizes),
        via_steps=_append_step(incoming, step),
    )


def _handle_sink(
    node: object,
    spec: SinkSpec,
    dotted: str,
    receiver: TaintValue | None,
    positional: Sequence[tuple[object, TaintValue | None]],
    keywords: Mapping[str, tuple[object, TaintValue | None]],
    env: dict[str, TaintValue],
    ctx: _Context,
) -> TaintValue | None:
    """记录 sink 命中，并把「流入值」原样返回（sink 的返回值仍带污点）。

    返回污点而不是 None 是刻意的：`data = pickle.loads(uid)` 之后
    `os.system(data["cmd"])` 这条链必须能接上，而 `pickle.loads` 同时是
    sink 与传播器。若这里返回 None，二阶链就断在 sink 上了。
    """
    dangerous = _dangerous_args(spec, node, positional, keywords, ctx)
    for arg_node, value in dangerous:
        if value is None or not value.dirty:
            continue
        if spec.vuln_type in value.sanitized_types:
            # 该漏洞类型已被完全中和（`int()` / `secure_filename()` …）
            continue
        if len(ctx.hits) >= MAX_HITS_PER_FUNCTION:
            if not ctx.hit_limit_warned:
                logger.warning(
                    "函数 %s 的 sink 命中超过 %d 条，后续命中被丢弃",
                    ctx.function.qualname,
                    MAX_HITS_PER_FUNCTION,
                )
                ctx.hit_limit_warned = True
            continue
        sink_step = TaintStep(
            step_index=0,
            file_path=ctx.parsed.rel_path,
            line=node_line(node),
            column=node_column(node),
            symbol=dotted or spec.symbol,
            step_kind=TaintStepType.SINK,
            snippet=snippet_of(node, limit=200),
        )
        ctx.hits.append(
            SinkHit(
                vuln_type=spec.vuln_type,
                sink_spec=spec,
                sink=sink_step,
                line_start=node_line(node),
                line_end=max(node_line(node), node_end_line(node)),
                origin=value.origin,
                origin_path=value.origin_path,
                channel=value.origin_channel,
                arg_path=_symbol_of(arg_node, value.current_path),
                via_steps=value.via_steps,
                sanitized_types=value.sanitized_types,
                partial=value.partial,
                inter_procedural=value.inter_procedural,
                unexpanded=value.unexpanded,
            )
        )
    return _merge_values(
        [receiver, *(value for _, value in positional), *(v for _, v in keywords.values())]
    )


def _dangerous_args(
    spec: SinkSpec,
    node: object,
    positional: Sequence[tuple[object, TaintValue | None]],
    keywords: Mapping[str, tuple[object, TaintValue | None]],
    ctx: _Context,
) -> tuple[tuple[object, TaintValue | None], ...]:
    """按规则表挑出「危险参数位」，并处理三种豁免。

    三种豁免各自对应一类真实误报：

    1. `param_bindings_exempt` + `is_parametric_sql` → `execute(sql, params)`
       的 `params` 是绑定值，**不是** SQL 文本。少了这一条，参数化查询
       （也就是正确写法）会被报成注入 —— 最不可接受的误报。
    2. `requires_shell` → `subprocess.run(cmd, shell=False)` 是安全用法。
    3. `requires_unsafe_loader` → `yaml.load(x, Loader=SafeLoader)`。
    """
    if spec.param_bindings_exempt and is_parametric_sql(node, ctx.const_table):
        return ()
    if spec.requires_shell and not _has_shell_true(node):
        return ()
    if spec.requires_unsafe_loader and has_safe_loader(node):
        return ()

    if -1 in spec.dangerous_args:
        return (*positional, *keywords.values())
    selected: list[tuple[object, TaintValue | None]] = []
    for index in spec.dangerous_args:
        if 0 <= index < len(positional):
            selected.append(positional[index])
    return tuple(selected)


#: tree-sitter-python 里布尔字面量的节点类型。**不是 `boolean`** ——
#: `True` 的节点类型就是 `"true"`，`False` 是 `"false"`（实测确认）。
#: 多留 `"boolean"` 只是不把结论绑死在某个版本的节点命名上。
_TRUE_NODE_TYPES = frozenset({"true", "boolean"})


def _has_shell_true(node: object) -> bool:
    """`shell=True` —— 只看关键字实参（位置形式的 shell 位在实践中不存在）。

    ⚠️ 原先这里比的是 `value.type == "boolean"`，而 tree-sitter-python 给布尔
    字面量的节点类型是 **`"true"`** —— 于是这个函数**恒为 False**。
    后果不是"少报一条"，而是 `requires_shell=True` 的那一类 sink 全部静默失效：

        subprocess.run / call / check_call / check_output / Popen

    五个符号，`shell=True` 的命令注入一条也报不出来。而 `os.system` /
    `os.popen` 不带这个条件，照样能报 —— 所以**测试是绿的**：
    `test_taint_engine.py` 的正例用的是 `os.system`，反例用的是
    `subprocess.run(..., shell=False)`，而反例"通过"的真实原因不是
    "正确识别出 shell=False"，是"压根没识别 shell 这个参数"。
    一个因为错误原因而通过的反例，比没有反例更糟 —— 它让人以为这条路径被覆盖了。
    """
    value = call_keyword_args(node).get("shell")
    if value is None:
        return False
    return value.type in _TRUE_NODE_TYPES and value.text == b"True"


def _handle_project_call(
    node: object,
    dotted: str,
    receiver: TaintValue | None,
    positional: Sequence[tuple[object, TaintValue | None]],
    keywords: Mapping[str, tuple[object, TaintValue | None]],
    env: dict[str, TaintValue],
    ctx: _Context,
) -> TaintValue | None:
    """项目内调用：跨函数展开（一层）或标记未展开。"""
    ctx.uses_project_call = True
    candidates = ctx.table.candidates(dotted, ctx.parsed.rel_path, ctx.function.enclosing_class)
    if ctx.function.qualname in candidates:
        # 递归/自调用：**不做展开**。静态展开递归需要不动点，而递归函数的
        # 污点结论本来就依赖调用深度 —— 假装能算出来才是错的。按未展开标注。
        ctx.calls_self = True

    tainted_args = [value for _, value in positional if value is not None and value.dirty]
    tainted_args += [value for _, value in keywords.values() if value is not None and value.dirty]
    incoming = _merge_values(tainted_args)

    expanded = False
    if ctx.expand_inter and ctx.summaries is not None:
        for qualname in candidates:
            if qualname == ctx.function.qualname:
                continue
            summary = ctx.summaries.get(qualname)
            if summary is None:
                continue
            expanded = True
            _emit_inter_hits(node, dotted, summary, positional, keywords, ctx)
            if not tainted_args:
                break
            # 返回值传播：形参污点 → 返回值。`returns_tainted` 不区分具体形参，
            # 所以「任一实参脏 且 返回值可能脏」即认为结果是脏的 —— 这是
            # 已知的**高估**方向（见交付报告的精度边界一节）。
            #
            # 反过来，摘要说 `returns_tainted=False` 时**必须返回干净值**：
            # `q = build(uid)` 若 `build` 没有 return（或 return 的是常量），
            # `q` 就是 None，再把实参污点穿透过去会让紧随其后的
            # `execute(q)` 变成纯误报 —— 而这是「工具类代码」里极常见的形状。
            if not summary.returns_tainted or incoming is None:
                return None
            call_step = _mid_step(ctx.parsed, node, dotted)
            return replace(
                incoming,
                current_path=dotted,
                inter_procedural=True,
                via_steps=_append_step(incoming, call_step),
            )

    if incoming is None:
        return None
    if not expanded:
        # 没展开：**按污点穿过处理并标注 unexpanded**。
        # 静默返回 None 会让跨两层的漏洞彻底消失（不可见）；穿过的代价
        # 只是置信度上少一点确定性，而 Finding 上带着「未展开」的说明。
        return replace(
            incoming,
            inter_procedural=True,
            unexpanded=True,
            current_path=dotted,
            via_steps=_append_step(incoming, _mid_step(ctx.parsed, node, dotted)),
        )
    return replace(incoming, inter_procedural=True, current_path=dotted)


def _emit_inter_hits(
    node: object,
    dotted: str,
    summary: object,
    positional: Sequence[tuple[object, TaintValue | None]],
    keywords: Mapping[str, tuple[object, TaintValue | None]],
    ctx: _Context,
) -> None:
    """调用点 ← 摘要匹配：把调用点实参的污点接到被调函数的 sink 上。"""
    positions = [
        index for index, (_, value) in enumerate(positional) if value is not None and value.dirty
    ]
    keyword_names = [
        name for name, (_, value) in keywords.items() if value is not None and value.dirty
    ]
    flows = match_call_site(
        summary,  # type: ignore[arg-type]
        tainted_positions=positions,
        tainted_keywords=keyword_names,
    )
    if not flows:
        return
    call_step = _mid_step(ctx.parsed, node, dotted)

    def _arg_value(flow: object) -> TaintValue | None:
        index = getattr(flow, "param_index", -1)
        entry = summary.params[index] if 0 <= index < len(summary.params) else None  # type: ignore[attr-defined]
        if entry is not None and entry in keywords and keywords[entry][1] is not None:
            return keywords[entry][1]
        if 0 <= index < len(positional):
            return positional[index][1]
        return None

    for flow in flows:
        source_value = _arg_value(flow)
        if source_value is None or not source_value.dirty:
            continue
        if flow.reaches_sink is None or flow.reaches_sink in source_value.sanitized_types:
            continue
        if flow.sink is None or flow.sink_spec is None:
            continue
        if len(ctx.hits) >= MAX_HITS_PER_FUNCTION:
            continue
        via = source_value.via_steps
        middle: list[TaintStep] = [call_step]
        if flow.entry is not None:
            middle.append(flow.entry)
        middle.extend(flow.pre_steps)
        for step in middle:
            if len(via) >= MAX_PATH_STEPS:
                break
            via = (*via, step)
        ctx.hits.append(
            SinkHit(
                vuln_type=flow.reaches_sink,
                sink_spec=flow.sink_spec,
                sink=flow.sink,
                line_start=flow.line_start,
                line_end=flow.line_end,
                origin=source_value.origin,
                origin_path=source_value.origin_path,
                channel=source_value.origin_channel,
                arg_path=flow.arg_path,
                via_steps=via,
                sanitized_types=source_value.sanitized_types | flow.sanitized_types,
                partial=source_value.partial or flow.partial,
                inter_procedural=True,
                unexpanded=flow.unexpanded or source_value.unexpanded,
            )
        )


# ---------------------------------------------------------------------------
# 语句遍历
# ---------------------------------------------------------------------------


def _walk_block(block: object | None, env: dict[str, TaintValue], ctx: _Context) -> None:
    """按源码顺序遍历一个语句块。"""
    if block is None:
        return
    for statement in block.named_children:  # type: ignore[attr-defined]
        _handle_statement(statement, env, ctx)


def _handle_statement(node: object, env: dict[str, TaintValue], ctx: _Context) -> None:
    node_type = node.type  # type: ignore[attr-defined]

    if node_type == "expression_statement":
        # ⚠️ 赋值语句在 tree-sitter 里是**表达式**（`expression_statement` 包着
        # `assignment`），所以这里必须先按语句派发。写成「一律 `_eval`」会让
        # 所有赋值静默失效 —— 而表现是「一个 Finding 都没有」，
        # 不是报错。本文件里最阴的一个坑，留此注释。
        for child in node.named_children:  # type: ignore[attr-defined]
            if child.type in ("assignment", "augmented_assignment", "named_expression"):  # type: ignore[attr-defined]
                _handle_statement(child, env, ctx)
            else:
                _eval(child, env, ctx)
        return

    if node_type == "assignment":
        _handle_assignment(node, env, ctx)
        return

    if node_type == "named_expression":  # 海象运算符 `x := ...`
        _assign(
            node.child_by_field_name("name"),  # type: ignore[attr-defined]
            _eval(node.child_by_field_name("value"), env, ctx),  # type: ignore[attr-defined]
            env,
            ctx,
        )
        return

    if node_type == "augmented_assignment":
        left = node.child_by_field_name("left")  # type: ignore[attr-defined]
        right = node.child_by_field_name("right")  # type: ignore[attr-defined]
        path = access_path(left)
        current = _lookup(path, env, ctx.aliases) if path is not None else None
        merged = _merge_values([current, _eval(right, env, ctx)])
        _assign(left, merged, env, ctx)
        return

    if node_type in ("if_statement", "elif_clause"):
        _handle_if(node, env, ctx)
        return

    if node_type == "for_statement":
        _handle_for(node, env, ctx)
        return

    if node_type == "while_statement":
        _eval(node.child_by_field_name("condition"), env, ctx)  # type: ignore[attr-defined]
        _run_loop_body(node.child_by_field_name("body"), dict(env), ctx, env)  # type: ignore[attr-defined]
        _walk_clause(node.child_by_field_name("alternative"), env, ctx)  # type: ignore[attr-defined]
        return

    if node_type == "try_statement":
        _handle_try(node, env, ctx)
        return

    if node_type == "with_statement":
        _handle_with(node, env, ctx)
        return

    if node_type in ("match_statement", "case_clause"):
        _handle_match(node, env, ctx)
        return

    if node_type == "return_statement":
        values = [_eval(child, env, ctx) for child in node.named_children]  # type: ignore[attr-defined]
        if any(value is not None and value.dirty for value in values):
            ctx.returns_tainted = True
        return

    if node_type in ("function_definition", "class_definition", "decorated_definition"):
        # 嵌套定义是**独立符号**（符号表里带 qualname 前缀），
        # 在这里展开会把「定义时」与「调用时」混为一谈
        return

    if node_type in (
        "import_statement",
        "import_from_statement",
        "global_statement",
        "nonlocal_statement",
        "pass_statement",
        "break_statement",
        "continue_statement",
    ):
        return

    # 其余语句：把其中的调用表达式求值一遍，保证 sink 不被漏掉
    # （`raise HTTPException(...)` / `assert check(uid)` / `del d[uid]`）
    for child in node.named_children:  # type: ignore[attr-defined]
        if child.type == "call":  # type: ignore[attr-defined]
            _eval(child, env, ctx)


def _handle_assignment(node: object, env: dict[str, TaintValue], ctx: _Context) -> None:
    """赋值：**先求右值，再写左值**（设计文档 §4.2 规则 1）。

    顺序反了会误判 `b = a; a = taint` 这类代码 —— 这是设计文档点名的坑，
    所以整个赋值逻辑只在这一个函数里实现，别处不允许再写一遍。
    """
    left = node.child_by_field_name("left")  # type: ignore[attr-defined]
    right = node.child_by_field_name("right")  # type: ignore[attr-defined]
    targets = _unpack_targets(left)
    values = _unpack_values(right)
    if len(targets) > 1 and len(values) == len(targets):
        for target, value_node in zip(targets, values, strict=True):
            _assign(target, _eval(value_node, env, ctx), env, ctx)
        return
    value = _eval(right, env, ctx)
    for target in targets:
        _assign(target, value, env, ctx)


def _unpack_targets(left: object) -> tuple[object, ...]:
    """左值解包：`a, b = ...` / `(a, b) = ...` / `[a, b] = ...`。"""
    if left is None:
        return ()
    if left.type in ("pattern_list", "tuple_pattern", "list_pattern"):  # type: ignore[attr-defined]
        return tuple(
            child
            for child in left.named_children  # type: ignore[attr-defined]
            if child.type in ("identifier", "attribute", "subscript", "as_pattern")  # type: ignore[attr-defined]
        )
    return (left,)


def _unpack_values(right: object | None) -> tuple[object, ...]:
    if right is None:
        return ()
    if right.type in ("expression_list", "tuple", "list"):  # type: ignore[attr-defined]
        return tuple(right.named_children)  # type: ignore[attr-defined]
    return (right,)


def _assign(
    target: object,
    value: TaintValue | None,
    env: dict[str, TaintValue],
    ctx: _Context,
) -> None:
    """把污点写进 env。`value` 为 None 表示**显式赋了一个干净值**。

    干净值也必须写进 env（写成 `None` 而不是删除键）：`uid = "clean"`
    之后 `uid` 就干净了 —— 若保留旧污点，`uid = request.args.get("id"); uid = "1"`
    这种先脏后洗的代码会被永久误报。
    """
    if target is None:
        return
    if target.type == "as_pattern":  # type: ignore[attr-defined]
        target = target.child_by_field_name("alias")  # type: ignore[attr-defined]
        if target is None:
            return
    path = access_path(target)
    if path is None:
        # 解包目标（`for k, v in ...` 之外的 `(a, b) = f()`）
        for child in getattr(target, "named_children", ()):
            _assign(child, value, env, ctx)
        return
    canonical = _canonical(path, ctx.aliases)
    if value is None:
        env[canonical] = _CLEAN_MARKER  # type: ignore[assignment]
        return
    env[canonical] = replace(value, current_path=canonical)


#: env 里表示「这个路径现在是干净的」的哨兵。
#: 用哨兵而不是删键，理由见 `_assign` 的 docstring —— 删键会让
#: 「重新赋干净值」被当成「没有信息」，从而保留上游的旧污点。
_CLEAN_MARKER: TaintValue = TaintValue(
    origin=TaintStep(0, "", 0, 0, "", TaintStepType.SOURCE, ""),
    origin_path="",
    origin_channel="",
    current_path="",
    level=Level.CLEAN,
)


def _handle_if(node: object, env: dict[str, TaintValue], ctx: _Context) -> None:
    """if/elif：分支合并 + 白名单守卫（设计文档 §4.2 规则 4、§4.4）。"""
    condition = node.child_by_field_name("condition")  # type: ignore[attr-defined]
    _eval(condition, env, ctx)  # 条件里的 source/sink 也要处理

    guard = None
    if condition is not None:
        guard = is_whitelist_guard(
            condition,
            frozenset(path for path, value in env.items() if value.dirty),
            ctx.const_table,
        )

    env_true = dict(env)
    env_false = dict(env)
    if guard is not None:
        target_env = env_true if guard.positive else env_false
        _apply_guard(guard, target_env, condition, ctx)

    consequence = node.child_by_field_name("consequence")  # type: ignore[attr-defined]
    alternative = node.child_by_field_name("alternative")  # type: ignore[attr-defined]
    _walk_block(consequence, env_true, ctx)
    _walk_clause(alternative, env_false, ctx)

    # 终止的分支**整个不参与合并**：`if x not in A: return` 之后的代码
    # 只可能来自「没走那一支」的路径，直接取那一支的环境。
    #
    # ⚠️ 这里**不能**写成 `_merge_env(env, env_false)`。合并会把 if 之前的
    # 旧状态也算作一条到达路径，而净化集合取交集 —— 于是白名单守卫的
    # 「已净化」标记会被旧状态里的「未净化」抵消掉，守卫等于没生效。
    # 这个坑的表现是「白名单写了但还是报」，很容易被误判成规则没写对。
    if is_terminating(consequence):
        _replace_env(env, env_false)
    elif is_terminating(alternative):
        _replace_env(env, env_true)
    else:
        _merge_env(env, env_true)
        _merge_env(env, env_false)


def _apply_guard(
    guard: object, env: dict[str, TaintValue], condition: object, ctx: _Context
) -> None:
    """白名单守卫 → 把被约束的路径标成「该类型已净化」。

    白名单的含义是「这个值只能是集合里的那几个」，因此**所有注入类漏洞**
    都被中和（值不可能携带载荷）—— 这与「按 vuln_type 判定」并不矛盾：
    集合约束是比编码转义更强的约束。
    """
    operator = getattr(guard, "operator", "")
    for path in getattr(guard, "sanitized", ()):
        value = _lookup(path, env, ctx.aliases)
        if value is None or not value.dirty:
            continue
        env[path] = replace(
            value,
            current_path=path,
            sanitized_types=frozenset(VulnType),
            via_steps=_append_step(
                value,
                _mid_step(ctx.parsed, condition, f"whitelist:{operator}", TaintStepType.SANITIZE),
            ),
        )
        ctx.guarded.add(path)


def _merge_env(env: dict[str, TaintValue], other: Mapping[str, TaintValue]) -> None:
    """把 `other` 合并进 `env`（级别取并集、净化取交集）。"""
    for path, value in other.items():
        current = env.get(path)
        if current is None:
            env[path] = value
            continue
        merged = _merge_values([current, value])
        env[path] = merged if merged is not None else _CLEAN_MARKER


def _replace_env(env: dict[str, TaintValue], source: Mapping[str, TaintValue]) -> None:
    """用 `source` **整体替换** `env` 的内容（就地改，不重新绑定）。

    必须就地改：调用方持有的是同一个 dict 引用（`_walk_block` 一路传下来），
    重新绑定只会改局部变量，调用方看到的环境纹丝不动 —— 这是「看起来对、
    实际没生效」的经典写法。只在「另一支已终止」时使用，见 `_handle_if`。
    """
    env.clear()
    env.update(source)


def _walk_clause(clause: object | None, env: dict[str, TaintValue], ctx: _Context) -> None:
    """处理 `else_clause` / `elif_clause` / `finally_clause` / `except_clause`。

    这些子句的 AST 形状各不相同（`elif_clause` 与 `if_statement` 同构，
    `else_clause` 直接包一个 block），所以**单独抽一处**翻译，
    而不是在每个调用点各写一遍 `if` —— 那是同类逻辑散落的开始。
    """
    if clause is None:
        return
    clause_type = clause.type  # type: ignore[attr-defined]
    if clause_type == "elif_clause":
        _handle_if(clause, env, ctx)
        return
    if clause_type in ("else_clause", "finally_clause", "except_clause"):
        for child in clause.named_children:  # type: ignore[attr-defined]
            if child.type == "block":  # type: ignore[attr-defined]
                _walk_block(child, env, ctx)
        return
    if clause_type == "block":
        _walk_block(clause, env, ctx)
        return
    _handle_statement(clause, env, ctx)


def _handle_for(node: object, env: dict[str, TaintValue], ctx: _Context) -> None:
    """for：迭代对象的污点传给循环变量，循环体按不动点迭代最多 5 轮。"""
    right = node.child_by_field_name("right")  # type: ignore[attr-defined]
    left = node.child_by_field_name("left")  # type: ignore[attr-defined]
    iterable = _eval(right, env, ctx)
    _assign(left, iterable, env, ctx)
    _run_loop_body(node.child_by_field_name("body"), dict(env), ctx, env)  # type: ignore[attr-defined]
    _walk_clause(node.child_by_field_name("alternative"), env, ctx)


def _run_loop_body(
    body: object | None,
    loop_env: dict[str, TaintValue],
    ctx: _Context,
    outer: dict[str, TaintValue],
) -> None:
    """循环体的不动点迭代（设计文档 §4.2 规则 6）。

    为什么需要：`for x in items: q = q + x` 里 `q` 的污点在第二轮才稳定。
    单趟遍历只能看到第一轮的状态，回边上的污点会漏。

    为什么最多 5 轮：这是路径敏感分析，轮数越多越精确也越慢；
    5 轮覆盖了真实代码里几乎所有的累积形态（累加、追加、链式拼接），
    而更深的累积本来就依赖运行时的迭代次数 —— 静态不可能算准，
    报「最多 5 轮」的结论比报「算到收敛」的假象更诚实。
    """
    for _ in range(MAX_LOOP_ROUNDS):
        before = _env_signature(loop_env)
        _walk_block(body, loop_env, ctx)
        if _env_signature(loop_env) == before:
            break
    _merge_env(outer, loop_env)


def _env_signature(env: Mapping[str, TaintValue]) -> tuple:
    """env 的**可比较快照**，用于不动点收敛判定。

    必须只包含污点状态的语义字段（不包括 `via_steps` 这类只影响展示的内容），
    否则每轮都会「有变化」，5 轮全部跑满并让路径步数虚增。
    """
    return tuple(
        sorted(
            (
                path,
                int(value.level),
                value.origin.line,
                value.origin_path,
                value.partial,
                tuple(sorted(t.value for t in value.sanitized_types)),
                value.unexpanded,
            )
            for path, value in env.items()
            if value.dirty
        )
    )


def _handle_try(node: object, env: dict[str, TaintValue], ctx: _Context) -> None:
    """try/except/else/finally：各分支分别走一遍后合并。

    异常处理的分支语义（哪条语句抛、抛在哪一行）静态不可判定，
    所以按「任何位置都可能抛」保守处理：每个 handler 都看到 try 块
    **全部执行完**之后的环境。宁可多报。
    """
    body = node.child_by_field_name("body")  # type: ignore[attr-defined]
    _walk_block(body, env, ctx)

    except_envs: list[dict[str, TaintValue]] = []
    for child in node.named_children:  # type: ignore[attr-defined]
        if child.type != "except_clause":  # type: ignore[attr-defined]
            continue
        handler_env = dict(env)
        for grandchild in child.named_children:  # type: ignore[attr-defined]
            if grandchild.type == "block":  # type: ignore[attr-defined]
                _walk_block(grandchild, handler_env, ctx)
        except_envs.append(handler_env)
    for handler_env in except_envs:
        _merge_env(env, handler_env)

    for child in node.named_children:  # type: ignore[attr-defined]
        if child.type == "else_clause":  # type: ignore[attr-defined]
            _walk_clause(child, env, ctx)
        elif child.type == "finally_clause":  # type: ignore[attr-defined]
            _walk_clause(child, env, ctx)


def _with_item_parts(value_node: object | None) -> tuple[object | None, object | None]:
    """拆 `with <表达式> as <target>`。

    tree-sitter 的层级是 `with_statement → with_clause → with_item →
    as_pattern(表达式, as_pattern_target)`，**三层**。只遍历一层
    （以为 `with_statement` 的子节点直接就是 `with_item`）会让
    `with open(path) as fh` 里的 `open()` 永远不被求值 ——
    表现为「`with open(用户输入)` 这种最典型的路径穿越报不出来」，
    且不报错。`as_pattern` 的 `alias` 字段指向的是 **target**（`fh`），
    不是表达式，别按字段名想当然。
    """
    if value_node is None:
        return None, None
    if value_node.type != "as_pattern":  # type: ignore[attr-defined]
        return value_node, None
    expressions = [
        child
        for child in value_node.named_children  # type: ignore[attr-defined]
        if child.type != "as_pattern_target"  # type: ignore[attr-defined]
    ]
    target = value_node.child_by_field_name("alias")  # type: ignore[attr-defined]
    return (expressions[0] if expressions else None), target


def _handle_with(node: object, env: dict[str, TaintValue], ctx: _Context) -> None:
    """with：上下文表达式可能本身是 sink（`with open(path) as f`），
    且绑定名继承上下文表达式的污点。"""
    for child in node.named_children:  # type: ignore[attr-defined]
        child_type = child.type  # type: ignore[attr-defined]
        if child_type == "with_clause":
            for item in child.named_children:  # type: ignore[attr-defined]
                if item.type != "with_item":  # type: ignore[attr-defined]
                    continue
                expression, target = _with_item_parts(
                    item.child_by_field_name("value")  # type: ignore[attr-defined]
                )
                value = _eval(expression, env, ctx)
                if target is not None and value is not None:
                    _assign(target, value, env, ctx)
        elif child_type == "block":
            _walk_block(child, env, ctx)


def _handle_match(node: object, env: dict[str, TaintValue], ctx: _Context) -> None:
    """match：subject 求值，每个 case 单独走一遍后合并（同 if 的处理）。"""
    if node.type == "match_statement":  # type: ignore[attr-defined]
        _eval(node.child_by_field_name("subject"), env, ctx)  # type: ignore[attr-defined]
        for child in node.named_children:  # type: ignore[attr-defined]
            if child.type != "case_clause":  # type: ignore[attr-defined]
                continue
            case_env = dict(env)
            _handle_match(child, case_env, ctx)
            _merge_env(env, case_env)
        return
    body = None
    for child in node.named_children:  # type: ignore[attr-defined]
        if child.type == "block":  # type: ignore[attr-defined]
            body = child
    _walk_block(body, env, ctx)


# ---------------------------------------------------------------------------
# 一次函数分析
# ---------------------------------------------------------------------------


def _run_function(
    function: FunctionDef,
    seeds: tuple[Seed, ...],
    expand_inter: bool,
    *,
    parsed: ParsedFile,
    table: SymbolTable,
    summaries: SummaryTable | None,
) -> FunctionRunResult:
    """跑一遍函数体。签名与 `summary.RunBody` 一致（依赖注入的那一端）。"""
    env: dict[str, TaintValue] = {}
    for seed in seeds:
        # 形参入口（摘要生成）的种子没有源码片段，这里按行号补上。
        # 缺片段不是「少个装饰」：前端时间轴靠 `snippet` 高亮那一行，
        # 空串会让「形参入口」这一跳在界面上变成一个没有内容的空节点，
        # 而跨函数路径的可读性**全靠这一跳**说明污点是从哪个参数进来的。
        line = seed.line or function.line
        snippet = seed.snippet or " ".join(parsed.line_text(line).split())[:200]
        value = TaintValue(
            origin=TaintStep(
                step_index=0,
                file_path=parsed.rel_path,
                line=line,
                column=0,
                symbol=seed.symbol or seed.path,
                step_kind=seed.kind,
                snippet=snippet,
            ),
            origin_path=seed.path,
            origin_channel=seed.channel,
            current_path=seed.path,
        )
        env[seed.path] = value

    ctx = _Context(
        parsed=parsed,
        function=function,
        table=table,
        summaries=summaries,
        expand_inter=expand_inter,
        const_table=const_table_of(table, function.file_path),
        aliases=_request_aliases(function),
        hits=[],
        guarded=set(),
    )
    _walk_block(function.body, env, ctx)
    return FunctionRunResult(
        hits=tuple(ctx.hits),
        returns_tainted=ctx.returns_tainted,
        uses_project_call=ctx.uses_project_call,
        calls_self=ctx.calls_self,
        guarded_paths=frozenset(ctx.guarded),
    )


def _request_aliases(function: FunctionDef) -> dict[str, str]:
    """`def f(req: Request)` → `{req: request}`。

    只处理注解为 Request 的形参。**不做**类型推断、不看赋值 ——
    `r = request` 这类别名不跟进（要跟进就需要数据流分析本身，
    那正是我们在做的事，会绕成循环）。
    """
    aliases: dict[str, str] = {}
    for name, annotation in function.annotations.items():
        if annotation.rsplit(".", 1)[-1] in REQUEST_TYPES or annotation in REQUEST_TYPES:
            aliases[name] = "request"
    return aliases


#: FastAPI 注入标注 → 输入通道。`Depends` **不在**其中：
#: 它注入的通常是「当前用户」这类已经过鉴权的对象，
#: 当成 source 会让每个 `current_user.id` 都变成不可信输入。
_DEFAULT_CHANNELS: dict[str, str] = {
    "Query": "http_param",
    "Path": "http_param",
    "Body": "http_body",
    "Form": "http_body",
    "File": "http_body",
    "UploadFile": "http_body",
    "Header": "header",
    "Cookie": "cookie",
}


def _seed_params(function: FunctionDef) -> tuple[Seed, ...]:
    """FastAPI 注入形参 → 起始污点（设计文档 §4.5 的「框架注入参数」）。

    三种判据任一成立即视为外部输入：
    1. 默认值是 `Query()/Path()/Form()/...` 的调用，**且该函数是路由**；
    2. 形参名出现在路由路径模板里（`/order/{uid}`）；
    3. （注解为 Request 的形参不在这里 —— 它是「请求对象」，
        其属性在符号匹配阶段自然成为 source，见 `_request_aliases`。）

    判据 1 与 2 都要求**保留形参声明**这一证据：只看名字（`uid`）会把
    `def compute(uid)` 这样的内部函数形参也当成外部输入。

    判据 1 额外要求 `is_route`：`Query(...)` 的默认值只有**由框架按签名注入**
    时才有「外部可控」的含义，而非路由函数（工具函数、`Depends` 目标的内部
    辅助）里的 `def helper(limit: int = Query(10))` 是普通默认值 ——
    不要求这一条的话，每个带 FastAPI 风格默认值的辅助函数都会变成
    一条凭空出现的注入 Finding。
    """
    seeds: list[Seed] = []
    for name, _node in function.param_nodes:
        default = function.defaults.get(name)
        if function.is_route and default is not None and default.type == "call":  # type: ignore[attr-defined]
            function_node = call_function_node(default)
            marker = (
                dotted_name(function_node).rsplit(".", 1)[-1] if function_node is not None else ""
            )
            channel = _DEFAULT_CHANNELS.get(marker)
            if channel is not None:
                seeds.append(
                    Seed(
                        path=name,
                        kind=TaintStepType.SOURCE,
                        symbol=name,
                        channel=channel,
                        line=function.line,
                        snippet=snippet_of(default, limit=80),
                    )
                )
                continue
        annotation = function.annotations.get(name, "")
        if function.is_route and annotation.rsplit(".", 1)[-1] in PARAM_SOURCE_DEFAULTS:
            # 注解成 `UploadFile` / `File` 等但没写默认值
            channel = _DEFAULT_CHANNELS.get(annotation.rsplit(".", 1)[-1])
            if channel is not None:
                seeds.append(
                    Seed(
                        path=name,
                        kind=TaintStepType.SOURCE,
                        symbol=name,
                        channel=channel,
                        line=function.line,
                        snippet=annotation,
                    )
                )
                continue
        if name in function.route_params:
            seeds.append(
                Seed(
                    path=name,
                    kind=TaintStepType.SOURCE,
                    symbol=name,
                    channel="http_param",
                    line=function.line,
                    snippet=f"路径模板参数 {name}",
                )
            )
    return tuple(seeds)


# ---------------------------------------------------------------------------
# 命中 → Finding
# ---------------------------------------------------------------------------


def _hit_to_finding(hit: SinkHit) -> Finding:
    """把一次 sink 命中翻译成契约里的 Finding。

    路径 = 首跳（source）+ 中间步骤（净化 / 调用点 / 形参入口）+ 末跳（sink）。
    中间步骤**不含**函数内的普通赋值传播：一个 `uid` 在函数里被转手五次，
    路径就会长出 5 跳、比代码本身还长。中间步骤只保留「读的人需要知道」的
    三类：净化点、跨函数边界、绕过防护的位置。

    `confidence` 一律由 `finding.compute_confidence` 按设计文档 §4.5 的公式
    算出（跨函数 ×0.9、弱净化 ×0.6、RCE ×1.1）—— 这里不出现任何魔数。
    """
    steps = (hit.origin, *hit.via_steps, hit.sink)
    return make_finding(
        vuln_type=hit.vuln_type,
        file_path=hit.sink.file_path,
        line_start=hit.line_start,
        line_end=hit.line_end,
        symbol=hit.sink.symbol,
        steps=steps,
        source_kind=hit.channel or "unknown",
        sink_kind=hit.sink_spec.symbol,
        guard_blocked=hit.partial,
        detection_method=(
            DetectionMethod.TAINT_INTER if hit.inter_procedural else DetectionMethod.TAINT_INTRA
        ),
        inter_procedural=hit.inter_procedural,
        partial=hit.partial,
        unexpanded=hit.unexpanded,
    )


# ---------------------------------------------------------------------------
# 编排
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _FileEntry:
    rel_path: str
    size_bytes: int
    language: str


def _manifest_entries(manifest: object) -> tuple[tuple[_FileEntry, ...], bool]:
    """从 manifest 里取「要分析哪些文件」。

    期望的形态（`app/projects/types.py::SourceManifest` 的子集）：
    `entries[*].{rel_path, size_bytes, language}` 与 `truncated`。

    用**结构化协议**而不是 `import app.projects.types`：那样会让 B4 反向
    依赖 B2（L3 不硬禁止，但依赖方向是错的）；而且 `analyze` 的调用方
    只要给一个形状对的对象就能用，靶场回归脚本不必构造 B1 的 DTO。
    dict 与对象两种形态都接受，理由同上。

    可选字段一律用 `.get` / `getattr(..., 默认值)`：`entries` 是必需的，
    其余字段缺了就当默认值。写成 `manifest["truncated"]` 会让
    「上游版本稍旧的 manifest」直接抛 KeyError —— 而这一层的失败模式
    应当是**降级并记录**，不是把整轮分析炸掉。
    """
    raw_entries = manifest["entries"] if isinstance(manifest, Mapping) else manifest.entries  # type: ignore[union-attr]
    if isinstance(manifest, Mapping):
        truncated = bool(manifest.get("truncated", False))
    else:
        truncated = bool(getattr(manifest, "truncated", False))
    entries: list[_FileEntry] = []
    for raw in raw_entries:
        if isinstance(raw, Mapping):
            rel_path = str(raw.get("rel_path", ""))
            size = int(raw.get("size_bytes", 0))
            language = str(raw.get("language", "python"))
        else:
            rel_path = str(getattr(raw, "rel_path", ""))
            size = int(getattr(raw, "size_bytes", 0) or 0)
            language = str(getattr(raw, "language", "python") or "python")
        if rel_path:
            entries.append(_FileEntry(rel_path=rel_path, size_bytes=size, language=language))
    return tuple(entries), truncated


def analyze_sources(
    sources: Mapping[str, str],
    *,
    truncated: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    language: str = "python",
) -> AnalysisResult:
    """**核心同步入口**：直接吃「相对路径 → 源码文本」。

    B3 走 `analyze()`（带 read_source 回调），`analyze_project` / `analyze_file`
    走文件系统，而单测与靶场回归直接调这个 —— 不碰文件系统，
    样例代码以字符串字面量的形式写在测试里，改一行就能看到结论变化。
    """
    started = time.perf_counter()
    files_scanned = 0
    total_loc = 0
    findings: list[Finding] = []
    skipped: list[SkipRecord] = []

    parsed_files: list[ParsedFile] = []
    for index, (rel_path, source) in enumerate(sorted(sources.items())):
        if index >= max_files:
            truncated = True
            skipped.append(SkipRecord(rel_path, f"文件数超过上限 {max_files}", "L2"))
            continue
        if len(source.encode("utf-8", errors="replace")) > max_file_bytes:
            skipped.append(
                SkipRecord(
                    rel_path,
                    f"文件超过 {max_file_bytes} 字节上限，仅尝试匹配硬编码凭据",
                    "L1",
                )
            )
            findings.extend(_oversize_secret_findings(rel_path, source))
            continue
        parsed_files.append(parse_file(rel_path, source, language=language))

    files_scanned = len(parsed_files)
    total_loc = sum(count_loc(parsed.lines) for parsed in parsed_files)

    if parsed_files:
        filed = tuple(parsed_files)
        table = build_symbol_table(filed)
        for parsed in filed:
            if parsed.has_error:
                skipped.append(
                    SkipRecord(
                        parsed.rel_path,
                        "存在语法错误（已按可解析部分分析，结论可能不完整）",
                        "L1",
                    )
                )
        findings.extend(_analyze_taint(filed, table))

    findings = list(dedupe(findings))
    unexpanded = sum(1 for finding in findings if finding.unexpanded)
    return AnalysisResult(
        findings=tuple(findings),
        files_scanned=files_scanned,
        total_loc=total_loc,
        duration_ms=int((time.perf_counter() - started) * 1000),
        truncated=truncated,
        files_skipped=tuple(skipped),
        unexpanded_calls=unexpanded,
    )


def _oversize_secret_findings(rel_path: str, source: str) -> list[Finding]:
    """超大文件：不做污点分析，只做一次**行级**的硬编码凭据匹配（设计文档 §6 场景 3）。

    为什么留这一条而不是直接跳过：超大文件往往正是配置/生成代码，
    硬编码凭据的密度不低；而这条规则的实现是纯行扫描，成本与文件大小线性相关，
    不做 AST 解析就不会触发「单文件超时」。

    规则本身（正则与值形态判定）与 `patterns.py` **共用同一份实现** ——
    降级路径最容易变成「规则的第二份副本」，然后两份慢慢不一致。
    """
    findings: list[Finding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        name_part, sep, literal_part = line.partition("=")
        # 必须**先去空白再匹配**：`SECRET_NAME_RE` 的边界是 `^`/`_`/`$`，
        # 而 `line.partition("=")` 会把 `API_KEY ` 连同尾随空格一起交出来，
        # 于是 `API_KEY = "..."` 这种最常见（带空格）的写法一条都匹配不上 ——
        # 降级路径静默失效，没有任何报错。
        name = name_part.strip()
        if not sep or not name_looks_like_secret(name):
            continue
        literal = literal_part.strip()
        if len(literal) < 2 or literal[0] not in "\"'":
            continue
        if not is_secret_literal(literal.strip("\"'")):
            continue
        findings.append(
            make_secret_finding(
                file_path=rel_path,
                line=line_number,
                name=name,
                snippet=line.strip(),
            )
        )
    return findings


def _analyze_taint(files: tuple[ParsedFile, ...], table: SymbolTable) -> list[Finding]:
    """两遍分析：先建摘要，再带摘要跑一遍产出 Finding（设计文档 §4.3）。

    第一遍的 `run` 回调**恒定**传 `summaries=None`：摘要必须建立在
    「只做函数内传播」的基础上，否则深度就不止一层了（那正是设计文档
    在 §7.2 取舍 1 里明确不要的东西）。
    """
    functions = tuple(sorted(table.functions.values(), key=lambda f: f.qualname))
    parsed_by_path = {parsed.rel_path: parsed for parsed in files}

    def run(
        function: FunctionDef, seeds: tuple[Seed, ...], expand_inter: bool
    ) -> FunctionRunResult:
        return _run_function(
            function,
            seeds,
            expand_inter,
            parsed=parsed_by_path[function.file_path],
            table=table,
            summaries=None,
        )

    # ---- 第一遍：摘要 ----
    summary_table = build_summary_table(functions, run)
    for qualname, reason in summary_table.skipped:
        logger.warning("未生成函数摘要：%s（%s）", qualname, reason)

    # ---- 第二遍：带摘要正向分析 ----
    findings: list[Finding] = []
    for function in functions:
        result = _run_function(
            function,
            _seed_params(function),
            True,
            parsed=parsed_by_path[function.file_path],
            table=table,
            summaries=summary_table,
        )
        findings.extend(_hit_to_finding(hit) for hit in result.hits)

    findings.extend(run_pattern_rules(files, table))
    return findings


def _parsed_of(function: FunctionDef, files: Sequence[ParsedFile]) -> ParsedFile:
    for parsed in files:
        if parsed.rel_path == function.file_path:
            return parsed
    raise AssertionError(f"函数 {function.qualname} 的文件不在已解析集合中")


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------


def analyze_project(
    root: str | Path,
    *,
    include_globs: Sequence[str] | None = None,
    exclude_dirs: frozenset[str] | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    language: str = "python",
) -> AnalysisResult:
    """「扔一个目录进来」的入口：靶场回归与单测用。

    ⚠️ 它**会读文件系统**。B3 的生产路径走 `analyze(manifest, read_source)`，
    这是刻意保留的第二入口（`parser.iter_py_files` 的 docstring 已承诺它存在）。
    """
    started = time.perf_counter()
    root_path = Path(root)
    read = make_fs_reader(root_path)
    sources: dict[str, str] = {}
    truncated = False
    skipped: list[SkipRecord] = []
    deadline = started + max_seconds
    for rel_path in iter_py_files(
        root_path,
        include=include_globs,
        **({"exclude_dirs": exclude_dirs} if exclude_dirs is not None else {}),
    ):
        if len(sources) >= max_files:
            truncated = True
            skipped.append(SkipRecord(rel_path, f"文件数超过上限 {max_files}", "L2"))
            continue
        if time.perf_counter() > deadline:
            truncated = True
            skipped.append(SkipRecord(rel_path, f"超过 {max_seconds:.0f}s 预算，未分析", "L2"))
            continue
        try:
            sources[rel_path] = read(rel_path)
        except SourceUnreadable as exc:
            skipped.append(SkipRecord(rel_path, str(exc), "L1"))

    result = analyze_sources(
        sources,
        truncated=truncated,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        language=language,
    )
    return replace(
        result,
        files_skipped=result.files_skipped + tuple(skipped),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )


def analyze_file(
    path: str | Path,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> AnalysisResult:
    """单文件分析（单测最常用的入口）。`rel_path` 取文件名。"""
    file_path = Path(path)
    source = read_text_file(file_path)
    return analyze_sources({file_path.name: source}, max_file_bytes=max_file_bytes)


ReadSource = Callable[[str], str] | Callable[[str], Awaitable[str]]


async def analyze(
    manifest: object,
    read_source: ReadSource,
    *,
    include_globs: Sequence[str] | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    language: str = "python",
) -> AnalysisResult:
    """**B3 的正式入口**（契约 4）。

    `read_source` 是回调，B4 因此完全不知道工作区长什么样 ——
    这是刻意的解耦（设计文档 §2 的「B4 不依赖具体的工作区实现」），
    别改成在这里直接读文件系统。

    回调**同步/异步都支持**：`app/projects/workspace.py::read_source`
    是 `async def`，而靶场回归脚本往往给一个同步函数。用 `isawaitable`
    判一次，比要求所有调用方统一签名更省事，也不会掩盖真正的错误
    （回调抛异常照常向上传播）。
    """
    started = time.perf_counter()
    entries, truncated = _manifest_entries(manifest)
    skipped: list[SkipRecord] = []
    sources: dict[str, str] = {}
    deadline = started + max_seconds
    for entry in entries:
        # 按**扩展名**判，不按 manifest 的 `language` —— 理由见 `_EXT_TO_LANGUAGE`
        # 上面那段（B1 给的是显示名 "Python"，与引擎的标识符 "python" 不是一套）。
        suffix = PurePosixPath(entry.rel_path).suffix.lower()
        if suffix not in _EXT_TO_LANGUAGE:
            # 本期只做 Python（设计文档 §7.2 取舍 10）。**显式记录**而不是
            # 静默跳过：调用方看到「files_scanned 比 entries 少」时需要能查到原因。
            # 报后缀而不是报 `entry.language`：后缀是判据本身，
            # 而显示名在「为什么这个文件被跳过」上给不出可操作的信息。
            skipped.append(
                SkipRecord(entry.rel_path, f"暂不支持的文件类型：{suffix or '(无扩展名)'}", "L5")
            )
            continue
        if len(sources) >= max_files:
            truncated = True
            skipped.append(SkipRecord(entry.rel_path, f"文件数超过上限 {max_files}", "L2"))
            continue
        if time.perf_counter() > deadline:
            truncated = True
            skipped.append(
                SkipRecord(entry.rel_path, f"超过 {max_seconds:.0f}s 预算，未分析", "L2")
            )
            continue
        if entry.size_bytes > max_file_bytes:
            skipped.append(SkipRecord(entry.rel_path, f"文件超过 {max_file_bytes} 字节上限", "L1"))
            continue
        try:
            content = read_source(entry.rel_path)
            if inspect.isawaitable(content):
                content = await content
        except Exception as exc:  # noqa: BLE001 —— 单文件读失败不终止整轮（设计文档 §6 场景 1）
            skipped.append(SkipRecord(entry.rel_path, f"读取失败：{exc}", "L1"))
            continue
        sources[entry.rel_path] = content

    result = analyze_sources(
        sources,
        truncated=truncated,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        language=language,
    )
    return replace(
        result,
        files_skipped=result.files_skipped + tuple(skipped),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )


__all__ = [
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_SECONDS",
    "Level",
    "TaintValue",
    "analyze",
    "analyze_file",
    "analyze_project",
    "analyze_sources",
]
