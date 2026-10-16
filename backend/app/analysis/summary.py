"""函数摘要与调用点匹配（设计文档 §2 的 summary、§4.3 的单层跨函数传播）。

**本文件不 import `taint.py`，而由 `taint.py` 传入传播规则回调**（依赖注入）。
设计文档 §2.1 专门点名了这个约束：函数摘要的生成必须复用函数内传播规则
（否则「函数内能追上、跨函数追不上」会变成两条会漂移的实现），
但直接 `import taint` 会构成循环 import。所以这里定义**回调签名**与
**数据结构**，`taint.py` 提供实现。

**深度只展开一层**（设计文档 §7.2 取舍 1、总纲 D6）：生成摘要时遇到更深一层的
项目内调用，只记 `unexpanded_depth = 1` 并让下游把 Finding 标成「未展开」，
**不继续递归**。理由不是懒：第二层的边际召回远低于它引入的虚假精确 ——
一份「调用链更深、静态未展开」的诚实标注，比一条看似精确其实靠猜的路径值钱。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from app.analysis.sinks import SinkSpec
from app.analysis.symbols import FunctionDef
from app.analysis.types import TaintStep, VulnType
from app.models.enums import TaintStepType


@dataclass(frozen=True, slots=True)
class Seed:
    """函数内传播的「起始污点」。

    - `kind=SOURCE`：真实 source（`uid` 来自 `request.args`），正常分析用；
    - `kind=PROPAGATE`：**形参入口**（摘要生成用）。它对应路径里的「形参」那一跳，
      不是漏洞的源头 —— 真正的 source 在调用点，由调用方拼在前面。

    用一个显式字段区分，而不是靠「传进来的算形参」这类隐式约定：
    跨函数路径的 source/sink 两端是补丁复验的身份锚（设计文档 §3.4），
    这里标错会让「补丁后这条路径还在吗」判错。
    """

    path: str
    kind: TaintStepType
    symbol: str
    channel: str = ""
    line: int = 0
    snippet: str = ""


@dataclass(frozen=True, slots=True)
class SinkHit:
    """一次「污点到达 sink」的事实。**只描述事实，不做取舍**。

    取舍（报不报、置信度多少）在 `taint.py` 与 sink 匹配阶段完成 ——
    同一个 hit 在函数内分析与摘要生成两种上下文下的结论不同
    （后者不产出 Finding，只描述「形参 0 能到达这个 sink」）。
    """

    vuln_type: VulnType
    sink_spec: SinkSpec
    sink: TaintStep  # 末尾那一跳
    line_start: int
    line_end: int
    origin: TaintStep  # 首跳：真实 source，或摘要里的形参入口
    origin_path: str
    #: 首跳的输入通道（`sources.CHANNELS` 之一）—— Finding 的 `source_kind`
    channel: str
    arg_path: str
    #: 首跳与末跳**之间**的步骤，按顺序（净化点、跨函数调用点、形参入口…）。
    #: 名字不叫 sanitize_steps：跨函数命中时这里还会放进「调用点」与「形参」两跳，
    #: 叫 sanitize 会让人以为里面只有净化点，进而漏读跨函数的关键两跳。
    via_steps: tuple[TaintStep, ...]
    #: 该路径上**被完全中和**的漏洞类型集合（强度 full 且覆盖该类型）
    sanitized_types: frozenset[VulnType]
    #: 路径上有弱净化（只改表示形态）→ 置信度 ×0.6 的信号
    partial: bool
    inter_procedural: bool
    unexpanded: bool


@dataclass(frozen=True, slots=True)
class FunctionRunResult:
    """跑一遍函数体的产出（由 `taint.py` 的 runner 填充）。"""

    hits: tuple[SinkHit, ...]
    returns_tainted: bool
    #: 体内存在项目内调用（含递归自调用）—— 决定 `unexpanded_depth`
    uses_project_call: bool
    calls_self: bool
    #: 被约束住的访问路径（白名单守卫识别出的），供调试与后续扩展
    guarded_paths: frozenset[str]


#: 传播规则回调的签名：`(函数定义, 起始污点, 是否展开跨函数调用) -> 一次运行的产出`。
#:
#: 第三个参数是**两种调用场景的分水岭**：
#: - 摘要生成时传 False —— 只记「体内还有项目内调用」，不递归（depth=1）；
#: - 正向分析时传 True —— 调用点真的去查摘要并产出跨函数 Finding。
RunBody = Callable[[FunctionDef, tuple[Seed, ...], bool], FunctionRunResult]


@dataclass(frozen=True, slots=True)
class ParamFlow:
    """单个形参的流向摘要（设计文档 §4.3 的 `ParamFlow`）。

    `path` 的拼装规则见 `build_summary` 的 docstring：摘要侧只给
    「形参入口 → … → sink」这一段，调用点再往前拼真实 source 与调用点两跳。
    """

    param_index: int
    param_name: str
    reaches_sink: VulnType | None
    sink_spec: SinkSpec | None
    sink: TaintStep | None
    entry: TaintStep | None
    pre_steps: tuple[TaintStep, ...]
    sanitized_types: frozenset[VulnType]
    partial: bool
    unexpanded: bool
    line_start: int
    line_end: int
    arg_path: str


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """函数摘要（设计文档 §3.3 的 `FunctionSummary`）。

    `param_flows` 的值是**元组**而不是单个 `ParamFlow`：设计文档写的是
    `dict[str, ParamFlow]`，但一个形参到达多个 sink（`def q(uid)` 里两条
    `execute`）是常见形态，只留第一条会静默丢漏洞。类型是内部词汇
    （B3 不落库、B5 不消费），改成元组的代价是零，收益是不丢。
    """

    qualname: str
    file_path: str
    params: tuple[str, ...]
    param_flows: dict[str, tuple[ParamFlow, ...]]
    returns_tainted: bool
    unexpanded_depth: int
    is_public_entry: bool
    recursive: bool
    line: int

    def flows_for(self, param_index: int) -> tuple[ParamFlow, ...]:
        return self.param_flows.get(f"param{param_index}", ())

    def param_index_of(self, name: str) -> int | None:
        try:
            return self.params.index(name)
        except ValueError:
            return None


def build_summary(
    function: FunctionDef,
    run: RunBody,
    *,
    max_sink_flows: int = 8,
) -> FunctionSummary:
    """为一个函数生成摘要（设计文档 §4.3 的第一遍）。

    **逐形参跑 N 次**（而不是一次把所有形参都标脏）：一次全标脏虽然更快，
    但 sink 上的污点来自哪个形参就没法归属了 —— 而「param0 能到达 sink」
    正是摘要唯一的用途。形参个数在真实代码里是个位数，N 次遍历的代价可以忽略。

    `max_sink_flows` 限制单个形参最多展开几条 sink 流：一个形参打到 20 个 sink
    的函数（批量执行器之类）会让调用点产出 20 条内容几乎相同的 Finding，
    噪声大于信息。截断后仍如实标注（`ParamFlow` 只是少几条，不假装完整）。
    """
    all_run = run(function, tuple(), False)
    flows: dict[str, tuple[ParamFlow, ...]] = {}
    #: 形参污点能否**污染返回值**。必须独立于 sink 流统计：
    #: `def build(uid): return "select " + uid` 这类「只传播、不落 sink」的函数
    #: 体内一个 sink 都没有，若把它和 sink 流绑在一起（例如
    #: `any(flow.reaches_sink is not None and ...)`），这个函数就会被判成
    #: 「返回值干净」—— 于是 `q = build(uid); execute(q)` 整条链静默消失。
    #: 这类「工具函数 + 调用点落 sink」的形状在真实代码里极常见。
    returns_tainted = all_run.returns_tainted

    for index, param_name in enumerate(function.params):
        seed = Seed(
            path=param_name,
            kind=TaintStepType.PROPAGATE,
            symbol=param_name,
            line=function.line,
        )
        result = run(function, (seed,), False)
        # 同一次运行既给出 sink 流，也给出「这个形参污染了返回值吗」——
        # 分开跑第二遍只会在两处之间制造漂移的可能。
        returns_tainted = returns_tainted or result.returns_tainted
        collected: list[ParamFlow] = []
        # 按 sink 行号排序后再截断：不排序的话「保留哪几条」取决于
        # AST 遍历顺序，虽然确定，但改一处遍历顺序就会让摘要整体漂移
        hits = sorted(result.hits, key=lambda h: (h.line_start, h.vuln_type.value, h.sink.symbol))
        for hit in hits[:max_sink_flows]:
            collected.append(
                ParamFlow(
                    param_index=index,
                    param_name=param_name,
                    reaches_sink=hit.vuln_type,
                    sink_spec=hit.sink_spec,
                    sink=hit.sink,
                    entry=hit.origin,
                    pre_steps=hit.via_steps,
                    sanitized_types=hit.sanitized_types,
                    partial=hit.partial,
                    unexpanded=hit.unexpanded,
                    line_start=hit.line_start,
                    line_end=hit.line_end,
                    arg_path=hit.arg_path,
                )
            )
        flows[f"param{index}"] = tuple(collected)

    return FunctionSummary(
        qualname=function.qualname,
        file_path=function.file_path,
        params=function.params,
        param_flows=flows,
        returns_tainted=returns_tainted,
        unexpanded_depth=1 if all_run.uses_project_call else 0,
        is_public_entry=function.is_route,
        recursive=all_run.calls_self,
        line=function.line,
    )


#: SummaryTable 的规模上限（设计文档 §6 场景 7）。
DEFAULT_MAX_FUNCTIONS_FOR_SUMMARY = 5000


@dataclass(frozen=True, slots=True)
class SummaryTable:
    """qualname → 摘要。`skipped` 记录**没建成摘要**的函数与原因。

    「没建成」必须显式记录下来：调用点查不到摘要时是静默降级的
    （只记 WARN、不产出跨函数 Finding）。若不留痕，表现为
    「某些跨函数漏洞就是查不出来」，而排查时无从下手。
    """

    summaries: dict[str, FunctionSummary]
    skipped: tuple[tuple[str, str], ...] = ()

    def get(self, qualname: str) -> FunctionSummary | None:
        return self.summaries.get(qualname)

    def skip_reason(self, qualname: str) -> str | None:
        for name, reason in self.skipped:
            if name == qualname:
                return reason
        return None


def build_summary_table(
    functions: Sequence[FunctionDef],
    run: RunBody,
    *,
    call_indegree: dict[str, int] | None = None,
    max_functions: int = DEFAULT_MAX_FUNCTIONS_FOR_SUMMARY,
) -> SummaryTable:
    """为全项目函数建摘要表，超限时按**调用入度**取前 N 个（设计文档 §6 场景 7）。

    为什么按入度而不是按文件顺序取：入度为 0 的函数（没人调用）建了摘要也用不上，
    而入库顺序完全取决于目录结构 —— 大仓库上「超限了要砍哪些」一旦与
    目录结构绑定，同一份代码换个目录名就会得出不同结论，确定性地基就没了。
    入度并列时按 qualname 兜底排序，保证顺序唯一确定。
    """
    ordered = list(functions)
    skipped: list[tuple[str, str]] = []
    if len(ordered) > max_functions:
        degree = call_indegree or {}
        ordered.sort(key=lambda f: (-degree.get(f.qualname, 0), f.qualname))
        dropped = ordered[max_functions:]
        ordered = ordered[:max_functions]
        skipped.extend((f.qualname, "摘要表规模超限，未建摘要") for f in dropped)

    summaries: dict[str, FunctionSummary] = {}
    for function in sorted(ordered, key=lambda f: f.qualname):
        try:
            summaries[function.qualname] = build_summary(function, run)
        except RecursionError:  # pragma: no cover - 防御性：AST 极深时的兜底
            skipped.append((function.qualname, "摘要生成递归过深，未建摘要"))
        except Exception as exc:  # noqa: BLE001
            # 单个函数的摘要失败**不该让整轮分析失败**：它是 L2 级问题，
            # 降级成「该函数调用点不产出跨函数 Finding」
            skipped.append((function.qualname, f"摘要生成失败：{exc}"))
    return SummaryTable(summaries=summaries, skipped=tuple(skipped))


def match_call_site(
    summary: FunctionSummary,
    *,
    tainted_positions: Sequence[int],
    tainted_keywords: Sequence[str],
) -> tuple[ParamFlow, ...]:
    """调用点匹配（设计文档 §4.3 的第二遍）。

    关键字实参按**形参名**映射，位置实参按**下标**映射 —— 两条路径分别处理，
    不混成一条「参数字典」。混起来的写法在 `f(x, y=z)` 这种
    「位置与关键字混用」的真实代码上会让第 1 个实参落到 `y` 上，
    而这类错配在跨函数 Finding 里表现为「路径指向了一个无关的行号」。
    """
    flows: list[ParamFlow] = []
    seen: set[tuple[int, int, str]] = set()

    def _add(param_index: int) -> None:
        for flow in summary.flows_for(param_index):
            if flow.reaches_sink is None:
                continue
            key = (param_index, flow.line_start, flow.reaches_sink.value)
            if key in seen:
                continue
            seen.add(key)
            flows.append(flow)

    for index in tainted_positions:
        _add(index)
    for name in tainted_keywords:
        index = summary.param_index_of(name)
        if index is not None:
            _add(index)
    return tuple(flows)


#: 「调用链更深、未展开」的提示文本。放在这里是为了让 B3/B6 与前端
#: 用同一份措辞 —— 三处各自写一遍的话，演示时同一件事会有三种说法。
UNEXPANDED_NOTE = "调用链更深，静态未展开"
