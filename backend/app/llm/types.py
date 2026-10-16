"""LLM 层的输入视图与输出结构。

## 为什么需要 `FindingView` 这层适配

契约 3 说四个用点的输入是「`Finding`（含污点路径）」，而契约 2 把 `Finding`
定义在 `app/analysis/types.py`（B4 拥有）。本包**不能 import 它** —— 那是 L3，
L4 反过来依赖 L3 就是环。于是这里用 `FindingView.of(obj)` 做**结构化适配**：
只要对象有那些属性就能被吃进来，B4 的 `Finding`、B5 的验证结果、以及 B6 从 ORM
`Vulnerability` 行构造出来的对象，三种来源共用一条入口。

⚠️ 适配里处理的**命名冲突是既有的、不是我发明的**（见最终报告「设计文档与契约
文档对不上的地方」）：契约 2 的 `Finding` 用 `step_kind` / `snippet`，
`models/vulnerability.py` 的列叫 `step_type` / `code_snippet`。适配器按
「契约 2 名优先、ORM 列名兜底」读，两个来源都不会静默丢字段。

**不叫 `FindingDTO` 也不做二次改名**：`vuln_type` / `line_start` / `taint_path`
这些名字一律照抄 `models/vulnerability.py`（PRD §6 是命名 SSOT）。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# `llm_model` 的取值 —— 契约 3：「要能区分 deepseek-chat 与 template」
# ---------------------------------------------------------------------------

#: 真正调用了模型时的标注。默认取 `settings.llm_model`，这里是兜底常量。
DEFAULT_MODEL = "deepseek-chat"
#: 降级到确定性模板时的标注。前端与报告据此显示「模板生成」（PRD §7.6.2 L4）。
TEMPLATE_MODEL = "template"


# ---------------------------------------------------------------------------
# 输入视图
# ---------------------------------------------------------------------------


def _as_str(value: Any, default: str = "") -> str:
    """把 StrEnum / None / 任意值收敛成字符串。

    `StrEnum.__str__` 返回的是**值**而不是成员名，所以 `str(Severity.HIGH) == "high"`；
    这里仍显式取 `.value`，是为了把「依赖 enum 基类行为」这件事写明白 ——
    换成普通 `Enum` 时 `str()` 会给出 `Severity.HIGH`，报告里就会出现这种字样。
    """
    if value is None:
        return default
    return str(getattr(value, "value", value))


def _as_opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = _as_str(value)
    return text or None


@dataclass(frozen=True, slots=True)
class TaintStepView:
    """污点路径上的一跳。字段名对齐契约 2 的 `TaintStep`。"""

    step_index: int
    step_kind: str  # source | propagate | sanitize | sink
    file_path: str
    line: int
    symbol: str | None = None
    snippet: str = ""

    @classmethod
    def of(cls, obj: Any) -> TaintStepView:
        kind = _as_str(getattr(obj, "step_kind", None) or getattr(obj, "step_type", None))
        return cls(
            step_index=int(getattr(obj, "step_index", 0) or 0),
            step_kind=kind or "propagate",
            file_path=_as_str(getattr(obj, "file_path", None)),
            line=int(getattr(obj, "line", 0) or 0),
            symbol=_as_opt_str(getattr(obj, "symbol", None)),
            snippet=_as_str(
                getattr(obj, "snippet", None) or getattr(obj, "code_snippet", None)
            ).strip(),
        )


@dataclass(frozen=True, slots=True)
class FindingView:
    """一个漏洞在表达层所需的全部事实。**全部是「已被判定」的值，不是待判断的问题。**"""

    vuln_type: str
    severity: str
    file_path: str
    line_start: int
    line_end: int

    #: 人类可读编号（`VULN-2026-0001`）。契约 2 的 `Finding` 没有这个字段
    #: （编号是入库时才分配的），所以允许为空 —— 空时模板不编造编号。
    code: str | None = None
    title: str = ""
    symbol: str | None = None
    cwe_id: str | None = None
    cvss_vector: str | None = None
    cvss_score: float = 0.0
    confidence: float = 1.0
    #: source_kind / sink_kind：污点从哪里来、到哪里去（B4 判定）
    source_kind: str | None = None
    sink_kind: str | None = None
    #: 路径上是否存在**生效的**净化函数（B4 判定）。guard_blocked 的条目报告里要标出来。
    guard_blocked: bool = False
    taint_path: tuple[TaintStepView, ...] = ()
    rule_id: str | None = None
    #: 已验证漏洞的验证状态（verified / potential / unverified / rejected）。
    #: **是输入，不是让模型判断的东西** —— 模型只负责把这个状态用中文表述。
    status: str | None = None
    #: 已有的人工/上游 rationale（如 B5 补丁的说明），供措辞参考
    rationale: str | None = None
    #: ±20 行源码片段（PRD §7.6.1「只送必要上下文」），用点 ① ② 用
    source_snippet: str = ""

    @classmethod
    def of(cls, obj: Any, **overrides: Any) -> FindingView:
        """从任意带这些属性的对象构造。`overrides` 用于补齐调用方才知道的字段。"""
        steps = getattr(obj, "taint_path", None)
        if steps is None:
            steps = getattr(obj, "taint_paths", None) or ()
        base = cls(
            vuln_type=_as_str(getattr(obj, "vuln_type", None) or getattr(obj, "type", None)),
            severity=_as_str(getattr(obj, "severity", None)),
            file_path=_as_str(getattr(obj, "file_path", None)),
            line_start=int(getattr(obj, "line_start", 0) or 0),
            line_end=int(getattr(obj, "line_end", 0) or 0),
            code=_as_opt_str(getattr(obj, "code", None)),
            title=_as_str(getattr(obj, "title", None)),
            symbol=_as_opt_str(getattr(obj, "symbol", None) or getattr(obj, "sink_symbol", None)),
            cwe_id=_as_opt_str(getattr(obj, "cwe_id", None)),
            cvss_vector=_as_opt_str(getattr(obj, "cvss_vector", None)),
            cvss_score=float(getattr(obj, "cvss_score", 0.0) or 0.0),
            confidence=float(getattr(obj, "confidence", 1.0) or 0.0),
            source_kind=_as_opt_str(getattr(obj, "source_kind", None)),
            sink_kind=_as_opt_str(getattr(obj, "sink_kind", None)),
            guard_blocked=bool(getattr(obj, "guard_blocked", False)),
            taint_path=tuple(TaintStepView.of(s) for s in steps),
            rule_id=_as_opt_str(getattr(obj, "rule_id", None)),
            status=_as_opt_str(getattr(obj, "status", None)),
            rationale=_as_opt_str(getattr(obj, "rationale", None)),
            source_snippet=_as_str(
                getattr(obj, "source_snippet", None) or getattr(obj, "code_snippet", None)
            ).strip(),
        )
        # 用 replace 而不是手拼参数字典：字段增删时这里不用跟着改，
        # 少一处「加了字段忘了同步」的地方
        return replace(base, **overrides) if overrides else base


@dataclass(frozen=True, slots=True)
class ChainNodeView:
    """攻击链上的一环。`verification_status` 是输入（B5 写入），不是让模型判断的东西。"""

    label: str
    node_type: str
    order_index: int
    verification_status: str  # verified | inferred
    detail: str | None = None
    stage_name: str | None = None
    rule_id: str | None = None
    vuln_code: str | None = None

    @classmethod
    def of(cls, obj: Any) -> ChainNodeView:
        return cls(
            label=_as_str(getattr(obj, "label", None)),
            node_type=_as_str(getattr(obj, "node_type", None)),
            order_index=int(getattr(obj, "order_index", 0) or 0),
            verification_status=_as_str(getattr(obj, "verification_status", None)) or "inferred",
            detail=_as_opt_str(getattr(obj, "detail", None)),
            stage_name=_as_opt_str(getattr(obj, "stage_name", None)),
            rule_id=_as_opt_str(getattr(obj, "rule_id", None)),
            vuln_code=_as_opt_str(getattr(obj, "vuln_code", None)),
        )


@dataclass(frozen=True, slots=True)
class ChainView:
    """一条攻击链。节点顺序由 B5 的 `order_index` 决定，**不由模型排**。"""

    name: str
    nodes: tuple[ChainNodeView, ...] = ()
    description: str | None = None
    entry_point: str | None = None
    target_asset: str | None = None
    severity: str | None = None

    @classmethod
    def of(cls, obj: Any) -> ChainView:
        raw_nodes = getattr(obj, "nodes", None) or ()
        nodes = tuple(sorted((ChainNodeView.of(n) for n in raw_nodes), key=lambda n: n.order_index))
        return cls(
            name=_as_str(getattr(obj, "name", None)),
            nodes=nodes,
            description=_as_opt_str(getattr(obj, "description", None)),
            entry_point=_as_opt_str(getattr(obj, "entry_point", None)),
            target_asset=_as_opt_str(getattr(obj, "target_asset", None)),
            severity=_as_opt_str(getattr(obj, "severity", None)),
        )

    @property
    def vuln_codes(self) -> tuple[str, ...]:
        """本链**实际**涉及的漏洞编码集合 —— 用点 ③ 的校验基准。"""
        return tuple(n.vuln_code for n in self.nodes if n.vuln_code)

    @property
    def verified_count(self) -> int:
        return sum(1 for n in self.nodes if n.verification_status == "verified")

    @property
    def inferred_count(self) -> int:
        return sum(1 for n in self.nodes if n.verification_status != "verified")


# ---------------------------------------------------------------------------
# 输出结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TextResult:
    """用点 ① ③ ④ 的统一返回。

    **只有文本与来源标注，没有任何参与判定的字段** —— 这是 L1 在类型层面的落点：
    调用方即使想把 LLM 的产出接进控制流，也找不到可接的东西。
    """

    text: str
    #: `deepseek-chat`（真调用了）或 `template`（降级了）。报告与前端据此标注「模板生成」。
    llm_model: str
    degraded: bool
    #: 降级原因码（`no_api_key` / `timeout` / `guard_rejected` …）；未降级时为 None
    reason: str | None = None

    def __post_init__(self) -> None:
        # 降级模板是「结论不变」这个承诺的载体，写成 `return ""` 就等于悄悄丢了一章。
        # 这里把不变量钉在类型里，而不是指望每个调用方都记得断言。
        if not self.text.strip():
            raise ValueError("LLM 表达层不允许产出空文本（模板也必须给出可读文案）")


@dataclass(frozen=True, slots=True)
class PatchDraft:
    """用点 ② 的返回。

    契约 3 规定降级产物是「**无补丁**（`patch=null`）」，所以 `diff` 为 None 是
    **正确的降级结果**，不是失败。但只回一个 null 什么都没交付，因此同时给出
    确定性的 `advice`（通用修复方向）—— PRD §7.6.3 用点 ② 的降级列写的正是
    「通用修复建议」。

    ⚠️ `diff` 若不为 None，它**仍然只是草案**：必须过 `app/verify/patch_guard.py`
    的四道校验（那归 B5），本层不校验补丁、更不允许自动应用。
    """

    diff: str | None
    llm_model: str
    degraded: bool
    advice: str
    reason: str | None = None
    target_file: str | None = None

    def __post_init__(self) -> None:
        if not self.advice.strip():
            raise ValueError("补丁降级必须给出通用修复建议，不能只回一个空补丁")
        if self.diff is not None and not self.diff.strip():
            raise ValueError("补丁要么是 None（降级），要么是合法的 unified diff 文本")


# ---------------------------------------------------------------------------
# 客户端协议与消息
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    """一条对话消息。用 Pydantic 而不是裸 dict —— 跨模块传数据不传裸 dict（总纲 §3.4）。"""

    role: str = Field(pattern="^(system|user|assistant)$")
    content: str


@runtime_checkable
class TextCompleter(Protocol):
    """表达层真正依赖的**全部**能力：给一段消息，回一段文本。

    只有这两个成员是刻意的 —— 四个用点不需要 temperature、不需要 token 计数、
    不需要 tool call。把依赖面压到最小，测试就能用一个十行的假客户端把
    「超时 / 500 / 畸形 JSON」全部演出来，而不必起 HTTP 服务或打桩 httpx。
    """

    @property
    def model_name(self) -> str: ...

    async def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = ...,
        max_tokens: int = ...,
    ) -> str: ...


@dataclass(slots=True)
class NoteBatch:
    """一批文案产出的汇总（供报告层统计降级比例）。"""

    texts: dict[str, TextResult] = field(default_factory=dict)

    @property
    def any_degraded(self) -> bool:
        return any(r.degraded for r in self.texts.values())

    @property
    def models(self) -> set[str]:
        return {r.llm_model for r in self.texts.values()}


__all__ = [
    "DEFAULT_MODEL",
    "TEMPLATE_MODEL",
    "ChainNodeView",
    "ChainView",
    "ChatMessage",
    "FindingView",
    "NoteBatch",
    "PatchDraft",
    "TaintStepView",
    "TextCompleter",
    "TextResult",
]
