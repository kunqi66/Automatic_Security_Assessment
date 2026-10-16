"""编排上下文 —— 阶段之间唯一的传递通道（B3 设计 §3.3、总纲 §6.1）。

**为什么 Agent 之间不互相调用**（B3 设计 T5）：如果 `PocVerifyAgent` 直接持有
`CodeAuditAgent` 的引用，那么「验证阶段需要审计阶段的什么」这件事就变成了两个
模块之间的私有约定，编排引擎看不见。第 6 个 Agent 想复用审计结果时，
要么穿进别人的调用链，要么复制一份。全部经上下文传递的代价是上下文会膨胀，
换来的是**数据流向在引擎里一览无余**。

---

## 体积：本模块唯一需要权衡的地方

设计文档 §3.3 把 `findings` 写成 `list[Finding]`，而 §7 的 T12 写的是
「Finding 只存摘要 + `vulnerability_id` 指针」。**两处冲突，本文档按 T12 实现**，
理由：

`result_ref` 是一个 JSON 列。一个中型工程的污点分析产出几千条 finding，
每条带完整污点路径（`taint_path` 是十几跳，每跳带一行源码片段）——
内联进 JSON 列是几十 MB 量级，会直接撑爆行、拖垮读写。

改成 `FindingRef` 之后快照是自足的**索引**而非自足的数据：完整记录在
`vulnerabilities` 表里，阶段需要细节时按 id 回表。这与「阶段边界是原子提交点」
是自洽的 —— 阶段的事务同时提交了表里的行和快照里的指针，不存在只写了一半的中间态。
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import Severity, StageName

logger = get_logger(__name__)

#: 快照结构版本。改 `AssessmentContext` 的字段时**必须**同时 +1。
#:
#: 为什么不用 Pydantic 的校验失败来发现漂移：字段改名后旧快照仍然能通过校验
#: （多余字段默认被忽略），只是解析出来是空的 —— 表现为「续跑后技术栈丢了」，
#: 静默且难查。显式版本号让这种情况变成一次干脆的拒绝，走「退回复跑」路径。
CONTEXT_SCHEMA_VERSION = 1


class FindingRef(BaseModel):
    """Finding 的**轻量指针**，不是 Finding 本身。

    字段是刻意挑的：既能支撑「按严重度排序后逐个验证」的调度，
    又能在进度条和日志里直接显示，不需要回表。**不含源码片段、不含污点路径** ——
    那两样是体积的大头，而只有真正要验证某一条时才需要。
    """

    vuln_id: int
    rule_id: str
    vuln_type: str
    severity: Severity
    file_path: str
    line_start: int


class StageSnapshot(BaseModel):
    """落进 `assessment_stages.result_ref` 的内容。

    `payload` 是整个上下文在该阶段**结束时刻**的形态，而不是该阶段的增量输出。
    选整体的理由：续跑要的是「世界现在的样子」，增量形式需要从头重放所有阶段
    才能重建，而重放正是续跑要避免的事。
    """

    schema_version: int = CONTEXT_SCHEMA_VERSION
    stage: StageName
    payload: dict[str, Any]


class ContextDecodeError(Exception):
    """快照解不开。

    **不是致命错误**：调用方（engine）应把该阶段退回 `pending` 就地重跑。
    阶段是幂等的（重跑 `code_audit` 只是覆盖同一批 finding），
    代价是重跑一个阶段，远小于让整个评估失败。
    """


class AssessmentContext(BaseModel):
    """贯穿五个阶段的载体。"""

    assessment_id: int
    project_id: int
    #: 控制面工作区根（绝对路径）。**这是唯一允许出现绝对路径的地方** ——
    #: 它是本轮运行的运行时坐标，不落库（落进 result_ref 的是快照，
    #: 而快照里的 file_path 一律是相对工作区根的 POSIX 路径，见契约 5）。
    workspace: str

    #: 技术栈识别结果（`ReconAgent` 产出）。用 dict 而不是强类型：
    #: 识别出的键会随支持的框架增加而变，强类型会让每加一个框架都要改三处。
    tech_stack: dict[str, Any] | None = None

    findings: list[FindingRef] = Field(default_factory=list)
    #: 攻击链只存 id。链的结构本身在 `attack_chain_nodes` / `attack_chain_edges` 里，
    #: 报告与前端都从表读 —— 快照里再存一份就是同一份数据两个真相。
    chain_ids: list[int] = Field(default_factory=list)

    #: 各阶段 `result_ref` 的指针（总纲 §6.1）—— 断点续跑的索引
    stage_outputs: dict[str, str] = Field(default_factory=dict)

    #: 运行时态，**序列化时排除**。
    #:
    #: 类型是 `Any` 而不是 B2 的 `SandboxHandle`：容器句柄里有 socket、有锁，
    #: 既不可 JSON 序列化，也不该跨进程传递。写成 Any 是承认「这里装的是一个
    #: 引擎不该理解的东西」，比伪造一个能通过类型检查的壳更诚实。
    sandbox_handle: Any | None = Field(default=None, exclude=True)

    #: 沙箱参数（管理页「沙箱与环境配置」那一行），由 B3 在**每次运行开始时**解析。
    #:
    #: 这就是总纲 §6.1 说的那个注入点。之前它一直缺着 ——
    #: `verify/types.py` 的 `SandboxConfig` 因此在注释里记了一笔「B3 已落地的
    #: `orchestrator/context.py` 里没有这个字段」，只好自己从全局配置兜底。
    #: 兜底本身没错（降级是允许的），但结果是管理页改的参数**没有任何引擎读**。
    #:
    #: 同样是运行时态、同样 `exclude=True`：参数以**当前**配置为准，
    #: 快照里那份是上次运行的坐标 —— 与 `workspace` 同理（见 `engine._load_context`）。
    #: 类型写 `Any` 的理由与 `sandbox_handle` 相同：编排层不必理解引擎的参数类型。
    sandbox_config: Any | None = Field(default=None, exclude=True)

    # ------------------------------------------------------------------
    # 序列化
    # ------------------------------------------------------------------

    def to_snapshot(self, stage: StageName) -> StageSnapshot:
        """打包成本阶段的结果快照，准备写进 `result_ref`。

        超限时**不抛异常**，而是抛给调用方一个明确信号 —— 见 `encode_for_storage`。
        """
        return StageSnapshot(stage=stage, payload=self.model_dump(mode="json"))

    def encoded_size(self, stage: StageName) -> int:
        """快照的 UTF-8 字节数。落库前用它做体积预检。"""
        return len(self.to_snapshot(stage).model_dump_json().encode("utf-8"))


def encode_for_storage(ctx: AssessmentContext, stage: StageName) -> dict[str, Any]:
    """产出可直接写进 `result_ref` 列的 dict。

    超过 `context_payload_max_bytes` 时**只记录不截断**：截断一个快照会得到
    一份「看起来正常但内容缺失」的数据，续跑时表现为莫名其妙的空字段；
    而完整写下去最多是行大一点。真的撑爆了，数据库会报错 —— 那是个响亮的、
    指向正确的失败。用截断把它变成静默的错误才是更坏的选择。

    ⚠️ 这里只做**预检告警**，真正的上限由 MySQL 的列类型与 `max_allowed_packet` 决定。
    """
    snapshot = ctx.to_snapshot(stage)
    size = len(snapshot.model_dump_json().encode("utf-8"))
    if size > settings.context_payload_max_bytes:
        logger.warning(
            "评估 %s 的阶段 %s 快照体积 %d 字节，超过建议上限 %d —— "
            "续跑时读取会变慢。根因通常是 findings 数量异常，见本模块顶部的体积说明。",
            ctx.assessment_id,
            stage,
            size,
            settings.context_payload_max_bytes,
        )
    return snapshot.model_dump(mode="json")


def decode_from_storage(raw: dict[str, Any] | None) -> AssessmentContext:
    """从 `result_ref` 还原上下文。

    失败一律抛 `ContextDecodeError`（调用方据此把阶段退回 `pending` 重跑），
    并且**把原始异常链在上面**：Pydantic 的报错会指出具体是哪个字段，
    而「快照解不开」这句话本身对排查没用。
    """
    if raw is None:
        raise ContextDecodeError("快照为空")

    version = raw.get("schema_version")
    if version != CONTEXT_SCHEMA_VERSION:
        raise ContextDecodeError(
            f"快照结构版本 {version!r} 与当前 {CONTEXT_SCHEMA_VERSION} 不符，需重跑该阶段"
        )

    payload = raw.get("payload")
    if not isinstance(payload, dict):
        raise ContextDecodeError(f"快照 payload 不是对象：{type(payload).__name__}")

    try:
        return AssessmentContext.model_validate(payload)
    except ValidationError as exc:
        raise ContextDecodeError(f"快照字段校验失败：{exc.error_count()} 处") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ContextDecodeError(f"快照无法解析：{type(exc).__name__}") from exc
