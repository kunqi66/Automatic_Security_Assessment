"""`code_audit` 阶段：调 B4 污点引擎，把 Finding 落库（B3 设计 §4.2）。

## 这个 Agent 的全部工作就是「搬运 + 落库」

判定在 `app/analysis/` 里，一条也不在这里。本模块只做三件事：

1. 把工作区读源码的能力包成 B4 要的回调（B4 不知道工作区长什么样）；
2. 把 `Finding` 逐字段搬进 `vulnerabilities` 行（**不改写任何判定**）；
3. 把上下文里的 `findings` 换成轻量指针 `FindingRef`。

第 3 点是本阶段唯一有设计含量的地方，理由见 `_to_refs`。

## 为什么这里不调 LLM

`vulnerabilities.description` / `remediation_note` 两列都是 LLM 的产出，
但**不在这里生成**。它们由 `report_gen` 阶段统一填 —— 那样做的原因是
L4 铁律「LLM 降级不阻塞」在报告层已经有一整套（预算、并发上限、模板兜底、
`llm/guard.py` 的编码校验），在审计阶段再搭一套会得到两个行为不一致的降级路径。
审计阶段是**纯计算**的，这一点让「拿掉 LLM 结论不变」在阶段粒度上直接成立：
这一阶段根本没接 LLM。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select

from app.agents.base import BaseAgent, FaultTolerance
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import DetectionMethod, StageName, TaintStepType, VulnStatus
from app.models.vulnerability import TaintPath, Vulnerability
from app.orchestrator.context import AssessmentContext, FindingRef
from app.orchestrator.events import LogLevel

logger = get_logger(__name__)

#: 一条漏洞最多落几跳污点路径。
#:
#: 路径是**给人看的**（前端时间轴、报告插图），不是给机器算的。一条跨 8 个
#: 函数的路径写成 40 跳不会让人更懂，只会让表格没人看。截断时**保留首尾** ——
#: source 与 sink 是这条路径的结论，中间的传播过程才是可省的。
_MAX_PATH_STEPS = 20

#: `assessment_stages.log_excerpt` 里最多列几条跳过原因。
#: 全列出来的话，一个不含 Python 的项目会写进几千行「暂不支持的语言」。
_MAX_SKIP_NOTES = 10


class CodeAuditAgent(BaseAgent[AssessmentContext, list[FindingRef]]):
    """静态污点分析。**致命档** —— 没有审计结果就没有报告。

    `SKIPPABLE` 在这里是危险的：一个「分析失败 → 跳过 → 报告：0 个漏洞」
    的流程会输出一份**看起来很干净**的报告，而它实际上什么都没查。
    """

    name = "静态代码审计"
    stage = StageName.CODE_AUDIT
    fault_tolerance = FaultTolerance.FATAL

    async def run(self, ctx: AssessmentContext, inp: AssessmentContext) -> list[FindingRef]:
        from app.analysis import analyze
        from app.core.exceptions import StageFatalError
        from app.projects.workspace import read_manifest_async, read_whole_source

        await self.emit(LogLevel.INFO, "开始静态污点分析")

        manifest = await read_manifest_async(ctx.project_id)
        if manifest is None:
            raise StageFatalError(
                "找不到源码清单，无法开始静态分析",
                detail={"project_id": ctx.project_id},
                remediation="请重新导入项目源码后再发起评估",
            )

        async def read_source(rel_path: str) -> str:
            """B4 要的单参数回调。

            `read_whole_source` 在文件读不到时抛业务异常，而 **B4 自己会接住**
            （`analysis/taint.py` 的 `analyze` 把回调异常记成一条 `SkipRecord` 并跳过该文件）。
            所以这里**不要**自己 try/except —— 那会变成两层各自认为对方该处理，
            而真正的读取失败原因在翻译过程中被丢掉。
            """
            return await read_whole_source(ctx.project_id, rel_path)

        await self.emit(
            LogLevel.INFO,
            f"载入 {manifest.total_files} 个文件（{manifest.total_loc} 行）进入分析队列",
        )

        # 规模闸从配置显式传入，而不是让 B4 用它的模块内默认值。
        # B4 是纯函数、不许读全局配置（那是它能被单测穷举的前提），
        # 所以「这一轮扫多少」的决定权在这里 —— 改限额不必动分析引擎。
        result = await analyze(
            manifest,
            read_source,
            max_files=settings.analysis_max_files,
            max_seconds=settings.analysis_max_seconds,
            max_file_bytes=settings.analysis_max_file_bytes,
        )

        await self._report_outcome(ctx, result)

        refs = await self._persist(ctx, result)
        return refs

    def apply_output(self, ctx: AssessmentContext, out: list[FindingRef]) -> None:
        ctx.findings = out

    # ------------------------------------------------------------------

    async def _report_outcome(self, ctx: AssessmentContext, result: Any) -> None:
        """把 B4 的产出讲清楚 —— **包括它没扫的部分**。

        `truncated` 与 `files_skipped` 是这份产出里最容易被忽略、
        也最容易被误读的两个字段：一份「扫了 200/3000 个文件、0 个漏洞」的
        结果，如果不明说前面那个数，用户看到的就是「这个项目很安全」。
        """
        await self.emit(
            LogLevel.INFO,
            f"分析完成：扫描 {result.files_scanned} 个文件，"
            f"发现 {len(result.findings)} 条疑似漏洞（{result.duration_ms}ms）",
        )

        if result.truncated:
            await self.emit(
                LogLevel.WARN,
                "本次分析因规模上限被截断，**未覆盖全部代码**；报告将标注此限制",
            )

        if result.unexpanded_calls:
            await self.emit(
                LogLevel.INFO,
                f"有 {result.unexpanded_calls} 处调用点的调用链更深、未展开"
                "（不会漏报该调用点本身，但更内层的污点传播未追踪）",
            )

        if result.files_skipped:
            by_reason = _summarize_skips(result.files_skipped)
            await self.emit(
                LogLevel.WARN,
                f"有 {len(result.files_skipped)} 个文件被跳过：{by_reason}",
            )

    async def _persist(self, ctx: AssessmentContext, result: Any) -> list[FindingRef]:
        """落 `vulnerabilities` + `taint_paths`，返回轻量指针。

        **重跑即覆盖**：先删掉本评估已有的漏洞行再写新的。理由是
        `code_audit` 是幂等的（见 `context.ContextDecodeError` 的说明 ——
        快照坏了就退回该阶段重跑），而它是 `vulnerabilities` 的**唯一写入方**。
        不先删的话，一次重跑会得到两倍数量的漏洞，且新旧混杂。

        **不 commit** —— 提交点在阶段边界（T4），由引擎统一做。
        """
        session = self.deps.session

        await session.execute(
            delete(Vulnerability).where(Vulnerability.assessment_id == ctx.assessment_id)
        )

        if not result.findings:
            await session.flush()
            return []

        base = await self._next_code_base()
        refs: list[FindingRef] = []

        for offset, finding in enumerate(result.findings):
            row = Vulnerability(
                assessment_id=ctx.assessment_id,
                code=_format_code(base + offset),
                title=finding.title or finding.vuln_type,
                vuln_type=str(finding.vuln_type),
                severity=finding.severity,
                cvss_score=finding.cvss_score,
                cvss_vector=finding.cvss_vector,
                # **静态阶段只产出 unverified**（总纲 §5.3）。其余三态是动态验证
                # 阶段与人工复核的产物，在这里赋任何别的值都是越权。
                status=VulnStatus.UNVERIFIED,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                code_snippet=finding.code_snippet or None,
                sink_symbol=finding.sink_symbol,
                # 两列 NOT NULL，先给空串。真正的文案由 `report_gen` 阶段填（见模块 docstring）。
                description="",
                remediation_note="",
                confidence=finding.confidence,
                detection_method=_detection_method(finding),
            )
            row.taint_paths = _to_paths(finding)
            session.add(row)
            # flush 拿到自增 id —— `FindingRef` 需要它，而 `add` 之后 id 还是 None
            await session.flush()
            refs.append(_to_ref(row, finding))

        logger.info(
            "评估 %s 落库 %d 条漏洞（截断=%s）",
            ctx.assessment_id,
            len(refs),
            result.truncated,
        )
        return refs

    async def _next_code_base(self) -> int:
        """全局年度流水号的起点。

        `vulnerabilities.code` 上有唯一约束，重复插入会直接报
        `IntegrityError`。取「当年已有编号的最大值 + 1」是够用的：
        **并发恒为 1**（T3），不存在两个评估同时取到同一个号。

        从 `code` 里解析而不是维护一张计数表：多一张表就多一个
        可能与真实数据不一致的地方，而 `MAX(code)` 永远与真实数据一致。
        """
        prefix = f"VULN-{datetime.now(UTC).year}-"
        latest = await self.deps.session.scalar(
            select(func.max(Vulnerability.code)).where(Vulnerability.code.like(f"{prefix}%"))
        )
        if not latest:
            return 1
        try:
            return int(latest.rsplit("-", 1)[-1]) + 1
        except ValueError:
            # 库里有一条手工造的畸形编号。**不要让它把整轮评估炸掉** ——
            # 退回到按「本评估已有条数」起步，唯一的代价是新号可能与旧号重号，
            # 而那会以 IntegrityError 的形式明确地报出来。
            logger.warning("漏洞编号 %s 无法解析，本次从 1 开始编号", latest)
            return 1


# ---------------------------------------------------------------------------
# 纯函数
# ---------------------------------------------------------------------------


def _format_code(seq: int) -> str:
    return f"VULN-{datetime.now(UTC).year}-{seq:04d}"


def _detection_method(finding: Any) -> DetectionMethod:
    """`Finding.detection_method` 已经是 `DetectionMethod`，这里只做**兜底**。

    B4 的类型是 StrEnum，可空路径上仍可能拿到裸字符串（数据来自 JSON 时）。
    用 `DetectionMethod(...)` 转一次，转不了就落到最保守的 `PATTERN` ——
    报「模式匹配」而实际是污点分析，只是低估了置信度；
    反过来（把模式匹配标成函数内污点）是在**高估**证据强度，那个方向不能走。
    """
    raw = getattr(finding, "detection_method", None)
    if isinstance(raw, DetectionMethod):
        return raw
    try:
        return DetectionMethod(str(raw))
    except ValueError:
        return DetectionMethod.PATTERN


def _to_paths(finding: Any) -> list[TaintPath]:
    """污点路径 → ORM 行。超长时**保留首尾**（见 `_MAX_PATH_STEPS`）。"""
    steps = list(finding.taint_path or ())
    if len(steps) > _MAX_PATH_STEPS:
        head = _MAX_PATH_STEPS // 2
        steps = steps[:head] + steps[-(_MAX_PATH_STEPS - head) :]

    return [
        TaintPath(
            step_index=step.step_index,
            step_type=_step_type(step.step_kind),
            file_path=step.file_path,
            line=step.line,
            symbol=step.symbol or None,
            code_snippet=step.snippet or None,
            note=None,
        )
        for step in steps
    ]


def _step_type(kind: Any) -> TaintStepType:
    if isinstance(kind, TaintStepType):
        return kind
    try:
        return TaintStepType(str(kind))
    except ValueError:
        # 未知的步骤类型落到 `propagate`：它在时间轴上的语义是「中间的一跳」，
        # 是最不具误导性的兜底 —— 标成 source 或 sink 会伪造路径的端点。
        return TaintStepType.PROPAGATE


def _to_ref(row: Vulnerability, finding: Any) -> FindingRef:
    """转成上下文里的轻量指针。

    **只带 6 个字段**，这是有意的：完整 Finding 带十几跳污点路径，
    几千条内联进 `assessment_stages.result_ref` 是几十 MB 量级，
    会把行撑爆、把续跑时的读取拖垮（见 `orchestrator/context.py` 顶部的体积说明）。
    完整记录在 `vulnerabilities` / `taint_paths` 表里，需要细节时按 `vuln_id` 回表。

    这 6 个字段是「不需要回表就能用的那一部分」：调度（按 severity 排序）、
    日志（直接显示标题）、进度。**多带一个字段就是在快照里多存一份数据。**
    """
    return FindingRef(
        vuln_id=row.id,
        rule_id=getattr(finding, "rule_id", ""),
        vuln_type=row.vuln_type,
        severity=row.severity,
        file_path=row.file_path,
        line_start=row.line_start,
    )


def _summarize_skips(skipped: Any) -> str:
    """把逐文件的跳过原因压成一行。

    常见情况是几百个文件因为**同一个**原因被跳过（「暂不支持的语言：JavaScript」），
    逐条列出来会把日志面板刷满，反而看不见真正不同的那几条。
    """
    counts: dict[str, int] = {}
    for record in skipped:
        reason = str(getattr(record, "reason", "") or "未知原因")
        counts[reason] = counts.get(reason, 0) + 1

    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:_MAX_SKIP_NOTES]
    parts = [f"{reason}（{count} 个）" for reason, count in ranked]
    if len(counts) > _MAX_SKIP_NOTES:
        parts.append(f"另有 {len(counts) - _MAX_SKIP_NOTES} 类原因未列出")
    return "；".join(parts)


__all__ = ["CodeAuditAgent"]
