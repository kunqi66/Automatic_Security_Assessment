"""`poc_verify` 阶段：在沙箱里跑无害化探针（B3 设计 §4.3）。

## 这个阶段是**唯一**能把状态从 `unverified` 推到另外三态的地方

`总纲 §5.3` 把四态的所有权切得很干净：`unverified` 由静态阶段产出，
其余三态只由动态验证产出。本 Agent 就是那个动态阶段，所以
`vulnerabilities.status` 的写入只在这里——B4 那边的注释也写死了同一句话，
两处指的是同一条约束。

## 为什么它是 `SKIPPABLE`

沙箱连不上是**基础设施问题**，不是漏洞问题。让「Docker 挂了」把一份已经跑完的
静态分析判死，等于用一次运维故障抹掉二十分钟的计算。所以：

- 没配数据面（`deps.sandbox is None`）→ 抛 `StageSkippedError`，阶段标 `skipped`；
- 沙箱整体不可达（`VerifyOutcome.sandbox_reachable=False`）→ 同样跳过；
- **每一条漏洞仍然落 `POTENTIAL`**，报告里写明「本轮未做动态验证」。

最后那句是关键：跳过不等于什么都不写。一条验证都没做的漏洞如果留在
`unverified`，报告读起来就像「还没来得及看」；落 `POTENTIAL`
才是准确的 —— **风险模式存在，但本轮没有证实也没有证伪**。
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.agents.base import BaseAgent, FaultTolerance
from app.core.exceptions import StageSkippedError
from app.core.logging import get_logger
from app.models.enums import StageName, TaintStepType, VulnStatus
from app.models.vulnerability import PocAttempt, TaintPath, Vulnerability
from app.orchestrator.context import AssessmentContext
from app.orchestrator.events import LogLevel

logger = get_logger(__name__)


class PocVerifyAgent(BaseAgent[AssessmentContext, dict[str, int]]):
    """K 阶段：沙箱验证。**降级档 —— 失败只跳过，不拖垮整轮。**

    返回的是给日志与报告用的计数（`verified` / `potential` / `rejected`），
    不是给控制流用的判定：引擎不读它，后续阶段也不读它。
    """

    name = "PoC 动态验证"
    stage = StageName.POC_VERIFY
    fault_tolerance = FaultTolerance.SKIPPABLE

    async def run(self, ctx: AssessmentContext, inp: AssessmentContext) -> dict[str, int]:
        from app.verify.runner import verify_findings

        if self.deps.sandbox is None:
            # 部署时没配 `DOCKER_HOST` 就是这条路。**抛 `StageSkippedError`
            # 而不是把每条漏洞标成 rejected** —— 前者说「没验」，后者说
            # 「验过了，是假的」，而后者是伪造证据。
            await self.emit(
                LogLevel.WARN,
                "未配置沙箱（数据面），本轮跳过动态验证；"
                "所有漏洞保持「潜在」状态，报告将标注此限制",
            )
            await self._mark_all_potential(ctx, reason="未配置沙箱，本轮未执行动态验证")
            raise StageSkippedError("未配置沙箱", detail={"project_id": ctx.project_id})

        await self.emit(LogLevel.INFO, "开始动态验证（无害化探针）")

        handle = await self._prepare_handle(ctx)
        findings = await self._load_findings(ctx)

        if not findings:
            await self.emit(LogLevel.WARN, "没有待验证的漏洞，跳过本阶段")
            return {"verified": 0, "potential": 0, "rejected": 0}

        # 沙箱参数由 B3 从管理页配置解析后注入（总纲 §6.1）。`None` 表示库里没配，
        # 由 `verify` 侧回落到全局设置 —— 所以这里**不自己兜底**，兜底只有一处。
        cfg = ctx.sandbox_config

        # 这两个数字**照实报**，不写死。参数现在能从管理页改，写死的话
        # 日志会一边显示 30 秒、一边按别的值在跑 —— 又是一条会骗人的信息。
        if cfg is not None:
            await self.emit(
                LogLevel.INFO,
                f"待验证 {len(findings)} 条漏洞，每条最多 {cfg.max_probes_per_vuln} 个探针、"
                f"单个 {cfg.probe_timeout_s} 秒（来自管理页沙箱配置）",
            )
        else:
            await self.emit(
                LogLevel.INFO,
                f"待验证 {len(findings)} 条漏洞（沙箱参数取自全局设置，管理页未配置默认沙箱）",
            )

        outcome = await verify_findings(
            findings,
            self.deps.sandbox,
            handle,
            ctx,
            on_progress=self._progress,
            cfg=cfg,
        )

        if not outcome.sandbox_reachable:
            await self.emit(
                LogLevel.WARN,
                "沙箱整体不可达，本轮验证未取得任何结论；所有漏洞保持「潜在」状态",
            )
            await self._mark_all_potential(ctx, reason="沙箱不可达，本轮未取得验证结论")
            raise StageSkippedError("沙箱不可达", detail=outcome.model_dump(mode="json"))

        counts = await self._persist(ctx, outcome)
        await self._report_outcome(outcome, counts)
        return counts

    def apply_output(self, ctx: AssessmentContext, out: dict[str, int]) -> None:
        """进度计数**不进上下文**。

        快照里要装的是「后续阶段要用的东西」，而阶段计数是给报告看的 ——
        报告从 `vulnerabilities` 表里现算，比从快照里读一份可能过期的副本更准。
        """

    # ------------------------------------------------------------------
    # 准备
    # ------------------------------------------------------------------

    async def _prepare_handle(self, ctx: AssessmentContext) -> Any:
        """拿工作区句柄，必要时补同步到 ECS。

        用 `ensure_ready` 而不是 `workspace_of`：前者会在远端副本不在时重新推一次。
        ECS 重启过、或者上一轮评估被 LRU 清理过，`workspace_of` 会给出一个
        指向不存在目录的句柄 —— 而症状是容器里「源码目录是空的」，
        报错会指向分析结果为空，排查方向完全歪掉。
        """
        from app.projects.service import ProjectService

        return await ProjectService(self.deps.session).ensure_ready(ctx.project_id)

    async def _load_findings(self, ctx: AssessmentContext) -> list[Any]:
        """把 ORM 行还原成 B5 认识的 `Finding`。

        ## 为什么要绕这一圈

        上下文里只有 `FindingRef`（6 个字段的轻量指针），而 B5 需要
        `taint_path` 才能从 source 那一跳推出注入点参数名。**这个还原是有损的**：
        `TaintStep.column` 没有落库（`taint_paths` 表里没这一列），这里补 0。

        有损本身不危险 —— 危险的是**把有损的还原当成无损的用**。B5 的
        `injection_points()` 只读 `symbol`，不读 `column`，所以这一处损失
        不影响任何结论。换一个会读 `column` 的消费者时，这里必须重新评估。
        """
        from app.analysis.types import Finding, TaintStep, VulnType

        rows = (
            await self.deps.session.scalars(
                select(Vulnerability)
                .where(Vulnerability.assessment_id == ctx.assessment_id)
                # 顺序固定，探针配额才是可复现的：同样的输入跑两次，
                # 「哪几条漏洞用完了 20 个配额」必须一致。
                .order_by(Vulnerability.id)
            )
        ).all()

        findings: list[Finding] = []
        for row in rows:
            try:
                vuln_type = VulnType(row.vuln_type)
            except ValueError:
                # 规则库演进后库里可能留着旧类型名。**跳过而不是抛** ——
                # 一条认不出的历史漏洞不该让整轮验证作废。
                logger.warning(
                    "漏洞 %s 的类型 %r 不在当前规则库中，本轮跳过验证",
                    row.id,
                    row.vuln_type,
                )
                continue
            findings.append(_to_finding(row, vuln_type, TaintStep))
        return findings

    # ------------------------------------------------------------------
    # 落库
    # ------------------------------------------------------------------

    async def _persist(self, ctx: AssessmentContext, outcome: Any) -> dict[str, int]:
        """把验证结论写回 `vulnerabilities` 与 `poc_attempts`。

        **`status` 只在这里写**（总纲 §5.3）。写之前先清掉本评估已有的
        `poc_attempts`：本阶段是幂等的，重跑一次该得到一份证据，
        而不是两份新旧混杂的探针记录 —— 后者会让报告里的「尝试了 6 次」
        变成一句无法复核的话。
        """
        from app.analysis.cvss import severity_of

        session = self.deps.session

        await session.execute(_delete_attempts_for(ctx.assessment_id, PocAttempt, Vulnerability))

        counts = {"verified": 0, "potential": 0, "rejected": 0}
        rows = {
            row.id: row
            for row in await session.scalars(
                select(Vulnerability).where(Vulnerability.assessment_id == ctx.assessment_id)
            )
        }

        for result in outcome.results:
            row = rows.get(result.vuln_id)
            if row is None:
                # B5 回了我们没问过的 id。真出现说明两边对「本轮验证了哪些漏洞」
                # 的理解不一致，值得留一条日志。
                logger.warning(
                    "验证结果里的漏洞 %s 不属于评估 %s，已忽略",
                    result.vuln_id,
                    ctx.assessment_id,
                )
                continue

            # **`status` 由 B5 判定，这里只搬运** —— 不在本模块里写任何
            # 「匹配到探针就 verified」之类的推理，那正是 L1 要挡的东西。
            row.status = result.status
            if result.status is VulnStatus.VERIFIED and result.cvss_after:
                row.cvss_score = result.cvss_after
                # 分数变了，等级带也要跟着变。分与级不一致的症状是
                # 「报告里 9.8 分的高危」——一个自己打自己脸的结论。
                row.severity = severity_of(result.cvss_after)

            for attempt in result.attempts:
                session.add(
                    PocAttempt(
                        vulnerability_id=row.id,
                        # `probe_id` **不落库**：PRD §6 的 `poc_attempts` 列清单里
                        # 没有它。B5 的 DTO 带着它是为了「将来定案了再写」，
                        # 而 `technique` + `payload` 已经能唯一定位到是哪一条探针 ——
                        # 见下面 `_failure_reason` 上面那段关于命名的说明。
                        payload=attempt.payload,
                        technique=attempt.technique,
                        request_raw=attempt.request_raw,
                        response_raw=attempt.response_raw,
                        expected_pattern=attempt.expected_pattern,
                        matched=attempt.matched,
                        elapsed_ms=attempt.elapsed_ms,
                        http_status=attempt.http_status,
                        harmless_guard_passed=attempt.harmless_guard_passed,
                        # B5 的 `PocAttempt` 还带了 `probe_id` / `failed_gate` /
                        # `reason_code` 三个字段，而 `poc_attempts` 表**没有这三列**
                        # （PRD §6 的列表里没有，`核心数据字典` 里也没有）——
                        # 直接当关键字传会在构造 ORM 对象时抛 `TypeError`，
                        # 也就是这个阶段第一次真正验证成功时才炸。
                        #
                        # 这里**不补列**：PRD §6 是列名的唯一来源（本项目的命名 SSOT），
                        # 加列要先改 PRD；而 `app/schemas/` 与前端都**没有任何消费者**
                        # 读这三个字段，加列是为一个不存在的需求做迁移。
                        #
                        # 信息也没丢：PRD 把 `failure_reason` 定义为
                        # 「未通过验证的原因 / **被闸门拦截的原因**」，
                        # 正好就是 failed_gate + reason_code 想表达的那件事。
                        # 把机器可读的码拼在前面，人和 grep 都能用。
                        failure_reason=_failure_reason(attempt),
                    )
                )

            key = _bucket(result.status)
            counts[key] = counts.get(key, 0) + 1

        await session.flush()
        return counts

    async def _mark_all_potential(self, ctx: AssessmentContext, *, reason: str) -> None:
        """没验证成的漏洞统一落 `POTENTIAL`。

        **不是 `rejected`** —— 这两者的区别就是「没验」与「验过是假的」，
        而后者需要证据。没有证据就写 `rejected` 是在伪造结论，
        也是这个系统里最容易发生、最难被发现的一种错。

        `reason` 会写进 `description` 的位置吗？不会 —— `description` 是
        LLM 的表达层产物，由 `report_gen` 填。这里只记 `logger`，
        阶段性说明由本 Agent 的 `emit` 日志承载。
        """
        from sqlalchemy import update

        await self.deps.session.execute(
            update(Vulnerability)
            .where(
                Vulnerability.assessment_id == ctx.assessment_id,
                # 只动静态阶段留下的那一态。已经是终态的（人工复核过、
                # 或上一轮已验证）不该被这一轮的「跳过」覆盖。
                Vulnerability.status == VulnStatus.UNVERIFIED,
            )
            .values(status=VulnStatus.POTENTIAL)
        )
        await self.deps.session.flush()
        logger.info("评估 %s 的未验证漏洞已统一标为潜在（原因：%s）", ctx.assessment_id, reason)

    async def _progress(self, result: Any) -> None:
        """每条漏洞验证完就推一条日志。

        `on_progress` 的异常会被 B5 吞掉（见 `PocVerifier.verify_finding`），
        所以这里可以放心地直接 `emit` —— 一次日志广播失败不会改变验证结论。
        """
        if result.verdict.value == "verified":
            await self.emit(
                LogLevel.INFO,
                f"漏洞 {result.vuln_id} 验证通过（命中探针 {result.matched_probe_id}）",
            )
        elif result.verdict.value == "skipped":
            await self.emit(
                LogLevel.WARN,
                f"漏洞 {result.vuln_id} 未执行探测：{result.skip_reason or '未知原因'}",
            )
        else:
            await self.emit(
                LogLevel.INFO,
                f"漏洞 {result.vuln_id} 未确认：{result.unverified_reason or '未命中任何探针特征'}",
            )

    async def _report_outcome(self, outcome: Any, counts: dict[str, int]) -> None:
        await self.emit(
            LogLevel.INFO,
            f"动态验证完成：已验证 {counts['verified']} 条、"
            f"潜在 {counts['potential']} 条、已排除 {counts['rejected']} 条"
            f"（共执行 {outcome.executed_count} 个探针，{outcome.elapsed_ms}ms）",
        )
        if outcome.rejected_count:
            # 「已排除」是唯一会**减少**漏洞数的结论，值得单独说一句 ——
            # 用户看到总数从 12 变成 9 时会想知道那 3 条去哪了。
            await self.emit(
                LogLevel.INFO,
                f"其中 {outcome.rejected_count} 条漏洞被动态验证排除"
                "（探针执行成功但未触发预期特征）",
            )


# ---------------------------------------------------------------------------
# 纯函数
# ---------------------------------------------------------------------------


class _FindingWithId:
    """把 ORM 行的主键挂在 B4 的 `Finding` 旁边，再交给 B5。

    ## 为什么需要它

    B5 用 `vuln_id` 把探针结果对回到具体的 `vulnerabilities` 行
    （`runner._vuln_id` → `Probe.vuln_id` → `VerifyResult.vuln_id`），
    而 **B4 的 `Finding` 没有这个字段**。不补上的话 `_vuln_id` 退化成 0，
    所有探针都带着 id=0 去跑，回来时 `poc_verify._persist` 一条都对不上：

        实测（2026-10-16，靶场）：探针真的跑了（5 个漏洞 × 各 1-2 条，
        每条约 9 秒，容器确实起来了），但日志里刷了 7 行
        「验证结果里的漏洞 0 不属于评估 2，已忽略」，最终 7 条漏洞全是
        `unverified`。**整条动态验证链路的算力被全部丢弃，而阶段状态是
        `completed`** —— 一个只看总状态完全看不出来的失败。

    ## 为什么不给 `Finding` 加一个字段

    那是 B4（纯分析）的产物，而「数据库主键」是 B3 的概念。往 `Finding`
    里放 DB id，等于在 `analysis/` 与 `db/` 的分层上开一个口子
    （CLAUDE.md 分层铁律：`analysis/` 不碰 `db/`）。而且 `Finding` 是
    `frozen=True, slots=True`，事后也挂不上属性。

    ## 为什么是包装而不是复制字段

    B5 按结构化方式读 finding（`getattr`），转发一次 `__getattr__` 就够；
    若把字段逐个复制过来，以后契约 2 新增一个字段，这里会**静默**少一个 ——
    正是 B5 docstring 警告过的那种「两个模块各自跑得通、拼起来 `AttributeError`」。

    B5 本来就为这条路留了口子：`runner._vuln_id` 依次找
    `vuln_id` / `id` / `vulnerability_id`，其 docstring 写着
    「取不到就退 0 —— 落库前 B3 必然已经知道真实 id」。**这个类就是
    「B3 知道真实 id」那一步的落点。**
    """

    __slots__ = ("vuln_id", "_finding")

    def __init__(self, vuln_id: int, finding: Any) -> None:
        self.vuln_id = vuln_id
        self._finding = finding

    def __getattr__(self, name: str) -> Any:
        # `_finding` 还没赋值时（反序列化的中间态）必须直接抛：
        # 否则 `getattr(self._finding, ...)` 会再触发一次 `__getattr__`，
        # 变成无限递归 —— 症状是 RecursionError 而不是「缺个字段」。
        if name == "_finding":
            raise AttributeError(name)
        return getattr(self._finding, name)

    def __repr__(self) -> str:
        return f"<_FindingWithId vuln_id={self.vuln_id} {self._finding!r}>"


def _to_finding(row: Vulnerability, vuln_type: Any, step_cls: Any) -> Any:
    """ORM 行 → 带主键的 B4 `Finding` 视图。见 `_FindingWithId` 与 `_load_findings`。"""
    from app.analysis.types import Finding

    return _FindingWithId(row.id, _build_finding(row, vuln_type, step_cls, Finding))


def _build_finding(row: Vulnerability, vuln_type: Any, step_cls: Any, finding_cls: Any) -> Any:
    return finding_cls(
        rule_id=f"{vuln_type.value}/{row.sink_symbol or 'unknown'}",
        vuln_type=vuln_type,
        severity=row.severity,
        file_path=row.file_path,
        line_start=row.line_start,
        line_end=row.line_end,
        # `Finding.symbol` 是**下沉点符号名**（B4 的契约），ORM 那一列叫
        # `sink_symbol`。两个名字指同一个东西，这里是它们的唯一换算点。
        symbol=row.sink_symbol or "",
        cwe_id=None,
        cvss_vector=row.cvss_vector or "",
        cvss_score=row.cvss_score,
        confidence=row.confidence,
        source_kind="",
        sink_kind=row.sink_symbol or "",
        # ORM 不存这个标记（它只影响 B4 内部的置信度计算，已经乘进
        # `confidence` 了）。回填 False 不会影响 B5 —— 它不看这个字段。
        guard_blocked=False,
        taint_path=tuple(_to_step(path, step_cls) for path in row.taint_paths),
        title=row.title,
        detection_method=row.detection_method,
        code_snippet=row.code_snippet or "",
    )


def _to_step(path: TaintPath, step_cls: Any) -> Any:
    return step_cls(
        step_index=path.step_index,
        file_path=path.file_path,
        line=path.line,
        # 有损：`taint_paths` 没有 column 列。B5 不读它（见 `_load_findings`）。
        column=0,
        symbol=path.symbol or "",
        step_kind=_step_kind(path.step_type),
        snippet=path.code_snippet or "",
    )


def _step_kind(raw: Any) -> TaintStepType:
    if isinstance(raw, TaintStepType):
        return raw
    try:
        return TaintStepType(str(raw))
    except ValueError:
        return TaintStepType.PROPAGATE


def _failure_reason(attempt: Any) -> str | None:
    """把 B5 的三个字段压进 `failure_reason` 一个列。

    输出形如 `[gate=HARMLESS_GUARD reason=PAYLOAD_REJECTED] 载荷含破坏性动词`。
    **码在前、人话在后**：码是给筛选与统计用的（`grep gate=` 就能分类），
    人话是给报告读者用的。反过来写的话，按前缀筛就得靠正则去猜。

    三个字段都空时返回 `None` 而不是空串 —— `failure_reason` 可空，
    而空串在报告里会渲成一个空的原因栏，看起来像「有原因但没写出来」。
    """
    parts: list[str] = []
    if getattr(attempt, "failed_gate", None):
        gate = attempt.failed_gate
        parts.append(f"gate={getattr(gate, 'value', gate)}")
    if getattr(attempt, "reason_code", None):
        code = attempt.reason_code
        parts.append(f"reason={getattr(code, 'value', code)}")

    detail = (attempt.failure_reason or "").strip()
    head = f"[{' '.join(parts)}]" if parts else ""

    if head and detail:
        return f"{head} {detail}"
    return head or detail or None


def _bucket(status: VulnStatus) -> str:
    if status is VulnStatus.VERIFIED:
        return "verified"
    if status is VulnStatus.REJECTED:
        return "rejected"
    return "potential"


def _delete_attempts_for(assessment_id: int, attempt_cls: Any, vuln_cls: Any) -> Any:
    """删掉本评估下所有漏洞的探针记录。

    写成一条 `DELETE ... WHERE vulnerability_id IN (SELECT ...)` 而不是
    先把漏洞查出来再逐个删：本阶段的漏洞可能有几百条，逐个删是几百个
    round-trip，而这是一句 SQL 就能表达的事。
    """
    from sqlalchemy import delete

    return delete(attempt_cls).where(
        attempt_cls.vulnerability_id.in_(
            select(vuln_cls.id).where(vuln_cls.assessment_id == assessment_id)
        )
    )


__all__ = ["PocVerifyAgent"]
