"""快照 → `ReportData`：B6 的核心装配步骤（B6 设计 §3.1 assembler）。

## 为什么要拆成「取数」与「装配」两半

`load_snapshot()` 碰数据库，`build_report_data()` **不碰**。这样做的直接好处是
装配逻辑（排序、派生字段、措辞标注）可以用一个手搓的 `Snapshot` 直接测 ——
而它恰恰是报告里最该被反复断言的部分（第 3 章标题、第 4 章占位、
空态、`rejected` 的排除计数）。装一个数据库只为验证「skipped 会不会被写成无风险」
是不划算的，也更容易在 CI 里悄悄不跑。

## 一次性把派生字段算完（设计 §4.1 ②）

`chapter3_title` / `chapter3_note` / `chapter4_placeholder` / `empty_state` /
`notes_template_count` 这些**都在这里算完**，模板里一个 `if` 的业务判断都不留。
理由不是洁癖：三份模板（HTML / MD / PDF 共用 HTML）各写一遍判断，
迟早会有一份漏改 —— 而漏改的那一份会安静地给出不同口径的结论。
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.llm import expressions, fallback
from app.llm.types import TEMPLATE_MODEL, ChainView, FindingView, TextCompleter, TextResult
from app.models.assessment import Assessment
from app.models.chain import AttackChain
from app.models.enums import PatchStatus, ReportFormat, VulnStatus
from app.models.project import Project
from app.models.vulnerability import Patch, PocAttempt, Vulnerability
from app.report import scoring
from app.report.errors import ReportSnapshotError
from app.report.render import render_html, render_markdown
from app.report.types import (
    ChainEntry,
    ChainNodeEntry,
    PatchEntry,
    PocEvidence,
    Recommendation,
    ReportData,
    ReportDraft,
    ReportMeta,
    ReportSummary,
    StageSummary,
    TaintStepEntry,
    VulnEntry,
    build_verification_footnote,
    severity_label,
    status_label,
)

logger = get_logger(__name__)

#: 第 3 章的三个标题。**不是措辞偏好**：清单里只要还有一条未验证条目，
#: 标题写「已验证漏洞清单」就是在诱导读者把静态结论读成已确认事实。
#: 判据是「**全部**条目都已验证」，不是「有没有一条已验证」——
#: 后者会让「9 条未验证 + 1 条已验证」的清单也挂上「已验证」的标题。
_TITLE_VERIFIED = "已验证漏洞清单"
_TITLE_MIXED = "漏洞清单（含未经验证条目）"
_TITLE_EMPTY = "漏洞清单"


# ---------------------------------------------------------------------------
# 一、取数（唯一碰数据库的地方）
# ---------------------------------------------------------------------------


class Snapshot:
    """一次评估的完整只读快照。

    **用普通类而不是 dataclass 是有意的**：这里持有的是 ORM 实例，它们带
    `lazy="selectin"` 的关联集合。冻结语义（`frozen=True`）会给人「不可变」
    的错觉，而真正需要不可变的是 `ReportData`；这里只是「一批已经取出来的行」。
    """

    __slots__ = ("assessment", "chains", "project", "vulnerabilities")

    def __init__(
        self,
        *,
        assessment: Assessment,
        project: Project,
        vulnerabilities: Sequence[Vulnerability],
        chains: Sequence[AttackChain],
    ) -> None:
        self.assessment = assessment
        self.project = project
        self.vulnerabilities = list(vulnerabilities)
        self.chains = list(chains)


async def load_snapshot(session: AsyncSession, assessment_id: int) -> Snapshot:
    """把评估相关的四张表读成内存快照。

    **关联一律靠 `lazy="selectin"` 一次性带走**（`taint_paths` / `poc_attempts` /
    `patches` / `stages` / `nodes` 在建表时就是这么声明的），所以这里不需要
    自己拼 `selectinload` —— 但**必须知道它们已经是 selectin**：如果哪天有人把
    某个关联改成 `lazy="select"`，这里就会在 async 上下文里炸
    `MissingGreenlet`，而不是安静地多打几次查询。

    取不到 `assessments` 行是 **L5 不可降级**（设计 §6）：没有快照就没有报告，
    编一份「部分数据」的报告比不出报告危险得多。
    """
    # 用显式 `select` 而不是 `session.get()`：`get()` 命中身份映射时**不发 SQL**，
    # 于是 `lazy="selectin"` 的 `stages` 不会被预加载，后面 `build_report_data`
    # 里读 `assessment.stages` 就会在非 greenlet 上下文触发懒加载 →
    # `MissingGreenlet`。这在「同一次评估里编排器刚更新过 assessment 行」的
    # 真实场景下是会发生的，不是只有测试才碰得到。
    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == assessment_id))
    ).scalar_one_or_none()
    if assessment is None:
        raise ReportSnapshotError(
            f"评估 #{assessment_id} 不存在或已被删除，无法生成报告",
            detail={"assessment_id": assessment_id},
        )

    project = await session.get(Project, assessment.project_id)
    if project is None:
        # 外键是 ondelete="CASCADE"，正常情况下不可能走到这里。
        # 留着这个分支是因为「不可能」在数据被人手工改过之后就不成立了，
        # 而那时的报错必须说清是数据问题，不能是一串 AttributeError。
        raise ReportSnapshotError(
            f"评估 #{assessment_id} 关联的项目 #{assessment.project_id} 不存在"
            "（数据被手工改动过？）",
            detail={"assessment_id": assessment_id, "project_id": assessment.project_id},
        )

    vulns = (
        (
            await session.execute(
                select(Vulnerability)
                .where(Vulnerability.assessment_id == assessment_id)
                .order_by(Vulnerability.id)
            )
        )
        .scalars()
        .all()
    )
    chains = (
        (
            await session.execute(
                select(AttackChain)
                .where(AttackChain.assessment_id == assessment_id)
                .order_by(AttackChain.id)
            )
        )
        .scalars()
        .all()
    )

    logger.info(
        "报告快照已加载：assessment=#%s 漏洞 %d 条 / 攻击链 %d 条",
        assessment_id,
        len(vulns),
        len(chains),
    )
    return Snapshot(
        assessment=assessment,
        project=project,
        vulnerabilities=vulns,
        chains=chains,
    )


# ---------------------------------------------------------------------------
# 二、装配（纯函数，不碰数据库）
# ---------------------------------------------------------------------------


def build_report_data(
    snapshot: Snapshot,
    *,
    notes: Mapping[str, TextResult] | None = None,
    narratives: Mapping[int, TextResult] | None = None,
    generated_at: datetime | None = None,
) -> ReportData:
    """快照 + 表达层文案 → `ReportData`。

    `notes` / `narratives` 都**可以缺席**：不传时走确定性模板。
    这不是「兜底分支」，而是没有 LLM 时的**正式路径** —— 所以在缺省参数上
    直接给模板，而不是给空串或 None 让调用方去处理（PRD §7.6.2 L4）。
    """
    assessment = snapshot.assessment
    project = snapshot.project
    generated = generated_at or datetime.now(UTC).replace(tzinfo=None)

    vulns: list[Vulnerability] = snapshot.vulnerabilities
    patch_of: dict[int, Patch | None] = {v.id: _latest_patch(v) for v in vulns}
    rows = [scoring.ScoringInput.of(v, patch_of[v.id]) for v in vulns]

    score = scoring.compute_security_score(rows)
    matrix = scoring.build_severity_matrix(rows)

    # 清单顺序与整改顺序都来自 `scoring.py`（L1：排序是结论，不能由模型决定）
    ordered = sorted(rows, key=scoring.chapter3_sort_key)
    vuln_by_code: dict[str, Vulnerability] = {v.code: v for v in vulns}
    vuln_by_id: dict[int, Vulnerability] = {v.id: v for v in vulns}

    entries = [
        _vuln_entry(vuln_by_code[row.code], row, patch_of[vuln_by_code[row.code].id])
        for row in ordered
        if row.code in vuln_by_code
    ]

    chain_entries = [
        _chain_entry(
            chain,
            vuln_by_id,
            (narratives or {}).get(chain.id),
        )
        for chain in snapshot.chains
    ]

    # 第 5 章：顺序 → 文案。**先排序再要文案**，因为 `rank` 是喂给模型的输入，
    # 反过来的话模型拿到的序号与最终呈现的顺序会不一致。
    ranked = scoring.rank_recommendations(rows)
    recommendations = _recommendations(ranked, vuln_by_code, patch_of, notes or {})

    degraded = _degraded_marks(
        notes=notes or {}, narratives=narratives or {}, project=project, vulns=vulns
    )
    meta = ReportMeta(
        assessment_id=assessment.id,
        project_id=project.id,
        project_name=project.name,
        project_description=project.description,
        source_type=str(getattr(project.source_type, "value", project.source_type) or "upload"),
        source_url=project.source_url,
        source_branch=project.source_branch,
        tech_stack=_tech_stack(project.tech_stack),
        total_loc=int(project.total_loc or 0),
        started_at=assessment.started_at,
        finished_at=assessment.finished_at,
        duration_seconds=_duration(assessment.started_at, assessment.finished_at),
        stages=_stages(assessment),
        degraded=degraded,
        generated_at=generated,
    )

    has_verified = any(v.status == VulnStatus.VERIFIED for v in vulns)
    notes_template_count = sum(1 for r in recommendations if r.note_degraded)

    return ReportData(
        meta=meta,
        score=score,
        severity_matrix=matrix,
        severity_counts=_severity_counts(rows, include_rejected=False),
        severity_row_totals=_severity_counts(rows, include_rejected=True),
        type_distribution=scoring.build_type_distribution(rows, _type_labels()),
        vulnerabilities=entries,
        chains=chain_entries,
        recommendations=recommendations,
        degraded=degraded,
        has_verified=has_verified,
        chapter3_title=_chapter3_title(vulns),
        chapter3_note=_chapter3_note(vulns, has_verified),
        chapter4_placeholder=None if chain_entries else _CHAPTER4_PLACEHOLDER,
        empty_state=not vulns,
        excluded_rejected=scoring.count_rejected(rows),
        notes_template_count=notes_template_count,
    )


def build_summary(data: ReportData, formats: Sequence[Any] | None = None) -> ReportSummary:
    """写进 `reports.summary` 的摘要 JSON（供报告中心列表直接展示，免去解析正文）。

    `top_codes` 严格按第 3 章**同一个顺序**取前若干条 —— 摘要里另立一套排序
    是报告类产品的经典事故：列表页说「最严重的三条」与正文第 3 章的头三条不一样。
    """
    by_status: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    for (severity, status), count in data.severity_matrix.items():
        by_severity[severity] += count
        by_status[status] += count

    return ReportSummary(
        assessment_id=data.meta.assessment_id,
        project_name=data.meta.project_name,
        generated_at=data.meta.generated_at,
        score=data.score.score,
        grade=data.score.grade,
        grade_cn=data.score.grade_cn,
        total=len(data.vulnerabilities),
        by_status=dict(by_status),
        by_severity=dict(by_severity),
        chain_count=len(data.chains),
        formats=list(formats or []),
        degraded=list(data.degraded),
        top_codes=[v.code for v in data.vulnerabilities[:5]],
    )


# ---------------------------------------------------------------------------
# 三、契约 4 的入口
# ---------------------------------------------------------------------------


async def build_report(
    assessment_id: int,
    session: AsyncSession,
    *,
    client: TextCompleter | None = None,
    generated_at: datetime | None = None,
) -> ReportDraft:
    """契约 4：`report.build_report(assessment_id, session) -> ReportDraft`。

    **只装配 + 渲染，不落盘、不写库。** 事务边界属于调用方（总纲 §9.3：阶段边界
    才是提交点），所以 `report_gen` 阶段可以把「生成报告」和「写 `reports` 行 +
    回写 `assessments.security_score`」放在同一个事务里，失败时整体回滚 ——
    不会留下「报告写好了但评分没落库」的半成品。

    ⚠️ 契约文档只写了两个位置参数。这里多出的 `client` / `generated_at` 是
    **关键字参数**（`client` 供测试注入假客户端，`generated_at` 供测试固定时间戳），
    不影响契约调用方式；位置参数签名与契约一致。
    """
    snapshot = await load_snapshot(session, assessment_id)

    notes = await _generate_notes(snapshot, client)
    narratives = await _generate_narratives(snapshot, client)
    data = build_report_data(
        snapshot, notes=notes, narratives=narratives, generated_at=generated_at
    )

    draft = ReportDraft(
        assessment_id=assessment_id,
        data=data,
        html=render_html(data),
        markdown=render_markdown(data),
        # HTML / MD 在本步同步产出，PDF 由 exporter 惰性生成 ——
        # 摘要里如实列出**已经产出的**格式，不预先写上 pdf
        summary=build_summary(data, formats=[ReportFormat.HTML, ReportFormat.MD]),
        degraded=list(data.degraded),
    )
    logger.info(
        "报告已装配：assessment=#%s 漏洞 %d 条 / 链 %d 条 / 降级项 %s",
        assessment_id,
        len(data.vulnerabilities),
        len(data.chains),
        data.degraded or "无",
    )
    return draft


# ---------------------------------------------------------------------------
# 内部：表达层调用
# ---------------------------------------------------------------------------


async def _generate_notes(
    snapshot: Snapshot, client: TextCompleter | None
) -> dict[str, TextResult]:
    """用点 ④ 的批量调用，结果按 `code` 索引回装配层。

    `suggest_remediations` 在未配 key 时**在批量层就短路**成模板，所以这里
    不需要再加一层「有没有 key」的判断 —— 加了反而会造成两处判断不一致。
    """
    ranked = scoring.rank_recommendations(
        [scoring.ScoringInput.of(v, _latest_patch(v)) for v in snapshot.vulnerabilities]
    )
    if not ranked:
        return {}

    by_id = {v.code: v for v in snapshot.vulnerabilities}
    findings = [_finding_view(by_id[row.code], patch=None) for row, _ in ranked]
    texts = await expressions.suggest_remediations(findings, client=client)
    return {
        row.code: text for (row, _), text in zip(ranked, texts, strict=True) if row.code in by_id
    }


async def _generate_narratives(
    snapshot: Snapshot, client: TextCompleter | None
) -> dict[int, TextResult]:
    """用点 ③ 逐链生成叙事。

    逐条 `await` 而不是 `gather`：一条评估里的链通常个位数，且**每条链的叙事
    都要过实体白名单**，并发收益有限；反过来，串行能让「第几条链被拒收」在日志里
    有确定顺序，排查时不用去猜是哪一条。
    """
    out: dict[int, TextResult] = {}
    for chain in snapshot.chains:
        out[chain.id] = await expressions.narrate_chain(ChainView.of(chain), client=client)
    return out


# ---------------------------------------------------------------------------
# 内部：ORM 行 → 报告条目
# ---------------------------------------------------------------------------


def _latest_patch(vuln: Vulnerability) -> Patch | None:
    """取「可参考」的最新补丁：`status != rejected` 里 `id` 最大的那条。

    关联本身已按 `Patch.id.desc()` 排序，所以第一个命中就是答案 ——
    但仍显式遍历而不是取 `[0]`，因为「关联的 order_by 改了」是一个
    静默会改行为的改动，这里的循环能在那种改动后依然正确。
    """
    for patch in vuln.patches:
        if patch.status != PatchStatus.REJECTED:
            return patch
    return None


def _patch_entry(patch: Patch, vuln: Vulnerability) -> PatchEntry:
    return PatchEntry(
        # `target_file` 列可为空；空时退回漏洞自身的位置 ——
        # 报告里出现一个空的「目标文件」字段比给一个已知正确的路径更糟
        target_file=patch.target_file or vuln.file_path,
        diff=patch.diff_content or "",
        status=patch.status,
        source=patch.source,
        llm_model=patch.llm_model,
        rationale=patch.rationale,
        valid_diff=patch.valid_diff,
        window_ok=patch.window_ok,
        apply_check_ok=patch.apply_check_ok,
        taint_cleared=patch.taint_cleared,
        failure_reason=patch.failure_reason,
    )


def _poc_evidence(attempts: Sequence[PocAttempt], *, bound: bool) -> PocEvidence | None:
    """挑一条**可作为验证依据**的探针记录。

    只收 `harmless_guard_passed=True` 的：被闸门拦下的尝试证明的是「这次尝试被
    拦下了」，不是「这里能打」—— 把它摆进报告当证据，等于用一条失败记录支撑一个结论。

    排序基准显式用 `id`：`poc_attempts` 关联**没有** `order_by`，
    靠数据库返回顺序会让「同一份数据两次生成选到不同的探针」变成可能，
    而报告里换一段载荷就是换了一套事实。
    """
    usable = sorted((a for a in attempts if a.harmless_guard_passed), key=lambda a: a.id)
    if not usable:
        return None
    best = next((a for a in usable if a.matched), usable[-1])
    return PocEvidence(
        technique=best.technique,
        payload=best.payload,
        request_raw=best.request_raw,
        response_raw=best.response_raw,
        expected_pattern=best.expected_pattern,
        matched=best.matched,
        http_status=best.http_status,
        elapsed_ms=best.elapsed_ms,
        failure_reason=best.failure_reason,
        bound_to_finding=bound,
    )


def _vuln_entry(vuln: Vulnerability, row: scoring.ScoringInput, patch: Patch | None) -> VulnEntry:
    taint_path = [
        TaintStepEntry(
            step_index=step.step_index,
            step_type=str(getattr(step.step_type, "value", step.step_type)),
            file_path=step.file_path,
            line=step.line,
            symbol=step.symbol,
            code_snippet=step.code_snippet,
            note=step.note,
        )
        for step in sorted(vuln.taint_paths, key=lambda s: s.step_index)
    ]
    poc = _poc_evidence(vuln.poc_attempts, bound=vuln.status is VulnStatus.VERIFIED)
    guard_blocked = any(not a.harmless_guard_passed for a in vuln.poc_attempts)

    return VulnEntry(
        id=vuln.id,
        code=vuln.code,
        title=vuln.title,
        vuln_type=vuln.vuln_type,
        type_label=fallback.vuln_type_label(vuln.vuln_type),
        severity=vuln.severity,
        severity_cn=severity_label(vuln.severity),
        # 报告里展示的是**生效值**（缺失时已代入中位值），并用 `cvss_estimated`
        # 标出来 —— 显示 0.0 会让人以为「CVSS 确实是 0」，那是个错误的结论
        cvss_score=row.effective_cvss,
        cvss_vector=vuln.cvss_vector,
        cvss_estimated=row.cvss_estimated,
        status=vuln.status,
        status_cn=status_label(vuln.status),
        file_path=vuln.file_path,
        line_start=vuln.line_start,
        line_end=vuln.line_end,
        sink_symbol=vuln.sink_symbol,
        code_snippet=vuln.code_snippet,
        description=vuln.description,
        remediation_note=vuln.remediation_note,
        confidence=vuln.confidence,
        detection_method=vuln.detection_method,
        guard_blocked=guard_blocked,
        taint_path=taint_path,
        poc=poc,
        patch=_patch_entry(patch, vuln) if patch is not None else None,
        # 「已通过验证但没有探针记录」本身就是一处数据缺口：结论说验证过了，
        # 证据却不在。标出来而不是假装完整。
        data_incomplete=(
            row.cvss_estimated
            or not taint_path
            or (vuln.status == VulnStatus.VERIFIED and poc is None)
        ),
    )


def _chain_entry(
    chain: AttackChain,
    vuln_by_id: Mapping[int, Vulnerability],
    narrative: TextResult | None,
) -> ChainEntry:
    nodes = [
        ChainNodeEntry(
            order_index=node.order_index,
            node_type=node.node_type,
            label=node.label,
            detail=node.detail,
            stage_name=node.stage_name,
            precondition=node.precondition,
            postcondition=node.postcondition,
            rule_id=node.rule_id,
            vuln_code=(vuln_by_id[node.vuln_id].code if node.vuln_id in vuln_by_id else None),
            # ★ Q24 方案 A：`verification_status` 由 B5 写入，是**输入**。
            # 这里只做搬运 —— 一旦某一环是 inferred 而报告写成 verified，
            # 系统就变成在宣称自己做了没做的事，这比漏报严重。
            verification_status=node.verification_status,
        )
        for node in sorted(chain.nodes, key=lambda n: (n.order_index, n.id))
    ]

    text = narrative or TextResult(
        text=fallback.narrate_chain(ChainView.of(chain)),
        llm_model=TEMPLATE_MODEL,
        degraded=True,
        reason="no_llm",
    )

    return ChainEntry(
        id=chain.id,
        name=chain.name,
        description=chain.description,
        severity=chain.severity,
        entry_point=chain.entry_point,
        target_asset=chain.target_asset,
        confidence=chain.confidence,
        nodes=nodes,
        narrative=text.text,
        narrative_model=text.llm_model,
        narrative_degraded=text.degraded,
        # 脚注按**实际**环数生成（设计 §4.5 第 3 条：不得写死）
        verification_footnote=build_verification_footnote(nodes),
    )


def _recommendations(
    ranked: Sequence[tuple[scoring.ScoringInput, dict[str, float]]],
    vuln_by_code: Mapping[str, Vulnerability],
    patch_of: Mapping[int, Patch | None],
    notes: Mapping[str, TextResult],
) -> list[Recommendation]:
    out: list[Recommendation] = []
    total = len(ranked)
    for index, (row, factors) in enumerate(ranked):
        vuln = vuln_by_code.get(row.code)
        if vuln is None:
            continue
        rank = index + 1
        # 文案缺位时**当场走模板**，而不是把这一项从清单里删掉：
        # 整改项的**存在与顺序**是结论，不能因为「模型没回话」就少一条。
        text = notes.get(row.code) or TextResult(
            text=fallback.suggest_remediation(
                _finding_view(vuln, patch=patch_of.get(vuln.id)),
                rank=rank,
                total=total,
            ),
            llm_model=TEMPLATE_MODEL,
            degraded=True,
            reason="no_llm",
        )
        patch = patch_of.get(vuln.id)
        out.append(
            Recommendation(
                rank=rank,
                code=vuln.code,
                title=vuln.title,
                type_label=fallback.vuln_type_label(vuln.vuln_type),
                severity=vuln.severity,
                severity_cn=severity_label(vuln.severity),
                status=vuln.status,
                status_cn=status_label(vuln.status),
                cvss_score=row.effective_cvss,
                file_path=vuln.file_path,
                line_start=vuln.line_start,
                line_end=vuln.line_end,
                priority=factors.get(scoring.FACTOR_PRIORITY, 0.0),
                priority_factors=dict(factors),
                note=text.text,
                note_model=text.llm_model,
                note_degraded=text.degraded,
                patch=_patch_entry(patch, vuln) if patch is not None else None,
            )
        )
    return out


def _finding_view(vuln: Vulnerability, *, patch: Patch | None) -> FindingView:
    """ORM 行 → 表达层输入视图。

    额外补两样 ORM 里没有的东西：

    * `source_kind` / `sink_kind` —— 从污点路径的**首尾两跳**推出来。库里没这两列，
      而模板要讲清「数据从哪来、到哪去」，缺了它们降级文案就只剩「这里有个洞」。
      （`rule_id` 同样不在库里，但它是 B4/B5 分析期的中间产物，无法从行反推，
      因此如实留空、不编。）
    * `cvss_score` 用**代入后的生效值** —— 原始列在缺数据时是 0.0，直接喂进模板
      会让文案写「CVSS 0.0」，那是在陈述一个错误的事实。
    """
    steps = sorted(vuln.taint_paths, key=lambda s: s.step_index)
    source_kind = steps[0].symbol if steps else None
    sink_kind = steps[-1].symbol if steps else None
    base = FindingView.of(
        vuln,
        source_kind=source_kind,
        sink_kind=sink_kind,
        rationale=patch.rationale if patch is not None else None,
    )
    return replace(
        base,
        cvss_score=scoring.ScoringInput.of(vuln, patch).effective_cvss,
    )


# ---------------------------------------------------------------------------
# 内部：metas / 呈现派生字段
# ---------------------------------------------------------------------------


def _tech_stack(raw: Any) -> dict[str, str]:
    """`projects.tech_stack` 是 `JSON` 列，类型上可以是任何东西。

    收敛成 `dict[str, str]`：模板只做展示，不该在模板里对 `Any` 做属性访问。
    """
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if v not in (None, "")}


def _duration(started: Any, finished: Any) -> float | None:
    if started is None or finished is None:
        return None
    return round((finished - started).total_seconds(), 2)


def _stages(assessment: Assessment) -> list[StageSummary]:
    return [
        StageSummary(
            stage=row.stage,
            status=row.status,
            started_at=row.started_at,
            finished_at=row.finished_at,
            duration_seconds=_duration(row.started_at, row.finished_at),
            note=row.note,
        )
        for row in assessment.stages
    ]


def _severity_counts(
    rows: Sequence[scoring.ScoringInput], *, include_rejected: bool
) -> dict[str, int]:
    """`severity → 计数`。

    `include_rejected=False` 给柱状图用（「实际风险分布」），
    `True` 给分布矩阵的行合计用。「已复核排除」是已经判定为**不是漏洞**的条目，
    把它画进风险图会让图与「漏洞总数」对不上，读者的第一反应是数字错了。
    """
    counter: Counter[str] = Counter()
    for row in rows:
        if not include_rejected and row.status == VulnStatus.REJECTED.value:
            continue
        counter[row.severity] += 1
    return {sev: counter.get(sev, 0) for sev in ("critical", "high", "medium", "low")}


def _type_labels() -> dict[str, str]:
    return dict(fallback.VULN_TYPE_LABEL)


def _degraded_marks(
    *,
    notes: Mapping[str, TextResult],
    narratives: Mapping[int, TextResult],
    project: Project,
    vulns: Sequence[Vulnerability],
) -> list[str]:
    """收集本次生成过程中真实发生的降级项，写进报告首页横幅。

    **只登记真的发生了的。** 一个固定的「本报告可能降级」免责声明没有信息量，
    反而会让人忽略掉真正的降级；这里每一项都对应一个具体的成因。
    """
    marks: list[str] = []
    if any(r.degraded for r in notes.values()) or any(r.degraded for r in narratives.values()):
        marks.append("llm")
    if not project.tech_stack:
        marks.append("tech_stack")
    if not project.total_loc:
        marks.append("loc")
    if project.source_type == "git" and not project.source_url:
        marks.append("source_url")
    # `cvss` 与 `llm` 是两回事：前者是**上游数据缺口**（B4 没算出 CVSS），
    # 后者只是措辞降级。合成一项会让「报告里的数字不完整」被当成排版问题。
    if any(not v.cvss_score or v.cvss_score <= 0 for v in vulns):
        marks.append("cvss")
    return marks


_CHAPTER4_PLACEHOLDER = (
    "本次评估未产出攻击链。可能原因是 `exploit_chain` 阶段被跳过（沙箱不可达或前序阶段未完成），"
    "或现有漏洞组合未命中任何一条推演规则（R1–R8）。"
    "本章不生成占位链 —— 未匹配上就是未匹配上，编一条看起来完整的链比缺一章糟得多。"
)


def _chapter3_title(vulns: Sequence[Vulnerability]) -> str:
    """清单标题：**只有全部条目都已验证，才配得上「已验证漏洞清单」这个名字。**

    `rejected` 的条目也列在第 3 章（留痕），但它已经被判定为「不是漏洞」，
    不该因为它而否掉标题 —— 真正需要防的是**未验证**的条目被「已验证」这个词罩住。
    """
    if not vulns:
        return _TITLE_EMPTY
    settled = {VulnStatus.VERIFIED, VulnStatus.REJECTED}
    if all(v.status in settled for v in vulns):
        return _TITLE_VERIFIED
    return _TITLE_MIXED


def _chapter3_note(vulns: Sequence[Vulnerability], has_verified: bool) -> str:
    """第 3 章的证据强度说明。**这一段是本报告最该被逐字读的部分。**

    ⚠️ 产出的是**纯文本**：同一份文案同时进 HTML 与 Markdown 模板
    （见 `fallback.py` 模块文档「纯文本」一节），所以这里**不能出现 `**` 或反引号**——
    它们在 HTML 里会原样显示成星号与反引号，而这类残留不会报错。
    需要强调时用中文引号「」。
    """
    total = len(vulns)
    if total == 0:
        return ""
    verified = sum(1 for v in vulns if v.status == VulnStatus.VERIFIED)
    potential = sum(1 for v in vulns if v.status == VulnStatus.POTENTIAL)
    rejected = sum(1 for v in vulns if v.status == VulnStatus.REJECTED)
    if has_verified:
        return (
            f"本次共 {total} 条漏洞，其中 {verified} 条已通过沙箱无害化验证，"
            f"{potential} 条存在利用线索但未完全坐实，"
            f"{rejected} 条经动态探针未能复现（「机器判定，未经人工确认」——"
            f"该结论仅表示本次无害化探针没取到证据，不足以单独认定为误报）。"
            "清单按「漏洞严重度降序 → CVSS 降序 → 漏洞编号升序」排列，"
            "每条均标注其验证状态 —— 未经验证的条目「不等于」不存在风险，"
            "也不等于风险已被确认，请在修复前补充验证。"
        )
    return (
        f"本次共 {total} 条漏洞，「没有任何一条通过动态验证」（沙箱不可达、"
        "未生成有效探针，或该阶段被跳过）。以下全部为静态分析结论。"
        "「未经验证」既不等于「无风险」，也不等于「已确认」——"
        "它表示数据流未经过有效净化这件事已被确认，但「能否被真正利用」尚未验证。"
        "请在据此排期前先补一次动态验证。"
    )


__all__ = [
    "Snapshot",
    "build_report",
    "build_report_data",
    "build_summary",
    "load_snapshot",
]
