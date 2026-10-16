"""漏洞查询、人工复核与补丁建议（L1 接口层）。

**人工复核是唯一被允许覆盖引擎结论的入口**（需求 2.5.2）。正因为它有这个权力，
两个约束必须在这里落地，而不是指望前端自觉：

1. 只允许改成 `rejected` / `potential`。**不允许改成 `verified`** ——
   「已验证」意味着有沙箱实测证据（`poc_attempts` 里有一条 `matched=True`），
   那不是点个按钮能声明的事。放开这个口子，`verified` 就失去了全部含义。
2. 每次复核都写 `audit_logs`（与业务变更**同一个事务**）。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select

from app.api.deps import DBSession, Permission, require
from app.core.exceptions import BadRequestError, NotFoundError
from app.core.logging import get_logger
from app.db import audit
from app.models.assessment import Assessment
from app.models.enums import PatchSource, PatchStatus, Severity, VulnStatus
from app.models.user import User
from app.models.vulnerability import Patch, Vulnerability
from app.schemas.common import Page
from app.schemas.vulnerability import (
    PatchSuggestionOut,
    PatchValidationOut,
    VulnerabilityOut,
    VulnStatusUpdate,
)

logger = get_logger(__name__)

router = APIRouter(tags=["漏洞"])

VulnViewer = Annotated[User, Depends(require(Permission.VULN_VIEW))]
VulnReviewer = Annotated[User, Depends(require(Permission.VULN_REVIEW))]
PatchAccepter = Annotated[User, Depends(require(Permission.PATCH_ACCEPT))]

#: 人工复核允许改成的状态。**白名单而不是黑名单** ——
#: 将来 `VulnStatus` 加值（比如 `fixed`）时，黑名单会静默放行新值。
_REVIEWABLE = (VulnStatus.REJECTED, VulnStatus.POTENTIAL)


@router.get(
    "/assessments/{assessment_id}/vulnerabilities",
    response_model=Page[VulnerabilityOut],
    summary="评估下的漏洞列表",
)
async def list_vulnerabilities(
    assessment_id: int,
    session: DBSession,
    _: VulnViewer,
    severity: Annotated[Severity | None, Query()] = None,
    status_filter: Annotated[VulnStatus | None, Query(alias="status")] = None,
    vuln_type: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 20,
) -> Page[VulnerabilityOut]:
    conditions = [Vulnerability.assessment_id == assessment_id]
    if severity is not None:
        conditions.append(Vulnerability.severity == severity)
    if status_filter is not None:
        conditions.append(Vulnerability.status == status_filter)
    if vuln_type:
        conditions.append(Vulnerability.vuln_type == vuln_type)

    total = await session.scalar(select(func.count()).select_from(Vulnerability).where(*conditions))
    rows = (
        (
            await session.execute(
                select(Vulnerability)
                .where(*conditions)
                # **按严重度排序，而不是按 id**：一个评估里几十条漏洞，
                # 用户要的是「先看最要命的」，而不是「先看最先被扫出来的」。
                # 严重度是字符串枚举，直接排会按字母序（critical < high < low < medium），
                # 所以给一个显式权重。
                .order_by(
                    _severity_rank().desc(),
                    Vulnerability.cvss_score.desc(),
                    Vulnerability.id.asc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )

    return Page[VulnerabilityOut](
        items=[VulnerabilityOut.from_model(row) for row in rows],
        total=int(total or 0),
        page=page,
        page_size=page_size,
    )


@router.get(
    "/vulnerabilities/{vuln_id}",
    response_model=VulnerabilityOut,
    summary="漏洞详情（含污点路径与最新补丁）",
)
async def get_vulnerability(vuln_id: int, session: DBSession, _: VulnViewer) -> VulnerabilityOut:
    return VulnerabilityOut.from_model(await _load(session, vuln_id))


@router.patch(
    "/vulnerabilities/{vuln_id}",
    response_model=VulnerabilityOut,
    summary="人工复核（改判为 已排除 / 疑似）",
)
async def review_vulnerability(
    vuln_id: int,
    payload: VulnStatusUpdate,
    session: DBSession,
    user: VulnReviewer,
    request: Request,
) -> VulnerabilityOut:
    vuln = await _load(session, vuln_id)

    if payload.status not in _REVIEWABLE:
        raise BadRequestError(
            f"人工复核只能改判为 {' / '.join(s.value for s in _REVIEWABLE)}",
            remediation="「已验证」需由沙箱实测产生，不能人工声明",
        )
    if vuln.status not in _REVIEWABLE and vuln.status != VulnStatus.UNVERIFIED:
        raise BadRequestError(
            f"当前状态 {vuln.status.value} 不可再复核",
            remediation="已排除/疑似之间可以互相改判，已验证的不可改",
        )

    before = vuln.status
    vuln.status = payload.status

    # 与业务变更同一个事务：审计写失败时这次改判应该一起回滚。
    # 否则会出现「改了但没留痕」—— 那正是审计最该防的情况。
    audit.record(
        session,
        user=user,
        action="vulnerability.review",
        target_type="vulnerability",
        target_id=vuln.id,
        detail={
            "from": before.value,
            "to": payload.status.value,
            "reason": payload.reason,
        },
        request=request,
    )
    await session.commit()
    await session.refresh(vuln)

    logger.info(
        "用户 %s 将漏洞 %s 由 %s 改判为 %s",
        user.username,
        vuln.id,
        before.value,
        payload.status.value,
    )
    return VulnerabilityOut.from_model(vuln)


# ---------------------------------------------------------------------------
# 补丁
# ---------------------------------------------------------------------------


@router.post(
    "/vulnerabilities/{vuln_id}/patch/generate",
    response_model=PatchSuggestionOut,
    summary="生成修复建议补丁（**绝不自动应用**）",
)
async def generate_patch(vuln_id: int, session: DBSession, _: VulnReviewer) -> PatchSuggestionOut:
    """走「LLM 出草案 → 四道校验 → 落库」。

    **本函数只做排序与持久化，不做任何判断**：草案由 `app/llm` 出，
    四道校验全部由 `app/verify/patch_guard.py` 判定，通过与否不由这里决定。

    四道校验全过 → `source=llm`；任何一道没过 → `source=validate_failed`，
    照样返回给用户看，但前端与报告必须标注「仅供参考，未通过校验」
    （PRD §7.6.3）。**降级暴露比静默隐藏更有价值** —— 一个被拦下的补丁
    往往能让人看出漏洞的真实成因。
    """
    # 延迟 import：`app.verify` 要起子进程跑 `git apply`、还要重跑污点分析，
    # 在不需要补丁的部署里不该阻塞应用启动。
    from app.llm import expressions
    from app.projects.workspace import read_whole_source
    from app.verify.patch_guard import check_patch

    vuln = await _load(session, vuln_id)
    view = _to_view(vuln)

    draft = await expressions.suggest_patch(view)
    if draft.diff is None:
        # LLM 降级且没有可用的模板补丁。**这不是错误** —— 契约 3 的降级列
        # 明确写了「无补丁（patch=null）」，前端据此显示「暂无建议」。
        raise BadRequestError(
            "未能生成可用的补丁草案",
            remediation=draft.advice or "可稍后重试，或参考整改建议手工修复",
        )

    # 第 ③④ 道校验要在**原始源码**上做（`git apply --check` 与「打上后重跑
    # 污点引擎」都需要全文）。源码在这里读，而不是从漏洞行号拼一段 ——
    # 用 ±20 行去 apply 一个补丁必然失败，而失败原因会显示成「补丁格式不对」。
    project_id = await session.scalar(
        select(Assessment.project_id).where(Assessment.id == vuln.assessment_id)
    )
    if project_id is None:
        raise NotFoundError(f"漏洞 {vuln.id} 所属的评估不存在")
    source = await read_whole_source(project_id, vuln.file_path)

    verdict = await check_patch(
        draft.diff,
        finding=vuln,
        file_path=vuln.file_path,
        source=source,
    )

    patch = Patch(
        vulnerability_id=vuln.id,
        target_file=draft.target_file or vuln.file_path,
        diff_content=draft.diff,
        status=PatchStatus.SUGGESTED,
        # `PatchCheck.accepted` 是唯一判据 —— 不在这里重复写一遍
        # `and` 链，那种重复迟早会和 `patch_guard` 里的定义漂移。
        source=PatchSource.LLM if verdict.accepted else PatchSource.VALIDATE_FAILED,
        llm_model=draft.llm_model,
        rationale=draft.advice,
        **verdict.to_orm_fields(),
    )
    session.add(patch)
    await session.commit()
    await session.refresh(patch)

    return PatchSuggestionOut(
        source=patch.source,
        diff=patch.diff_content,
        target_file=patch.target_file or vuln.file_path,
        validation=PatchValidationOut(
            valid_diff=patch.valid_diff,
            window_ok=patch.window_ok,
            apply_check_ok=patch.apply_check_ok,
            taint_cleared=patch.taint_cleared,
            failure_reason=patch.failure_reason,
        ),
    )


@router.post(
    "/vulnerabilities/{vuln_id}/patch/accept",
    response_model=VulnerabilityOut,
    summary="采纳补丁（**仅记录，不改动源码**）",
)
async def accept_patch(
    vuln_id: int,
    session: DBSession,
    user: PatchAccepter,
    request: Request,
    patch_id: Annotated[int | None, Query(description="缺省采纳最新一条")] = None,
) -> VulnerabilityOut:
    """采纳 = 把这条补丁标成 `accepted`，**仅此而已**。

    **系统不会去改用户的源码**。需求 2.5.2 写的是「生成修复建议」，不是
    「自动修复」；把 diff 打进别人的仓库，后果由谁承担是说不清的。
    这里落库的是「人看过并认可了这条建议」这个事实，供报告与审计引用。
    """
    vuln = await _load(session, vuln_id)

    if patch_id is None:
        patch = await session.scalar(
            select(Patch)
            .where(Patch.vulnerability_id == vuln.id)
            .order_by(Patch.id.desc())
            .limit(1)
        )
    else:
        patch = await session.scalar(
            select(Patch).where(Patch.id == patch_id, Patch.vulnerability_id == vuln.id)
        )
    if patch is None:
        raise NotFoundError("该漏洞下没有可采纳的补丁")

    patch.status = PatchStatus.ACCEPTED
    audit.record(
        session,
        user=user,
        action="patch.accept",
        target_type="patch",
        target_id=patch.id,
        detail={
            "vulnerability_id": vuln.id,
            # 记下四道校验的结果。采纳一条**未过校验**的补丁是允许的
            # （人有权判断），但事后必须能看出当时它没过 —— 否则
            # 「为什么这条坏补丁被采纳了」永远查不清。
            "valid_diff": patch.valid_diff,
            "window_ok": patch.window_ok,
            "apply_check_ok": patch.apply_check_ok,
            "taint_cleared": patch.taint_cleared,
        },
        request=request,
    )
    await session.commit()
    await session.refresh(vuln)

    logger.info("用户 %s 采纳了补丁 %s（漏洞 %s）", user.username, patch.id, vuln.id)
    return VulnerabilityOut.from_model(vuln)


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

#: 严重度排序权重。写成显式映射而不是依赖枚举定义顺序 ——
#: 定义顺序是「人写代码时的顺序」，不是「业务优先级」，两者会漂移。
_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def _severity_rank():
    from sqlalchemy import case

    return case(
        _SEVERITY_WEIGHT,
        value=Vulnerability.severity,
        else_=0,
    )


async def _load(session: DBSession, vuln_id: int) -> Vulnerability:
    vuln = await session.get(Vulnerability, vuln_id)
    if vuln is None:
        raise NotFoundError(f"漏洞 {vuln_id} 不存在")
    return vuln


def _to_view(vuln: Vulnerability):  # noqa: ANN202 —— 返回 llm.types.FindingView
    """ORM 行 → LLM 表达层的 `FindingView`。

    **转换发生在 L1 而不是 L3**：`app/llm` 不认识 ORM（它只认 `FindingView`），
    反过来让 ORM 直接产出表达层对象会把两个模块耦死。

    用 `FindingView.of()` 而不是手写字段映射：`TaintPath.step_type` 与
    `TaintStepView.step_kind`、`Vulnerability.sink_symbol` 与 `FindingView.symbol`
    名字都不一样，手写映射就是两份会各自漂移的真相。
    """
    from app.llm.types import FindingView

    return FindingView.of(vuln)
