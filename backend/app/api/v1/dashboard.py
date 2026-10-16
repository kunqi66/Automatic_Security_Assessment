"""首页看板聚合统计（L1 接口层）。

**一堆 `GROUP BY` 而不是一个复杂查询**：数据量本来就小（单机、并发 1），
把它们拆开写是为了让每一块都能单独看懂、单独改。合并成一个大 SQL 省下的
那几毫秒，换不来「这一列为什么是 0」的排查时间。

**分母为 0 时返回空字典而不是报错**：一个刚部署、还没跑过评估的系统，
看板应该显示「0」而不是 500。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import DBSession, Permission, require
from app.models.assessment import Assessment
from app.models.enums import AssessmentStatus
from app.models.project import Project
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.assessment import AssessmentOut, StageStateOut
from app.schemas.dashboard import DashboardStatsOut

router = APIRouter(tags=["看板"])

Viewer = Annotated[User, Depends(require(Permission.ASSESSMENT_VIEW))]

#: 最近评估的条数。看板是入口页，塞太多行只会让人不知道先看哪个。
_RECENT_LIMIT = 5


@router.get(
    "/dashboard/stats",
    response_model=DashboardStatsOut,
    summary="全局统计",
)
async def get_dashboard_stats(
    session: DBSession,
    _: Viewer,
    recent: Annotated[int, Query(ge=1, le=20)] = _RECENT_LIMIT,
) -> DashboardStatsOut:
    project_count = await _count(session, select(func.count()).select_from(Project))
    assessment_count = await _count(session, select(func.count()).select_from(Assessment))
    running_count = await _count(
        session,
        select(func.count())
        .select_from(Assessment)
        .where(Assessment.status == AssessmentStatus.RUNNING),
    )
    vuln_total = await _count(session, select(func.count()).select_from(Vulnerability))

    vuln_by_severity = await _grouped(
        session, select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)
    )
    vuln_by_status = await _grouped(
        session, select(Vulnerability.status, func.count()).group_by(Vulnerability.status)
    )
    # 只统计**已出分**的评估：把还没跑完的（security_grade 为 NULL）算进分布，
    # 会让「安全评级」这张图的样本与标题说的不是一回事。
    grade_distribution = await _grouped(
        session,
        select(Assessment.security_grade, func.count())
        .where(Assessment.security_grade.is_not(None))
        .group_by(Assessment.security_grade),
    )

    recent_rows = (
        await session.execute(
            select(Assessment, Project.name)
            .join(Project, Project.id == Assessment.project_id)
            .order_by(Assessment.id.desc())
            .limit(recent)
        )
    ).all()

    return DashboardStatsOut(
        project_count=project_count,
        assessment_count=assessment_count,
        running_count=running_count,
        vuln_total=vuln_total,
        vuln_by_severity=vuln_by_severity,
        vuln_by_status=vuln_by_status,
        grade_distribution=grade_distribution,
        recent_assessments=[_to_recent(assessment, name) for assessment, name in recent_rows],
    )


async def _count(session: DBSession, stmt) -> int:  # noqa: ANN001
    return int(await session.scalar(stmt) or 0)


async def _grouped(session: DBSession, stmt) -> dict[str, int]:  # noqa: ANN001
    """`GROUP BY` 结果 → `{枚举值: 计数}`。

    用 `.value` 取枚举的字面量而不是 `str(enum)`：`StrEnum` 的 `str()` 恰好
    等于 value，但换成普通 `Enum` 就会变成 `Severity.CRITICAL` ——
    前端按 `'critical'` 取值，那样会静默全落空。
    """
    rows = (await session.execute(stmt)).all()
    out: dict[str, int] = {}
    for key, count in rows:
        if key is None:
            continue
        out[key.value if hasattr(key, "value") else str(key)] = int(count)
    return out


def _to_recent(assessment: Assessment, project_name: str | None) -> AssessmentOut:
    return AssessmentOut(
        id=assessment.id,
        project_id=assessment.project_id,
        project_name=project_name,
        status=assessment.status,
        current_stage=assessment.current_stage,
        progress=assessment.progress,
        security_grade=assessment.security_grade,
        stages=[
            StageStateOut(
                stage=row.stage,
                status=row.status,
                started_at=row.started_at,
                finished_at=row.finished_at,
                note=row.note,
            )
            for row in assessment.stages
        ],
        started_at=assessment.started_at,
        finished_at=assessment.finished_at,
        created_at=assessment.created_at,
    )
