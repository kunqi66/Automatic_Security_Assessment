"""报告查询、导出与下载（L1 接口层）。

**报告在 `report_gen` 阶段就已经生成并落盘了**。本模块的导出接口是给
「重新出一份别的格式」用的，不是主路径 —— 一次评估正常走完，
`reports` 表里就已经有 HTML 了。

**下载走的是 `content_path` + 根目录拼接，且必须复用 `safe_join`**：
报告内容里含被评估项目的源码，路径一旦能被 `..` 影响，就是一个任意文件读取。
`content_path` 虽然是系统自己写的（不是用户输入），但用拼接函数而不是
`Path(root) / rel`，是为了让「这里不信任这段字符串」这件事在代码里看得见。
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse
from sqlalchemy import func, select

from app.api.deps import DBSession, Permission, require
from app.core.config import settings
from app.core.exceptions import BadRequestError, NotFoundError
from app.core.logging import get_logger
from app.models.assessment import Assessment
from app.models.enums import ReportFormat, ReportStatus
from app.models.project import Project
from app.models.report import Report
from app.models.user import User
from app.schemas.common import Page
from app.schemas.report import ReportOut

logger = get_logger(__name__)

router = APIRouter(tags=["报告"])

Viewer = Annotated[User, Depends(require(Permission.REPORT_VIEW))]
Exporter = Annotated[User, Depends(require(Permission.REPORT_EXPORT))]

_MEDIA_TYPES = {
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.MD: "text/markdown; charset=utf-8",
    ReportFormat.PDF: "application/pdf",
}


@router.get("/reports", response_model=Page[ReportOut], summary="报告列表")
async def list_reports(
    session: DBSession,
    _: Viewer,
    assessment_id: Annotated[int | None, Query()] = None,
    fmt: Annotated[ReportFormat | None, Query(alias="format")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Page[ReportOut]:
    conditions = []
    if assessment_id is not None:
        conditions.append(Report.assessment_id == assessment_id)
    if fmt is not None:
        conditions.append(Report.format == fmt)

    total = await session.scalar(select(func.count()).select_from(Report).where(*conditions))
    rows = (
        await session.execute(
            select(Report, Project.name)
            .join(Assessment, Assessment.id == Report.assessment_id)
            .join(Project, Project.id == Assessment.project_id)
            .where(*conditions)
            .order_by(Report.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()

    return Page[ReportOut](
        items=[_to_out(report, name) for report, name in rows],
        total=int(total or 0),
        page=page,
        page_size=page_size,
    )


@router.get(
    "/assessments/{assessment_id}/report",
    response_model=ReportOut,
    summary="取指定格式的报告记录（未生成则 404）",
)
async def get_report(
    assessment_id: int,
    session: DBSession,
    _: Viewer,
    fmt: Annotated[ReportFormat, Query(alias="format")] = ReportFormat.HTML,
) -> ReportOut:
    report = await _latest(session, assessment_id, fmt)
    if report is None:
        raise NotFoundError(
            f"该评估还没有 {fmt.value} 格式的报告",
            remediation="可调用导出接口生成",
        )
    name = await session.scalar(
        select(Project.name)
        .join(Assessment, Assessment.project_id == Project.id)
        .where(Assessment.id == assessment_id)
    )
    return _to_out(report, name)


@router.post(
    "/assessments/{assessment_id}/report/export",
    response_model=ReportOut,
    summary="导出指定格式（PDF 可能降级）",
)
async def export_report(
    assessment_id: int,
    session: DBSession,
    _: Exporter,
    fmt: Annotated[ReportFormat, Query(alias="format")] = ReportFormat.HTML,
) -> ReportOut:
    from app.report.service import ReportService

    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise NotFoundError(f"评估 {assessment_id} 不存在")

    # 走门面而不是直接调 `exporter`：导出这条路有四种情况
    # （已有文件 / 没生成过就地补生成 / PDF 惰性生成 / PDF 降级），
    # 门面已经把它们收在一处；在这里再分一次支就会有两份判断。
    #
    # `commit=True`（默认）：这是用户主动点的一次操作，不是流水线里的一个阶段，
    # 没有「阶段边界统一提交」可依靠。
    result = await ReportService(session).export(assessment_id, fmt)
    if result.degraded:
        # **降级不是错误**：PDF 需要 Chromium，没装就退化成「不产出 PDF」。
        # 用 warning 而不是抛异常 —— 抛了就变成「导出按钮点了报错」，
        # 而实际上 HTML/MD 都好好的，用户只是拿不到 PDF 而已。
        logger.warning("评估 %s 导出 %s 降级：%s", assessment_id, fmt.value, result.message)

    report = await _latest(session, assessment_id, fmt)
    if report is None:
        raise BadRequestError(
            result.message or f"未能产出 {fmt.value} 格式的报告",
            remediation="检查报告生成阶段的日志",
        )

    name = await session.scalar(
        select(Project.name)
        .join(Assessment, Assessment.project_id == Project.id)
        .where(Assessment.id == assessment_id)
    )
    return _to_out(report, name)


@router.get(
    "/assessments/{assessment_id}/report/download/{fmt}",
    summary="下载报告文件",
    response_class=FileResponse,
)
async def download_report(
    assessment_id: int,
    fmt: ReportFormat,
    session: DBSession,
    _: Viewer,
) -> FileResponse:
    report = await _latest(session, assessment_id, fmt)
    if report is None or not report.content_path:
        raise NotFoundError(f"该评估还没有 {fmt.value} 格式的报告文件")

    path = _resolve(report.content_path)
    if not path.is_file():
        # 库里有记录但文件没了（被清理 / 换了机器）。这时说「文件不存在」
        # 比抛 500 有用得多 —— 它直接指向「重新导出一次」。
        raise NotFoundError(
            "报告文件已不存在",
            remediation="可能已被清理，请重新导出",
        )

    return FileResponse(
        path,
        media_type=_MEDIA_TYPES.get(fmt, "application/octet-stream"),
        filename=f"assessment-{assessment_id}-report.{fmt.value}",
        # 内联展示 PDF 与 HTML，其余走附件下载。HTML 内联是安全的：
        # 它是自包含的（零外部资源），且前端预览用**空 sandbox 的 iframe** 承载。
        content_disposition_type="inline" if fmt != ReportFormat.MD else "attachment",
    )


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _resolve(rel: str) -> Path:
    """相对报告根 → 绝对路径。

    **拒绝绝对路径与 `..`**，而不是「拼上去看看」。`content_path` 理论上是
    系统自己写的，但下载接口是这类系统里最典型的任意文件读取入口，
    多一层检查的成本是零。
    """
    candidate = Path(rel)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise BadRequestError("报告路径非法")
    root = settings.report_root.resolve()
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root):
        raise BadRequestError("报告路径越界")
    return resolved


async def _latest(session: DBSession, assessment_id: int, fmt: ReportFormat) -> Report | None:
    return await session.scalar(
        select(Report)
        .where(
            Report.assessment_id == assessment_id,
            Report.format == fmt,
            # 只认 ready 的：`generating` 是中间态，`failed` 的没有文件可给。
            Report.status == ReportStatus.READY,
        )
        .order_by(Report.id.desc())
        .limit(1)
    )


def _to_out(report: Report, project_name: str | None) -> ReportOut:
    return ReportOut(
        id=report.id,
        assessment_id=report.assessment_id,
        project_name=project_name or "",
        title=report.title,
        format=report.format,
        status=report.status,
        content_path=report.content_path,
        size_bytes=report.size_bytes,
        generated_at=report.generated_at,
    )
