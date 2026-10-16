"""`reports` 表与两列回写的持久化（B6 设计 §5.2）。

## **这里一个 `commit()` 都没有，是有意的**

事务边界属于调用方。`report_gen` 阶段会把三件事放进**同一个事务**：

1. 写 `reports` 行（html / md，失败时 pdf 也一并）
2. 回写 `assessments.security_score` / `security_grade`
3. 更新 `assessment_stages` 的 `report_gen` 行

任何一步失败就整体回滚。反过来，如果在 `repository` 内部 commit，
就会出现「报告文件已落盘 + `reports` 行已提交，但 `security_score` 还没写」
这种半成品 —— 而半成品不会报错，它只会在报告中心里显示一个空等级。

## upsert 而不是 insert

`reports` 上有 `uk_report_assessment_format`：同一评估的同一格式只应有一份。
PDF 是**惰性生成**的（首次下载时才做），用户点两次下载就会触发两次生成 ——
唯一约束保证第二次是覆盖而不是 `IntegrityError`。
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.assessment import Assessment
from app.models.enums import ReportFormat, ReportStatus
from app.models.report import Report
from app.report.types import SecurityScore

logger = get_logger(__name__)


async def get_report(
    session: AsyncSession, assessment_id: int, fmt: ReportFormat | str
) -> Report | None:
    value = _value(fmt)
    return (
        await session.execute(
            select(Report).where(
                Report.assessment_id == assessment_id,
                Report.format == value,
            )
        )
    ).scalar_one_or_none()


async def list_reports(session: AsyncSession, assessment_id: int) -> list[Report]:
    """列出某次评估的全部报告行。

    排序用 `format` 升序：`html / md / pdf` 恰好也是「先有的在前」的顺序，
    而且它**不依赖时间戳** —— 同一秒内写入的两行不该有先后歧义。
    """
    rows = (
        (
            await session.execute(
                select(Report).where(Report.assessment_id == assessment_id).order_by(Report.format)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def upsert_report(
    session: AsyncSession,
    *,
    assessment_id: int,
    fmt: ReportFormat | str,
    title: str,
    content_path: str | None,
    size_bytes: int | None = None,
    summary: dict[str, Any] | None = None,
    status: ReportStatus = ReportStatus.READY,
) -> Report:
    """按 `(assessment_id, format)` 覆盖写入。

    **不 commit**（见模块文档）。返回 ORM 行，调用方可继续改字段。
    """
    value = _value(fmt)
    row = await get_report(session, assessment_id, value)
    if row is None:
        row = Report(assessment_id=assessment_id, format=value, title=title)
        session.add(row)

    row.title = title
    row.status = status
    row.content_path = content_path
    row.size_bytes = size_bytes
    row.summary = summary
    return row


async def mark_failed(
    session: AsyncSession, *, assessment_id: int, fmt: ReportFormat | str, title: str
) -> Report:
    """把某个格式标成 `failed`。

    **行要留在表里**（`content_path=None`）。删掉行看起来更干净，但那样报告中心
    只会显示「没有这份报告」—— 与「报告生成失败过」是完全不同的两件事，
    而后者才是用户需要知道的（B6 设计 §6 的 `REPORT_WRITE_FAILED`）。
    """
    return await upsert_report(
        session,
        assessment_id=assessment_id,
        fmt=fmt,
        title=title,
        content_path=None,
        size_bytes=None,
        status=ReportStatus.FAILED,
    )


async def writeback_score(
    session: AsyncSession, assessment_id: int, score: SecurityScore
) -> Assessment | None:
    """回写两个评分列（PRD §6：这两个列**只由 B6 写**）。

    ⚠️ **要按 id 再查一次行，而不是从 `ReportDraft` 里拿 ORM 对象。**
    `ReportDraft` 是可序列化的 DTO（测试会直接手搓它、将来也可能被缓存），
    它带上 ORM 实例就等于把 session 生命周期绑进了 DTO —— 那个耦合不会报错，
    它只会在某次「在别的 session 里用 draft」时炸 `DetachedInstanceError`。
    代价是一次主键查询（`session.get` 命中 identity map 时连 SQL 都不发）。

    返回 None 表示评估行已不存在（被并发删除）—— 调用方据此决定是否继续。
    """
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        logger.warning("回写评分失败：评估 #%s 已不存在", assessment_id)
        return None
    assessment.security_score = score.score
    assessment.security_grade = score.grade
    return assessment


def _value(fmt: ReportFormat | str) -> str:
    return str(getattr(fmt, "value", fmt))


__all__ = [
    "get_report",
    "list_reports",
    "mark_failed",
    "upsert_report",
    "writeback_score",
]
