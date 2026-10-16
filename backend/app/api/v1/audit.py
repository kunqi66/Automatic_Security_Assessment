"""审计日志查询（L1 接口层，需求 2.5.2）。

**只读，没有任何写接口**。审计表由 `app/db/audit.py` 的 `record()` 在业务事务里
顺带写入 —— 给它开一个「手动补一条」的接口，等于让被审计者自己填证据。
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import DBSession, Permission, require
from app.models.observability import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogOut
from app.schemas.common import Page

router = APIRouter(tags=["审计"])

Auditor = Annotated[User, Depends(require(Permission.AUDIT_VIEW))]


@router.get(
    "/admin/audit-logs",
    response_model=Page[AuditLogOut],
    summary="审计日志",
)
async def list_audit_logs(
    session: DBSession,
    _: Auditor,
    action: Annotated[str | None, Query(description="如 vulnerability.review")] = None,
    target_type: Annotated[str | None, Query()] = None,
    target_id: Annotated[int | None, Query()] = None,
    user_id: Annotated[int | None, Query()] = None,
    since: Annotated[datetime | None, Query(description="起始时间（含）")] = None,
    until: Annotated[datetime | None, Query(description="结束时间（不含）")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Page[AuditLogOut]:
    conditions = []
    if action:
        conditions.append(AuditLog.action == action)
    if target_type:
        conditions.append(AuditLog.target_type == target_type)
    if target_id is not None:
        conditions.append(AuditLog.target_id == target_id)
    if user_id is not None:
        conditions.append(AuditLog.user_id == user_id)
    if since is not None:
        conditions.append(AuditLog.created_at >= since)
    if until is not None:
        # 左闭右开。用 `<=` 的话，「查今天」会把明天 00:00:00.000 的那条也带进来，
        # 而调用方几乎总是按「天」来问。
        conditions.append(AuditLog.created_at < until)

    total = await session.scalar(select(func.count()).select_from(AuditLog).where(*conditions))
    rows = (
        (
            await session.execute(
                select(AuditLog)
                .where(*conditions)
                .order_by(AuditLog.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )

    return Page[AuditLogOut](
        items=[AuditLogOut.model_validate(row) for row in rows],
        total=int(total or 0),
        page=page,
        page_size=page_size,
    )
