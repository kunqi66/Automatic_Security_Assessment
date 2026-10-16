"""审计留痕辅助。

**为什么这件事必须集中做**：需求 2.5.2 要求管理员可查系统审计日志，
而真正会改变结论的操作只有四类（人工复核漏洞 / 采纳补丁 / 改沙箱配置 / 改 LLM 参数）。
分散在各路由里手写，结果是漏掉一两个，且漏了不会有任何症状 ——
直到有人问「这条漏洞为什么被判成已排除」时才发现查无实据。
"""

from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.observability import AuditLog
from app.models.user import User


def client_ip(request: Request | None) -> str | None:
    """取客户端 IP。

    只信 `request.client`，**不解析 `X-Forwarded-For`** —— 那个头客户端可以随便伪造，
    在没有可信反代的前提下拿它当审计依据，等于让被审计者自己填来源。
    """
    if request is None or request.client is None:
        return None
    return request.client.host


def record(
    session: AsyncSession,
    *,
    user: User | None,
    action: str,
    target_type: str,
    target_id: int | None = None,
    detail: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditLog:
    """构造一条审计记录并挂到会话上（**不提交** —— 提交点由调用方与业务写操作共用）。

    与业务写操作放同一个事务是刻意的：审计记录写失败时，被审计的那次变更也应该回滚。
    否则会出现「改了但没留痕」——那正是审计最该防的情况。
    """
    entry = AuditLog(
        user_id=user.id if user else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        ip=client_ip(request),
    )
    session.add(entry)
    return entry
