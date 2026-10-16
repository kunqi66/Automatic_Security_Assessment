"""审计日志 DTO。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas.common import ORMModel


class AuditLogOut(ORMModel):
    id: int
    user_id: int | None
    #: 如 vulnerability.review / patch.accept / sandbox_config.update
    action: str
    target_type: str
    target_id: int | None
    detail: dict[str, Any] | None
    ip: str | None
    created_at: datetime
