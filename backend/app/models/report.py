"""报告产物表（B6 报告汇编模块）。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import DDL_NOW, Base
from app.models.enums import ReportFormat, ReportStatus, sa_enum


class Report(Base):
    """报告从**数据库快照**生成，不读内存态（总纲 §9.3）—— 因此可重生成、可复现。"""

    __tablename__ = "reports"
    #: 同一评估的同一格式只应有一份 —— PDF 惰性生成时靠它做 upsert
    __table_args__ = (
        UniqueConstraint("assessment_id", "format", name="uk_report_assessment_format"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )

    format: Mapped[ReportFormat] = mapped_column(sa_enum(ReportFormat), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[ReportStatus] = mapped_column(
        sa_enum(ReportStatus), nullable=False, default=ReportStatus.GENERATING
    )

    #: 相对 workspace 根的 POSIX 路径；`generating` / `failed` 时为 NULL
    content_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: 摘要 JSON（等级、计数、TOP 漏洞），供报告中心列表直接展示，免去解析正文
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    generated_at: Mapped[datetime] = mapped_column(DateTime, server_default=DDL_NOW, nullable=False)

    assessment: Mapped[Assessment] = relationship(lazy="selectin")  # noqa: F821
