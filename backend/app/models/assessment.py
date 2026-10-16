"""评估与阶段持久化（B3 编排引擎的载体）。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import AssessmentStatus, SecurityGrade, StageName, StageStatus, sa_enum


class Assessment(Base, TimestampMixin):
    """一次评估 = 一个 project 的一次运行。"""

    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )

    status: Mapped[AssessmentStatus] = mapped_column(
        sa_enum(AssessmentStatus), nullable=False, default=AssessmentStatus.CREATED, index=True
    )
    current_stage: Mapped[StageName | None] = mapped_column(sa_enum(StageName), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: 由 B6 `scoring.py` 在 report_gen 阶段写回，不由 LLM 产出（总纲 §8.5 L1）
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    security_grade: Mapped[SecurityGrade | None] = mapped_column(
        sa_enum(SecurityGrade), nullable=True
    )

    #: 真正开跑的时刻；`created_at` 是行创建时刻。两者不同义。
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: 汇总统计快照（各severity计数等），供大盘快速读取，免去每次聚合
    stats: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    project: Mapped[Project] = relationship(back_populates="assessments")  # noqa: F821
    stages: Mapped[list[AssessmentStage]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="AssessmentStage.id",
    )

    def __repr__(self) -> str:
        return f"<Assessment id={self.id} status={self.status} stage={self.current_stage}>"


class AssessmentStage(Base, TimestampMixin):
    """阶段级持久化 —— **断点续跑的全部依据**。

    续跑时已 `completed` 的阶段直接反序列化 `result_ref`，不重跑（总纲 §9.3）。
    """

    __tablename__ = "assessment_stages"
    __table_args__ = (UniqueConstraint("assessment_id", "stage", name="uk_assessment_stage"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )

    stage: Mapped[StageName] = mapped_column(sa_enum(StageName), nullable=False)
    status: Mapped[StageStatus] = mapped_column(
        sa_enum(StageStatus), nullable=False, default=StageStatus.PENDING
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    #: 阶段产出快照（序列化后的 AssessmentContext 片段）—— 续跑的基石
    result_ref: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    log_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: 失败或 skip 的原因。**不叫 error_message**：skip 是降级而非错误（总纲 §9.1 L3）
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    assessment: Mapped[Assessment] = relationship(back_populates="stages")

    def __repr__(self) -> str:
        return f"<AssessmentStage {self.stage}={self.status}>"
