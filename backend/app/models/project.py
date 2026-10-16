"""项目表（B1 项目管理模块）。"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import ProjectStatus, sa_enum


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)

    source_type: Mapped[str] = mapped_column(String(16), nullable=False)  # git | upload
    source_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: 指向密钥存储的引用，**不落明文口令**（PRD §6）
    credential_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)

    #: 控制面源码工作区，**相对 workspace_root 的 POSIX 路径**（总纲 §7.4）。
    #: 绝对路径由配置解析，绝不入库 —— 否则报告里的路径换台机器就读不了。
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    #: B1 只建列不填值，由 recon 阶段回填（B1 不负责技术栈识别）
    tech_stack: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    total_loc: Mapped[int | None] = mapped_column(Integer, nullable=True)

    status: Mapped[ProjectStatus] = mapped_column(
        sa_enum(ProjectStatus), nullable=False, default=ProjectStatus.CREATED, index=True
    )
    #: 建档失败原因，**必须自带 remediation 指引**（总纲 §9.2）
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    assessments: Mapped[list[Assessment]] = relationship(  # noqa: F821
        back_populates="project", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<Project id={self.id} name={self.name!r} status={self.status}>"
