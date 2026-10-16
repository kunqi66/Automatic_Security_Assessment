"""沙箱配置表（需求 2.5.3 沙箱配置页）。"""

from __future__ import annotations

from sqlalchemy import Boolean, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.models.enums import NetworkPolicy, sa_enum


class SandboxConfig(Base, TimestampMixin):
    __tablename__ = "sandbox_configs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    #: 基础镜像，如 asa/sandbox-base:latest
    base_image: Mapped[str] = mapped_column(String(255), nullable=False)

    #: **默认 internal**：仅回环 + 任务内网，禁出站。这不是性能选项，是安全模型的基石。
    network_policy: Mapped[NetworkPolicy] = mapped_column(
        sa_enum(NetworkPolicy), nullable=False, default=NetworkPolicy.INTERNAL
    )

    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    #: 界面上暴露但默认 1（总纲 §8.1）：2 vCPU 下并发只会让所有任务都变慢，且撞 OOM。
    #: 把资源约束变成透明的事实，而不是隐藏的瓶颈。
    max_concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    cpu_limit: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    memory_limit_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=1024)

    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
