"""观测层：资源指标与审计日志（总纲 §7.2，滚动清理）。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import DDL_NOW, Base


class ResourceMetric(Base):
    """容器资源采样。

    **写入方是 B3 的 `MetricsSampler`**（不是 B2）：B2 的 `SandboxService.stats()`
    只返回 `tuple[cpu_percent, memory_mb]` 这个纯值，**不碰数据库** ——
    「沙箱模块不认识 ORM」是刻意的边界，它让 B2 可以在没有 MySQL 的情况下单测。

    采样与落库由 `app/orchestrator/metrics.py` 负责，SSE 推送由
    `LogBroadcaster.metric()` 负责。两者**都要有**：数据库里的是「回看历史」，
    SSE 推的是「此刻在涨」。只有前者则页面刷新才更新，只有后者则刷新后曲线清空。
    """

    __tablename__ = "resource_metrics"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=DDL_NOW, nullable=False, index=True
    )


class AuditLog(Base):
    """操作审计 —— 谁在何时对哪个资源做了什么。

    **会改变结论的操作必须留痕**：人工复核漏洞、采纳补丁、改沙箱配置、改 LLM 参数。
    尤其是人工复核：它是唯一被允许覆盖引擎结论的入口，不留痕就无法解释
    「这条为什么被判成已排除」。
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    #: 如 vulnerability.review / patch.accept / sandbox_config.update / llm_config.update
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: 变更前后等上下文，便于追责与回放
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=DDL_NOW, nullable=False, index=True
    )
