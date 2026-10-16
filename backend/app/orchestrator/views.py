"""引擎对外返回的只读视图（B3 设计 §3.1）。

`ProgressView` 会被 `GET /api/v1/assessments/{id}` 直接序列化给前端，
所以字段名就是前端要用的名字，中间不做映射层。

**阶段的 DTO 复用 `events.StageRecord`**（而不是再定义一个 `StageView`）：
两者形状完全相同不是巧合 —— 前端用同一个组件渲染「实时推来的阶段状态」
和「刷新页面后拉到的阶段列表」，它们本来就必须长得一样。
定义两个类，就等于给自己留了一个「改了其中一个忘了另一个」的机会，
而症状是「刷新之后进度条和刚才看到的不一致」。
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from app.models.assessment import AssessmentStage
from app.models.enums import AssessmentStatus, StageName
from app.orchestrator.events import StageRecord


class ProgressView(BaseModel):
    """一次评估的完整进度快照。"""

    assessment_id: int
    project_id: int
    status: AssessmentStatus
    current_stage: StageName | None = None
    #: 0–100。折算规则见 `engine.stage_progress`
    progress: int = 0
    stages: list[StageRecord] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    #: 失败原因（§9.2 的四要素载荷序列化后的文本）。**只在 `failed` 时有值。**
    error_message: str | None = None


class ResumeOutcome(StrEnum):
    """`resume()` 的结果。**不是一个布尔值**，因为调用方对几种情况的反应不同：
    `NOT_FOUND` 要报 404，`ALREADY_TERMINAL` 要提示「已经跑完了」，
    而 `RESUMED` 要开始等 —— 压成 True/False 就把这些区别丢了。"""

    RESUMED = "resumed"
    #: 已经 `completed` / `failed`，无需续跑
    ALREADY_TERMINAL = "already_terminal"
    #: 所有阶段都是 `completed`（状态却没落成 `completed`，说明上次崩在最后一步）
    NOTHING_TO_DO = "nothing_to_do"
    NOT_FOUND = "not_found"


def to_stage_record(row: AssessmentStage) -> StageRecord:
    """ORM 行 → 视图。

    `duration_ms` 是**算出来的**而不是存的：存一份就要维护它和
    `started_at`/`finished_at` 的一致性，而这两对值在「阶段正在跑」时
    必然不一致（`finished_at` 还是 None）。算出来的值不会说谎。
    """
    duration_ms: int | None = None
    if row.started_at is not None and row.finished_at is not None:
        duration_ms = int((row.finished_at - row.started_at).total_seconds() * 1000)

    return StageRecord(
        stage=row.stage,
        status=row.status,
        started_at=row.started_at,
        finished_at=row.finished_at,
        duration_ms=duration_ms,
        note=row.note,
    )
