"""评估与阶段 DTO（B3）。"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.models.enums import AssessmentStatus, SecurityGrade, StageName, StageStatus
from app.schemas.common import ORMModel


class StageStateOut(ORMModel):
    stage: StageName
    status: StageStatus
    started_at: datetime | None
    finished_at: datetime | None
    #: 失败**或 skip** 的原因。skip 是降级不是错误，前端用黄色提示条而非红色报错。
    note: str | None


class AssessmentOut(ORMModel):
    id: int
    project_id: int
    #: 派生字段：列表页要显示项目名，让前端再打一次 /projects/{id} 是浪费
    project_name: str
    status: AssessmentStatus
    current_stage: StageName | None
    progress: int
    security_grade: SecurityGrade | None
    stages: list[StageStateOut]
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class AssessmentCreate(BaseModel):
    """`POST /projects/{id}/assessments` 无 body —— 项目 id 来自路径。

    保留此类是为将来可能出现的「只跑部分阶段」留位；当前为空。
    """


class ResourceSampleOut(ORMModel):
    """容器资源采样点（`GET /assessments/{id}/metrics`）。

    SSE 只推增量，指标曲线的**首屏历史**必须由这个 REST 端点提供（总纲 §6.3）。
    """

    #: 采样时刻。注意这里对外叫 `ts`、表列叫 `recorded_at` ——
    #: 这是给前端画曲线用的紧凑形状，字段名沿用前端既有的 `ResourceSample`。
    ts: datetime
    cpu_percent: float
    memory_mb: float
