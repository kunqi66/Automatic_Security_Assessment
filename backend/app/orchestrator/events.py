"""广播事件载荷（B3 设计 §3.3）。

这些对象会被 `model_dump_json()` 后 `XADD` 进 Redis Stream，SSE 端点再 `XRANGE`
读出来原样转发给浏览器。因此有三条硬要求：

1. **必须可 JSON 序列化**。任何 `datetime` 都会由 Pydantic 转成 ISO 字符串，
   但任何自定义对象都不会 —— 加字段时要先想清楚它能不能进 Stream。
2. **必须是自足的**。SSE 是单向流，浏览器收到一个 `stage` 事件时无法回头问
   「这个阶段现在是什么状态」，所以事件里必须带完整快照（`StageRecord`），
   而不是「阶段变了」这种需要再查一次的信号。
3. **字段名要能直接喂给前端**。前端不做映射层，这里写什么它用什么。
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.enums import StageName, StageStatus


class LogLevel(StrEnum):
    """日志级别。**刻意只有四级**：加 `TRACE` 对本系统没有信息量，
    而级别越多，前端着色规则和维护成本越高。"""

    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class StageRecord(BaseModel):
    """阶段的**完整状态快照**（不是增量）。

    `stage` 事件里带的是它，而不是 `{"stage": "recon", "status": "completed"}` ——
    断线重连的浏览器拿到任何一个事件，都能就地重建整条进度条，
    不需要额外发一次 REST 查询。这是「SSE 只承载增量、快照走 REST」原则的例外，
    而且是有意的例外：阶段事件本身就是快照，没有增量可言。
    """

    stage: StageName
    status: StageStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
    #: 失败原因或降级原因。**两者共用一个字段**：`skipped` 不是错误（总纲 §9.1 L3），
    #: 但用户需要看到「为什么没跑」，所以它也要有地方写。
    note: str | None = None


class ResourceSample(BaseModel):
    """一次容器资源采样。"""

    container_id: str
    cpu_percent: float
    memory_mb: float
    recorded_at: datetime


class LogEvent(BaseModel):
    """Stream 里的一条消息，三种类型共用一个信封。

    三种事件走同一个 Stream 而不是三条，是因为 SSE 只推一条连接 ——
    分成三条流的话，服务端要做多流合并与时序对齐，而 Redis 的 `XRANGE`
    只保证单流有序。合并后 `ts` 就是唯一的时序依据。
    """

    type: Literal["log", "stage", "metric"]
    assessment_id: int
    stage: StageName

    #: type=log 时有值
    level: LogLevel | None = None
    message: str | None = None
    #: 结构化附加信息（如 `{"file": "a.py", "line": 12}`）。
    #: **只放可 JSON 序列化的标量**，放进去的东西前端会直接渲染。
    extra: dict[str, Any] = Field(default_factory=dict)

    #: type=stage 时有值 —— 完整快照，见 StageRecord 的说明
    snapshot: StageRecord | None = None
    #: type=metric 时有值
    metric: ResourceSample | None = None

    ts: datetime


def stream_key(assessment_id: int) -> str:
    """日志流键。**一次评估一条流**，不是全局一条。

    全局单流的后果是 `XRANGE` 读取时要按 `assessment_id` 过滤，
    而 `XTRIM` 是按条数裁剪的 —— 一个话痨的评估会把别人的日志挤掉。
    分流的代价只是键多一些，Redis 的键是廉价的。
    """
    return f"log:{assessment_id}"
