"""B3 多 Agent 编排引擎（L2 编排层）。

**本包是系统里唯一知道「流程」的地方**：五个阶段谁先谁后、失败了怎么办、
中断了怎么续。五个 Agent、B1–B6 六个领域模块，都不含这些知识。

`__init__` **刻意不 import `engine` / `queue`**：那两个模块会拉起
沙箱、Redis、各 Agent 的依赖，而 `events` / `context` 里的类型
（`LogEvent`、`AssessmentContext`）是被上层频繁引用的轻量对象。
把重的和轻的混在一个 `__init__` 里，会让「只想用一下 `LogEvent`」的调用方
连带把整个运行时就拖进来。

需要引擎时按模块路径 import：`from app.orchestrator.engine import OrchestrationEngine`。
"""

from app.orchestrator.broadcaster import LogBroadcaster
from app.orchestrator.context import (
    CONTEXT_SCHEMA_VERSION,
    AssessmentContext,
    ContextDecodeError,
    FindingRef,
    StageSnapshot,
)
from app.orchestrator.events import LogEvent, LogLevel, ResourceSample, StageRecord, stream_key
from app.orchestrator.views import ProgressView, ResumeOutcome

__all__ = [
    "CONTEXT_SCHEMA_VERSION",
    "AssessmentContext",
    "ContextDecodeError",
    "FindingRef",
    "LogBroadcaster",
    "LogEvent",
    "LogLevel",
    "ProgressView",
    "ResourceSample",
    "ResumeOutcome",
    "StageRecord",
    "StageSnapshot",
    "stream_key",
]
