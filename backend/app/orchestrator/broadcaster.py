"""日志/阶段/指标事件广播（B3 设计 §3.1、§5.2）。

**用 Redis Stream 而不是 Pub/Sub**（总纲 §6.3）：Pub/Sub 是即发即弃的，
没有历史。SSE 连接断开的那几秒里发布的日志**永久丢失** —— 而断线恰恰是
用户最需要看日志的时候（比如他刚从后台切回来，或者网络抖了一下）。
Stream 保留历史，浏览器重连时 `EventSource` 自动带上 `Last-Event-ID`，
服务端 `XRANGE <那个id> +` 就能把断线期间的补齐。

代价是内存：靠 `XTRIM MAXLEN ~` 兜底。特意用近似裁剪（`~`）——
Redis 按节点粒度删除，比精确裁剪快得多，代价是实际长度可能略微超过设定值。
日志不是账本，不需要精确。

**日志不落全量表**：只在阶段结束时把最近若干行摘要写进
`assessment_stages.log_excerpt`。需求要的是「实时终端日志流」，
而 19G 磁盘上做全量日志持久化是纯负担。
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime

from redis.exceptions import RedisError

from app.core.config import settings
from app.core.logging import get_logger
from app.db.redis import get_redis
from app.models.enums import StageName
from app.orchestrator.events import LogEvent, LogLevel, ResourceSample, StageRecord, stream_key

logger = get_logger(__name__)

#: 一条摘要行的近似开销（JSON 引号、时间戳、级别前缀）。
#: 估算而非精确：它的唯一用途是给环形缓冲一个字节预算，
#: 精确统计的复杂度换不来任何东西。
_LINE_OVERHEAD = 32


class LogBroadcaster:
    """事件出口。

    **实例级持有 `log_excerpt` 的环形缓冲**：一个评估从头到尾由同一个
    `OrchestrationEngine` 实例驱动，所以缓冲放实例上就够了。
    放进 Redis 反而要处理「谁清理」的问题 —— 而它的生命周期恰好等于一次评估。
    """

    def __init__(self, *, maxlen: int | None = None) -> None:
        self._maxlen = maxlen or settings.log_stream_maxlen
        #: (assessment_id, stage) -> 最近若干行。**按阶段分桶**：
        #: 阶段结束时写的是「这个阶段」的摘要，混在一起就得再按阶段过滤一遍。
        self._excerpts: dict[tuple[int, StageName], deque[str]] = defaultdict(deque)
        self._excerpt_bytes: dict[tuple[int, StageName], int] = defaultdict(int)

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------

    async def emit(self, event: LogEvent) -> None:
        """把一条事件 `XADD` 进 `log:{assessment_id}`。"""
        client = get_redis()
        try:
            await client.xadd(
                stream_key(event.assessment_id),
                {"data": event.model_dump_json()},
                maxlen=self._maxlen,
                approximate=True,
            )
        except RedisError as exc:
            # **广播失败不阻断评估**。日志是可观测性，不是正确性 ——
            # 让「日志写不进 Redis」把一次跑了二十分钟的评估判死，是本末倒置。
            # 事件本身仍在本地 logger 里留有痕迹，不至于完全丢失。
            logger.warning(
                "广播事件失败（评估 %s / %s）：%s", event.assessment_id, event.stage, exc
            )

    async def log(
        self,
        *,
        assessment_id: int,
        stage: StageName,
        level: LogLevel,
        message: str,
        extra: dict[str, object] | None = None,
    ) -> None:
        """Agent 的 `emit()` 落到这里。"""
        event = LogEvent(
            type="log",
            assessment_id=assessment_id,
            stage=stage,
            level=level,
            message=message,
            extra=dict(extra or {}),
            ts=datetime.now().astimezone(),
        )
        self._append_excerpt(assessment_id, stage, level, message)
        await self.emit(event)

    async def stage_changed(self, *, assessment_id: int, record: StageRecord) -> None:
        """阶段状态变更。

        带的是**完整快照**而不是「变了」这个信号：断线重连的浏览器拿到任意
        一条 stage 事件就能就地重建进度条，不必再发一次 REST 查询。
        """
        await self.emit(
            LogEvent(
                type="stage",
                assessment_id=assessment_id,
                stage=record.stage,
                snapshot=record,
                ts=datetime.now().astimezone(),
            )
        )

    async def metric(self, *, assessment_id: int, stage: StageName, sample: ResourceSample) -> None:
        await self.emit(
            LogEvent(
                type="metric",
                assessment_id=assessment_id,
                stage=stage,
                metric=sample,
                ts=datetime.now().astimezone(),
            )
        )

    # ------------------------------------------------------------------
    # 摘要缓冲
    # ------------------------------------------------------------------

    def _append_excerpt(
        self, assessment_id: int, stage: StageName, level: LogLevel, message: str
    ) -> None:
        """维护环形缓冲。按**行数**和**字节数**双重裁剪。

        两个上限都要有：只看行数挡不住「一行 10MB 的堆栈」，
        只看字节数挡不住「十万行短消息」。
        """
        key = (assessment_id, stage)
        line = f"[{level.value.upper()}] {message}"
        buf = self._excerpts[key]
        buf.append(line)
        self._excerpt_bytes[key] += len(line.encode("utf-8")) + _LINE_OVERHEAD

        while buf and (
            len(buf) > settings.log_excerpt_max_lines
            or self._excerpt_bytes[key] > settings.log_excerpt_max_bytes
        ):
            dropped = buf.popleft()
            self._excerpt_bytes[key] -= len(dropped.encode("utf-8")) + _LINE_OVERHEAD

    def excerpt(self, assessment_id: int, stage: StageName) -> str:
        """取出该阶段的摘要，供写进 `assessment_stages.log_excerpt`。"""
        return "\n".join(self._excerpts.get((assessment_id, stage), ()))

    def drop_excerpt(self, assessment_id: int, stage: StageName) -> None:
        """阶段摘要已落库后释放缓冲。

        不释放的后果：一个 worker 跑过几十次评估后，内存里攒着所有评估所有阶段的
        摘要，而它们早就落库了 —— 这是那种「跑一天才显形」的泄漏。
        """
        self._excerpts.pop((assessment_id, stage), None)
        self._excerpt_bytes.pop((assessment_id, stage), None)
