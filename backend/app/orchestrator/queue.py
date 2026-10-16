"""Redis Stream 任务队列（B3 设计 §2、§5.2、T7）。

**为什么不用 Celery**（T7）：Celery 的价值在于多进程并行与跨机器分发，
而本系统的并发度恒为 1（T3）—— 2 vCPU 加一个常驻 Milvus，并发只会撞 OOM。
引入 Celery 意味着一个 broker 抽象、一套 worker 生命周期、一份序列化协议，
换来的能力一条也用不上。Stream 自带消费确认（`XACK`）与待处理列表，
断点续跑需要的原语它都有。

**代价**（如实写在设计文档里，这里也是）：重试与死信要自己写。
下面 `_handle_failure` 那段就是那个代价。

---

**关于 `>` 与待处理消息**：`XREADGROUP` 用 `>` 只投递**从未投递过**的消息。
worker 在 `XACK` 之前崩溃的话，那条消息会永远留在待处理列表里，
用 `>` 再也读不到 —— 表现为「任务凭空消失了，日志里什么都没有」。
所以 `claim_stale()` 是必需的，不是可选优化：它用 `XAUTOCLAIM` 把
空闲超过阈值的待处理消息抢回来重投。没有它，本模块的「可续跑」是假的。
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from redis.exceptions import RedisError, ResponseError

from app.core.config import settings
from app.core.logging import get_logger
from app.db.redis import get_redis

if TYPE_CHECKING:
    from app.orchestrator.engine import OrchestrationEngine

logger = get_logger(__name__)

RETRY_KEY_PREFIX = "asa:retry:"

#: 待处理消息的空闲阈值：超过它说明持有它的 worker 已经不在了。
#: 取值要大于任何单次评估的耗时量级吗？**不需要** —— `XAUTOCLAIM` 抢的是
#: 整条消息的处理权，而我们的消费者是单线程串行消费，一条消息被处理期间
#: 消费者根本不会来读下一条。所以这里只防「worker 崩了」，取一个远大于
#: 单次 Redis 往返、又远小于人愿意等的值即可。
STALE_CLAIM_IDLE_MS = 60_000


def retry_key(assessment_id: int) -> str:
    return f"{RETRY_KEY_PREFIX}{assessment_id}"


class TaskQueue:
    """单 worker 串行消费。"""

    def __init__(
        self,
        engine: OrchestrationEngine,
        *,
        stream: str | None = None,
        group: str | None = None,
        consumer: str | None = None,
    ) -> None:
        self._engine = engine
        self._stream = stream or settings.task_queue_name
        self._dead = settings.task_queue_dead_name
        self._group = group or settings.task_consumer_group
        #: 消费者名做成可注入的形参但本期恒为一个（设计 §8 待定项 11）。
        #: 未来要扩容时，这里得先解决「一条消息在同一时刻只被一个消费者处理」
        #: 之外的问题 —— 编排引擎是单实例内存态（`LogBroadcaster` 的摘要缓冲），
        #: 多消费者会让 `log_excerpt` 落在错误的进程里。
        self._consumer = consumer or settings.task_consumer_name
        #: 「当前没有消息在处理」的信号。`drain()` 等它。
        #: 由 `_process` 的 finally 置位 —— 无论是正常返回还是抛异常，
        #: 都要置位，否则一次失败会让 worker 永远停不下来。
        self._idle = asyncio.Event()
        self._idle.set()

    # ------------------------------------------------------------------
    # 生产
    # ------------------------------------------------------------------

    async def enqueue(self, assessment_id: int) -> str:
        """投递一个评估任务，返回消息 id。"""
        client = get_redis()
        return await client.xadd(self._stream, {"assessment_id": str(assessment_id)})

    async def ensure_group(self) -> None:
        """建消费组。幂等。

        `mkstream=True`：流不存在时一并建出来。不加的话首次部署会因为
        「流还没有任何消息」而建组失败，然后启动就报错 —— 一个纯粹由
        「还没有人用过」引起的启动失败。
        """
        client = get_redis()
        try:
            await client.xgroup_create(self._stream, self._group, id="0", mkstream=True)
            logger.info("已创建消费组 %s@%s", self._group, self._stream)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
            # 已存在是正常路径，不是错误

    # ------------------------------------------------------------------
    # 消费
    # ------------------------------------------------------------------

    async def consume_forever(self, *, stop: asyncio.Event | None = None) -> None:
        """消费循环。

        每条消息处理完都 `XACK`，无论成功失败 —— 失败的消息走
        `_handle_failure` 自己的重投路径。若失败时**不** XACK，
        它会一直挂在待处理列表里，被 `claim_stale` 反复抢回来，形成死循环。

        `stop` 置位后，**当前这条会跑完**再退出。这是刻意的：在阶段中间
        硬取消会把评估留在半个状态上（容器还在、库里写着 running），
        而恢复逻辑本该处理异常，不该变成每次部署的常态路径。
        代价是最多 `block_ms`（默认 5s）的退出延迟。
        """
        await self.ensure_group()
        await self.claim_stale()

        while stop is None or not stop.is_set():
            try:
                await self.consume_once()
            except asyncio.CancelledError:
                logger.info("队列消费已停止")
                raise
            except RedisError as exc:
                # Redis 是存储类依赖，不可降级 —— 但也不该让消费循环直接退出。
                # 退出的后果是「worker 进程还活着，但再也不处理任何任务」，
                # 这比崩溃更难发现。所以这里退避重试，让故障留在日志里。
                logger.error("读取任务队列失败，5 秒后重试：%s", exc)
                await asyncio.sleep(5)

        logger.info("队列消费循环已退出")

    async def drain(self) -> None:
        """等手上这条消息处理完。供 `worker._shutdown` 调用。"""
        await self._idle.wait()

    async def consume_once(self, *, block_ms: int | None = None) -> bool:
        """取一条并处理。返回是否真的处理了消息（供测试驱动）。

        `block_ms` 默认取 `settings.worker_poll_block_ms` —— **不要再写死一个
        字面量**。它与 Redis 客户端的 `socket_timeout` 是一对必须满足大小关系的
        参数（阻塞时长必须小于套接字超时），写死在这里就会和配置里那个值漂移，
        而漂移的症状是 worker 空闲时刷 `Timeout reading from`（见 config 里
        那两个字段的说明）。测试仍可显式传一个更小的值来加速。
        """
        if block_ms is None:
            block_ms = settings.worker_poll_block_ms
        client = get_redis()
        resp = await client.xreadgroup(
            self._group,
            self._consumer,
            {self._stream: ">"},
            count=1,
            block=block_ms,
        )
        if not resp:
            return False

        for _stream_name, messages in resp:
            for msg_id, fields in messages:
                await self._process(msg_id, fields)
        return True

    async def _process(self, msg_id: str, fields: dict[str, Any]) -> None:
        self._idle.clear()
        try:
            await self._process_inner(msg_id, fields)
        finally:
            # finally 而不是正常路径：`_handle_failure` 里也可能抛
            # （比如死信队列也写不进去），那时若没置位，`drain()` 会永远等下去，
            # 于是 `docker stop` 退化成 `docker kill`。
            self._idle.set()

    async def _process_inner(self, msg_id: str, fields: dict[str, Any]) -> None:
        client = get_redis()
        raw = fields.get("assessment_id")
        try:
            assessment_id = int(raw)
        except (TypeError, ValueError):
            logger.error("任务消息 %s 的 assessment_id 不合法（%r），直接丢弃", msg_id, raw)
            await client.xack(self._stream, self._group, msg_id)
            return

        try:
            await self._engine.start(assessment_id)
        except Exception as exc:  # noqa: BLE001 —— 消费层要接住一切，见 _handle_failure
            await self._handle_failure(msg_id, assessment_id, exc)
            return

        await client.xack(self._stream, self._group, msg_id)
        await client.delete(retry_key(assessment_id))

    async def _handle_failure(self, msg_id: str, assessment_id: int, exc: Exception) -> None:
        """重试或进死信。

        退避用 `asyncio.sleep` 直接睡 —— 看起来粗暴，但并发度恒为 1（T3），
        这个循环本来就是串行的，睡在这里不会耽误任何别的工作。
        换成「带可见性延迟的重投」要自己在消息里编码 `retry_after`，
        并在每次读取时过滤未到期的消息，复杂度和收益不成比例。
        """
        client = get_redis()
        attempts = await client.incr(retry_key(assessment_id))
        await client.expire(retry_key(assessment_id), 24 * 3600)

        if attempts > settings.task_max_retries:
            await client.xadd(
                self._dead,
                {
                    "assessment_id": str(assessment_id),
                    "attempts": str(attempts),
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
            logger.error(
                "评估 %s 重试 %d 次仍失败，已转入死信队列 %s", assessment_id, attempts, self._dead
            )
            await self._engine.fail(
                assessment_id,
                f"任务重试 {attempts} 次仍失败：{type(exc).__name__}: {exc}",
                remediation="已转入死信队列，排查后可用 resume 手动续跑",
            )
            await client.xack(self._stream, self._group, msg_id)
            return

        delay = settings.task_retry_backoff_seconds * (2 ** (attempts - 1))
        logger.warning(
            "评估 %s 第 %d 次失败（%s），%.1fs 后重投", assessment_id, attempts, exc, delay
        )
        await asyncio.sleep(delay)
        # 先投新的再 XACK 旧的：反过来的话，两步之间崩溃就彻底丢了任务。
        # 正过来的代价是极端情况下同一条任务被处理两次 —— 而阶段是幂等的
        # （`_mark_stage_completed` 覆盖写、Agent 重跑覆盖同一批 finding），
        # **宁可重复，不可丢失**。
        await client.xadd(self._stream, {"assessment_id": str(assessment_id)})
        await client.xack(self._stream, self._group, msg_id)

    # ------------------------------------------------------------------
    # 崩溃恢复
    # ------------------------------------------------------------------

    async def claim_stale(self) -> int:
        """把空闲过久的待处理消息抢回来重投。返回抢回条数。

        见模块顶部：没有这一步，「崩溃后任务不丢」是假的。
        """
        client = get_redis()
        try:
            _cursor, claimed, _deleted = await client.xautoclaim(
                self._stream,
                self._group,
                self._consumer,
                min_idle_time=STALE_CLAIM_IDLE_MS,
                start_id="0-0",
                count=100,
            )
        except ResponseError as exc:
            # `XAUTOCLAIM` 需要 Redis 6.2+。老版本上退化成记一条日志：
            # 此时崩溃恢复能力降级为「靠 recover_on_boot 兜底」，
            # 而那一条路径是覆盖启动场景的。
            logger.warning("XAUTOCLAIM 不可用（需要 Redis 6.2+），跳过待处理消息回收：%s", exc)
            return 0

        for msg_id, fields in claimed or []:
            if not fields:
                # 消息已被 XDEL 删除，XAUTOCLAIM 会返回空字段
                await client.xack(self._stream, self._group, msg_id)
                continue
            logger.warning("回收僵尸任务 %s（上一个 worker 未确认）", msg_id)
            await self._process(msg_id, fields)
        return len(claimed or [])
