"""评估 worker 入口：`python -m app.worker`。

## 为什么是**独立进程**，而不是在 API 的 lifespan 里起一个后台任务

看着更省事的那条路（API 启动时 `asyncio.create_task(consume_forever())`）有三个
具体问题，每一个都会在演示时暴露：

1. **重启 API = 杀掉正在跑的评估**。改一行代码热重载，跑了十分钟的评估没了。
2. **SSE 会变得没有意义**。日志流之所以走 Redis Stream，前提就是
   「写的人和读的人不是一个进程」。合成一个进程后，直接推内存队列更简单 ——
   于是那套断线重放的设计就成了一段没人说得清为什么存在的代码。
3. **`--reload` 会起两个消费者**。uvicorn 的 reloader 是个父进程，
   它会连 lifespan 一起跑一遍。两个消费者抢同一个 group，
   `XAUTOCLAIM` 开始互相抢消息，症状是**同一个评估被跑两遍**。

## 启动顺序

```
日志 → 校验 Agent 注册完整性 → 连 MySQL → 恢复中断的评估 → 认领僵尸消息 → 消费
```

**校验注册排在连库之前**：漏注册一个 Agent 是纯代码错误，它不该等到
「数据库连不上」这种运维问题被排查完之后才暴露出来。这里让它第一个炸。

**恢复排在消费之前**：先把自己上次留下的烂摊子捡起来，再接受新任务。
反过来的话，新任务会和恢复出来的旧任务抢同一个「并发 1」的名额，
而且顺序不确定。
"""

from __future__ import annotations

import asyncio
import signal

from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.db.redis import close_redis
from app.db.session import dispose_engine, verify_connection
from app.llm.client import close_default_client
from app.orchestrator.engine import STAGE_ORDER, OrchestrationEngine
from app.orchestrator.queue import TaskQueue
from app.orchestrator.registry import assert_complete

logger = get_logger(__name__)


async def _shutdown(stop: asyncio.Event, queue: TaskQueue, engine: OrchestrationEngine) -> None:
    """收到 SIGINT/SIGTERM 后把当前这件事做完再退。

    **不立刻 `sys.exit`**：正在跑的评估会停在半个阶段上（容器还在，
    数据库里状态是 running）。虽然 `recover_on_boot` 下次能捡回来，
    但每次部署都留一条需要恢复的记录，恢复逻辑本身就成了常态路径 ——
    而它本该是异常路径。给 `consume_forever` 一个退出信号，让它跑完手上这条。
    """
    logger.info("收到停止信号，等待当前任务结束（不再领取新任务）…")
    stop.set()
    # 兜底：某些阶段（探针、git apply）可能卡在外部进程上，
    # 无限等下去会让 `docker stop` 变成 `docker kill`。超时后照常退出，
    # 剩下的事交给下次启动的 recover_on_boot。
    try:
        await asyncio.wait_for(queue.drain(), timeout=settings.worker_shutdown_grace_seconds)
    except TimeoutError:
        logger.warning(
            "等待超时（%.0fs），仍有阶段在执行；下次启动时会自动恢复",
            settings.worker_shutdown_grace_seconds,
        )


async def main() -> None:
    setup_logging()

    # ① 纯代码错误，第一个炸
    assert_complete(STAGE_ORDER)
    logger.info("Agent 注册完整：%s", ", ".join(s.value for s in STAGE_ORDER))

    # ② 存储类依赖不可降级
    await verify_connection()

    engine = OrchestrationEngine()
    queue = TaskQueue(engine)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(
                sig, lambda: asyncio.create_task(_shutdown(stop, queue, engine))
            )
        except NotImplementedError:
            # Windows 的 ProactorEventLoop 不支持 add_signal_handler。
            # 生产跑在 Linux 容器里，所以这里只是让开发机能起得来 ——
            # 开发时 Ctrl+C 走 KeyboardInterrupt 分支（下面捕获）。
            logger.debug("当前事件循环不支持信号处理器，改用 KeyboardInterrupt 退出")

    try:
        # ③ 恢复上次崩溃/重启留下的评估
        recovered = await engine.recover_on_boot()
        if recovered:
            logger.warning("恢复 %d 个中断的评估：%s", len(recovered), recovered)
            for assessment_id in recovered:
                await queue.enqueue(assessment_id)

        # ④ 认领僵尸消息（上个 worker 取走但没 XACK 的）
        await queue.ensure_group()
        claimed = await queue.claim_stale()
        if claimed:
            logger.warning("认领了 %d 条未确认的任务消息", claimed)

        logger.info(
            "%s 已就绪 | 队列=%s | group=%s | consumer=%s | 并发=1",
            settings.app_name,
            settings.task_queue_name,
            settings.task_consumer_group,
            settings.task_consumer_name,
        )

        # ⑤ 消费
        await queue.consume_forever(stop=stop)
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在退出…")
    finally:
        await close_default_client()
        await close_redis()
        await dispose_engine()
        logger.info("worker 已停止")


if __name__ == "__main__":
    asyncio.run(main())
