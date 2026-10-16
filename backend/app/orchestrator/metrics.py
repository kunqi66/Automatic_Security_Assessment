"""容器资源采样（B3 设计 §2、§5.1）。

**为什么采样循环在 B3 而不是 B2**：B2 知道「怎么读一个容器的 CPU/内存」，
但不知道「现在哪个评估的哪个阶段正在跑」—— 那是编排层的知识。
所以 B2 提供 `stats(container_id)` 这一个取值动作（契约 1），
B3 负责定时驱动并把结果落到 `resource_metrics`。

> ⚠️ `models/observability.py` 里 `ResourceMetric` 的 docstring 写的是
> 「只有 B2 写这张表」，与本节冲突。**以 B3 设计 §5.1 为准**（那里明确列了
> `resource_metrics | 写`），模型 docstring 已过时。

**采样是旁路任务**：它的任何失败都不影响阶段执行。为了「记录 CPU 占用」
而让一次评估失败，是明显的本末倒置 —— 所以这里所有异常都就地吞掉并记日志。
"""

from __future__ import annotations

import asyncio
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import AsyncSessionLocal
from app.models.enums import StageName
from app.models.observability import ResourceMetric
from app.orchestrator.broadcaster import LogBroadcaster
from app.orchestrator.events import ResourceSample
from app.sandbox.ports import Sandbox

logger = get_logger(__name__)


class MetricsSampler:
    """阶段运行期的资源采样器。

    用法：阶段开始时 `start()`，阶段结束时 `stop()`。成对调用 ——
    每个阶段一个采样器实例，而不是一个评估一个：跨阶段的采样点意义不大，
    而且「哪个阶段吃掉了内存」这个问题只在按阶段切分时才有答案。
    """

    def __init__(
        self,
        sandbox: Sandbox,
        *,
        broadcaster: LogBroadcaster,
        interval_seconds: float | None = None,
    ) -> None:
        self._sandbox = sandbox
        self._broadcaster = broadcaster
        self._interval = interval_seconds or settings.metrics_sample_interval_seconds
        self._task: asyncio.Task[None] | None = None

    async def start(self, *, assessment_id: int, stage: StageName, container_id: str) -> None:
        if self._task is not None:
            # 说明上一个阶段忘了 stop。不抛异常：采样器是可观测性组件，
            # 为一个记账错误打断评估不划算 —— 但这是个真 bug，得让它响。
            logger.warning(
                "采样器重复启动（评估 %s / 阶段 %s），旧任务将被替换", assessment_id, stage
            )
            await self.stop()
        self._task = asyncio.create_task(
            self._loop(assessment_id=assessment_id, stage=stage, container_id=container_id),
            name=f"metrics:{assessment_id}:{stage}",
        )

    async def stop(self) -> None:
        """停止采样。**先取消再 await**，且吞掉 `CancelledError` ——
        吞掉是对的：这个协程是我们自己取消的，它的「被取消」是预期结果而不是异常。"""
        if self._task is None:
            return
        task, self._task = self._task, None
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001 —— 旁路任务不得把异常带上主流程
            logger.warning("采样任务退出时抛错：%s", exc)

    async def _loop(self, *, assessment_id: int, stage: StageName, container_id: str) -> None:
        while True:
            try:
                await self._sample_once(
                    assessment_id=assessment_id, stage=stage, container_id=container_id
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                # 单次采样失败不该终止整条采样循环：容器可能刚被销毁、
                # 远端 Docker 可能抖了一下。下一轮再试。
                logger.debug("采样失败（评估 %s / 阶段 %s）：%s", assessment_id, stage, exc)

            await asyncio.sleep(self._interval)

    async def _sample_once(
        self, *, assessment_id: int, stage: StageName, container_id: str
    ) -> None:
        cpu_percent, memory_mb = await self._sandbox.stats(container_id)
        recorded_at = datetime.now().astimezone()

        try:
            async with AsyncSessionLocal() as session:
                session.add(
                    ResourceMetric(
                        assessment_id=assessment_id,
                        stage=stage.value,
                        container_id=container_id,
                        cpu_percent=cpu_percent,
                        memory_mb=memory_mb,
                        # 显式给值而不是用 server_default：这里要记的是**采样时刻**，
                        # 而 server_default 记的是**插入时刻**。两者在写库被延迟时
                        # 会差出好几秒，而采样点的意义全在时间上。
                        recorded_at=recorded_at,
                    )
                )
                await session.commit()
        except SQLAlchemyError as exc:
            # 落库失败**不上抛**，但也不静默：SSE 那条路还能把数据送出去，
            # 用户仍能看到实时曲线，只是历史记录缺了一个点。
            logger.warning("资源指标落库失败（评估 %s）：%s", assessment_id, exc)

        await self._broadcaster.metric(
            assessment_id=assessment_id,
            stage=stage,
            sample=ResourceSample(
                container_id=container_id,
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                recorded_at=recorded_at,
            ),
        )


async def purge_old_metrics(session_factory=None) -> int:
    """清理过期采样（B3 设计 §8 待定项 7：30 天滚动清理）。返回删除行数。

    设计文档把这一条列在「待定项」里但给了倾向值，这里按倾向值实现。
    它没有被任何调度器调用 —— 需要时由运维手动跑或挂 cron。**如实标注**：
    一个「写了但从没被调用过」的清理函数，比没有更危险，
    因为它会让人以为磁盘有自动回收。
    """
    from datetime import timedelta

    from sqlalchemy import delete

    cutoff = datetime.now().astimezone() - timedelta(days=settings.metrics_retention_days)
    factory = session_factory or AsyncSessionLocal

    async with factory() as session:
        result = await session.execute(
            delete(ResourceMetric).where(ResourceMetric.recorded_at < cutoff)
        )
        await session.commit()
        return int(result.rowcount or 0)
