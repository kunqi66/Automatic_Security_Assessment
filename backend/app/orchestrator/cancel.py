"""协作式取消（B3 设计 §4.2、总纲 §4.2 与 D11）。

**为什么不用 `asyncio.Task.cancel()`**：它会在**任意** `await` 点抛出
`CancelledError`，而阶段执行里有大量 await 落在数据库事务中间。恰好在那里
被中断的后果是「`Finding` 提交了、它的 `TaintPath` 没提交」——
孤儿记录，而且因为阶段边界本应是原子提交点，这类损坏没有任何机制会去发现它。

协作式的代价是停止不即时：标志位写进去后，当前阶段要跑完才生效。
最坏情况是 `poc_verify` 里一个正在等待的探针，等它 30s 超时。
所以 API 对 stop 返回 `202 Accepted`，前端提示「正在停止」而不是「已停止」。

---

**为什么标志位在 Redis 而不是进程内存**：`POST /stop` 由 API 进程处理，
而编排执行在消费 worker 里 —— 两者不是同一个进程，甚至可能不是同一时刻的实例。
Redis 是唯一共享的、且带 TTL 能自动过期的地方（TTL 免去了「评估结束后忘了删标志」）。
"""

from __future__ import annotations

from redis.exceptions import RedisError

from app.core.logging import get_logger
from app.db.redis import get_redis

logger = get_logger(__name__)

CANCEL_KEY_PREFIX = "asa:cancel:"

#: 24 小时。远大于任何单次评估的耗时（`assessment_timeout_seconds` 默认 1 小时），
#: 所以正常流程里标志位总是被显式清除；这个 TTL 只是防「清除那一步也失败了」。
CANCEL_TTL_SECONDS = 24 * 60 * 60


def cancel_key(assessment_id: int) -> str:
    return f"{CANCEL_KEY_PREFIX}{assessment_id}"


async def request_cancel(assessment_id: int) -> None:
    """置位取消标志。

    **只置位，不打断任何协程** —— 见模块顶部说明。此函数返回后评估仍在跑。
    """
    client = get_redis()
    try:
        await client.set(cancel_key(assessment_id), "1", ex=CANCEL_TTL_SECONDS)
    except RedisError as exc:
        # 这里**必须**向上抛：调用方是 API，用户需要知道「停止请求没被受理」。
        # 与下面的 is_cancelled 不同 —— 那个是读，这个是写，语义不对称是对的。
        logger.error("写入取消标志失败（评估 %s）：%s", assessment_id, exc)
        raise


async def is_cancelled(assessment_id: int) -> bool:
    """阶段边界调用。

    Redis 不可达时**返回 False 并记警告**，而不是抛异常：

    - 抛异常 → 整个评估因为「读不到一个标志位」而死掉，这是把可用性问题
      升级成了功能问题；
    - 返回 True（保守取消）→ 一次瞬时抖动就能毁掉一个已经跑了半小时的评估。

    返回 False 的代价是「这次 stop 被忽略了」，用户重新点一次即可。
    **在一个『误取消代价远大于漏取消』的场景里，这是唯一合理的默认值。**
    """
    client = get_redis()
    try:
        return bool(await client.exists(cancel_key(assessment_id)))
    except RedisError as exc:
        logger.warning("读取取消标志失败（评估 %s），本次按未取消处理：%s", assessment_id, exc)
        return False


async def clear_cancel(assessment_id: int) -> None:
    """评估终结时清除标志位。

    不清的后果不是「下次会被误取消」（键里带 assessment_id），
    而是让一个已经结束的评估在 Redis 里留下垃圾直到 TTL 到期。属于卫生问题，
    所以这里失败只记日志、不上抛。
    """
    client = get_redis()
    try:
        await client.delete(cancel_key(assessment_id))
    except RedisError as exc:
        logger.warning("清除取消标志失败（评估 %s，将由 TTL 回收）：%s", assessment_id, exc)
