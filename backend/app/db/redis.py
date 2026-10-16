"""Redis 客户端与跨进程锁。

用 **db=3**（`settings.redis_db`）：阿里云那台 Redis 上 6379 已被其它服务占用，
本系统必须与它们隔离，否则 `FLUSHDB` 之类的运维动作会互相误伤。

任务队列与日志流（B3）也用这个客户端，见 `core/events.py`。
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_client: Redis | None = None

#: 比较后删除：只有锁的持有者才能释放它。
#:
#: 朴素写法 `GET` 再 `DEL` 之间有一个窗口：锁在这期间因 TTL 到期被别人拿到，
#: 原来的持有者醒来后 `DEL` 掉的是**别人的锁**。Lua 脚本在 Redis 侧原子执行，
#: 没有这个窗口。
_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


def get_redis() -> Redis:
    global _client
    if _client is None:
        _client = Redis.from_url(
            settings.redis_dsn,
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=30,
            # **必须显式给值**：redis-py 8.x 的默认套接字超时是 5 秒
            # （`redis/_defaults.py::DEFAULT_SOCKET_TIMEOUT`），而 worker 的阻塞读
            # 会静默一段时间再拿空结果。不给值就会踩到「阻塞读先撞上套接字超时」，
            # 症状是 worker 空闲时不停报 `Timeout reading from`。
            # 与 `worker_poll_block_ms` 的大小关系由 config 的 validator 保证。
            socket_timeout=settings.redis_socket_timeout_seconds,
        )
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def ping() -> bool:
    try:
        return bool(await get_redis().ping())
    except RedisError as exc:
        logger.warning("Redis 不可达：%s", exc)
        return False


@asynccontextmanager
async def redis_lock(key: str, *, ttl_seconds: int = 600) -> AsyncIterator[bool]:
    """SETNX 互斥锁，yield `True` 表示拿到锁，`False` 表示没拿到。

    **Redis 不可达时降级为「总是拿到锁」并记警告**，而不是拒绝请求。
    理由：这把锁防的是同一项目的并发 ingest，它是一致性优化而非正确性保证
    （真正的一致性由数据库事务兜底）。Redis 挂了就让建档也别用，
    是把可用性问题升级成了功能问题 —— 与 §8.2「存储类依赖不可降级」的
    适用对象（MySQL）不同，Redis 在这里不是权威存储。
    """
    client = get_redis()
    token = uuid.uuid4().hex

    try:
        acquired = bool(await client.set(key, token, nx=True, ex=ttl_seconds))
    except RedisError as exc:
        logger.warning("Redis 不可达，锁 %s 降级为放行：%s", key, exc)
        yield True
        return

    if not acquired:
        yield False
        return

    try:
        yield True
    finally:
        try:
            await client.eval(_RELEASE_SCRIPT, 1, key, token)
        except RedisError as exc:  # 释放失败不影响业务，等 TTL 自然过期
            logger.warning("释放 Redis 锁 %s 失败（将由 TTL 回收）：%s", key, exc)
