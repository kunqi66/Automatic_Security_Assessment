"""阻塞读与套接字超时的关系 —— 一个只在**真实 Redis** 上才发作的 bug。

## 这个文件钉的是什么

`redis-py 8.x` 把 `DEFAULT_SOCKET_TIMEOUT` 改成了 **5 秒**（`redis/_defaults.py`），
不再是旧版本的 `None`。于是「不设 socket_timeout 就永不超时」这个老心智模型
失效了 —— 而这**不会让任何单测变红**：单测要么用 fakeredis，要么根本不发
阻塞命令。

真实症状（2026-10-16 在 ECS 的 Redis 上实测）：

    XREADGROUP ... BLOCK 5000   →  TimeoutError: Timeout reading from 127.0.0.1:16379
    XREADGROUP ... BLOCK 3000   →  正常返回 []，用时 3.1s
    XREADGROUP ... BLOCK 8000   →  TimeoutError，用时 5.0s

即：**Redis 完全正常，是套接字先超时**。而 worker 的消费循环会把
`RedisError` 记成「读取任务队列失败，5 秒后重试」并退避 ——
一个空闲的 worker 于是每 5 秒往日志里写一条 ERROR，
排查的人会去查网络、查隧道、查 Redis 负载，不会想到是两个秒数撞在一起。

## 为什么断言的是「配置关系」而不是「跑一次阻塞读」

跑真阻塞读要先有真 Redis，而这里测的是**让那个 bug 无法被写回来** ——
只要两个值的大小关系成立，5 秒默认值就再也咬不到我们。
"""

from __future__ import annotations

import pytest

from app.core.config import Settings


def test_默认配置下阻塞时长小于套接字超时() -> None:
    """开箱即用的默认值必须是安全的那一对。"""
    s = Settings(_env_file=None, debug=True)
    assert s.worker_poll_block_ms / 1000 < s.redis_socket_timeout_seconds


def test_阻塞时长等于套接字超时会被拒绝() -> None:
    """**这条就是那个 bug 的最小复现。**

    等于也不行：阻塞让套接字静默整整 `block` 毫秒，而超时也是同样的秒数时
    两者赛跑，实测套接字先输（见模块 docstring 的实测数据）。
    """
    with pytest.raises(ValueError, match="必须大于"):
        Settings(
            _env_file=None,
            debug=True,
            worker_poll_block_ms=5000,
            redis_socket_timeout_seconds=5.0,
        )


def test_阻塞时长大于套接字超时会被拒绝() -> None:
    with pytest.raises(ValueError, match="必须大于"):
        Settings(
            _env_file=None,
            debug=True,
            worker_poll_block_ms=30000,
            redis_socket_timeout_seconds=10.0,
        )


def test_校验与_DEBUG_无关() -> None:
    """**不允许「生产才检查」**。

    这个组合在开发态同样是坏的 —— worker 在本地跑时一样会刷超时日志。
    放进只对 DEBUG=false 生效的那个 validator 里，等于开发期永远发现不了。
    """
    for debug in (True, False):
        with pytest.raises(ValueError, match="必须大于"):
            Settings(
                _env_file=None,
                debug=debug,
                jwt_secret="x" * 32,
                mysql_password="x",  # noqa: S106 —— 占位符，只为过生产自检
                git_url_allowlist=["https://example.invalid/"],
                worker_poll_block_ms=5000,
                redis_socket_timeout_seconds=5.0,
            )


def test_客户端真的把超时传下去了() -> None:
    """配置填对但**没接到客户端上**，等于没改。

    这一条防的是「加了配置项、写了注释、忘了 `from_url` 那行」——
    那种改动所有测试都是绿的，而线上行为一点没变。
    """
    from app.db import redis as redis_mod

    redis_mod._client = None  # 清掉单例，强制按当前配置重建
    client = redis_mod.get_redis()
    try:
        kwargs = client.connection_pool.connection_kwargs
        assert (
            kwargs.get("socket_timeout")
            == Settings(_env_file=None, debug=True).redis_socket_timeout_seconds
        )
    finally:
        redis_mod._client = None
