"""`deploy/tunnel.py` 的通道容量记账 —— 一次真实的控制面全停事故的回归测试。

## 为什么这个开发脚本值得有测试

它不是"部署脚本"那么轻。控制面（API + worker）到自己数据库的**唯一**通路
就是这条隧道：ECS 的安全组把 3306/6379 挡在公网外（对的，那台机器
2026-10-01 正因数据库暴露公网被勒索）。隧道一坏，整个系统起不来。

而它坏掉的方式是**静默**的：

    netstat      → 127.0.0.1:13306 LISTENING   ✅ 看起来活着
    TCP 握手     → 成功                          ✅ 更确信它活着
    MySQL 客户端 → Lost connection               ❌ 而错误指向 MySQL

## 被锁住的那条判据

服务端 `sshd -T` 的 `maxsessions` 是 **10**，而它数的是**通道**
（`direct-tcpip` 也算），不是"10 个客户端"。控制面启动时连接池一次要好几条，
撞上限后 `open_channel` 抛 "Unable to open channel" ——
**而那条 SSH 连接的 `is_active()` 仍然是 True**。

旧实现在这一刻调 `invalidate()` 把整条连接关掉。那条连接上还挂着别处
**正在用**的通道，于是"一次超限"升级成"一次全面断连"，重连、再超限、再断。

所以这里锁死两件事：

1. 容量满了要**新开一条**，不是复用一条已经满的；
2. 开通道失败要 `retire`（不再加新通道、留着已有的），
   **不是**把健康的连接关掉。

第 2 条尤其重要 —— 它正是"看起来在做自愈、实际在放大故障"的那一步。
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# `deploy/` 不在 `backend/` 里，按路径加载 —— 不为了测试去改包结构。
_TUNNEL_PATH = Path(__file__).resolve().parents[2] / "deploy" / "tunnel.py"


def _load_tunnel():
    spec = importlib.util.spec_from_file_location("asa_deploy_tunnel", _TUNNEL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tunnel = _load_tunnel()


class FakeTransport:
    def __init__(self, active: bool = True) -> None:
        self.active = active

    def is_active(self) -> bool:
        return self.active


class FakeClient:
    """只需要 `get_transport()` / `close()` 两件事。"""

    def __init__(self, active: bool = True) -> None:
        self._transport = FakeTransport(active)
        self.closed = False

    def get_transport(self):
        return self._transport

    def close(self) -> None:
        self.closed = True
        self._transport.active = False


def _link_with_fake_conns(monkeypatch: pytest.MonkeyPatch, count: int):
    """造一条 `_Link`，它的 `_connect` 返回假客户端 —— 不碰任何 socket。"""
    made: list[FakeClient] = []

    def fake_connect() -> FakeClient:
        client = FakeClient()
        made.append(client)
        return client

    monkeypatch.setattr(tunnel, "_connect", fake_connect)
    link = tunnel._Link(13306, "127.0.0.1", 3306)
    monkeypatch.setattr(link, "_conns", [], raising=False)
    return link, made


def test_容量未满时复用同一条_ssh_连接(monkeypatch: pytest.MonkeyPatch) -> None:
    """没满就复用 —— 否则每条库连接都做一次 SSH 握手，慢得没法用。"""
    link, made = _link_with_fake_conns(monkeypatch, 0)

    first, conn_a = link.acquire()
    second, conn_b = link.acquire()

    assert first is second
    assert conn_a is conn_b
    assert len(made) == 1, "容量没满却又开了一条新 SSH 连接"
    assert conn_a.open_channels == 2


def test_容量用满时新开一条而不是硬塞(monkeypatch: pytest.MonkeyPatch) -> None:
    """⚠️ 这是事故的正面：撞到服务端 maxsessions 就必须分摊到新连接上。

    硬塞进一条已满的连接 = 让服务端返回 "Unable to open channel"，
    而那正是旧实现处理错的那个错误。
    """
    link, made = _link_with_fake_conns(monkeypatch, 0)

    conns = set()
    for _ in range(tunnel.CHANNELS_PER_CONN + 1):
        _, conn = link.acquire()
        conns.add(id(conn))

    assert len(made) == 2, "容量满了没有新开连接"
    assert len(conns) == 2

    # 上限本身要留在服务端 maxsessions(10) 之下
    assert tunnel.CHANNELS_PER_CONN < 10


def test_释放之后容量能重新用(monkeypatch: pytest.MonkeyPatch) -> None:
    link, made = _link_with_fake_conns(monkeypatch, 0)

    for _ in range(tunnel.CHANNELS_PER_CONN):
        _, conn = link.acquire()
    link.release(conn)
    _, again = link.acquire()

    assert len(made) == 1, "释放出来的容量没有被复用"
    assert again is conn


def test_开通道失败要_retire_而不是关掉健康连接(monkeypatch: pytest.MonkeyPatch) -> None:
    """🔴 本文件的核心：故障不能被"自愈"放大。

    旧实现在 `open_channel` 失败时 `invalidate()` 整条连接 —— 而那条连接
    可能还挂着别处正在用的通道。一次超限就升级成一次全面断连。
    正确行为：标记 `retired`，已有的留着，新的走新连接。
    """
    link, made = _link_with_fake_conns(monkeypatch, 0)
    _, victim = link.acquire()
    healthy_client = victim.client

    link.retire(victim)

    assert healthy_client.closed is False, "把一条还活着的连接关掉了"
    assert victim.has_room() is False

    _, fresh = link.acquire()
    assert fresh is not victim, "retired 的连接不该再被复用"
    assert len(made) == 2


def test_连接死掉之后不再被复用(monkeypatch: pytest.MonkeyPatch) -> None:
    """`is_active()` 为假 = 真死了，这时才该换一条。"""
    link, made = _link_with_fake_conns(monkeypatch, 0)
    _, dead = link.acquire()
    dead.client.get_transport().active = False

    _, fresh = link.acquire()

    assert fresh is not dead
    assert len(made) == 2


def test_全部关闭时把每条连接都关掉(monkeypatch: pytest.MonkeyPatch) -> None:
    link, _ = _link_with_fake_conns(monkeypatch, 0)
    conns = [link.acquire()[1] for _ in range(tunnel.CHANNELS_PER_CONN + 1)]

    link.close()

    assert all(c.client.closed for c in conns)
    assert link._conns == []
