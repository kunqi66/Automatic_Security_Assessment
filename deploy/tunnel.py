"""开发态 SSH 隧道：把 ECS 上的 MySQL / Redis 映射到本机端口。

**为什么需要这个**：阿里云安全组把 3306 和 6379 挡在公网之外（这是对的 ——
那台机器 2026-10-01 正是因为数据库暴露在公网才被勒索）。控制面在 Windows 上，
要访问这两个服务就必须过一条加密通道。隧道既解决连通性，
又**不需要在安全组上再开任何口子**。

这不只是"懒得开端口"：评估系统要存客户的源码片段、漏洞详情和补丁，
把这些放在一条明文公网连接上，等于给同一个攻击面又添了一份高价值数据。

用法：

    ECS_PASSWORD=... uv run --with paramiko python deploy/tunnel.py            # 前台跑，Ctrl+C 停
    ECS_PASSWORD=... uv run --with paramiko --with aiomysql --with cryptography \
        ASA_DB_PASSWORD=... python deploy/tunnel.py --check                    # 验一次连通性

⚠️ **推荐先配好 SSH 密钥**（`ssh-copy-id -i ~/.ssh/id_rsa.pub root@<ecs>`）。
密钥不是"更方便"，而是**架构上的硬要求**：`DOCKER_HOST=ssh://` 走的 Docker SDK
根本不支持密码认证，没有密钥，沙箱那半边就跑不起来。
密码入口只是为了在配好密钥之前不挡住开发。

--- 实现说明（这里踩过一次坑，值得写下来）---

**本地转发要用 `direct-tcpip`，不是 `request_port_forward`。** paramiko 里：

  - `Transport.open_channel("direct-tcpip", dest, src)` == `ssh -L`（本地监听，转发出去）
  - `Transport.request_port_forward(address, port)` == `ssh -R`（让**服务器**开监听）

两者名字很像，用错了报的是 `TCP forwarding request denied` —— 看起来像服务器禁用了
转发，实际上 `sshd -T` 里 `allowtcpforwarding` 是 `yes`。**错误信息指向的排查方向
完全是歪的**，这也是为什么值得在这里留一段注释。
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
from pathlib import Path

try:
    import paramiko
except ImportError:  # pragma: no cover
    sys.exit("缺少 paramiko：uv run --with paramiko python deploy/tunnel.py")

HOST = os.environ.get("ECS_HOST", "60.205.138.167")
USER = os.environ.get("ECS_USER", "root")
PORT = int(os.environ.get("ECS_PORT", "22"))
KEY = Path.home() / ".ssh" / "id_rsa"

#: (本地端口, 名字, 远端主机, 远端端口)。
#: **本地端口刻意避开 3306/6379**：本机若哪天也起了 MySQL，撞端口会得到一个
#: "连上了但不是那台机器"的假象，而报错会指向认证失败，排查方向全歪。
FORWARDS: list[tuple[int, str, str, int]] = [
    (13306, "MySQL", "127.0.0.1", 3306),
    (16379, "Redis", "127.0.0.1", 6379),
]

BUF = 32768


def _close_write(obj: socket.socket | paramiko.Channel) -> None:
    """半关闭。socket 和 Channel 的 API 不同名，这里抹平。"""
    try:
        if isinstance(obj, paramiko.Channel):
            obj.shutdown_write()
        else:
            obj.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _pump(src, dst) -> None:
    """单向搬运。读到 EOF 就半关闭对端的写方向 —— 不做的话对端会一直等，
    表现出来是连接"挂着"而不是"断开"，两端都卡死。"""
    try:
        while True:
            data = src.recv(BUF)
            if not data:
                break
            dst.sendall(data)
    except (OSError, paramiko.SSHException):
        pass
    finally:
        _close_write(dst)


#: 单条 SSH 连接上最多同时开几条转发通道。
#:
#: 🔴 服务端 `sshd -T` 的 `maxsessions` 是 **10**，而它数的是**通道**，
#: `direct-tcpip` 也算一条 —— 不是"10 个客户端"。控制面启动时 SQLAlchemy
#: 连接池会一次要好几条，Redis 再要几条，很容易撞到上限。留 2 条余量。
CHANNELS_PER_CONN = 8


class _Conn:
    """一条 SSH 连接，以及它当前挂了几条转发通道。"""

    def __init__(self, client: paramiko.SSHClient) -> None:
        self.client = client
        self.open_channels = 0
        #: 这条连接还活着，但已经**开不出新通道**了（撞了服务端 maxsessions）。
        #: 已经挂着的通道不受影响，只是不再往上加。
        self.retired = False

    def transport(self) -> paramiko.Transport | None:
        fresh = self.client.get_transport()
        if fresh is None or not fresh.is_active():
            return None
        return fresh

    def has_room(self) -> bool:
        return not self.retired and self.open_channels < CHANNELS_PER_CONN

    def close(self) -> None:
        try:
            self.client.close()
        except Exception as exc:  # noqa: BLE001 —— 关闭失败不影响"已丢弃"这个事实
            print(f"  关闭 SSH 连接时报错（已忽略）：{exc}", file=sys.stderr)


class _Link:
    """一条转发（本机某端口 → 远端某服务），**带自愈和通道上限管理**。

    ## 两个失败模式，长得完全不同

    **① 连接死了。** 网络抖动、对端重启 sshd、NAT 空闲超时。
    原先 `serve` 是死循环，把启动时那一个 `transport` 传给每条连接，
    于是连接一死，后续**每一条**都在 `open_channel` 处失败。
    自愈办法：`transport()` 发现 `is_active()` 为假就重建。

    **② 连接活着，但开不出通道了。** 这是后来才撞上的、也是更坏的一个 ——
    服务端 `maxsessions` 默认 10，`direct-tcpip` 也占坑位。控制面启动时
    连接池一次要好几条，撞上限后 `open_channel` 抛 "Unable to open channel"，
    **而那条连接的 `is_active()` 仍然是 True**。

    ② 的原始处理是错的：失败时 `invalidate()` 掉整条连接。那条连接上
    **其它健康的通道正被别处用着**，把它关掉等于让一次超限变成一次全面断连，
    然后重连、再超限、再断——日志里就是同一句失败连着刷。
    现在的处理是：**只把这条连接标记为 retired（不再加新通道），不关它**，
    下一次 `acquire` 自然会新开一条 SSH 连接来分摊。

    ## 共同症状：一个"看起来活着"的隧道

        netstat      → 127.0.0.1:13306 LISTENING   ✅ 看起来活着
        TCP 握手     → 成功                          ✅ 更确信它活着
        MySQL 客户端 → Lost connection during query  ❌ 而错误指向 MySQL

    实测症状就是这个：MySQL 容器好好的（本地 `mysql -uroot` 能连），
    只有**过隧道**的那条路断了。一个半死的隧道比一个直接崩掉的隧道难查得多
    —— 崩掉的会有人重启，半死的只会让人去翻 MySQL 的日志。
    """

    def __init__(self, local_port: int, rhost: str, rport: int) -> None:
        self.local_port = local_port
        self.rhost = rhost
        self.rport = rport
        self._lock = threading.Lock()
        self._conns: list[_Conn] = []
        self.connects = 0

    def acquire(self) -> tuple[paramiko.Transport, _Conn]:
        """借一条**还有余量**的 SSH 连接，返回 (transport, 它属于哪个 _Conn)。

        没有余量就新开一条。这样上层不必关心 `maxsessions`，
        只管"我要一条通道"，池子负责别把服务端撑爆。
        """
        with self._lock:
            # 顺手清掉死掉的连接：paramiko 不会自己回收，
            # 留着它只会在下一次 is_active() 继续返回 False。
            self._conns = [c for c in self._conns if c.transport() is not None]
            for candidate in self._conns:
                if candidate.has_room():
                    fresh = candidate.transport()
                    if fresh is not None:
                        candidate.open_channels += 1
                        return fresh, candidate
            conn = _Conn(_connect())
            self._conns.append(conn)
            conn.open_channels = 1
            self.connects += 1
            if self.connects > 1:
                fresh = conn.transport()
                assert fresh is not None
                label = f"127.0.0.1:{self.local_port}"
                print(
                    f"  [{label}] 新开第 {self.connects} 条 SSH 连接"
                    f"（前面的通道已满或已失效）",
                    flush=True,
                )
            transport = conn.transport()
            assert transport is not None
            return transport, conn

    def release(self, conn: _Conn) -> None:
        with self._lock:
            conn.open_channels = max(0, conn.open_channels - 1)

    def retire(self, conn: _Conn) -> None:
        """这条连接开不出新通道了 —— 留着手上的通道，别再往上加。"""
        with self._lock:
            conn.retired = True

    def close(self) -> None:
        with self._lock:
            for conn in self._conns:
                conn.close()
            self._conns = []


def _bridge(conn: socket.socket, link: _Link) -> None:
    lease: _Conn | None = None
    try:
        transport, lease = link.acquire()
        chan = transport.open_channel(
            "direct-tcpip", (link.rhost, link.rport), conn.getpeername()
        )
    except (paramiko.SSHException, OSError) as exc:
        print(f"  转发到 {link.rhost}:{link.rport} 失败：{exc}", file=sys.stderr)
        if lease is not None:
            link.release(lease)
            # ⚠️ 这里**不**关连接。走到这一步的典型原因是服务端 maxsessions 满了，
            # 而那条连接上还挂着别处正在用的通道 —— 关掉它，一次超限就升级成
            # 一次全面断连（旧实现就是这么写的，日志里同一句失败连着刷）。
            # 正确做法是让它退出轮转：已经挂上的通道照常用，新的走新连接。
            if lease.transport() is not None:
                link.retire(lease)
        conn.close()
        return

    # 两条泵都跑完才代表这条转发真的没人用了。**必须显式关掉**：
    # 不关的话 SSH 通道会一直挂在服务端，而服务端是按 maxsessions 计数的
    # （direct-tcpip 也算）—— 漏够 10 条，之后**所有** open_channel 全部失败，
    # 症状就是上面那个"看起来活着"。
    outbound = threading.Thread(target=_pump, args=(conn, chan), daemon=True)
    inbound = threading.Thread(target=_pump, args=(chan, conn), daemon=True)
    outbound.start()
    inbound.start()
    outbound.join()
    inbound.join()
    link.release(lease)
    try:
        chan.close()
    except Exception as exc:  # noqa: BLE001 —— 对端先关掉通道是正常的
        print(f"  关闭 SSH 通道时报错（已忽略）：{exc}", file=sys.stderr)
    conn.close()


def bind_listener(local_port: int) -> socket.socket:
    """绑定本地监听端口。**在调用方线程里同步绑定** —— 这样返回时端口
    一定已经可连，调用方不必靠 `sleep` 猜多久能就绪。"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SO_REUSEADDR：上一个隧道刚 Ctrl+C 掉时端口会留在 TIME_WAIT，
    # 不设这个就得等一分多钟才能重启，而这段时间看起来像"脚本坏了"
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", local_port))
    server.listen(64)
    return server


def serve(server: socket.socket, link: _Link) -> None:
    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            return
        threading.Thread(target=_bridge, args=(conn, link), daemon=True).start()


def _connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(
        HOST,
        port=PORT,
        username=USER,
        key_filename=str(KEY) if KEY.is_file() else None,
        password=os.environ.get("ECS_PASSWORD"),
        timeout=15,
        allow_agent=True,
        look_for_keys=True,
    )
    return client


def open_tunnel(local_port: int, rhost: str, rport: int) -> tuple[socket.socket, _Link]:
    """一条转发 = 一条独立 SSH 连接。

    **不共用连接**：一个 `Transport` 上开的 direct-tcpip 通道无法反查它原本要
    去哪个远端端口，想共用就得自己接管通道与目标的映射表。多一条 SSH 连接的开销，
    远小于把这段路由逻辑写错的代价 —— 而写错的症状是"数据串到了另一个服务"。

    连上之后立刻建首条 SSH 连接（`link.transport()`），
    这样"凭据不对"会在**建隧道时**就报出来，而不是等到第一个客户端连进来。
    """
    link = _Link(local_port, rhost, rport)
    _, warm = link.acquire()
    link.release(warm)  # 预热：让认证失败在**建隧道时**暴露，而不是等第一个客户端
    server = bind_listener(local_port)
    threading.Thread(target=serve, args=(server, link), daemon=True).start()
    return server, link


# ---------------------------------------------------------------------------
# check —— 发真实协议请求，而不是只看端口能不能连上
# ---------------------------------------------------------------------------


def check() -> int:
    """逐条验证隧道。

    **不满足于 TCP 握手**：握手成功只说明隧道通了，不代表后面那个服务可用
    （MySQL 可能拒绝认证、Redis 可能还在 loading）。所以这里发真实请求 ——
    端口能连、但认证过不去，是最容易误判成"配好了"的一种失败。
    """
    results: list[tuple[str, bool, str]] = []
    servers: list[socket.socket] = []
    links: list[_Link] = []

    try:
        for local_port, label, rhost, rport in FORWARDS:
            server, link = open_tunnel(local_port, rhost, rport)
            servers.append(server)
            links.append(link)
            print(f"  {label:<6} 127.0.0.1:{local_port} -> {HOST} -> {rhost}:{rport}")

        results.append(_probe_mysql())
        results.append(_probe_redis())
    finally:
        for server in servers:
            server.close()
        for link in links:
            link.close()

    print(f"\n到 {HOST} 的连通性：")
    for name, ok, detail in results:
        print(f"  [{'OK' if ok else 'FAIL'}] {name:<6} {detail}")
    return 0 if all(ok for _, ok, _ in results) else 1


def _probe_mysql() -> tuple[str, bool, str]:
    import asyncio

    try:
        import aiomysql
    except ImportError:
        return "MySQL", False, "缺 aiomysql：加 --with aiomysql"

    async def run() -> str:
        conn = await aiomysql.connect(
            host="127.0.0.1",
            port=13306,
            user=os.environ.get("ASA_DB_USER", "asa_user"),
            password=os.environ["ASA_DB_PASSWORD"],
            db=os.environ.get("ASA_DB_NAME", "security_assessment"),
            charset="utf8mb4",
        )
        cur = await conn.cursor()
        await cur.execute(
            "select current_user(), database(), @@version, @@character_set_database"
        )
        row = await cur.fetchone()
        conn.close()
        return str(row)

    try:
        return "MySQL", True, asyncio.run(run())
    except KeyError:
        return "MySQL", False, "未设置 ASA_DB_PASSWORD"
    except Exception as exc:  # noqa: BLE001 —— 检查脚本要报出任何失败原因
        return "MySQL", False, f"{type(exc).__name__}: {exc}"


def _probe_redis() -> tuple[str, bool, str]:
    try:
        with socket.create_connection(("127.0.0.1", 16379), timeout=5) as sock:
            # 直接发 RESP。不引 redis 库 —— 检查脚本的依赖越少，它自己越不容易坏
            sock.sendall(b"*2\r\n$6\r\nSELECT\r\n$1\r\n3\r\n*1\r\n$4\r\nPING\r\n")
            sock.settimeout(5)
            reply = sock.recv(4096).decode("utf-8", errors="replace")
        return "Redis", "PONG" in reply, reply.strip().replace("\r\n", " ")
    except Exception as exc:  # noqa: BLE001
        return "Redis", False, f"{type(exc).__name__}: {exc}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="只验证连通性后退出")
    args = parser.parse_args()

    if args.check:
        sys.exit(check())

    if not KEY.is_file() and not os.environ.get("ECS_PASSWORD"):
        sys.exit(
            f"没有可用凭据：{KEY} 不存在，且未设置 ECS_PASSWORD。\n"
            f"推荐先配密钥：ssh-copy-id -i {KEY}.pub {USER}@{HOST}"
        )

    print(f"隧道已建立，Ctrl+C 停止（目标 {USER}@{HOST}）：")
    for local_port, label, rhost, rport in FORWARDS:
        open_tunnel(local_port, rhost, rport)
        print(f"  {label:<6} 127.0.0.1:{local_port} -> {HOST} -> {rhost}:{rport}")

    try:
        threading.Event().wait()  # 永不返回，直到 Ctrl+C
    except KeyboardInterrupt:
        print("\n隧道已关闭")


if __name__ == "__main__":
    main()
