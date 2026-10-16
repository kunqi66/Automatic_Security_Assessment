"""B2 唯一对外门面 `SandboxService` —— **远程 Docker over SSH**（B2 模块设计 §3.1）。

本机没有 Docker，沙箱跑在阿里云 ECS 上，走 `DOCKER_HOST=ssh://root@<host>`。
Docker SDK 是**同步**库，所有调用一律 `asyncio.to_thread` 包住 —— 直接在事件循环里
调 `container.wait()` 会把整个进程（含 SSE 心跳）冻住几十秒。

**构造函数接受注入的 client**，这不是为了好看：单测不该依赖远程 ECS 的连通性，
而「注入一个假 client」是本模块安全边界（超时强杀、成败都删容器、配额真的传下去）
唯一能被验证的方式。

契约见 `ports.py`（`模块间契约.md` 契约 1），错误分级见 B2 模块设计 §6。
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from typing import Any

import docker
import requests

from app.core.config import settings
from app.core.logging import get_logger
from app.sandbox import metrics
from app.sandbox.errors import (
    SandboxDiskFullError,
    SandboxImageMissingError,
    SandboxUnavailableError,
)
from app.sandbox.ports import ContainerSpec, ExecResult

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# 常量：这些值没有进 Settings 是有原因的，不要顺手搬过去
#
# `core/config.py` 只放**会随部署环境变化**的值（地址、密钥、镜像名）。下面这些是
# 安全模型的固定参数，把它们变成可配置项等于给了「把 pids 上限调成 0（无限）」的口子。
# ---------------------------------------------------------------------------

#: 容器内只读根上唯一可写的挂载点。`noexec` 关键：否则被写进 /tmp 的二进制可以直接跑。
TMPFS_TMP_SPEC = "rw,noexec,nosuid,size=64m,mode=1777"
# S108 的告警在这里是反向的：`/tmp` 不是「本机的临时目录」，而是**容器内**那个
# tmpfs 的挂载目标（还要 noexec）。它出现在 HostConfig 里，不在本机文件系统上。
TMPFS_MOUNTS: dict[str, str] = {"/tmp": TMPFS_TMP_SPEC}  # noqa: S108

#: 源码只读挂载的容器内落点（bind mount 目标）。
CONTAINER_WORKSPACE = "/workspace"

#: PID 上限。fork 炸弹不需要 root 也不需要出网，`pids_limit` 是在内核 cgroup 层
#: 拦停它，而不是靠事后发现容器卡死（设计 E9）。
PIDS_LIMIT = 128

#: 本系统给容器打的标签 —— `reap_orphans` **只认这个**（设计 T13）。
#: 同一台 ECS 上还有 Milvus / MySQL / Redis / 未知 :8000，任何「全量 prune」
#: 都会误伤它们，而误删不可回滚。
MANAGED_LABEL = "asa.managed"
TASK_ID_LABEL = "asa.task_id"

#: `ContainerSpec` 没带 task_id（契约 1 的字段就这些），所以只能靠「是本系统建的」
#: 来判定归属。要按任务维度回收，得先扩契约。
_MANAGED_FILTER = {"label": f"{MANAGED_LABEL}=true"}

#: E4 降级默认值。`core/config.py` 只有 `sandbox_exec_timeout_seconds`，
#: 内存/CPU 的默认值在这里 —— 设计 §6 E4 写的 256M / 0.5 核。
DEFAULT_MEMORY_LIMIT_MB = 256
DEFAULT_CPU_LIMIT = 0.5

#: 单条命令的超时不该超过任务级 TTL 的量级，超了必然是调用方拼错了单位（秒/毫秒）
MAX_TIMEOUT_SECONDS = 3600

#: E1：SSH 抖动的重试次数与退避基数（1s → 2s → 4s）。测试会把它 patch 成 0。
PING_ATTEMPTS = 3
PING_BACKOFF_BASE_SECONDS = 1.0

#: Docker 客户端自身超时（SSH 握手 + 请求）。60s 与 docker CLI 的默认一致。
CLIENT_TIMEOUT_SECONDS = 60

#: 日志回传上限。靶场代码在验证语境下已经是**不可信**的，
#: 一个 for 循环 print 就能把控制面内存顶上去。
LOG_TAIL_LINES = 2000
MAX_CAPTURE_CHARS = 64 * 1024

#: 进程内并发硬闸门（总纲 D12）。2 vCPU + Milvus 常驻 2–4G + 0 swap，
#: 两个沙箱容器同时跑就是撞 OOM。**恒为 1，不做成配置项。**
_gate_state: tuple[asyncio.AbstractEventLoop, asyncio.Semaphore] | None = None


def _concurrency_gate() -> asyncio.Semaphore:
    """取当前事件循环上的并发闸门。

    绑定到 loop 是必须的：pytest 每个用例一个新 loop，而复用一个挂在旧 loop 上的
    `Semaphore` 会在真正开始等待时抛 "is bound to a different event loop" ——
    而且只在有竞争时才出现，是最难复现的那类失败。
    """
    global _gate_state
    loop = asyncio.get_running_loop()
    if _gate_state is None or _gate_state[0] is not loop:
        _gate_state = (loop, asyncio.Semaphore(1))
    return _gate_state[1]


def build_docker_client() -> docker.DockerClient:
    """按 `settings` 构造远程 Docker 客户端。**不在这里 ping** —— 可达性归 `_ensure_reachable`。

    用 `use_ssh_client=True` 而不是 paramiko：shell-out 复用系统 OpenSSH，
    与 B1 的源码同步（`projects/sync.py` 也是调 `ssh` 命令）走同一套配置与密钥，
    不会出现「源码传得上去、容器建不起来」这种两边 SSH 行为分叉的怪事。
    """
    host = settings.docker_host.strip()
    if not host:
        raise SandboxUnavailableError(
            "未配置 DOCKER_HOST（沙箱宿主地址为空），无法创建沙箱",
            remediation="在 .env 中设置 DOCKER_HOST=ssh://root@<ecs-host>；该阶段将标记为跳过",
        )

    if settings.docker_ssh_key_path:
        # ⚠️ 如实说明：docker-py 的 SSHHTTPAdapter 只从 base_url 取 user/host/port，
        # **没有**接受密钥路径的入口（shell-out 模式下它只是 spawn `ssh <host> ...`）。
        # 不说清楚的话，运维改了 DOCKER_SSH_KEY_PATH 却不生效，会去查网络、查安全组，
        # 方向从一开始就是歪的。B1 的源码同步会用这个配置（它自己拼 `-i`）。
        logger.warning(
            "DOCKER_SSH_KEY_PATH 对 Docker SDK 的 ssh:// 传输不生效（docker-py 无此入口）；"
            "请在 ~/.ssh/config 中为该主机配置 IdentityFile，或把密钥加入 ssh-agent"
        )

    try:
        return docker.DockerClient(
            base_url=host,
            use_ssh_client=True,
            timeout=CLIENT_TIMEOUT_SECONDS,
        )
    except ImportError as exc:
        # **实测**：docker-py 的 `DockerClient` 在 `ssh://` 分支里才 `import paramiko`
        # （`docker/transport/sshconn.py` 顶部无条件导入，与是否 shell-out 无关），
        # 于是缺依赖时抛的是 `ModuleNotFoundError` 而**不是** `DockerException` ——
        # 只 catch DockerException 会让它裸奔到编排层，把整轮评估带走。
        raise SandboxUnavailableError(
            f"创建 Docker 客户端失败（缺少 ssh:// 传输的依赖）：{exc}",
            detail={"docker_host": host},
            remediation="uv add paramiko（docker-py 的 ssh:// 传输必需，与 use_ssh_client 无关）",
        ) from exc
    except docker.errors.DockerException as exc:
        raise SandboxUnavailableError(
            f"创建 Docker 客户端失败：{exc}",
            detail={"docker_host": host},
            remediation="确认宿主地址格式正确（ssh://user@host）且 ssh 可达；该阶段将标记为跳过",
        ) from exc


class SandboxService:
    """实现 `ports.Sandbox` 协议（结构化匹配，不显式继承 —— 契约 1 的要求）。

    **每次调用都是自洽的一次性执行**：`run_once` 内部完成
    建容器 → 启动 → 等（超时强杀）→ 收集 → 删容器，调用方不需要任何后续清理。
    """

    def __init__(self, client: docker.DockerClient | None = None) -> None:
        #: 允许注入（单测传假 client）。为 None 时按 settings 懒构造 —— 见 `client`。
        self._client = client
        #: 在途容器 id。`reap_orphans` 靠它区分「正常在跑」与「上次没清干净的残留」。
        self._active: set[str] = set()

    @property
    def client(self) -> docker.DockerClient:
        """懒构造：没有 Docker 的机器上 `import app.sandbox` 仍然要能成功。

        模块顶层只 `import docker`（纯 Python 包，不需要 daemon），
        真正碰 daemon 的动作全部推迟到这里之后。
        """
        if self._client is None:
            self._client = build_docker_client()
        return self._client

    # ------------------------------------------------------------------
    # 契约主路径
    # ------------------------------------------------------------------

    async def run_once(self, spec: ContainerSpec) -> ExecResult:
        """建容器 → 启动 → 等结束（到 `timeout_seconds` 强杀）→ 收集输出 → **无论成败都删容器**。

        **调用方不需要、也无法自己清理** —— 契约里没有 destroy。这条语义是刻意的：
        「容器泄漏」会造成 256M 级的内存占用 + IPAM 地址段耗尽，而 2 vCPU / 无 swap 的
        ECS 上两个孤儿就足以让下一次评估 OOM；把清理放进 `finally`，让它在任何一条
        出口（成功 / 非零退出 / 超时 / 启动失败 / 取消）上都发生。

        抛出 `SandboxUnavailableError`（及其子类）表示**沙箱不可用**，B3 据此把
        `poc_verify` 标 `skipped` 并继续；容器内的非零退出**不抛**，由返回值表达（E10）。
        """
        spec = _sanitize_spec(spec)

        started_ns = time.perf_counter()
        # 并发硬闸门（D12）：同一时刻阿里云上只有一个沙箱容器 + 一份 256M 内存占用。
        # 在 `create` 之前取、`finally` 里释放，取不到就等 —— 排队而不是并发。
        async with _concurrency_gate():
            await self._ensure_reachable()  # E1 重试 → E2 抛出（L3 可跳过）

            container: Any = None
            try:
                try:
                    container = await asyncio.to_thread(self._create_container, spec)
                    # 先登记再启动：启动调用本身可能超时，那时容器已经存在了
                    self._active.add(_container_id(container))
                    await asyncio.to_thread(container.start)
                except docker.errors.ImageNotFound as exc:
                    raise SandboxImageMissingError(
                        f"沙箱基础镜像不存在：{spec.image}",
                        detail={"image": spec.image},
                    ) from exc
                except docker.errors.APIError as exc:
                    # 磁盘满、配额被拒、端口冲突……都在这里。分级的依据是**人该怎么修**，
                    # 所以只看错误文本里有没有磁盘信号，其余一律归「这一次沙箱用不了」。
                    raise _classify_api_error(exc, spec) from exc

                exit_code, timed_out = await self._wait_for_exit(container, spec.timeout_seconds)
                stdout, stderr = await self._collect_output(container)
            finally:
                # 唯一的清理点。`_safe_remove` 自己吞掉「已经没了」与「删不掉」，
                # 所以这里不必再套一层 except —— 清理失败不该覆盖掉真正的失败原因。
                await self._safe_remove(container)

        return ExecResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=int((time.perf_counter() - started_ns) * 1000),
            timed_out=timed_out,
        )

    async def stats(self, container_id: str) -> tuple[float, float]:
        """`(cpu_percent, memory_mb)` —— 单核归一化，见 `metrics`。

        **尽力而为**（E12，L1 可忽略）：采样失败返回 `(0.0, 0.0)` 并且不抛。
        观测数据可以丢，评估不能因为采不到样而停。代价是「0.0」有两种含义
        （真的空闲 / 没采到），调用方若要在报告里画曲线，需要自行接受这个模糊性 ——
        契约把返回类型钉成了 `tuple[float, float]`，没有留「未知」的位置。
        """
        try:
            container = await asyncio.to_thread(self.client.containers.get, container_id)
            raw = await asyncio.to_thread(container.stats, stream=False)
        except Exception as exc:  # docker SDK 的异常族跨 requests / docker.errors，逐个列举只会漏
            logger.warning("容器资源采样失败（忽略）：container=%s err=%s", container_id, exc)
            return (0.0, 0.0)
        return (metrics.compute_cpu_percent(raw), metrics.compute_memory_mb(raw))

    # ------------------------------------------------------------------
    # 生命周期与运维
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        """单次探活，**返回布尔而不抛**。

        用途是「启动评估之前先问一句」：把「沙箱根本没接上」与「探针没打通」分开，
        否则一次连接失败会在 B5 里变成 N 次「验证失败」，报告读起来像分析错了。

        不做重试：这是个前置探测，慢比错更烦人；真正的重试在 `_ensure_reachable` 里，
        它是执行路径上的那一份。
        """
        try:
            await asyncio.to_thread(self.client.ping)
        except Exception as exc:
            logger.info("沙箱探活失败（不阻断调用方）：%s", exc)
            return False
        return True

    async def reap_orphans(self, tag: str | None = None) -> int:
        """回收本系统遗留的容器，返回回收数量（B2 模块设计 §4.2）。

        `tag` 可给 `"42"` 或 `"asa.task_id=42"`（设计文档两处写法不一致，两种都收）。
        给 `None` 表示「后端启动 / 续跑」时的全量收尸。

        **只删带 `asa.managed=true` 的容器**（设计 T13）：同机的 Milvus / MySQL /
        Redis 绝不能被「顺手打扫」掉。过滤在服务端做一次，返回后再**逐条复核一次标签**
        —— 服务端过滤器一旦因为 API 版本差异失效，代价是删掉别人的容器，不值得赌。

        单个容器删除失败只记 WARN 并继续（E14，L1 可忽略），汇总成功计数。
        """
        task_id = _normalize_tag(tag)
        try:
            found = await asyncio.to_thread(
                self.client.containers.list, all=True, filters=dict(_MANAGED_FILTER)
            )
        except Exception as exc:
            logger.warning("孤儿回收：列举容器失败（忽略，下次再收）：%s", exc)
            return 0

        reaped = 0
        for container in found:
            labels = getattr(container, "labels", None) or {}
            cid = _container_id(container)

            # 逐条复核归属：不信任服务端过滤器的结果
            if str(labels.get(MANAGED_LABEL, "")).lower() != "true":
                continue
            if cid in self._active:
                continue  # 正常在跑，不是孤儿
            if task_id is not None and labels.get(TASK_ID_LABEL) != task_id:
                continue

            try:
                await asyncio.to_thread(container.remove, force=True, v=True)
            except Exception as exc:
                logger.warning("孤儿回收：删除容器 %s 失败（跳过，下次再收）：%s", _short(cid), exc)
                continue
            reaped += 1
            logger.info("孤儿回收：已删除容器 %s（tag=%s）", _short(cid), tag)

        if reaped:
            logger.info("孤儿回收完成：tag=%s，回收 %d 个容器", tag, reaped)
        return reaped

    async def aclose(self) -> None:
        """释放客户端（关掉 ssh 子进程与连接池）。幂等 —— 重复调用无副作用。

        不做成 `__del__` / 后台任务：SSH 传输会 spawn 一个常驻的 `ssh` 进程，
        靠 GC 回收它的时机不确定；调用方（B3）在评估收尾时显式调一次更可控。
        """
        client, self._client = self._client, None
        if client is None:
            return
        try:
            await asyncio.to_thread(client.close)
        except Exception as exc:  # 关不掉不该让收尾流程失败
            logger.warning("关闭 Docker 客户端失败（忽略）：%s", exc)

    # ------------------------------------------------------------------
    # 内部：与 Docker daemon 的每一次往返都是同步调用，必须走线程
    # ------------------------------------------------------------------

    async def _ensure_reachable(self) -> None:
        """E1 可重试 / E2 可跳过：指数退避 ping 3 次，耗尽抛 `SandboxUnavailableError`。

        重试放在**执行路径**上而不是客户端构造时：ssh 抖动是常态（移动网络 / 跨境链路），
        一次抖就判死会让整个 `poc_verify` 白跳过。
        """
        last: Exception | None = None
        for attempt in range(1, PING_ATTEMPTS + 1):
            try:
                await asyncio.to_thread(self.client.ping)
                return
            except SandboxUnavailableError:
                # 客户端**根本没能构造出来**（缺 paramiko / DOCKER_HOST 为空）：
                # 这是永久性故障，不是抖动。重试三次只会把一个确定的错误拖成三倍等待，
                # 而它已经带着正确的 remediation，直接抛出去即可。
                raise
            except Exception as exc:  # SSHException / DockerException / requests 异常族
                last = exc
                if attempt < PING_ATTEMPTS:
                    delay = PING_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                    logger.warning(
                        "沙箱不可达（第 %d/%d 次尝试，%.0fs 后重试）：%s",
                        attempt,
                        PING_ATTEMPTS,
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)

        raise SandboxUnavailableError(
            f"沙箱（远程 Docker）连续 {PING_ATTEMPTS} 次不可达",
            detail={"docker_host": settings.docker_host, "last_error": repr(last)},
        )

    def _create_container(self, spec: ContainerSpec) -> Any:
        """`containers.create(**kwargs)` —— host-config 类参数由 docker-py 自己落到 `HostConfig`。

        用 `containers.create` 而不是 `client.api.create_container + HostConfig(...)`：
        `HostConfig` 的第一个位置参数是 **API 版本**（`HostConfig(version, ...)`），
        手搓它就得先跟 daemon 协商版本，等于把连接细节抄进业务代码。
        """
        return self.client.containers.create(
            spec.image,
            command=spec.command,
            working_dir=spec.workdir,
            environment=spec.env or None,
            labels={MANAGED_LABEL: "true"},
            # 源码**只读**挂进容器（设计 T5）：天然阻断「写 shell / 写 webshell 到靶场目录」
            # 这类载荷。bind 的 host 侧路径由**远端 daemon** 解析，所以源码必须已在 ECS 侧。
            volumes={spec.source_mount: {"bind": CONTAINER_WORKSPACE, "mode": "ro"}},
            # 闸门 1：无出网。容器只剩回环，探针仍能打 localhost（设计 T8）。
            network_disabled=spec.network_disabled,
            # detach=True 是必须的：容器跑在后台，我们等的是**它**而不是我们自己的进程。
            # 不显式传 tty（默认 False）—— docker-py 只在非 TTY 时才解复用日志流，
            # 传了 tty 会把 stdout/stderr 混成一坨，本模块的 ExecResult 就分不开了。
            detach=True,
            # ---- 资源硬限 ----
            nano_cpus=int(spec.cpu_limit * 1_000_000_000),  # 0.5 核 → 5e8（设计 T6）
            mem_limit=spec.memory_limit_mb * 1024 * 1024,
            # memswap 必须跟着一起限！只限 memory 的话容器可以吃掉等量的 swap：
            # 「256M 上限」实际能占 512M，在 0 swap 的 ECS 上表现是**整机**卡死而不是
            # 这个容器被 OOM 掉 —— 内存限制形同虚设。
            memswap_limit=spec.memory_limit_mb * 1024 * 1024,
            pids_limit=PIDS_LIMIT,  # fork 炸弹在内核 cgroup 层被拦停（E9）
            read_only=spec.read_only_root,
            # 只读根上唯一的可写处；noexec 让写进来的二进制没法直接执行
            tmpfs=dict(TMPFS_MOUNTS) if spec.read_only_root else None,
            cap_drop=["ALL"],  # 容器不需要任何 capability
            security_opt=["no-new-privileges:true"],  # 挡 setuid 提权
        )

    async def _wait_for_exit(self, container: Any, timeout_seconds: int) -> tuple[int, bool]:
        """等容器退出。返回 `(exit_code, timed_out)`。

        `wait(timeout=...)` 的 timeout 是**HTTP 读超时**：容器在 timeout 内没退出，
        requests 抛 `ReadTimeout`。这正是我们要的「到点强杀」信号 ——
        它一到就必须 `kill()`，而不是把连接留着等下一次。

        被强杀时 `exit_code` 返回 `-1`（负数 = 不是正常退出，契约 1 的约定）；
        容器内部命令真的返回 137（OOM）时是**正数** 137，两者不可混淆。
        """
        try:
            result = await asyncio.to_thread(container.wait, timeout=timeout_seconds)
        except requests.exceptions.ReadTimeout:
            logger.warning(
                "沙箱执行超时（%ds），强杀容器 %s（超时是 L2 可降级：本次探针判失败，"
                "容器不保留但也不影响其它探针）",
                timeout_seconds,
                _short(_container_id(container)),
            )
            await self._safe_kill(container)
            return -1, True

        status = result.get("StatusCode", 0) if isinstance(result, dict) else 0
        return int(status), False

    async def _collect_output(self, container: Any) -> tuple[str, str]:
        """分别取 stdout / stderr。

        分两次调 `logs` 是有意的：一次拿两路会被 daemon 按 `stdcopy` 交错复用成一坨，
        `ExecResult` 里就再也分不出「命令的正常输出」与「报错」——
        而 B5 要在 stdout 里做 nonce 匹配，stderr 里判 fork / OOM 迹象。
        """
        stdout = await asyncio.to_thread(
            container.logs, stdout=True, stderr=False, tail=LOG_TAIL_LINES
        )
        stderr = await asyncio.to_thread(
            container.logs, stdout=False, stderr=True, tail=LOG_TAIL_LINES
        )
        return _decode(stdout), _decode(stderr)

    async def _safe_kill(self, container: Any) -> None:
        """强杀。已经退出 → `NotFound`/`APIError` 都吞掉（设计 T9：要的是「立即注销」）。"""
        try:
            await asyncio.to_thread(container.kill)
        except Exception as exc:
            logger.info(
                "强杀容器 %s 未生效（可能已自行退出）：%s", _short(_container_id(container)), exc
            )

    async def _safe_remove(self, container: Any) -> None:
        """删除容器。**幂等且不抛** —— 它在 `finally` 里，抛出去会盖掉真正的失败原因。

        `force=True`：需求 2.5.4 要求「立即注销进程」，等它优雅退出会拖慢 STOP 响应
        （设计 T9）。删不掉只记 WARN：留给下一次 `reap_orphans` 收（E14）。
        """
        if container is None:
            return
        cid = _container_id(container)
        try:
            await asyncio.to_thread(container.remove, force=True, v=True)
        except docker.errors.NotFound:
            logger.info("删除容器 %s：已不存在（幂等路径）", _short(cid))
        except Exception as exc:
            logger.warning("删除容器 %s 失败（跳过，留给 reap_orphans）：%s", _short(cid), exc)
        finally:
            self._active.discard(cid)


# ---------------------------------------------------------------------------
# 纯函数（无 Docker 依赖，单测直接打）
# ---------------------------------------------------------------------------


def _sanitize_spec(spec: ContainerSpec) -> ContainerSpec:
    """E4（L2 可降级）：非法配额回落到默认值，只记 WARN，不抛。

    直接抛会让一次「配置页填了 0」演变成整轮评估失败，而这些参数都有安全默认值。
    刻意只在**非法**（≤0 / 空）时替换，不静默收紧合法值 ——
    把调用方要的 1G 悄悄降成 256M，会表现为「探针莫名其妙 OOM」，比报错难查得多。
    """
    timeout = (
        spec.timeout_seconds
        if 0 < spec.timeout_seconds <= MAX_TIMEOUT_SECONDS
        else (settings.sandbox_exec_timeout_seconds)
    )
    memory = spec.memory_limit_mb if spec.memory_limit_mb > 0 else DEFAULT_MEMORY_LIMIT_MB
    cpu = spec.cpu_limit if spec.cpu_limit > 0 else DEFAULT_CPU_LIMIT
    image = spec.image.strip() or settings.sandbox_default_image

    if (
        timeout == spec.timeout_seconds
        and memory == spec.memory_limit_mb
        and cpu == spec.cpu_limit
        and image == spec.image
    ):
        return spec

    logger.warning(
        "沙箱配额非法，已回落到默认值：timeout %s→%s，memory %s→%s，cpu %s→%s，image %r→%r",
        spec.timeout_seconds,
        timeout,
        spec.memory_limit_mb,
        memory,
        spec.cpu_limit,
        cpu,
        spec.image,
        image,
    )
    return dataclasses.replace(
        spec, timeout_seconds=timeout, memory_limit_mb=memory, cpu_limit=cpu, image=image
    )


def _classify_api_error(
    exc: docker.errors.APIError, spec: ContainerSpec
) -> SandboxUnavailableError:
    """把 daemon 的 `APIError` 映射到「人该怎么修」更具体的那一类。

    只认磁盘满一种信号，其余统一归 `SandboxUnavailableError`：
    按文本去猜「端口冲突 / 权限不足 / 配额被拒」会写出一个随 Docker 版本变化的
    字符串匹配表，而它一旦失配就会把异常漏成 500 —— 归到一个可降级的类里更安全。
    """
    text = f"{exc} {getattr(exc, 'explanation', '') or ''}".lower()
    if "no space left" in text or "disk full" in text:
        return SandboxDiskFullError(
            "沙箱宿主磁盘已满，无法创建容器", detail={"image": spec.image, "error": str(exc)[:500]}
        )
    return SandboxUnavailableError(
        f"沙箱容器创建/启动失败：{exc}",
        detail={"image": spec.image, "error": str(exc)[:500]},
    )


def _normalize_tag(tag: str | None) -> str | None:
    """`"42"` / `"asa.task_id=42"` / `""` / `None` → `"42"` / `None`。

    设计文档两处写法不一致（§4.2 传标签表达式、§5.2 说参数就是 task_id），
    两种都收比强迫调用方记住哪一种更省事。
    """
    if tag is None:
        return None
    value = tag.strip()
    if not value:
        return None
    prefix = f"{TASK_ID_LABEL}="
    return value[len(prefix) :] if value.startswith(prefix) else value


def _decode(raw: bytes | None) -> str:
    """bytes → str，并截断。

    截断保留**尾部**：探针的响应特征（nonce / HTTP 状态行）总是最后输出的，
    砍掉尾巴等于把最有用的部分扔掉。
    """
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    if len(text) <= MAX_CAPTURE_CHARS:
        return text
    dropped = len(text) - MAX_CAPTURE_CHARS
    return f"...(前 {dropped} 字符已截断)...\n{text[-MAX_CAPTURE_CHARS:]}"


def _container_id(container: Any) -> str:
    return str(getattr(container, "id", "") or "")


def _short(container_id: str) -> str:
    """日志里只打 12 位短 id，与 `docker ps` 一致，便于人眼对照。"""
    return container_id[:12] or "<unknown>"


__all__ = ["SandboxService", "build_docker_client"]
