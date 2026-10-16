"""B2 沙箱生命周期测试 —— **不连 Docker**。

沙箱是「不可信代码唯一的执行通道」，所以本文件与 B1 的 `test_archive_safety.py`
同等地位：验证的不是「功能对不对」，而是**容器一定会被清掉**、**配额一定真的传下去了**、
**Docker 挂了不会把整个评估带走**。

不连真 Docker 的理由有两条，缺一不可：
1. 本机没有 Docker，而把远程 ECS 的连通性变成单测的依赖，等于让 CI 看网络脸色；
2. 真正要验的是「调用序列」与「传给 SDK 的 kwargs」—— 假 client 能把这两样
   精确记下来，真容器反而只能间接推断（容器删没删还要另跑 `docker ps`）。

`SandboxService` 因此接受注入的 client：**可注入不是为了好看，是这个模块唯一可测的形态**。
"""

from __future__ import annotations

from typing import Any

import docker
import pytest
import requests

from app.sandbox import service as service_mod
from app.sandbox.errors import SandboxImageMissingError, SandboxUnavailableError
from app.sandbox.ports import ContainerSpec
from app.sandbox.service import SandboxService

# ---------------------------------------------------------------------------
# 假 Docker：只实现被调用到的方法，把所有调用与 kwargs 原样记下来
# ---------------------------------------------------------------------------


class FakeContainer:
    def __init__(
        self,
        client: FakeDocker | None = None,
        cid: str = "c0ffee000000",
        *,
        labels: dict[str, str] | None = None,
        status: int = 0,
        start_error: Exception | None = None,
        wait_error: Exception | None = None,
        stdout: bytes = b"",
        stderr: bytes = b"",
        stats: dict[str, Any] | None = None,
    ) -> None:
        self._client = client
        self.id = cid
        self.labels = labels if labels is not None else {}
        self.status = status
        self.start_error = start_error
        self.wait_error = wait_error
        self.stdout = stdout
        self.stderr = stderr
        self.stats_payload = stats if stats is not None else {}
        self.waited_with: int | None = None

    def start(self) -> None:
        self._client.calls.append(f"start:{self.id}")
        if self.start_error is not None:
            raise self.start_error

    def wait(self, timeout: int | None = None) -> dict[str, Any]:
        self._client.calls.append(f"wait:{self.id}")
        self.waited_with = timeout
        if self.wait_error is not None:
            raise self.wait_error
        return {"StatusCode": self.status}

    def kill(self) -> None:
        self._client.calls.append(f"kill:{self.id}")

    def remove(self, force: bool = False, v: bool = False) -> None:
        self._client.calls.append(f"remove:{self.id}")

    def logs(self, stdout: bool = True, stderr: bool = True, tail: Any = "all") -> bytes:
        self._client.calls.append("logs")
        if stdout and not stderr:
            return self.stdout
        if stderr and not stdout:
            return self.stderr
        return self.stdout + self.stderr

    def stats(self, stream: bool = False) -> dict[str, Any]:
        self._client.calls.append("stats")
        return self.stats_payload


class FakeContainers:
    def __init__(self, client: FakeDocker) -> None:
        self._client = client

    def create(self, image: str, **kwargs: Any) -> FakeContainer:
        self._client.calls.append("create")
        # 记下**原样的** kwargs —— 「配额是否真的传下去了」全靠这里断言
        self._client.create_kwargs = {"image": image, **kwargs}
        if self._client.create_error is not None:
            raise self._client.create_error
        return self._client.next_container

    def list(self, all: bool = False, filters: Any = None) -> list[FakeContainer]:
        self._client.calls.append("list")
        self._client.list_filters = filters
        return list(self._client.orphans)

    def get(self, container_id: str) -> FakeContainer:
        self._client.calls.append("get")
        if self._client.get_error is not None:
            raise self._client.get_error
        return self._client.next_container


class FakeDocker:
    """记录调用序列的假客户端。**刻意不继承** `docker.DockerClient`。

    不继承才有意义：继承会把真实 SDK 的行为悄悄带进来，
    于是「测过」的东西从我们的代码变成了 docker-py 的实现细节。
    """

    def __init__(
        self,
        *,
        ping_error: Exception | None = None,
        create_error: Exception | None = None,
        get_error: Exception | None = None,
        orphans: list[FakeContainer] | None = None,
        **container_kwargs: Any,
    ) -> None:
        self.calls: list[str] = []
        self.ping_error = ping_error
        self.create_error = create_error
        self.get_error = get_error
        self.orphans: list[FakeContainer] = list(orphans or [])
        self.create_kwargs: dict[str, Any] = {}
        self.list_filters: Any = None
        self.containers = FakeContainers(self)
        self.next_container = (
            self.orphans[0] if self.orphans else FakeContainer(self, **container_kwargs)
        )
        # 假对象的内部接线，与业务代码无关
        for orphan in self.orphans:
            orphan._client = self

    def ping(self) -> None:
        self.calls.append("ping")
        if self.ping_error is not None:
            raise self.ping_error

    def close(self) -> None:
        self.calls.append("close")


def make_spec(**overrides: Any) -> ContainerSpec:
    base: dict[str, Any] = {
        "image": "asa/sandbox-base:latest",
        "command": ["python", "-c", "print(1)"],
        "source_mount": "/srv/asa/tasks/42/src",
        "workdir": "/workspace",
        "env": {"PYTHONUNBUFFERED": "1"},
        "cpu_limit": 0.5,
        "memory_limit_mb": 256,
        "timeout_seconds": 30,
    }
    base.update(overrides)
    return ContainerSpec(**base)


def calls_of(client: FakeDocker, prefix: str) -> list[str]:
    return [c for c in client.calls if c.startswith(prefix)]


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """把重试退避压成 0 —— 否则不可达用例要真睡 1+2 秒。"""
    monkeypatch.setattr(service_mod, "PING_BACKOFF_BASE_SECONDS", 0.0)


# ---------------------------------------------------------------------------
# 清理语义：无论成败都必须删容器
# ---------------------------------------------------------------------------


async def test_timeout_force_kills_and_still_removes() -> None:
    """超时到点：强杀 + **仍然删除容器**。

    两件事都要断言。只杀不删是最危险的那种半成品 —— 容器停在 Exited 状态，
    看起来「没在跑」，但它仍占着容器名与写层磁盘；下一次同名创建会失败，
    而错误信息指向「容器名冲突」，让人去查一个根本不存在的并发问题。
    """
    client = FakeDocker(wait_error=requests.exceptions.ReadTimeout("read timed out"))

    result = await SandboxService(client).run_once(make_spec(timeout_seconds=5))

    assert result.timed_out is True
    assert result.exit_code == -1  # 负数 = 非正常退出（契约 1）
    assert client.next_container.waited_with == 5  # 超时值确实传给了 wait
    assert calls_of(client, "kill"), "超时必须强杀，否则容器会一直跑到天荒地老"
    assert calls_of(client, "remove"), "超时路径同样要删容器 —— 否则就是孤儿"
    # 顺序：先 kill 再 remove。反过来的话 force remove 会顺手杀，
    # 但那意味着「强杀」这一步实际没被验证到
    assert client.calls.index(f"kill:{client.next_container.id}") < client.calls.index(
        f"remove:{client.next_container.id}"
    )


async def test_start_failure_still_removes_container() -> None:
    """启动失败（端口冲突 / 配额被拒）也删容器，不留孤儿。

    这条分支最容易漏：容器是**创建成功之后**才启动失败的，
    所以它是「已经存在但没用过」的状态 —— 不删就是永久残留。
    """
    client = FakeDocker(start_error=docker.errors.APIError("port is already allocated"))

    with pytest.raises(SandboxUnavailableError):
        await SandboxService(client).run_once(make_spec())

    assert calls_of(client, "remove"), "启动失败后容器必须被删掉"


async def test_image_missing_is_precise_and_leaves_no_container() -> None:
    """镜像不存在：给出可执行的修复指引，而不是一个笼统的「沙箱挂了」。

    容器**从未被创建**（create 就失败了），所以这里断言的是「没有孤儿」这一事实本身，
    而不是 remove 被调用 —— 断言一个不会发生的事件只会让用例看起来对、实际没测到。
    """
    client = FakeDocker(create_error=docker.errors.ImageNotFound("no such image"))

    with pytest.raises(SandboxImageMissingError) as excinfo:
        await SandboxService(client).run_once(make_spec(image="asa/gone:latest"))

    assert calls_of(client, "start") == []
    assert "Dockerfile" in excinfo.value.remediation
    assert excinfo.value.retryable is False  # 镜像不会因为再试一次就出现


async def test_normal_nonzero_exit_is_a_result_not_an_exception() -> None:
    """容器内命令非零退出是**业务路径**（E10），不是基础设施故障。

    它与「沙箱不可用」必须严格分开：混在一起的话，Docker 连不上时 B5 会把每条漏洞
    都记成一次「验证失败」，而正确结论是「这一阶段根本没验」。
    """
    client = FakeDocker(status=1, stdout=b"boom\n", stderr=b"traceback\n")

    result = await SandboxService(client).run_once(make_spec())

    assert result.exit_code == 1
    assert result.timed_out is False
    assert result.stdout == "boom\n"
    assert result.stderr == "traceback\n"
    assert calls_of(client, "remove"), "正常失败路径也要清容器"
    assert calls_of(client, "kill") == [], "没超时就不该强杀"


# ---------------------------------------------------------------------------
# 降级：Docker 不可达 ≠ 评估崩掉
# ---------------------------------------------------------------------------


async def test_unreachable_signals_instead_of_crashing() -> None:
    """Docker 不可达：返回「不可用」信号，且**不产生任何容器操作**。

    - `is_available()` 用于启动前探活：返回布尔，不抛；
    - `run_once()` 抛的是**有类型的** `SandboxUnavailableError`（继承 core 的
      `SandboxUnreachableError`，带 error_code / remediation / retryable 四要素），
      B3 `except SandboxUnavailableError` 就能把 `poc_verify` 标 `skipped` 并继续。

    断言「create 没被调用」同样重要：连不上时不建容器，才不会有「建了一半的孤儿」
    需要人来收拾。
    """
    client = FakeDocker(ping_error=docker.errors.DockerException("ssh: connect timed out"))
    service = SandboxService(client)

    assert await service.is_available() is False

    with pytest.raises(SandboxUnavailableError) as excinfo:
        await service.run_once(make_spec())

    assert excinfo.value.retryable is True
    assert excinfo.value.error_code == "SANDBOX_UNREACHABLE"
    assert excinfo.value.remediation  # §9.2 要求每个错误自带修复指引
    assert calls_of(client, "create") == []
    assert calls_of(client, "remove") == []
    assert len(calls_of(client, "ping")) >= 3  # E1：执行路径上重试 3 次才判死


async def test_missing_ssh_dependency_is_converted_not_propagated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """缺 paramiko 时 docker-py 抛的是 `ModuleNotFoundError`，**不是** `DockerException`。

    这是实测出来的分界（`docker/transport/sshconn.py` 顶部无条件 `import paramiko`，
    而 `DockerClient` 只在 `ssh://` 分支里导入它）。只 catch DockerException 的话，
    这个 ImportError 会一路穿透到编排层，把「沙箱用不了」变成「整轮评估崩掉」——
    与契约要求的降级语义正好相反。
    """
    monkeypatch.setattr(service_mod.settings, "docker_host", "ssh://root@sandbox.invalid")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise ModuleNotFoundError("No module named 'paramiko'")

    monkeypatch.setattr(service_mod.docker, "DockerClient", boom)

    with pytest.raises(SandboxUnavailableError) as excinfo:
        service_mod.build_docker_client()

    assert "paramiko" in excinfo.value.remediation  # 缺什么就让人装什么
    assert excinfo.value.error_code == "SANDBOX_UNREACHABLE"


async def test_permanent_unavailability_is_not_retried() -> None:
    """客户端**压根没构造出来** → 不重试。

    重试是给 ssh 抖动准备的（见上一个用例）；缺依赖 / DOCKER_HOST 为空是永久故障，
    重试三次只是把一个确定的错误拖成三倍等待，还要多写两条误导人的 WARN 日志。
    """
    client = FakeDocker(ping_error=SandboxUnavailableError("缺少 ssh:// 传输的依赖"))

    with pytest.raises(SandboxUnavailableError):
        await SandboxService(client).run_once(make_spec())

    assert len(calls_of(client, "ping")) == 1


async def test_unreachable_recovers_within_retries() -> None:
    """E1 的正面用例：抖两次、第三次通了，就不该判死。

    只测「重试 3 次后放弃」会漏掉真正想保住的东西 —— 一次 ssh 抖动
    不该让整个 `poc_verify` 白跳过。
    """

    class Flaky(FakeDocker):
        def ping(self) -> None:
            self.calls.append("ping")
            if len(self.calls) < 3:
                raise docker.errors.DockerException("connection reset by peer")

    client = Flaky()
    result = await SandboxService(client).run_once(make_spec())

    assert result.exit_code == 0
    assert len(calls_of(client, "ping")) == 3
    assert calls_of(client, "remove")


# ---------------------------------------------------------------------------
# 孤儿回收：绝不误伤同机的其他服务
# ---------------------------------------------------------------------------


async def test_reap_only_touches_managed_containers() -> None:
    """只删 `asa.managed=true` 的容器（设计 T13）。

    同一台 ECS 上还有 Milvus、MySQL、Redis 和一个未知的 :8000。
    这里刻意让假 client **无视服务端过滤条件**返回一个外来容器 ——
    目的是验证我们收到结果后又自己复核了一遍标签。只依赖服务端过滤的话，
    过滤器一旦因 API 版本差异失效，代价是删掉别人的容器，而删除没有事务能回滚。
    """
    orphan = FakeContainer(cid="a1", labels={"asa.managed": "true", "asa.task_id": "42"})
    foreign = FakeContainer(cid="f0", labels={"com.docker.compose.project": "milvus"})
    client = FakeDocker(orphans=[orphan, foreign])

    reaped = await SandboxService(client).reap_orphans()

    assert reaped == 1
    assert calls_of(client, "remove:a1")
    assert calls_of(client, "remove:f0") == []
    assert client.list_filters == {"label": "asa.managed=true"}


async def test_reap_skips_in_flight_container() -> None:
    """在途容器不是孤儿：`_active` 里的 id 必须跳过，否则会杀掉正在跑的探针。"""
    running = FakeContainer(cid="live", labels={"asa.managed": "true"})
    client = FakeDocker(orphans=[running])
    service = SandboxService(client)
    service._active.add("live")  # 模拟一次尚未完成的 run_once

    assert await service.reap_orphans() == 0
    assert calls_of(client, "remove:live") == []


async def test_reap_honours_task_tag_and_survives_single_failure() -> None:
    """按 task 回收；单条删除失败只跳过（E14 可忽略），不影响其它容器。"""
    kept = FakeContainer(cid="b1", labels={"asa.managed": "true", "asa.task_id": "43"})
    victim = FakeContainer(cid="b2", labels={"asa.managed": "true", "asa.task_id": "42"})
    broken = FakeContainer(cid="b3", labels={"asa.managed": "true", "asa.task_id": "42"})
    client = FakeDocker(orphans=[kept, victim, broken])

    def explode(force: bool = False, v: bool = False) -> None:
        client.calls.append(f"remove:{broken.id}")
        raise docker.errors.APIError("driver failed")

    broken.remove = explode  # type: ignore[method-assign]

    # 设计文档两处写法不一致（"42" 与 "asa.task_id=42"），两种都要能收
    reaped = await SandboxService(client).reap_orphans("asa.task_id=42")

    assert reaped == 1
    assert calls_of(client, "remove:b1") == []
    assert calls_of(client, "remove:b2")
    assert calls_of(client, "remove:b3")  # 试过了，失败被吞掉
