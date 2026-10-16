"""B2 契约与安全默认值测试。

`test_sandbox_lifecycle.py` 验的是「容器会不会被清掉」；本文件验的是**默认值本身**。

为什么要专门为「默认值」写测试：`ContainerSpec` 的两个默认值是整个沙箱安全模型的
承重点 —— `network_disabled=True`（闸门 1：载荷不能外连）与 `read_only_root=True`
（容器不能回写源码）。它们**一旦被人改成 `False`，所有现有测试都会继续通过**，
因为改的是「不传就该这样」的那一侧，而调用方大多不显式传这两个字段。
只有直接断言 dataclass 的默认值才能挡住这种改动。这类「静默变松」的安全回归
是审查里最难发现的。
"""

from __future__ import annotations

import dataclasses
import inspect
from typing import Any

import pytest
from test_sandbox_lifecycle import FakeDocker, make_spec

from app.core.exceptions import SandboxUnreachableError
from app.sandbox import service as service_mod
from app.sandbox.errors import (
    SandboxDiskFullError,
    SandboxImageMissingError,
    SandboxUnavailableError,
)
from app.sandbox.metrics import compute_cpu_percent, compute_memory_mb
from app.sandbox.ports import ContainerSpec, ExecResult, Sandbox
from app.sandbox.service import SandboxService

_MB = 1024 * 1024


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_mod, "PING_BACKOFF_BASE_SECONDS", 0.0)


# ---------------------------------------------------------------------------
# 安全默认值：必须是最严的一侧
# ---------------------------------------------------------------------------


def test_container_spec_defaults_are_the_strictest_side() -> None:
    """**直接断言 dataclass 的默认值**，而不是断言某个调用点的行为。

    断言行为的话，把默认改成 `False` 之后，只要测试里的 spec 显式传了 `True`，
    用例照样绿 —— 而被漏掉的恰恰是「没显式传」的真实调用点。
    """
    fields = {f.name: f for f in dataclasses.fields(ContainerSpec)}

    assert fields["network_disabled"].default is True, "默认必须无出网（闸门 1）"
    assert fields["read_only_root"].default is True, "默认必须只读根（不可回写源码）"


def test_container_spec_strict_defaults_apply_when_omitted() -> None:
    """不传这两个字段时，实例上确实是最严的一侧。"""
    spec = make_spec()

    assert spec.network_disabled is True
    assert spec.read_only_root is True


def test_container_spec_is_frozen() -> None:
    """spec 不可变：它会被在途的 `run_once` 反复读，中途改一个 timeout 会让
    「这个容器为什么跑了 60 秒」变成需要翻调用栈才能解释的问题。"""
    spec = make_spec()

    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.timeout_seconds = 999  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 契约 1：ContainerSpec / ExecResult / Sandbox 的字段与协议
# ---------------------------------------------------------------------------


def test_exec_result_field_names_match_contract() -> None:
    """契约 1 的字段名是 B2/B5 的兼容性锚点，改名 = 拼起来 AttributeError。"""
    assert [f.name for f in dataclasses.fields(ExecResult)] == [
        "exit_code",
        "stdout",
        "stderr",
        "duration_ms",
        "timed_out",
    ]


def test_sandbox_protocol_exposes_exactly_two_operations() -> None:
    """契约里**没有** destroy / expose —— 清理是 `run_once` 的内部语义。

    这条断言是防「顺手加方法」的：一旦 `Sandbox` 上出现 destroy，
    调用方就会开始自己管理生命周期，然后漏掉某一条出口。
    """
    assert {name for name in dir(Sandbox) if not name.startswith("_")} == {
        "run_once",
        "stats",
    }


def test_sandbox_service_structurally_satisfies_protocol() -> None:
    """B2 的实现必须**结构化**满足契约（不显式继承），参数名也要一致 ——
    调用方用关键字参数调用时，参数名就是契约的一部分。"""
    run_sig = inspect.signature(SandboxService.run_once)
    stats_sig = inspect.signature(SandboxService.stats)

    assert list(run_sig.parameters) == ["self", "spec"]
    assert list(stats_sig.parameters) == ["self", "container_id"]
    # 全异步：Docker SDK 是同步的，任何一处漏掉 `asyncio.to_thread` 都会
    # 在容器等待期间冻住整个事件循环（含 SSE 心跳）
    assert inspect.iscoroutinefunction(SandboxService.run_once) is True
    assert inspect.iscoroutinefunction(SandboxService.stats) is True


# ---------------------------------------------------------------------------
# 资源配额必须真的落到 docker SDK 的参数上
# ---------------------------------------------------------------------------


async def test_run_once_passes_resource_limits_to_docker() -> None:
    """配额不是注释里的承诺，必须出现在真正调 SDK 的 kwargs 上。

    假 client 把 `containers.create(**kwargs)` 原样记下来，这里逐个断言。
    最容易被漏掉的是 `memswap_limit`：只设 `mem_limit` 时，容器可以吃掉**等量**的
    swap，「256M 上限」实际能占 512M —— 在 0 swap 的 ECS 上表现是**整机**卡死，
    而不是这个容器被 OOM 掉，内存限制等于没有。
    """
    client = FakeDocker()

    await SandboxService(client).run_once(
        make_spec(cpu_limit=0.5, memory_limit_mb=256, timeout_seconds=30)
    )

    kwargs: dict[str, Any] = client.create_kwargs
    assert kwargs["image"] == "asa/sandbox-base:latest"

    # 0.5 核 → 5e8 nano_cpus（设计 §3.3 的取值）
    assert kwargs["nano_cpus"] == 500_000_000
    assert kwargs["mem_limit"] == 256 * _MB
    assert kwargs["memswap_limit"] == 256 * _MB
    assert kwargs["memswap_limit"] == kwargs["mem_limit"], (
        "memswap 必须一起限，否则内存上限形同虚设"
    )
    assert kwargs["pids_limit"] == 128, "fork 炸弹要在内核 cgroup 层被拦停"

    # 只读根 + 受控 tmpfs：/tmp 是容器内唯一的可写处，且 noexec
    # （写进来的二进制不能直接执行）。刻意不写字面量 "/tmp" ——
    # 断言要和 service 里的常量对得上，改了一处而另一处没改才会被发现。
    assert kwargs["read_only"] is True
    assert set(kwargs["tmpfs"]) == set(service_mod.TMPFS_MOUNTS)
    assert "noexec" in next(iter(service_mod.TMPFS_MOUNTS.values()))

    # 网络与挂载：闸门 1 的容器侧强制
    assert kwargs["network_disabled"] is True
    assert kwargs["volumes"] == {"/srv/asa/tasks/42/src": {"bind": "/workspace", "mode": "ro"}}

    # 权限最小化
    assert kwargs["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in kwargs["security_opt"]

    # 不传 tty：docker-py 只在非 TTY 时才解复用日志流，传了 tty 会把
    # stdout/stderr 混成一坨，ExecResult 就再也分不开了
    assert "tty" not in kwargs
    assert kwargs["detach"] is True


async def test_illegal_quota_falls_back_to_safe_defaults() -> None:
    """E4（L2 可降级）：非法配额回落到默认值并继续，而不是让整轮评估失败。"""
    client = FakeDocker()
    spec = make_spec(cpu_limit=-1.0, memory_limit_mb=0, timeout_seconds=0)

    result = await SandboxService(client).run_once(spec)

    assert result.exit_code == 0  # 没有抛异常 = 降级成功
    kwargs = client.create_kwargs
    assert kwargs["mem_limit"] == service_mod.DEFAULT_MEMORY_LIMIT_MB * _MB
    assert kwargs["nano_cpus"] == int(service_mod.DEFAULT_CPU_LIMIT * 1_000_000_000)
    assert client.next_container.waited_with == service_mod.settings.sandbox_exec_timeout_seconds


async def test_oversized_timeout_falls_back() -> None:
    """单位写错（秒/毫秒）是最常见的一类：30_000 秒的容器会把阶段超时拖穿。"""
    client = FakeDocker()
    await SandboxService(client).run_once(make_spec(timeout_seconds=30_000))

    assert client.next_container.waited_with == service_mod.settings.sandbox_exec_timeout_seconds


# ---------------------------------------------------------------------------
# 指标归一化（纯函数，不需要 Docker 就能验）
# ---------------------------------------------------------------------------


def test_cpu_percent_is_normalized_to_a_single_core() -> None:
    """`Δcpu_usage / Δsystem_cpu_usage * 100`，**不乘核数**。

    口径必须是「占满一核 = 100」。乘上核数（docker CLI 的算法）的话，
    `nano_cpus=0.5` 的容器拉满会显示成 50×N，与「0.5 核上限 → 峰值约 50」的约定
    对不上，图也没法看。这里 Δcpu=5e8、Δsystem=1e9 → 恰好 50.0。
    """
    stats = {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 2_000_000_000},
            "system_cpu_usage": 10_000_000_000,
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 1_500_000_000},
            "system_cpu_usage": 9_000_000_000,
        },
    }
    assert compute_cpu_percent(stats) == 50.0


def test_memory_subtracts_page_cache() -> None:
    """不扣 cache 的话，容器读几个大文件就能把「内存曲线」画成一条假的顶格直线，
    E9 的 OOM 判定（exit 137 + 内存触顶）也跟着误报 ——
    而 page cache 在内核有压力时随时可回收，它不算「用了」。"""
    v1 = {"memory_stats": {"usage": 300 * _MB, "stats": {"cache": 44 * _MB}}}
    v2 = {"memory_stats": {"usage": 300 * _MB, "stats": {"inactive_file": 50 * _MB}}}

    assert compute_memory_mb(v1) == 256.0
    assert compute_memory_mb(v2) == 250.0


def test_metrics_survive_missing_or_first_sample() -> None:
    """首次采样时 `precpu_stats` 与 `cpu_stats` 都可能缺席（daemon 只有一次读数）——
    这是「不可计算」而不是「错误」，返回 0 而不是抛。"""
    assert compute_cpu_percent({}) == 0.0
    assert compute_memory_mb({}) == 0.0
    assert compute_cpu_percent({"cpu_stats": {}, "precpu_stats": {}}) == 0.0
    # 计数器回绕 / 重启后 precpu 比 cpu 还大：差值为负，同样按不可计算处理
    assert (
        compute_cpu_percent(
            {
                "cpu_stats": {"cpu_usage": {"total_usage": 1}, "system_cpu_usage": 1},
                "precpu_stats": {"cpu_usage": {"total_usage": 9}, "system_cpu_usage": 9},
            }
        )
        == 0.0
    )


async def test_stats_degrades_to_zero_instead_of_raising() -> None:
    """E12（L1 可忽略）：采不到样返回 `(0.0, 0.0)`，绝不抛。

    观测数据可以丢，评估不能因为采不到样而停。返回 0.0 而不是 None 是契约定的
    （`stats -> tuple[float, float]`），代价是「0.0」有歧义，调用方需自行接受。
    """
    client = FakeDocker(get_error=RuntimeError("stats endpoint exploded"))

    assert await SandboxService(client).stats("c0ffee000000") == (0.0, 0.0)


async def test_stats_reads_the_contract_tuple() -> None:
    client = FakeDocker(
        stats={
            "cpu_stats": {
                "cpu_usage": {"total_usage": 1_000_000_000},
                "system_cpu_usage": 5_000_000_000,
            },
            "precpu_stats": {
                "cpu_usage": {"total_usage": 0},
                "system_cpu_usage": 0,
            },
            "memory_stats": {"usage": 128 * _MB, "stats": {"cache": 0}},
        }
    )

    cpu, memory = await SandboxService(client).stats("c0ffee000000")

    # 首帧：Δcpu=1e9、Δsystem=5e9 → 20%；内存 128MB
    assert (cpu, memory) == (20.0, 128.0)


# ---------------------------------------------------------------------------
# 「沙箱不可用」信号：一个族、一个判断点
# ---------------------------------------------------------------------------


def test_all_unavailable_errors_share_one_base_and_one_error_code() -> None:
    """B3 只需要 `except SandboxUnavailableError` 一处。

    三个子类各自带**不同的人该怎么修**（remediation），但错误码与基类相同 ——
    分成三个互不相干的异常只会让 B3 写三遍 except，然后漏掉第四个。
    """
    for cls in (SandboxImageMissingError, SandboxDiskFullError):
        err = cls("boom")
        assert isinstance(err, SandboxUnavailableError)
        assert isinstance(err, SandboxUnreachableError)  # core 的 503 / SANDBOX_UNREACHABLE
        assert err.error_code == "SANDBOX_UNREACHABLE"
        assert err.remediation  # §9.2 四要素：每个错误自带修复指引

    # 镜像缺失与磁盘满都不可重试：再试一次不会有不同的结果
    assert SandboxImageMissingError("x").retryable is False
    assert SandboxDiskFullError("x").retryable is False
    # 不可达本身可重试（E1 的退避重试就建立在这上面）
    assert SandboxUnavailableError("x").retryable is True


def test_disk_full_error_never_promises_automatic_prune() -> None:
    """修复指引里不能出现「系统会自动清理」—— 同机有 Milvus/MySQL/Redis，
    自动 prune 会误删别人的镜像，而删除没有事务能回滚。"""
    err = SandboxDiskFullError("boom")

    assert "维护窗口" in err.remediation
    assert "自动" in err.remediation  # 明确写出「刻意不自动 prune」


# ---------------------------------------------------------------------------
# 输出截断：靶场代码在验证语境下是不可信的
# ---------------------------------------------------------------------------


async def test_output_is_truncated_keeping_the_tail() -> None:
    """一个 `for` 循环 print 就能把控制面内存顶上去。

    截断保留**尾部**：探针的响应特征（nonce / HTTP 状态行）总是最后输出，
    砍掉尾巴等于把最有用的部分扔掉。
    """
    huge = b"A" * (service_mod.MAX_CAPTURE_CHARS + 4096) + b"\nNONCE-MATCHED\n"
    client = FakeDocker(stdout=huge)

    result = await SandboxService(client).run_once(make_spec())

    assert len(result.stdout) < len(huge)
    assert result.stdout.startswith("...(")
    assert result.stdout.endswith("NONCE-MATCHED\n")
