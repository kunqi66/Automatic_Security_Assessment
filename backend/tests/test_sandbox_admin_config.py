"""管理页沙箱配置 → 引擎参数的映射（`verify.types.SandboxConfig.from_admin_config`）。

**为什么单独一个文件**：这条映射是「管理页改的东西真的生效吗」的**唯一接缝**。
它一旦写错，症状分两种，都不报错：

- 少映射一个字段 → 管理员改了、存进去了、审计也留痕了，**引擎用的还是旧值**；
- 多映射一个字段 → 引擎开始读一个**从来没人打算让它读**的东西（比如网络模式），
  那是一个安全后果，不是一个显示问题。

所以这里逐条钉死「映射了什么」和「**刻意没映射什么**」。

不连 MySQL：`from_admin_config` 收的是鸭子类型对象，本文件自造一个就够。
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.verify.types import SandboxConfig


@dataclass
class _FakeRow:
    """`sandbox_configs` 表那一行的替身。字段与 ORM 模型一一对应。"""

    id: int = 1
    name: str = "默认沙箱"
    base_image: str = "asa/sandbox-base:latest"
    network_policy: str = "internal"
    timeout_seconds: int = 30
    max_concurrency: int = 1
    cpu_limit: float = 0.5
    memory_limit_mb: int = 256
    is_default: bool = True


def test_maps_the_fields_that_actually_take_effect() -> None:
    """四个字段必须**逐个**映射到位。少一个就是「改了不生效」。"""
    cfg = SandboxConfig.from_admin_config(
        _FakeRow(
            base_image="asa/sandbox-base:custom",
            cpu_limit=2.0,
            memory_limit_mb=4096,
            timeout_seconds=120,
        )
    )

    assert cfg.preset_image == "asa/sandbox-base:custom"
    assert cfg.cpu_limit == 2.0
    assert cfg.memory_limit_mb == 4096
    # 列名叫 timeout_seconds，引擎侧的字段叫 probe_timeout_s —— 名字不同、语义相同，
    # 正是这种改名最容易在重构时被漏掉。
    assert cfg.probe_timeout_s == 120


def test_does_not_touch_fields_the_row_has_no_business_setting() -> None:
    """行里没有的字段，必须保持引擎自己的默认值。

    这条防的是「顺手把整行 dict 展开进去」这种写法：它会让 `max_probes_per_vuln`
    与 `container_timeout_s` 跟着某次 schema 改动一起漂移，而这两个数是有账的
    （见 `SandboxConfig` 上的注释：20 探针 × 30s + 部署 + 余量 = 720s）。
    """
    cfg = SandboxConfig.from_admin_config(_FakeRow())

    assert cfg.max_probes_per_vuln == 20
    assert cfg.container_timeout_s == 720
    assert cfg.target_port == 5000
    assert cfg.app_entry == "app.py"


def test_network_policy_from_the_row_cannot_relax_the_sandbox() -> None:
    """**安全断言**：数据库里的 `network_policy` 无论是什么，都进不了引擎。

    容器恒为 `network_disabled=True`（`verify/runner.py`），这与 `allowed_hosts`
    一样是**不变量而不是配置项**。写入侧的 `_guard_network` 会拒掉 `bridge`，
    但那只是第一道；真正兜底的是这里 —— 引擎的参数视图里**根本没有**一个
    能表达网络模式的字段，所以就算有人绕开接口直接改库，也改不出网。

    这条断言用的是**结构性**判据（`hasattr`）而不是值比较：值比较只能证明
    「这次没被改」，结构判据证明的是「没有被改的途径」。
    """
    for policy in ("none", "internal", "bridge", "whatever", None):
        cfg = SandboxConfig.from_admin_config(_FakeRow(network_policy=policy))

        assert not hasattr(cfg, "network_policy"), f"{policy!r} 竟然映射出了网络模式字段"
        # 回环白名单是硬白名单，任何来源的行都不该动它。
        assert cfg.allowed_hosts == frozenset({"127.0.0.1", "localhost", "::1"})


def test_max_concurrency_is_not_mapped() -> None:
    """`max_concurrency` 同样不进引擎。

    调度并发由 worker 固定为 1（总纲 §8.1），引擎侧没有对应的执行参数。
    把它映射进来会让人以为「改这个数能提高吞吐」，而实际不会 —— 又一个假控件。
    """
    cfg = SandboxConfig.from_admin_config(_FakeRow(max_concurrency=8))

    assert not hasattr(cfg, "max_concurrency")


def test_row_object_is_not_retained() -> None:
    """映射结果是**值拷贝**，不是对那一行的引用。

    引擎会把它放进上下文带一路。若持有 ORM 行，一次会话结束后的惰性加载
    会在某个不相干的时刻抛 `DetachedInstanceError` —— 那种错最难查。
    """
    row = _FakeRow()
    cfg = SandboxConfig.from_admin_config(row)

    row.cpu_limit = 99.0  # 改原对象

    assert cfg.cpu_limit == 0.5


def test_falls_back_cleanly_when_row_has_a_bad_value() -> None:
    """行里的值越界时**抛错**，而不是悄悄截断。

    调用方（`engine._resolve_sandbox_config`）捕获后回落到全局设置，并留一条
    警告日志。返回一个「修正过的」值会掩盖配置错误 —— 而这里掩盖的代价特别大：
    `memory_limit_mb=0` 在 Docker 里是**不限内存**，在一个无 swap 的机器上
    等于放一个能吃光全部内存的容器出来。
    """
    with pytest.raises(ValueError):
        SandboxConfig.from_admin_config(_FakeRow(memory_limit_mb=0))

    with pytest.raises(ValueError):
        SandboxConfig.from_admin_config(_FakeRow(cpu_limit=0.0))

    with pytest.raises(ValueError):
        SandboxConfig.from_admin_config(_FakeRow(timeout_seconds=0))


def test_rejects_a_row_that_is_missing_the_image() -> None:
    """行里没有镜像时抛 `AttributeError`（鸭子类型的代价），由调用方一并兜住。

    这条钉的是「降级路径真的会被走到」：`engine` 捕的是 `(TypeError, ValueError)`，
    而属性缺失抛的是 `AttributeError` —— 两者都要被兜住，否则一个字段被改名
    就能让每一次评估在 `poc_verify` 崩掉，而报错信息指向的是引擎不是配置。
    """
    with pytest.raises(AttributeError):
        SandboxConfig.from_admin_config(object())
