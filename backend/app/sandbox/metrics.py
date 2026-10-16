"""容器 stats 的单位归一化（B2 模块设计 §2.1 / §3.3）。

**为什么把这两个函数单独拎出来**：它们是本模块里**唯一的纯计算**，也是唯一
不依赖 Docker 就能验证的部分。远程 ECS 的连通性不该是单测的依赖，
所以把「从 stats 字典算出 cpu%/内存MB」抽成无副作用函数，用真实抓取过的
stats 结构直接单测 —— 而不是为了测公式去起一个真容器。

⚠️ Docker SDK **不做**这个换算：`container.stats(stream=False)` 原样返回 daemon 的
计数器（累计纳秒、累计字节），`docker stats` 命令里的百分比是 CLI 自己算的。
不自己算就只能显示一串没有量纲的整数。
"""

from __future__ import annotations

from typing import Any

_MB = 1024 * 1024


def _as_int(value: Any) -> int:
    """daemon 的计数字段正常是 int，但协商失败时会缺字段或给 None。"""
    if isinstance(value, bool):  # bool 是 int 的子类，先挡掉
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    return 0


def _dig(data: Any, *keys: str) -> Any:
    """按路径取值，任一层缺失返回 None —— stats 的结构随 cgroup v1/v2 与 API 版本变化。"""
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def compute_cpu_percent(stats: dict[str, Any]) -> float:
    """把 daemon 的累计计数器差分成**单核归一化**的 CPU 使用率（0–100+）。

    公式是 `Δcpu_usage / Δsystem_cpu_usage * 100`。

    **刻意不乘核数**：`docker stats` 的算法是 `Δcpu/Δsystem * 核数 * 100`，得到的是
    「占满几核」。而本系统给容器的上限是 `nano_cpus=0.5e9`（半核），按 CLI 的口径
    0.5 核拉满会显示成 `50 * N`，与「0.5 核上限 → 峰值约 50」的约定对不上，
    图表也没法复用。归一化到单核后，「100 = 用满一核」是唯一需要记住的口径。
    """
    cpu_delta = _as_int(_dig(stats, "cpu_stats", "cpu_usage", "total_usage")) - _as_int(
        _dig(stats, "precpu_stats", "cpu_usage", "total_usage")
    )
    system_delta = _as_int(_dig(stats, "cpu_stats", "system_cpu_usage")) - _as_int(
        _dig(stats, "precpu_stats", "system_cpu_usage")
    )
    # 首次采样时 precpu_stats 为空（daemon 只有一次读数），差值为 0 或负数；
    # 这不是错误，就是一个不可计算的点，返回 0 而不是抛
    if cpu_delta <= 0 or system_delta <= 0:
        return 0.0
    return round(cpu_delta / system_delta * 100.0, 2)


def compute_memory_mb(stats: dict[str, Any]) -> float:
    """容器内存占用（MB），**扣掉 page cache**。

    不扣的后果：容器只是读了几个大文件，`usage` 就能贴着 mem_limit 顶格，
    于是「内存曲线」变成一条假的 100% 直线，OOM 判定（E9：exit 137 + 内存触顶）
    也就跟着误报 —— 而 page cache 在内核压力下是可以随时回收的，它不算「用了」。

    cgroup v1 的字段叫 `cache`，v2 叫 `inactive_file`，两个都要认：
    ECS 的 Docker 版本一变，字段名就换了，而缺字段的默认值是 0（不扣减）。
    """
    usage = _as_int(_dig(stats, "memory_stats", "usage"))
    detail = _dig(stats, "memory_stats", "stats") or {}
    cache = _as_int(detail.get("cache")) or _as_int(detail.get("inactive_file"))
    return round(max(usage - cache, 0) / _MB, 2)
