"""B2 ↔ B5 的接口契约（`模块间契约.md` 契约 1 的落点）。

**为什么是 `Protocol` 而不是让 B5 直接 import `SandboxService`**：B5 只需要「跑一个
容器、拿回结果」这一件事。让它依赖完整的沙箱服务，意味着 B2 换实现（Docker SDK →
containerd → 本地进程沙箱）会牵动 B5 一起改。**依赖倒置在这里不是洁癖，是因为这两个
模块的开发节奏天然不同** —— B2 要调远程 Docker API，B5 只管协议。

**本文件的字段名、类型、默认值一字不差地照抄契约 1，不要「顺手优化」**：
它是 B2/B5 并行开发时的兼容性锚点，改一个字段名，症状是「两个模块各自跑得通、
拼起来 `AttributeError`」，而两边单独看都没错，极难定位。若确实要改，先改契约文档。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ExecResult:
    """一次容器执行的结果。

    **非零退出、超时、被抢占一律用本对象表达，不走异常**（B2 模块设计 §3.1）：
    容器内的命令失败是「业务路径」，不是系统故障；只有基础设施故障（SSH 断、
    daemon 不可达）才抛异常。这样 B5 的探针循环可以写成一条直线，
    不必在每一步外面套 try —— 也就不会因为异常穿透而回滚未提交的事务。
    """

    #: 超时或被信号杀死时为负数
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool


@dataclass(frozen=True, slots=True)
class ContainerSpec:
    """一次沙箱执行的全部输入。**四类：镜像 + 挂载 + 配额 + 命令。**

    `frozen=True` 是刻意的：spec 会被在途的 `run_once` 反复读取（建容器、起容器、
    算超时），中途被改一个 `timeout_seconds` 会让「为什么这个容器跑了 60 秒」
    变成一个需要翻调用栈才能解释的问题。要改就 `dataclasses.replace()` 出一个新对象。
    """

    #: 如 asa/sandbox-base:latest
    image: str
    #: 容器内执行的命令（argv 列表，不经 shell 解析）
    command: list[str]
    #: **宿主侧**绝对路径（ECS 上），只读挂载。bind mount 由**远端 daemon** 解析，
    #: 所以源码必须已在 ECS 侧（依赖 B1 的源码同步，总纲 §12.2 Q23 定案 = 方案 A）。
    source_mount: str
    #: 容器内工作目录
    workdir: str
    env: dict[str, str]
    #: 核数，如 1.0 → nano_cpus=1_000_000_000
    cpu_limit: float
    memory_limit_mb: int
    timeout_seconds: int
    #: 默认无出网。**默认值本身就是安全边界**：闸门 1 要求载荷不能外连。
    network_disabled: bool = True
    #: 默认只读根。容器无法回写源码，也留不下持久化的进程外状态。
    read_only_root: bool = True


class Sandbox(Protocol):
    """B5 眼中的沙箱 —— 只有两个方法。

    **`run_once` 的语义（调用方不必自己清理）**：建容器 → 启动 →
    等结束（到 `spec.timeout_seconds` 强杀）→ 收集 stdout / stderr / 退出码 →
    **无论成败都删除容器**。也就是说调用方**不需要、也不应该**再调任何 destroy ——
    契约里根本没有这个方法，就是为了让「容器泄漏」在类型层面无法表达。
    """

    async def run_once(self, spec: ContainerSpec) -> ExecResult: ...

    async def stats(self, container_id: str) -> tuple[float, float]:
        """(cpu%, 内存MB)。**尽力而为**：采不到就返回 (0.0, 0.0)，不抛异常。"""
        ...
