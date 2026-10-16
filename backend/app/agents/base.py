"""`BaseAgent` 抽象 —— 五个 Agent 的共同父类（B3 设计 §2、PRD §7.5）。

## 可插拔的落点

新增第 6 个 Agent = ① 继承 `BaseAgent` ② 登记 `stage` ③ 在 `registry.py` 绑定。
`engine.py` 只遍历 `STAGE_ORDER`，**不含任何 `if stage is X` 分支** ——
这是 PRD §7.5 第 3 点的硬要求，也是「多 Agent」这个说法能成立的前提：
如果引擎里散落着阶段名的判断，那五个 Agent 就只是五个函数，谈不上可插拔。

## 容错档位为什么声明在 Agent 上

设计文档 T8 定的是「按**阶段名**硬编码决策，而非按异常类型」——
语义是清楚的：基础设施问题（沙箱）不该让已完成的静态分析作废。

但把那张表写成 `engine.py` 里的 `if stage in (POC_VERIFY, EXPLOIT_CHAIN)`，
就又回到「引擎里散落阶段名」了。改成在 Agent 类上声明 `fault_tolerance`：
**引擎仍然按阶段决策（它只是读一个属性），而档位的归属回到了离它最近的模块**。
新增 Agent 时，作者在写这个类的时候顺手就得回答「你失败了要不要拖垮整个评估」，
而不是去引擎里找一张表。

## `run` 的签名与依赖注入

设计文档写的是 `run(self, ctx, inp)`，本文档保持这个签名，把 session 与沙箱
经 `AgentDeps` 从构造函数注入。**这不是为了少写一个参数**：

T4 定的是「阶段边界是唯一原子提交点」—— 阶段内不得提交。所以 Agent 写库
必须用**引擎持有的那个 session**，由引擎在阶段结束时统一 commit。
如果把 session 塞进 `run` 的参数或者放进 `ctx`（像 `sandbox_handle` 那样），
前者改了签名，后者往一个会被序列化的载体里塞不可序列化的东西。
构造函数注入是唯一既保住签名、又不污染 `ctx` 的做法。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.enums import StageName
from app.orchestrator.broadcaster import LogBroadcaster
from app.orchestrator.context import AssessmentContext
from app.orchestrator.events import LogLevel
from app.orchestrator.metrics import MetricsSampler
from app.sandbox.ports import Sandbox

logger = get_logger(__name__)


class FaultTolerance(StrEnum):
    """阶段失败的处置档位（B3 设计 §6）。"""

    #: 失败 → 整个评估 `failed`。`recon` / `code_audit` / `report_gen` 属此档：
    #: 没有技术栈就没有审计，没有审计就没有报告 —— 后续阶段没有可用输入。
    FATAL = "fatal"
    #: 失败 → 阶段标 `skipped`，**后续阶段继续**。`poc_verify` / `exploit_chain` 属此档：
    #: 「没验证出来」不等于「不存在」，静态分析的成果不该因为沙箱连不上而作废。
    SKIPPABLE = "skippable"


@dataclass(frozen=True, slots=True)
class AgentDeps:
    """Agent 的运行时依赖。

    `frozen` 是刻意的：这些依赖在阶段执行期间不该被替换。
    `slots` 是为了让「往上面挂一个临时属性」这种写法在运行时直接报错 ——
    它本就是不该发生的事，早失败好过晚失败。
    """

    #: 引擎持有的会话。**Agent 不得 commit** —— 提交点在阶段边界（T4）。
    session: AsyncSession
    broadcaster: LogBroadcaster
    #: 只有 `poc_verify` 需要它。其余 Agent 拿到 None 是正常状态，
    #: 不是错误 —— 部署时没配数据面（`docker_host` 为空）就是这种情况。
    sandbox: Sandbox | None = None
    #: 资源采样器。**生命周期归引擎**（阶段结束统一停），
    #: 但「什么时候开始采」只有 Agent 知道 —— 它才是建容器的那一方。
    #: 所以这里给的是控制器，由 Agent 在建好容器后调 `start(...)`。
    metrics: MetricsSampler | None = None


class BaseAgent[InT, OutT](ABC):
    """五个 Agent 的父类。

    用 PEP 695 的 `class BaseAgent[InT, OutT]` 而不是 `Generic[InT, OutT]`：
    这里是纯 ABC，没有 `schemas/common.py` 里那个「Pydantic 需要 2.9+ 才支持
    新语法」的约束，所以用新的。
    """

    #: 人类可读名，出现在日志与报告里
    name: str = "agent"
    #: 本 Agent 负责的阶段。子类必须覆盖。
    stage: StageName
    #: 失败档位。默认最严 —— 新增 Agent 若忘了声明，宁可炸也不要静默跳过。
    fault_tolerance: FaultTolerance = FaultTolerance.FATAL

    def __init__(self, deps: AgentDeps) -> None:
        self.deps = deps

    @abstractmethod
    async def run(self, ctx: AssessmentContext, inp: InT) -> OutT:
        """执行本阶段。

        **实现里不得 `session.commit()`** —— 提交由引擎在阶段边界完成（T4）。
        需要中间态时用 `flush()`。

        抛出：
        - `StageSkippedError` → 引擎标 `skipped` 并继续（无论本 Agent 的档位是什么）；
        - 其它异常 → 引擎按 `fault_tolerance` 决定是标 `failed` 还是 `skipped`。
        """

    def gather_input(self, ctx: AssessmentContext) -> InT:
        """从上下文里取出本阶段的输入。

        **存在的理由是让引擎不必知道「哪个阶段吃什么」**。五个阶段的输入各不相同
        （工作区路径 / 技术栈 / finding 列表 / 已验证 finding / 整个上下文），
        若由引擎来分派，`engine.py` 里就会出现一张 `stage → 取哪个字段` 的表，
        「不含 `if stage is X`」这条要求当场失效。

        默认返回 `ctx` 本身 —— 多数阶段（推演、报告）的输入就是整个上下文。
        收窄输入类型的阶段（审计只要技术栈）覆盖它即可。
        """
        return cast(InT, ctx)

    def apply_output(self, ctx: AssessmentContext, out: OutT) -> None:
        """把本阶段产出写回上下文。默认什么都不做。

        与 `gather_input` 对称：**产出该落到上下文的哪个字段，是阶段自己的知识**。
        引擎只负责「调用它，然后把结果整体快照」，不负责理解里面装了什么。
        """
        return None

    async def emit(self, level: LogLevel, msg: str, **extra: object) -> None:
        """写一条日志进 Stream，同时进本阶段的摘要缓冲。

        **不要用 `print`，也不要用 `logger.info` 代替它**：本地 logger 写的是
        服务端的运维日志，`emit` 写的是**用户要看的那条流**。
        两者受众不同，混用会让终端面板上出现一堆用户不关心的框架日志。
        """
        await self.deps.broadcaster.log(
            assessment_id=self._assessment_id,
            stage=self.stage,
            level=level,
            message=msg,
            extra=extra or None,
        )

    #: 由引擎在调用 `run` 之前设置。放在属性上而不是 `run` 的参数里，
    #: 是因为 `emit()` 随时可能被调用（包括在异常处理里），
    #: 而它拿不到 `run` 的局部变量。
    _assessment_id: int = 0

    def bind(self, ctx: AssessmentContext) -> None:
        """引擎在 `run` 之前调用，把上下文里 Agent 需要的那部分接上。"""
        self._assessment_id = ctx.assessment_id

    def __repr__(self) -> str:
        return f"<{type(self).__name__} stage={self.stage}>"
