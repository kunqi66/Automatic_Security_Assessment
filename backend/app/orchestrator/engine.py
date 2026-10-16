"""五阶段状态机（B3 设计 §4.1、§4.3）。

**这是本系统里唯一一处「流程」的代码**。五个 Agent 各自不知道自己在流程中的
位置，也不知道下一步是什么 —— 那是这里的职责。

三条不能动的性质：

1. **阶段边界是唯一的提交点**（T4）。阶段内的写入与「阶段标 completed」
   必须在同一个事务里落库，否则会出现「阶段标了完成但产出没写」的中间态，
   而续跑逻辑会把那个阶段当成已完成从而跳过它 —— 数据永久缺失。
2. **容错档位只取决于阶段**（T8），不取决于异常类型。理由见 `_handle_stage_error`。
3. **取消是协作式的**（T2）：只在阶段边界检查，绝不在阶段中途打断。
   理由见 `cancel.py`。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.base import AgentDeps, FaultTolerance
from app.core.config import settings
from app.core.exceptions import AppError, StageFatalError, StageSkippedError
from app.core.logging import get_logger
from app.db.session import AsyncSessionLocal
from app.models.assessment import Assessment, AssessmentStage
from app.models.enums import AssessmentStatus, StageName, StageStatus
from app.models.sandbox import SandboxConfig as SandboxConfigRow
from app.orchestrator import cancel
from app.orchestrator.broadcaster import LogBroadcaster
from app.orchestrator.context import (
    AssessmentContext,
    ContextDecodeError,
    decode_from_storage,
    encode_for_storage,
)
from app.orchestrator.events import LogLevel
from app.orchestrator.metrics import MetricsSampler
from app.orchestrator.registry import build as build_agent
from app.orchestrator.views import ProgressView, ResumeOutcome, to_stage_record
from app.sandbox.ports import Sandbox
from app.verify.types import SandboxConfig as SandboxRuntimeConfig

logger = get_logger(__name__)

#: 阶段顺序。**这张元组是流程的唯一真相** —— 引擎遍历它，
#: 续跑靠它定位「第一个未完成的阶段」，进度条按它排序。
STAGE_ORDER: tuple[StageName, ...] = (
    StageName.RECON,
    StageName.CODE_AUDIT,
    StageName.POC_VERIFY,
    StageName.EXPLOIT_CHAIN,
    StageName.REPORT_GEN,
)

#: 每个阶段占进度的百分比。
#:
#: **`skipped` 按满权重计入**（设计 §8 待定项 4）。理由：`skipped` 是一个
#: **已终结**的状态 —— 那个阶段不会再有进展了。按 0 计的话，一个
#: 「沙箱没配好」的评估会永远停在 60%，用户在界面上看到的是一个永远不动的进度条，
#: 而实际上后端早就跑完了。进度条的语义是「还剩多少活要干」，不是「成功了多少」。
_PROGRESS_PER_STAGE = 100 // len(STAGE_ORDER)


class _StageOutcome(StrEnum):
    """单个阶段的执行结果。引擎内部用，不外露。"""

    COMPLETED = "completed"
    SKIPPED = "skipped"
    FATAL = "fatal"


class OrchestrationEngine:
    """五阶段编排。一个实例服务一次评估。"""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        broadcaster: LogBroadcaster | None = None,
        sandbox_provider: Callable[[], Sandbox | None] | None = None,
    ) -> None:
        self._session_factory = session_factory or AsyncSessionLocal
        self._broadcaster = broadcaster or LogBroadcaster()
        self._sandbox_provider = sandbox_provider or _default_sandbox_provider

    # ==================================================================
    # 对外接口（B3 设计 §3.1）
    # ==================================================================

    async def start(self, assessment_id: int) -> None:
        """从头跑一次评估。队列消费者调用它。

        整体套一层超时（`assessment_timeout_seconds`）：并发度恒为 1，
        一个卡死的 Agent 会占住唯一的 worker 让全线停摆。
        超时是兜底而非主控 —— 正常情况下靠「单探针 30s × 探针上限」收敛。
        """
        try:
            await asyncio.wait_for(
                self._advance(assessment_id, resuming=False),
                timeout=settings.assessment_timeout_seconds,
            )
        except TimeoutError:
            await self._fail(
                assessment_id,
                f"评估超过整体超时 {settings.assessment_timeout_seconds}s 未结束",
                remediation="检查是否有 Agent 卡死；可调大 ASSESSMENT_TIMEOUT_SECONDS",
            )

    async def request_stop(self, assessment_id: int) -> None:
        """请求停止。**只置标志位，返回时评估仍在跑**（见 `cancel.py`）。

        API 层应当据此返回 `202 Accepted`。
        """
        await cancel.request_cancel(assessment_id)

    async def resume(self, assessment_id: int) -> ResumeOutcome:
        """断点续跑（B3 设计 §4.3）。"""
        async with self._session_factory() as session:
            assessment = await session.get(Assessment, assessment_id)
            if assessment is None:
                return ResumeOutcome.NOT_FOUND
            if assessment.status in (AssessmentStatus.COMPLETED, AssessmentStatus.FAILED):
                return ResumeOutcome.ALREADY_TERMINAL
            if self._first_unfinished(assessment) is None:
                return ResumeOutcome.NOTHING_TO_DO

        # 续跑前先清僵尸容器：上次崩溃可能留下 poc_verify 的容器，
        # 不清的话它们会一直占着内存（那台机器只有 7.3G，且已经加了 swap）。
        await self._reap_orphans(assessment_id)

        await self._advance(assessment_id, resuming=True)
        return ResumeOutcome.RESUMED

    async def recover_on_boot(self) -> list[int]:
        """启动时扫描未完成的评估，返回**需要重新入队的 id 列表**。

        设计文档写的返回值是 `int`（被恢复的数量）。改成返回 id 列表是因为
        调用方拿到数量之后**什么也做不了** —— 它还得再查一次库才知道要入队哪些。
        返回 id 让「扫描」和「入队」之间不需要第二次查询。

        另外这里的「恢复」只做到「清僵尸容器 + 返回清单」，
        **不直接调 `resume()`**：那会让启动过程被一次长评估阻塞住，
        而启动路径上有个跑 20 分钟的任务是不可接受的。
        """
        async with self._session_factory() as session:
            rows = await session.execute(
                select(Assessment.id).where(
                    Assessment.status.in_([AssessmentStatus.RUNNING, AssessmentStatus.STOPPED])
                )
            )
            ids = [row[0] for row in rows.all()]

        for assessment_id in ids:
            await self._reap_orphans(assessment_id)

        if ids:
            logger.info("启动恢复：发现 %d 个未完成的评估 %s", len(ids), ids)
        return ids

    async def get_progress(self, assessment_id: int) -> ProgressView | None:
        """给 `GET /assessments/{id}` 用的快照。"""
        async with self._session_factory() as session:
            assessment = await session.get(Assessment, assessment_id)
            if assessment is None:
                return None
            return ProgressView(
                assessment_id=assessment.id,
                project_id=assessment.project_id,
                status=assessment.status,
                current_stage=assessment.current_stage,
                progress=assessment.progress,
                # `stages` 是 selectin 加载且带 order_by，这里不需要再排
                stages=[to_stage_record(row) for row in assessment.stages],
                started_at=assessment.started_at,
                finished_at=assessment.finished_at,
                error_message=assessment.error_message,
            )

    # ==================================================================
    # 主循环
    # ==================================================================

    async def _advance(self, assessment_id: int, *, resuming: bool) -> None:
        async with self._session_factory() as session:
            assessment = await session.get(Assessment, assessment_id)
            if assessment is None:
                logger.error("评估 %s 不存在，无法推进", assessment_id)
                return

            try:
                ctx = await self._load_context(session, assessment, resuming=resuming)
            except (StageFatalError, SQLAlchemyError) as exc:
                # 准备工作失败（源码工作区不存在 / 读库失败）→ 整体 failed。
                # **必须在这里接住**：这个位置在阶段循环之外，漏出去的话
                # 评估会停在 `created`/`running` 状态，而队列已经 XACK 掉了任务 ——
                # 表现为「评估永远转圈，日志里什么都没有」。
                await self._fail(
                    assessment.id,
                    self._describe(exc),
                    remediation=getattr(exc, "remediation", None),
                )
                return

            await self._mark_assessment_running(session, assessment)
        # 上面这一段用独立的短会话：加载上下文与置状态是一次性的准备工作，
        # 不该把事务拖进整个评估的时长里。

        for stage in STAGE_ORDER:
            # ① 阶段边界：检查取消标志。**这是取消唯一生效的地方。**
            if await cancel.is_cancelled(assessment_id):
                await self._mark_stopped(assessment_id)
                await cancel.clear_cancel(assessment_id)
                return

            async with self._session_factory() as session:
                assessment = await session.get(Assessment, assessment_id)
                if assessment is None:
                    return
                row = self._stage_row(assessment, stage)

                if row.status is StageStatus.COMPLETED:
                    # 续跑：已完成的阶段直接跳过，不重跑（§4.3 第 1 点）
                    continue

                outcome = await self._run_stage(session, assessment, ctx, stage)

            if outcome is _StageOutcome.FATAL:
                return  # `_run_stage` 内部已经落了 failed 状态

        await self._mark_completed(assessment_id)

    async def _run_stage(
        self,
        session: AsyncSession,
        assessment: Assessment,
        ctx: AssessmentContext,
        stage: StageName,
    ) -> _StageOutcome:
        """一个阶段的完整骨架：置 running → 跑 → 落 completed + 快照（单事务）。"""
        assessment_id = assessment.id
        await self._mark_stage_running(session, assessment, stage)

        # **只取一次**。`_sandbox_provider()` 每次调用都可能构造一个新实例
        # （它要建 Docker 客户端），在一个阶段里调三次会造出三个互不相干的沙箱，
        # 而其中两个永远不会被用到、也不会被关掉。
        sandbox = self._sandbox_provider()

        agent = build_agent(
            stage,
            AgentDeps(
                session=session,
                broadcaster=self._broadcaster,
                sandbox=sandbox,
                metrics=(
                    MetricsSampler(sandbox, broadcaster=self._broadcaster)
                    if sandbox is not None
                    else None
                ),
            ),
        )
        agent.bind(ctx)

        started = time.monotonic()
        try:
            inp = agent.gather_input(ctx)
            out = await agent.run(ctx, inp)
            agent.apply_output(ctx, out)
        except asyncio.CancelledError:
            # 不吞：这是进程级中断（关停），交给上层
            raise
        except Exception as exc:  # noqa: BLE001 —— 见 _handle_stage_error 的说明
            return await self._handle_stage_error(session, assessment, stage, agent, exc)
        finally:
            if agent.deps.metrics is not None:
                await agent.deps.metrics.stop()

        duration_ms = int((time.monotonic() - started) * 1000)
        await self._mark_stage_completed(session, assessment, ctx, stage, duration_ms)
        await self._broadcaster.log(
            assessment_id=assessment_id,
            stage=stage,
            level=LogLevel.INFO,
            message=f"阶段 {stage.value} 完成（{duration_ms} ms）",
        )
        return _StageOutcome.COMPLETED

    async def _handle_stage_error(
        self,
        session: AsyncSession,
        assessment: Assessment,
        stage: StageName,
        agent: Any,
        exc: Exception,
    ) -> _StageOutcome:
        """容错决策。**只依赖阶段档位，不依赖异常类型**（T8）。

        为什么不看异常类型：`SandboxUnreachableError` 在 `poc_verify` 里应该
        降级、在别处不该出现；而「连不上数据库」在**任何**阶段都该是致命的。
        按类型分派就等于要求每个抛异常的地方都正确标注自己的严重程度 ——
        而抛异常的地方恰恰是最容易写错的地方。按阶段分派把决策挪到了
        一个固定的、只有五行的地方。

        代价写在设计文档 T8 里：新增 Agent 时必须同时决定它的档位。
        本实现把这个决定放到了 Agent 类上（`fault_tolerance`），
        让作者在写类的时候就得回答。
        """
        skipped = (
            isinstance(exc, StageSkippedError) or agent.fault_tolerance is FaultTolerance.SKIPPABLE
        )

        detail = self._describe(exc)
        if skipped:
            await self._mark_stage_skipped(session, assessment, stage, detail)
            await self._broadcaster.log(
                assessment_id=assessment.id,
                stage=stage,
                level=LogLevel.WARN,
                message=f"阶段 {stage.value} 已跳过：{detail}",
            )
            return _StageOutcome.SKIPPED

        await self._fail(assessment.id, detail, remediation=getattr(exc, "remediation", None))
        return _StageOutcome.FATAL

    # ==================================================================
    # 状态落库 —— 每个方法一个短事务
    # ==================================================================

    async def _load_context(
        self, session: AsyncSession, assessment: Assessment, *, resuming: bool
    ) -> AssessmentContext:
        """建立或还原上下文。

        非续跑时从零建；续跑时读**最后一个已完成阶段**的 `result_ref` 还原 ——
        不重放所有阶段，因为重放正是续跑要避免的开销（§4.3 第 1 点）。
        """
        workspace = await self._resolve_workspace(session, assessment)
        # 沙箱参数与 workspace 同理：**以当前配置为准，不用快照里那份**。
        # 管理页改了参数，下一次运行就该生效。
        sandbox_config = await self._resolve_sandbox_config(session)

        if not resuming:
            return AssessmentContext(
                assessment_id=assessment.id,
                project_id=assessment.project_id,
                workspace=workspace,
                sandbox_config=sandbox_config,
            )

        completed = [r for r in assessment.stages if r.status is StageStatus.COMPLETED]
        if not completed:
            return AssessmentContext(
                assessment_id=assessment.id,
                project_id=assessment.project_id,
                workspace=workspace,
                sandbox_config=sandbox_config,
            )

        latest = max(completed, key=lambda r: _order_index(r.stage))
        try:
            ctx = decode_from_storage(latest.result_ref)
        except ContextDecodeError as exc:
            # 降级：快照坏了就退回该阶段重跑，而不是让整个评估失败（§4.3 第 3 点）。
            logger.warning("评估 %s 的快照无法还原（%s），该阶段将重跑", assessment.id, exc)
            await self._reset_stage(session, assessment, latest)
            return AssessmentContext(
                assessment_id=assessment.id,
                project_id=assessment.project_id,
                workspace=workspace,
                sandbox_config=sandbox_config,
            )

        # 工作区以**当前**配置为准，不用快照里那份：项目可能被重新上传过，
        # 而快照里的路径是上次运行时的坐标。
        ctx.workspace = workspace
        ctx.sandbox_handle = None
        ctx.sandbox_config = sandbox_config
        return ctx

    async def _resolve_sandbox_config(
        self, session: AsyncSession
    ) -> SandboxRuntimeConfig | None:
        """读管理页配的默认沙箱参数 —— 总纲 §6.1 说的那个注入点。

        **取不到就返回 `None`**，由 `verify` 侧回落到 `SandboxConfig.from_settings()`，
        也就是接通管理页之前的行为。四种情况都走这条路：表为空 / 没有 `is_default`
        行 / 值被写坏 / SQL 报错 —— 沙箱配置读不出来是**配置问题**，不该让一次评估
        挂掉。

        但**不能静默**（原理 8：「最坏的失败是静默失败」）。降级一律留日志：
        「表是空的」这件事如果一声不吭，下一个人会以为管理页配的参数真的生效了
        —— 那正是这次要修的毛病本身。
        """
        try:
            row = await session.scalar(
                select(SandboxConfigRow)
                .where(SandboxConfigRow.is_default.is_(True))
                .order_by(SandboxConfigRow.id.asc())
                .limit(1)
            )
        except SQLAlchemyError as exc:
            logger.warning("读取沙箱配置失败，本次运行回落到全局设置：%s", exc)
            return None

        if row is None:
            logger.info("没有 is_default 的沙箱配置行，本次运行回落到全局设置")
            return None

        try:
            return SandboxRuntimeConfig.from_admin_config(row)
        except (AttributeError, TypeError, ValueError) as exc:
            # AttributeError：映射函数按属性名取值（鸭子类型），列被改名就抛它 ——
            #   一个字段改名不该让每一次评估在 `poc_verify` 崩掉，而报错信息
            #   指向的还是引擎而不是配置。
            # ValueError：涵盖 pydantic 的 ValidationError，即行里的值超出引擎的合法区间。
            logger.warning("沙箱配置 %s 的值不可用（%s），本次运行回落到全局设置", row.id, exc)
            return None

    async def _mark_assessment_running(self, session: AsyncSession, assessment: Assessment) -> None:
        if assessment.status is not AssessmentStatus.RUNNING:
            assessment.status = AssessmentStatus.RUNNING
            assessment.started_at = assessment.started_at or _now()
        assessment.error_message = None

        # 补齐缺失的阶段行。**用「有则不动、无则新增」而不是「全删重建」**：
        # 重建会把已完成的 `result_ref` 一起抹掉，而那正是续跑的依靠。
        existing = {row.stage for row in assessment.stages}
        for stage in STAGE_ORDER:
            if stage not in existing:
                session.add(
                    AssessmentStage(
                        assessment_id=assessment.id, stage=stage, status=StageStatus.PENDING
                    )
                )
        await session.commit()

    async def _mark_stage_running(
        self, session: AsyncSession, assessment: Assessment, stage: StageName
    ) -> None:
        row = self._stage_row(assessment, stage)
        row.status = StageStatus.RUNNING
        row.started_at = _now()
        row.finished_at = None
        row.note = None
        assessment.current_stage = stage
        await session.commit()
        await self._broadcaster.stage_changed(
            assessment_id=assessment.id, record=to_stage_record(row)
        )

    async def _mark_stage_completed(
        self,
        session: AsyncSession,
        assessment: Assessment,
        ctx: AssessmentContext,
        stage: StageName,
        duration_ms: int,
    ) -> None:
        """**快照与状态写在同一个事务里**（T4 的核心）。

        分成两次提交的后果不难想象：第一次提交了 `status=completed`，
        进程在第二次提交前死掉 —— 续跑时这个阶段被跳过，而它的 `result_ref`
        永远是空的。数据缺失，且没有任何迹象表明它缺失。
        """
        row = self._stage_row(assessment, stage)
        row.status = StageStatus.COMPLETED
        row.finished_at = _now()
        row.result_ref = encode_for_storage(ctx, stage)
        row.log_excerpt = self._broadcaster.excerpt(assessment.id, stage)
        ctx.stage_outputs[stage.value] = f"assessment_stages:{assessment.id}:{stage.value}"

        self._broadcaster.drop_excerpt(assessment.id, stage)
        self._recompute_progress(assessment)
        await session.commit()
        await self._broadcaster.stage_changed(
            assessment_id=assessment.id, record=to_stage_record(row)
        )

    async def _mark_stage_skipped(
        self,
        session: AsyncSession,
        assessment: Assessment,
        stage: StageName,
        note: str,
    ) -> None:
        row = self._stage_row(assessment, stage)
        row.status = StageStatus.SKIPPED
        row.finished_at = _now()
        # `note` 而不是 `error_message`：skip 是降级不是错误（总纲 §9.1 L3）
        row.note = note
        row.log_excerpt = self._broadcaster.excerpt(assessment.id, stage)
        self._broadcaster.drop_excerpt(assessment.id, stage)
        self._recompute_progress(assessment)
        await session.commit()
        await self._broadcaster.stage_changed(
            assessment_id=assessment.id, record=to_stage_record(row)
        )

    async def _reset_stage(
        self, session: AsyncSession, assessment: Assessment, row: AssessmentStage
    ) -> None:
        """快照不可用时把阶段退回 `pending`，就地重跑。"""
        row.status = StageStatus.PENDING
        row.result_ref = None
        row.note = "上次运行的快照无法还原，本阶段将重跑"
        self._recompute_progress(assessment)
        await session.commit()

    async def _mark_completed(self, assessment_id: int) -> None:
        async with self._session_factory() as session:
            assessment = await session.get(Assessment, assessment_id)
            if assessment is None:
                return
            assessment.status = AssessmentStatus.COMPLETED
            assessment.finished_at = _now()
            assessment.progress = 100
            assessment.current_stage = None
            await session.commit()

        await self._broadcaster.log(
            assessment_id=assessment_id,
            stage=STAGE_ORDER[-1],
            level=LogLevel.INFO,
            message="评估完成",
        )
        await cancel.clear_cancel(assessment_id)

    async def _mark_stopped(self, assessment_id: int) -> None:
        """用户主动停止（§4.2）。

        剩余阶段**保持 `pending`，不标 `failed`** —— 它们没失败，
        只是没轮到。标 failed 会让 `resume()` 把整次评估判定为终态而拒绝续跑。
        """
        async with self._session_factory() as session:
            assessment = await session.get(Assessment, assessment_id)
            if assessment is None:
                return
            assessment.status = AssessmentStatus.STOPPED
            assessment.finished_at = _now()
            self._recompute_progress(assessment)
            await session.commit()

        await self._broadcaster.log(
            assessment_id=assessment_id,
            stage=STAGE_ORDER[0],
            level=LogLevel.WARN,
            message="评估已被用户停止；已产出的结果全部保留",
        )

    async def fail(
        self, assessment_id: int, detail: str, *, remediation: str | None = None
    ) -> None:
        """公开的失败入口。队列在重试耗尽、任务进死信时调它。

        `_fail` 之所以是私有的，是因为阶段内的失败要走 `_handle_stage_error`
        那条带档位判断的路径。而「任务重试三次仍失败」是**编排层之外**的失败
        （连阶段都没进去），没有档位可言，所以单独开一个口子 ——
        比让 queue.py 去调一个下划线方法是更好的选择。
        """
        await self._fail(assessment_id, detail, remediation=remediation)

    async def _fail(self, assessment_id: int, detail: str, *, remediation: str | None) -> None:
        """整体失败。**已产出的数据全部保留**（§6）。"""
        async with self._session_factory() as session:
            assessment = await session.get(Assessment, assessment_id)
            if assessment is None:
                return
            assessment.status = AssessmentStatus.FAILED
            assessment.finished_at = _now()
            assessment.error_message = f"{detail}｜建议：{remediation}" if remediation else detail
            await session.commit()

        await self._broadcaster.log(
            assessment_id=assessment_id,
            stage=STAGE_ORDER[0],
            level=LogLevel.ERROR,
            message=f"评估失败：{detail}",
        )
        await cancel.clear_cancel(assessment_id)

    # ==================================================================
    # 工具
    # ==================================================================

    @staticmethod
    async def _resolve_workspace(session: AsyncSession, assessment: Assessment) -> str:
        """把 `projects.storage_path` 解析成控制面工作区绝对路径。

        `storage_path` 存的是**相对 `workspace_root` 的 POSIX 路径**
        （总纲 §7.4），不是绝对路径 —— 直接拿它当路径用会得到一个相对路径，
        在 worker 进程的当前目录下被解析，结果是「源码找不到」，
        而错误会指向文件不存在，排查方向完全歪掉。

        这里是「三个路径空间靠配置换算」的落点之一（契约 5）。
        """
        project = await session.get(_project_model(), assessment.project_id)
        rel = getattr(project, "storage_path", None)
        if not rel:
            raise StageFatalError(
                f"项目 {assessment.project_id} 没有源码工作区（storage_path 为空）",
                stage=StageName.RECON.value,
                remediation="请先在该项目下上传源码包或从 Git 拉取",
            )
        return str(settings.workspace_root / rel)

    @staticmethod
    def _stage_row(assessment: Assessment, stage: StageName) -> AssessmentStage:
        for row in assessment.stages:
            if row.stage is stage:
                return row
        raise LookupError(f"评估 {assessment.id} 缺少阶段 {stage.value} 的行")

    @staticmethod
    def _first_unfinished(assessment: Assessment) -> StageName | None:
        done = {r.stage for r in assessment.stages if r.status is StageStatus.COMPLETED}
        for stage in STAGE_ORDER:
            if stage not in done:
                return stage
        return None

    @staticmethod
    def _recompute_progress(assessment: Assessment) -> None:
        """进度 = 已终结阶段数 × 单阶段权重。"""
        terminal = sum(
            1
            for row in assessment.stages
            if row.status in (StageStatus.COMPLETED, StageStatus.SKIPPED, StageStatus.FAILED)
        )
        assessment.progress = min(100, terminal * _PROGRESS_PER_STAGE)

    async def _reap_orphans(self, assessment_id: int) -> None:
        """清理上次运行残留的容器。

        失败只记日志：僵尸容器占内存，但清理不了它不该阻止评估继续。
        """
        sandbox = self._sandbox_provider()
        if sandbox is None:
            return
        reap = getattr(sandbox, "reap_orphans", None)
        if reap is None:
            return
        try:
            removed = await reap(assessment_id)
            if removed:
                logger.info("评估 %s 清理了 %d 个残留容器", assessment_id, removed)
        except Exception as exc:  # noqa: BLE001
            logger.warning("清理残留容器失败（评估 %s）：%s", assessment_id, exc)

    @staticmethod
    def _describe(exc: BaseException) -> str:
        """把异常转成能给人看的一句话。

        `AppError` 走 `message`（它本来就是给人写的），其余走
        `类型名: 内容` —— 只留 `str(exc)` 的话，一个 `KeyError('workspace')`
        会显示成光秃秃的 `'workspace'`。
        """
        if isinstance(exc, AppError):
            return exc.message
        return f"{type(exc).__name__}: {exc}"


def stage_progress(status: StageStatus) -> int:
    """暴露给测试与文档的进度折算。"""
    return (
        _PROGRESS_PER_STAGE
        if status
        in (
            StageStatus.COMPLETED,
            StageStatus.SKIPPED,
            StageStatus.FAILED,
        )
        else 0
    )


def _order_index(stage: StageName) -> int:
    try:
        return STAGE_ORDER.index(stage)
    except ValueError:
        return -1


def _now() -> datetime:
    return datetime.now().astimezone()


def _project_model() -> Any:
    from app.models.project import Project

    return Project


def _default_sandbox_provider() -> Sandbox | None:
    """惰性构造默认沙箱。

    **没有配置数据面时返回 None 是正常状态**，不是错误：开发时可能只想跑
    `recon` + `code_audit`（纯静态，不需要 Docker）。返回 None 后
    `poc_verify` 会按 L3 降级为 `skipped`，评估继续。
    """
    if not settings.docker_host:
        return None
    try:
        from app.sandbox.service import SandboxService

        # **这里只构造，不 ping。** 可达性由 `SandboxService._ensure_reachable`
        # 在**执行路径**上带退避地检查（它的 docstring 写了为什么：ssh 抖动是常态，
        # 在构造期判死会让整轮 poc_verify 白跳过）。而构造本身是惰性的 ——
        # `SandboxService()` 不碰 daemon，Docker 客户端推迟到首次访问 `.client`。
        return SandboxService()
    except (ImportError, SQLAlchemyError, OSError) as exc:
        logger.warning("沙箱不可用，poc_verify 将降级为 skipped：%s", exc)
        return None
