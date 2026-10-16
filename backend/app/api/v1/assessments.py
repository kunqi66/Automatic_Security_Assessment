"""评估任务接口（L1 接口层）。

**本模块不含任何业务判断**：创建评估的规则在编排引擎，进度折算在
`views.to_stage_record`，日志格式在 `events.LogEvent`。这里只做
「校验参数 → 调下层 → 序列化」。

---

**一个容易搞错的地方**：SSE 端点跑在 **API 进程**，而编排引擎跑在
**消费 worker 进程**。两者不是同一个进程，甚至可能不是同一台机器。
它们之间唯一的联系是 Redis Stream `log:{assessment_id}` ——
API 侧只读，worker 侧只写。所以本模块**拿不到引擎的内存状态**，
任何「现在跑到哪了」都必须回 Redis 或 MySQL 查。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy import func, select
from sse_starlette.sse import EventSourceResponse

from app.api.deps import DBSession, Permission, require
from app.core.exceptions import BadRequestError, DependencyDownError, NotFoundError
from app.core.logging import get_logger
from app.db.redis import get_redis
from app.models.assessment import Assessment, AssessmentStage
from app.models.enums import IN_FLIGHT_STATUSES, AssessmentStatus, StageStatus
from app.models.observability import ResourceMetric
from app.models.project import Project
from app.models.user import User
from app.orchestrator import views
from app.orchestrator.engine import STAGE_ORDER, OrchestrationEngine
from app.orchestrator.events import stream_key
from app.orchestrator.queue import TaskQueue
from app.schemas.assessment import AssessmentOut, ResourceSampleOut, StageStateOut
from app.schemas.common import Page

logger = get_logger(__name__)

router = APIRouter(tags=["评估任务"])

#: 只读权限三角色共有；写权限严格按需求 2.5.2 授予（见 deps.ROLE_PERMISSIONS）
AssessmentViewer = Annotated[User, Depends(require(Permission.ASSESSMENT_VIEW))]
AssessmentCreator = Annotated[User, Depends(require(Permission.ASSESSMENT_CREATE))]

#: SSE 的阻塞读超时。取值权衡：太短会让空闲连接疯狂空转，
#: 太长会让「评估结束 → 关闭流」这件事延迟很久才被察觉。
_SSE_BLOCK_MS = 15_000
#: 每隔这么多轮阻塞读检查一次评估是否已终结。用来决定要不要主动关流。
_SSE_TERMINAL_CHECK_EVERY = 4


# ---------------------------------------------------------------------------
# 查询
# ---------------------------------------------------------------------------


@router.get(
    "/assessments",
    response_model=Page[AssessmentOut],
    summary="评估任务列表",
)
async def list_assessments(
    session: DBSession,
    _: AssessmentViewer,
    project_id: Annotated[int | None, Query(description="按项目过滤")] = None,
    status_filter: Annotated[AssessmentStatus | None, Query(alias="status")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Page[AssessmentOut]:
    conditions = []
    if project_id is not None:
        conditions.append(Assessment.project_id == project_id)
    if status_filter is not None:
        conditions.append(Assessment.status == status_filter)

    total = await session.scalar(select(func.count()).select_from(Assessment).where(*conditions))
    rows = (
        await session.execute(
            select(Assessment, Project.name)
            .join(Project, Project.id == Assessment.project_id)
            .where(*conditions)
            .order_by(Assessment.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()

    return Page[AssessmentOut](
        items=[_to_out(assessment, project_name) for assessment, project_name in rows],
        total=int(total or 0),
        page=page,
        page_size=page_size,
    )


@router.get(
    "/assessments/{assessment_id}",
    response_model=AssessmentOut,
    summary="评估详情（含五阶段状态与进度）",
)
async def get_assessment(
    assessment_id: int, session: DBSession, _: AssessmentViewer
) -> AssessmentOut:
    assessment = await _load(session, assessment_id)
    project_name = await session.scalar(
        select(Project.name).where(Project.id == assessment.project_id)
    )
    return _to_out(assessment, project_name)


@router.get(
    "/assessments/{assessment_id}/metrics",
    response_model=list[ResourceSampleOut],
    summary="阶段资源采样",
)
async def get_metrics(
    assessment_id: int,
    session: DBSession,
    _: AssessmentViewer,
    limit: Annotated[int, Query(ge=1, le=2000)] = 300,
) -> list[ResourceSampleOut]:
    await _load(session, assessment_id)  # 顺带校验存在性，不存在就 404
    rows = (
        (
            await session.execute(
                select(ResourceMetric)
                .where(ResourceMetric.assessment_id == assessment_id)
                # 倒序取最近 N 条，再翻转 —— 正序 + LIMIT 会拿到**最早**的 N 条，
                # 而那对「看当前负载」毫无用处
                .order_by(ResourceMetric.id.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    return [
        ResourceSampleOut(ts=row.recorded_at, cpu_percent=row.cpu_percent, memory_mb=row.memory_mb)
        for row in reversed(rows)
    ]


# ---------------------------------------------------------------------------
# 创建 / 停止 / 续跑
# ---------------------------------------------------------------------------


@router.post(
    "/projects/{project_id}/assessments",
    response_model=AssessmentOut,
    status_code=status.HTTP_201_CREATED,
    summary="启动评估",
)
async def create_assessment(
    project_id: int, session: DBSession, user: AssessmentCreator
) -> AssessmentOut:
    project = await session.get(Project, project_id)
    if project is None:
        raise NotFoundError(f"项目 {project_id} 不存在")

    if not project.storage_path:
        # 建档了但源码还没到位。这时启动评估只会在 recon 阶段炸，
        # 不如在这里就说清楚 —— 错误信息能直接指向该做什么。
        raise BadRequestError(
            "该项目还没有源码，无法启动评估",
            remediation="请先上传源码包或从 Git 仓库拉取",
        )

    # 🔴 判 `IN_FLIGHT_STATUSES` 而不是 `== RUNNING`。
    #
    # 刚建出来的评估是 `created`，要等 worker 取走才转 `running`，
    # 所以只判 `RUNNING` 会在这个窗口里放行 —— 连点两次就得到两个评估，
    # 都被 `xadd` 入队（`orchestrator/queue.py` 没有去重），
    # 再由 worker 顺序跑完。实测确认过：第一次 POST 之后紧接着第二次，返回的是
    # **201 而不是 400**。终态（completed / failed / stopped）仍然允许重新发起。
    in_flight = await session.scalar(
        select(func.count())
        .select_from(Assessment)
        .where(
            Assessment.project_id == project_id,
            Assessment.status.in_(IN_FLIGHT_STATUSES),
        )
    )
    if in_flight:
        raise BadRequestError(
            "该项目已有正在排队或运行中的评估",
            remediation="等待它结束，或先调用停止接口",
        )

    assessment = Assessment(
        project_id=project_id,
        status=AssessmentStatus.CREATED,
        progress=0,
    )
    session.add(assessment)
    await session.flush()

    # 五个阶段行随评估一起建出来，而不是等到跑的时候再补。
    # 这样详情接口从第一秒起就能渲染完整的五步进度条，
    # 而不是「先显示一步，跑起来才长出其余的」。
    for stage in STAGE_ORDER:
        session.add(
            AssessmentStage(assessment_id=assessment.id, stage=stage, status=StageStatus.PENDING)
        )
    await session.commit()
    await session.refresh(assessment)

    # 入队在提交**之后**：反过来的话，worker 可能在事务提交前就取走任务，
    # 查不到那条评估记录，然后把它当成脏数据丢掉 —— 任务凭空消失。
    engine = OrchestrationEngine()
    try:
        await TaskQueue(engine).enqueue(assessment.id)
    except Exception as exc:  # noqa: BLE001 —— 依赖不可用，需转成业务错误
        await engine.fail(
            assessment.id,
            f"任务入队失败：{type(exc).__name__}: {exc}",
            remediation="检查 Redis 连通性；评估已创建但未入队",
        )
        # Redis 是**存储类依赖，不可降级**（总纲 §8.2）：队列不可用就没有「稍后重试」
        # 这回事，必须让调用方知道。不静默接受一个永远不会被执行的评估。
        raise DependencyDownError(
            "任务队列不可用，评估未能启动",
            remediation="检查 Redis 连通性与 db 索引配置",
        ) from exc

    logger.info("用户 %s 启动项目 %s 的评估 %s", user.username, project_id, assessment.id)
    return _to_out(assessment, project.name)


@router.post(
    "/assessments/{assessment_id}/stop",
    response_model=AssessmentOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="请求停止（协作式，非即时）",
)
async def stop_assessment(
    assessment_id: int, session: DBSession, _: AssessmentCreator
) -> AssessmentOut:
    """**返回 202 而不是 200**，因为此刻评估**还在跑**。

    取消是协作式的（总纲 D11）：标志位写进去后，要等当前阶段跑到边界才生效。
    最坏情况是 `poc_verify` 里一个正在等待的探针，等它 30s 超时。
    返回 200 会让前端显示「已停止」，而实际上容器还在转 —— 那是个谎。
    """
    assessment = await _load(session, assessment_id)

    if assessment.status not in IN_FLIGHT_STATUSES:
        raise BadRequestError(
            f"评估当前状态为 {assessment.status.value}，无需停止",
            remediation="只有在途（created / running）的评估可以停止",
        )

    # 先置 Redis 标志位再回写状态：反过来的话，API 崩在两步之间会留下
    # 「库里说 stopped、引擎不知道」的状态，而引擎会继续跑到下一个阶段边界。
    engine = OrchestrationEngine()
    await engine.request_stop(assessment_id)

    assessment.status = AssessmentStatus.STOPPED
    await session.commit()
    await session.refresh(assessment)

    project_name = await session.scalar(
        select(Project.name).where(Project.id == assessment.project_id)
    )
    return _to_out(assessment, project_name)


@router.post(
    "/assessments/{assessment_id}/resume",
    response_model=AssessmentOut,
    summary="断点续跑",
)
async def resume_assessment(
    assessment_id: int, session: DBSession, _: AssessmentCreator
) -> AssessmentOut:
    assessment = await _load(session, assessment_id)
    engine = OrchestrationEngine()

    outcome = await engine.resume(assessment_id)
    if outcome is views.ResumeOutcome.ALREADY_TERMINAL:
        raise BadRequestError(
            f"评估已终结（{assessment.status.value}），无法续跑",
            remediation="如需重跑，请重新启动一次评估",
        )
    if outcome is views.ResumeOutcome.NOTHING_TO_DO:
        raise BadRequestError("所有阶段均已完成，无需续跑")

    await session.refresh(assessment)
    project_name = await session.scalar(
        select(Project.name).where(Project.id == assessment.project_id)
    )
    return _to_out(assessment, project_name)


# ---------------------------------------------------------------------------
# SSE 日志流
# ---------------------------------------------------------------------------


@router.get(
    "/assessments/{assessment_id}/stream",
    summary="实时日志流（SSE，支持 Last-Event-ID 断线续读）",
    response_class=EventSourceResponse,
)
async def stream_assessment(
    assessment_id: int,
    request: Request,
    session: DBSession,
    _: AssessmentViewer,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> EventSourceResponse:
    """把 Redis Stream 里的事件转发给浏览器。

    **用 Stream 而不是 Pub/Sub 的意义就在这里**：Pub/Sub 是即发即弃的，
    断线那几秒的日志永久消失。Stream 保留历史，浏览器重连时
    （`useLogStream.ts` 手动回传 `Last-Event-ID` 头）从那个 id 之后补读，
    断线期间的日志一条不少。

    首连（无 `Last-Event-ID`）从 `0-0` 开始，也就是**把已保留的全部历史推一遍** ——
    用户点开一个跑了十分钟的评估，应该立刻看到那十分钟的日志，而不是从空白开始。
    """
    await _load(session, assessment_id)  # 404 早于建立流，避免前端空连

    start_id = last_event_id or "0-0"
    return EventSourceResponse(
        _event_source(request, assessment_id, start_id),
        # ping 让中间的 Nginx / 浏览器知道连接还活着。不发心跳的话，
        # 一个安静的阶段（比如 code_audit 正在啃大文件）会被代理当成死连接掐掉，
        # 而用户看到的是「日志流莫名断了」。
        ping=15,
    )


async def _event_source(
    request: Request, assessment_id: int, start_id: str
) -> AsyncIterator[dict[str, Any]]:
    client = get_redis()
    key = stream_key(assessment_id)
    cursor = start_id
    idle_rounds = 0

    while True:
        if await request.is_disconnected():
            # 不显式 return 会一直读下去，把 Redis 连接和内存都耗在这条死连接上
            return

        try:
            resp = await client.xread({key: cursor}, count=200, block=_SSE_BLOCK_MS)
        except Exception as exc:  # noqa: BLE001 —— 连接问题要告诉前端，不能静默
            logger.warning("SSE 读取日志流失败（评估 %s）：%s", assessment_id, exc)
            yield {"event": "error", "data": f'{{"message":"日志流读取失败：{exc}"}}'}
            return

        if not resp:
            idle_rounds += 1
            if idle_rounds >= _SSE_TERMINAL_CHECK_EVERY:
                idle_rounds = 0
                if await _is_terminal(assessment_id):
                    # 评估结束了就主动关流。不关的话前端的重连逻辑会一直重连，
                    # 而每次重连都会把历史日志重放一遍。
                    return
            continue

        idle_rounds = 0
        for _stream, messages in resp:
            for msg_id, fields in messages:
                cursor = msg_id
                payload = fields.get("data")
                if not payload:
                    continue
                # `id` 就是 Redis 的消息 ID —— 前端原样存下来，重连时回传，
                # 所以这里**不能**换成自增序号或 UUID。
                yield {"id": msg_id, "data": payload}


async def _is_terminal(assessment_id: int) -> bool:
    """查一次评估是否已终结。

    **用独立的短会话**：SSE 连接可以持续几十分钟，把会话挂在这条流上
    等于让一个数据库连接被长期占用 —— 池子只有 5 个。
    """
    from app.db.session import AsyncSessionLocal

    try:
        async with AsyncSessionLocal() as session:
            current = await session.get(Assessment, assessment_id)
            if current is None:
                return True
            return current.status in (
                AssessmentStatus.COMPLETED,
                AssessmentStatus.FAILED,
                AssessmentStatus.STOPPED,
            )
    except Exception as exc:  # noqa: BLE001
        # 查不出来时不关流：多留一条连接远好过把用户正在看的日志掐掉
        logger.warning("检查评估 %s 状态失败：%s", assessment_id, exc)
        return False


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


async def _load(session: DBSession, assessment_id: int) -> Assessment:
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise NotFoundError(f"评估 {assessment_id} 不存在")
    return assessment


def _to_out(assessment: Assessment, project_name: str | None) -> AssessmentOut:
    return AssessmentOut(
        id=assessment.id,
        project_id=assessment.project_id,
        project_name=project_name,
        status=assessment.status,
        current_stage=assessment.current_stage,
        progress=assessment.progress,
        security_grade=assessment.security_grade,
        stages=[
            StageStateOut(
                stage=row.stage,
                status=row.status,
                started_at=row.started_at,
                finished_at=row.finished_at,
                note=row.note,
            )
            for row in assessment.stages
        ],
        started_at=assessment.started_at,
        finished_at=assessment.finished_at,
        created_at=assessment.created_at,
    )
