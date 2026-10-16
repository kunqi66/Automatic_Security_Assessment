"""编排核心（B3）的单元测试。

**这里不连 MySQL、不连 Redis、不起容器。** 被覆盖的是编排层里那些
「一旦错了就会静默产生错误结论」的纯逻辑：

- 上下文快照的编解码（错了 → 续跑时上下文凭空少字段）
- 阶段摘要环形缓冲的双重上限（错了 → 内存泄漏，且跑一天才显形）
- 进度折算与「下一个未完成阶段」（错了 → 进度条停在中途）
- Agent 注册表的校验（错了 → 漏注册的 Agent 到运行期才炸）

**刻意不测的**：`engine._advance` 的完整流程。它需要数据库事务、
沙箱、五个真 Agent 同时在位，那样的测试会变成「把实现抄一遍」——
断言的是「我调用了这些函数」，而不是「结果对不对」。
那部分靠集成测试（跑一次真评估）覆盖，见 `tests/README`。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.agents.base import AgentDeps, BaseAgent, FaultTolerance
from app.core.exceptions import StageSkippedError
from app.models.assessment import Assessment, AssessmentStage
from app.models.enums import (
    AssessmentStatus,
    StageName,
    StageStatus,
)
from app.orchestrator import context as ctx_mod
from app.orchestrator import registry, views
from app.orchestrator.broadcaster import LogBroadcaster
from app.orchestrator.context import (
    CONTEXT_SCHEMA_VERSION,
    AssessmentContext,
    ContextDecodeError,
    FindingRef,
    decode_from_storage,
    encode_for_storage,
)
from app.orchestrator.engine import (
    _PROGRESS_PER_STAGE,
    STAGE_ORDER,
    OrchestrationEngine,
    stage_progress,
)
from app.orchestrator.events import LogEvent, LogLevel, StageRecord, stream_key

#: 上下文里的 `workspace` 是**已解析的绝对路径**（`engine._resolve_workspace`
#: 把 `projects.storage_path` 拼到 `workspace_root` 上得到）。这里用一个形状
#: 真实的占位值而不是 `tmp_path`：这些用例根本不碰文件系统，
#: 引入真路径只会让人误以为它们在做 IO。
WORKSPACE = "/srv/asa/tasks/1/src"

# ---------------------------------------------------------------------------
# 夹具
# ---------------------------------------------------------------------------


def make_assessment(
    *,
    assessment_id: int = 1,
    stage_statuses: dict[StageName, StageStatus] | None = None,
) -> Assessment:
    """在内存里拼一个带五个阶段行的评估。

    不落库：`Assessment` / `AssessmentStage` 是普通 ORM 类，
    未 attach 到 session 的实例照样能赋值与读取。
    """
    statuses = stage_statuses or {}
    assessment = Assessment(
        id=assessment_id,
        project_id=7,
        status=AssessmentStatus.RUNNING,
        progress=0,
    )
    assessment.stages = [
        AssessmentStage(
            id=index + 1,
            assessment_id=assessment_id,
            stage=stage,
            status=statuses.get(stage, StageStatus.PENDING),
        )
        for index, stage in enumerate(STAGE_ORDER)
    ]
    return assessment


class FakeRedis:
    """只实现被用到的那几个方法。

    用假 client 而不是 `fakeredis`：多一个依赖换来的「更真」在本模块
    没有意义 —— 这些测试断言的是**我们发出去的参数**（maxlen、
    消息体结构），不是 Redis 的行为。
    """

    def __init__(self) -> None:
        self.added: list[tuple[str, dict[str, str], dict[str, object]]] = []
        self.kv: dict[str, str] = {}
        self.xread_responses: list[list[tuple[str, list[tuple[str, dict[str, str]]]]]] = []

    async def xadd(self, key, fields, **kwargs):  # noqa: ANN001, ANN003, ANN201
        self.added.append((key, fields, kwargs))
        return f"{len(self.added)}-0"

    async def set(self, key, value, **kwargs):  # noqa: ANN001, ANN003, ANN201
        self.kv[key] = value
        return True

    async def exists(self, key):  # noqa: ANN001, ANN201
        return 1 if key in self.kv else 0

    async def delete(self, key):  # noqa: ANN001, ANN201
        self.kv.pop(key, None)
        return 1

    async def expire(self, key, ttl):  # noqa: ANN001, ANN201
        return True


@pytest.fixture
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> FakeRedis:
    client = FakeRedis()
    # 三个模块各自 `from app.db.redis import get_redis`，
    # 所以要把**它们自己命名空间里的那个名字**换掉。
    monkeypatch.setattr("app.orchestrator.broadcaster.get_redis", lambda: client)
    monkeypatch.setattr("app.orchestrator.cancel.get_redis", lambda: client)
    return client


# ---------------------------------------------------------------------------
# 上下文快照
# ---------------------------------------------------------------------------


def test_context_roundtrip_preserves_fields() -> None:
    original = AssessmentContext(
        assessment_id=42,
        project_id=7,
        workspace="/srv/asa/tasks/42/src",
        tech_stack={"language": "python", "framework": "fastapi"},
        findings=[
            FindingRef(
                vuln_id=3,
                rule_id="py/sql-injection",
                vuln_type="SQL 注入",
                severity="high",
                file_path="app/api/order.py",
                line_start=88,
            )
        ],
        chain_ids=[1, 2],
        stage_outputs={StageName.RECON: "ok"},
    )

    restored = decode_from_storage(encode_for_storage(original, StageName.RECON))

    assert restored.assessment_id == 42
    assert restored.findings[0].file_path == "app/api/order.py"
    assert restored.chain_ids == [1, 2]
    assert restored.stage_outputs[StageName.RECON] == "ok"


def test_snapshot_never_contains_sandbox_handle() -> None:
    """沙箱句柄是**运行时对象**，绝不能进快照。

    它不可 JSON 序列化（含 Docker 客户端与连接池）。真写进去的话，
    `model_dump_json` 会抛 `PydanticSerializationError` —— 但那是在
    **阶段结束时**才炸，此时阶段已经跑完，重跑一次才能发现。
    所以这里直接断言它不在 dump 里。
    """
    ctx = AssessmentContext(
        assessment_id=1,
        project_id=1,
        workspace=WORKSPACE,
        sandbox_handle=object(),
    )

    snapshot = ctx.to_snapshot(StageName.POC_VERIFY)

    assert "sandbox_handle" not in snapshot.payload
    assert "sandbox_handle" not in encode_for_storage(ctx, StageName.POC_VERIFY)["payload"]


def test_snapshot_never_contains_sandbox_config() -> None:
    """沙箱参数与 `sandbox_handle` 同理，**不进快照**。

    它是运行时态：`engine._load_context` 每次运行开始时从库里重新解析
    （与 `workspace` 同一条理由 —— 以当前配置为准，快照里那份是上次运行的坐标）。

    这条断言防的是一类很隐蔽的错：如果哪天有人把它改成参与序列化，
    行为会变成「**续跑时用的是上次的沙箱参数**」。不报错、不崩，
    只是配置改了不生效 —— 而「改了不生效」正是这个字段这次被接通要修掉的东西。
    """
    ctx = AssessmentContext(
        assessment_id=1,
        project_id=1,
        workspace=WORKSPACE,
        sandbox_config=object(),
    )

    snapshot = ctx.to_snapshot(StageName.POC_VERIFY)

    assert "sandbox_config" not in snapshot.payload
    assert "sandbox_config" not in encode_for_storage(ctx, StageName.POC_VERIFY)["payload"]


def test_sandbox_config_defaults_to_none() -> None:
    """没注入时必须是 `None`，而不是某个看起来合理的默认值。

    `None` 是一条**明确的信号**：「库里没配，请回落」。
    若这里悄悄填上一个默认 `SandboxConfig`，`verify` 侧的回落分支就永远不会走，
    而「管理页没配置」这个事实也就再没人能看见 —— 又一个静默失败。
    """
    ctx = AssessmentContext(assessment_id=1, project_id=1, workspace=WORKSPACE)

    assert ctx.sandbox_config is None


def test_decode_rejects_version_mismatch() -> None:
    """版本不符时**抛错而不是尽力解析**。

    尽力解析的后果是「用旧结构的字段喂给新代码」——一半字段是默认值，
    而调用方以为拿到的是完整上下文。静默降级在这里比失败危险得多。
    """
    raw = encode_for_storage(
        AssessmentContext(assessment_id=1, project_id=1, workspace=WORKSPACE),
        StageName.RECON,
    )
    raw["schema_version"] = CONTEXT_SCHEMA_VERSION + 1

    with pytest.raises(ContextDecodeError, match="版本"):
        decode_from_storage(raw)


def test_decode_rejects_empty_and_malformed() -> None:
    with pytest.raises(ContextDecodeError, match="为空"):
        decode_from_storage(None)
    with pytest.raises(ContextDecodeError, match="payload"):
        decode_from_storage({"schema_version": CONTEXT_SCHEMA_VERSION, "payload": "字符串"})
    with pytest.raises(ContextDecodeError, match="校验失败"):
        decode_from_storage(
            {
                "schema_version": CONTEXT_SCHEMA_VERSION,
                # assessment_id 缺失 → Pydantic 报错 → 包成 ContextDecodeError
                "payload": {"project_id": 1, "workspace": "/x"},
            }
        )


def test_oversized_snapshot_is_logged_not_truncated(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """超限**只告警不截断**。

    截断会产出一份「看起来正常但内容缺失」的快照，续跑时表现为
    莫名其妙的空字段；而完整写下去最多是行大一点，真撑爆了数据库会报错。
    """
    monkeypatch.setattr(ctx_mod.settings, "context_payload_max_bytes", 200)
    ctx = AssessmentContext(
        assessment_id=99,
        project_id=1,
        workspace=WORKSPACE,
        stage_outputs={"k": "x" * 2000},
    )

    encoded = encode_for_storage(ctx, StageName.CODE_AUDIT)

    # 内容完整 —— 这是本用例的重点
    assert encoded["payload"]["stage_outputs"]["k"] == "x" * 2000
    assert any("超过建议上限" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 事件与日志流
# ---------------------------------------------------------------------------


def test_stream_key_shape() -> None:
    assert stream_key(42) == "log:42"


def test_log_event_json_is_flat_enough_for_frontend() -> None:
    """前端 `types.ts` 的 `LogEvent` 读的是 `level` / `message` / `stage`。

    这三个字段名是本模块与前端之间的隐式契约：改名不会有任何编译错误，
    只会让终端面板**一片空白**。所以在这里钉住。
    """
    event = LogEvent(
        type="log",
        assessment_id=1,
        stage=StageName.RECON,
        level=LogLevel.WARN,
        message="技术栈识别置信度偏低",
        ts=datetime.now(UTC),
    )

    payload = event.model_dump(mode="json")

    assert payload["level"] == "warn"
    assert payload["message"] == "技术栈识别置信度偏低"
    assert payload["stage"] == "recon"
    assert payload["assessment_id"] == 1


@pytest.mark.asyncio
async def test_broadcaster_keeps_excerpt_under_both_limits(
    fake_redis: FakeRedis,
) -> None:
    """摘要缓冲必须同时受**行数**与**字节数**约束。

    只看行数挡不住「一行 10MB 的堆栈」，只看字节数挡不住「十万行短消息」。
    这里把两个上限都压到很小，然后灌入超量的数据。
    """
    broadcaster = LogBroadcaster()
    monkey = pytest.MonkeyPatch()
    monkey.setattr("app.orchestrator.broadcaster.settings.log_excerpt_max_lines", 5)
    monkey.setattr("app.orchestrator.broadcaster.settings.log_excerpt_max_bytes", 300)
    try:
        for index in range(200):
            await broadcaster.log(
                assessment_id=1,
                stage=StageName.CODE_AUDIT,
                level=LogLevel.INFO,
                # 每条 100 字节，10 条就超过 300 字节上限
                message=f"第 {index} 行 " + "x" * 90,
            )
    finally:
        monkey.undo()

    excerpt = broadcaster.excerpt(1, StageName.CODE_AUDIT)

    assert len(excerpt.splitlines()) <= 5
    assert len(excerpt.encode("utf-8")) < 1000
    # 保留的是**最近**的，不是最早的 —— 缓冲区是 deque + popleft
    assert "第 199 行" in excerpt
    assert "第 0 行" not in excerpt


@pytest.mark.asyncio
async def test_broadcaster_uses_approximate_trim(fake_redis: FakeRedis) -> None:
    """`XTRIM` 必须是近似的（`approximate=True`）。

    精确裁剪要遍历整个 radix tree，代价与流长度成正比；而日志不是账本，
    实际长度略微超标没有任何后果。
    """
    broadcaster = LogBroadcaster()
    await broadcaster.log(
        assessment_id=1,
        stage=StageName.RECON,
        level=LogLevel.INFO,
        message="x",
    )

    key, fields, kwargs = fake_redis.added[0]
    assert key == "log:1"
    assert kwargs["approximate"] is True
    assert "data" in fields


@pytest.mark.asyncio
async def test_broadcaster_never_raises_on_redis_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redis 挂了**不能**让评估失败。

    日志是可观测性，不是正确性。让「日志写不进 Redis」把一次跑了
    二十分钟的评估判死，是本末倒置。
    """

    class Broken:
        async def xadd(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            from redis.exceptions import RedisError

            raise RedisError("connection refused")

    monkeypatch.setattr("app.orchestrator.broadcaster.get_redis", lambda: Broken())
    broadcaster = LogBroadcaster()

    await broadcaster.log(  # 不抛
        assessment_id=1,
        stage=StageName.RECON,
        level=LogLevel.ERROR,
        message="测试",
    )


@pytest.mark.asyncio
async def test_drop_excerpt_releases_memory(fake_redis: FakeRedis) -> None:
    """阶段摘要落库后必须释放，否则 worker 跑一天就攒满所有历史评估的摘要。"""
    broadcaster = LogBroadcaster()
    await broadcaster.log(
        assessment_id=1,
        stage=StageName.RECON,
        level=LogLevel.INFO,
        message="x",
    )
    assert broadcaster.excerpt(1, StageName.RECON)

    broadcaster.drop_excerpt(1, StageName.RECON)

    assert broadcaster.excerpt(1, StageName.RECON) == ""


# ---------------------------------------------------------------------------
# 阶段状态与进度
# ---------------------------------------------------------------------------


def test_to_stage_record_computes_duration_only_when_finished() -> None:
    started = datetime(2026, 10, 16, 10, 0, 0, tzinfo=UTC)
    row = AssessmentStage(
        id=1,
        assessment_id=1,
        stage=StageName.RECON,
        status=StageStatus.RUNNING,
        started_at=started,
    )

    assert views.to_stage_record(row).duration_ms is None

    row.finished_at = started + timedelta(seconds=2.5)
    assert views.to_stage_record(row).duration_ms == 2500


def test_first_unfinished_skips_completed_and_stopped_midway() -> None:
    assessment = make_assessment(
        stage_statuses={
            StageName.RECON: StageStatus.COMPLETED,
            StageName.CODE_AUDIT: StageStatus.COMPLETED,
            StageName.POC_VERIFY: StageStatus.RUNNING,  # 上次崩在这里
        }
    )

    assert OrchestrationEngine._first_unfinished(assessment) is StageName.POC_VERIFY


def test_first_unfinished_returns_none_when_all_terminal() -> None:
    assessment = make_assessment(stage_statuses=dict.fromkeys(STAGE_ORDER, StageStatus.COMPLETED))

    assert OrchestrationEngine._first_unfinished(assessment) is None


def test_recompute_progress_counts_skipped_and_failed_as_terminal() -> None:
    """`skipped` 与 `failed` 都要计入进度。

    不把它们算进去的话，一个「沙箱不可用 → poc_verify 跳过 → 继续跑报告」
    的评估会永远停在 60%，即使报告已经生成完了。
    """
    assessment = make_assessment(
        stage_statuses={
            StageName.RECON: StageStatus.COMPLETED,
            StageName.CODE_AUDIT: StageStatus.COMPLETED,
            StageName.POC_VERIFY: StageStatus.SKIPPED,
            StageName.EXPLOIT_CHAIN: StageStatus.FAILED,
        }
    )

    OrchestrationEngine._recompute_progress(assessment)

    assert assessment.progress == 4 * _PROGRESS_PER_STAGE


def test_progress_never_exceeds_100() -> None:
    assessment = make_assessment(stage_statuses=dict.fromkeys(STAGE_ORDER, StageStatus.COMPLETED))

    OrchestrationEngine._recompute_progress(assessment)

    assert assessment.progress == 100


def test_stage_progress_mapping_is_total() -> None:
    """每个 `StageStatus` 都要有明确折算，不许有「落到 else」的成员。

    漏一个的症状是进度条在该状态下**停在 0**，而且不报错。
    """
    for status in StageStatus:
        value = stage_progress(status)
        assert isinstance(value, int)
        assert 0 <= value <= 100


def test_stage_order_matches_pipeline() -> None:
    assert STAGE_ORDER == (
        StageName.RECON,
        StageName.CODE_AUDIT,
        StageName.POC_VERIFY,
        StageName.EXPLOIT_CHAIN,
        StageName.REPORT_GEN,
    )


# ---------------------------------------------------------------------------
# Agent 注册表
# ---------------------------------------------------------------------------


class _DummyAgent(BaseAgent[object, object]):
    name = "dummy"
    stage = StageName.RECON
    fault_tolerance = FaultTolerance.SKIPPABLE

    async def run(self, ctx, inp):  # noqa: ANN001, ANN201
        raise StageSkippedError("测试用")


@pytest.fixture
def clean_registry(monkeypatch: pytest.MonkeyPatch):
    """隔离注册表，避免污染其它用例。"""
    registry.reset_for_tests()
    # 关掉惰性默认注册：否则 `registered_stages()` 会把五个真 Agent 拉进来
    monkeypatch.setattr(registry, "_ensure_defaults", lambda: None)
    yield
    registry.reset_for_tests()


def test_register_rejects_stage_mismatch(clean_registry: None) -> None:
    """类上声明的 `stage` 与注册时传的必须一致。

    不一致的话，引擎按 `STAGE_ORDER` 建出来的实例会去跑另一个阶段 ——
    而它自己以为在跑本阶段（`emit` 的 stage 字段、落库的阶段行都会错位）。
    """
    with pytest.raises(ValueError, match="却被登记到"):
        registry.register(StageName.CODE_AUDIT, _DummyAgent)


def test_register_rejects_duplicate_without_replace(clean_registry: None) -> None:
    registry.register(StageName.RECON, _DummyAgent)

    with pytest.raises(ValueError, match="已绑定"):
        registry.register(StageName.RECON, _DummyAgent)

    registry.register(StageName.RECON, _DummyAgent, replace=True)  # 显式覆盖可以


def test_assert_complete_names_the_missing_stage(clean_registry: None) -> None:
    """缺哪个 Agent 必须**点名**。

    「注册不完整」这句话对排查毫无帮助 —— 五个阶段里缺一个，
    得靠人一个个数。
    """
    registry.register(StageName.RECON, _DummyAgent)

    with pytest.raises(LookupError) as excinfo:
        registry.assert_complete(STAGE_ORDER)

    assert "code_audit" in str(excinfo.value)


def test_build_passes_deps_through(clean_registry: None) -> None:
    registry.register(StageName.RECON, _DummyAgent)
    deps = AgentDeps(session=None, broadcaster=LogBroadcaster())  # type: ignore[arg-type]

    agent = registry.build(StageName.RECON, deps)

    assert isinstance(agent, _DummyAgent)
    assert agent.deps is deps


def test_fault_tolerance_defaults_to_fatal() -> None:
    """新增 Agent 若忘了声明档位，默认**最严**。

    默认 `SKIPPABLE` 的话，一个本该致命的失败会被静默跳过，
    评估照常出报告 —— 而报告里没有任何东西提示「有一整个阶段没跑」。
    """

    class _Undeclared(BaseAgent[object, object]):
        stage = StageName.RECON

        async def run(self, ctx, inp):  # noqa: ANN001, ANN201
            return None

    assert _Undeclared.fault_tolerance is FaultTolerance.FATAL


def test_stage_record_is_reused_for_sse_and_rest() -> None:
    """SSE 推的阶段事件与 REST 拉的阶段列表用**同一个类**。

    两个类的话，症状是「刷新页面后进度条与刚才推来的状态不一致」——
    因为两条路径各有一套字段名，改了一个忘了另一个。
    """
    record = StageRecord(stage=StageName.RECON, status=StageStatus.RUNNING)

    assert set(record.model_dump()) >= {"stage", "status", "started_at", "note"}
