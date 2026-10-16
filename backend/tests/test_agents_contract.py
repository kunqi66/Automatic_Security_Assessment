"""五个 Agent 与编排引擎之间的**契约测试**。

## 这个文件存在的理由

`tests/test_orchestrator_core.py` 测注册表时**刻意关掉了** `_ensure_defaults`
（`monkeypatch.setattr(registry, "_ensure_defaults", lambda: None)`），
为的是把注册表当作一个纯数据结构来测。代价是**真实的五个 Agent 从来没有
被任何测试加载过**。

那意味着：`app/agents/report_gen.py` 里的类名被改成 `ReportAgent`、
或者 `registry.py` 里的 import 路径写错一个字母，任何单元测试都不会红 ——
它会一路安静地通过，直到 `worker.py` 启动时 `assert_complete` 抛
`LookupError`，**而 worker 是单独一个进程，CI 不跑它就发现不了**。

本文件补上这一段：真的 import 那五个类，真的跑一遍注册，并对齐
stage 与容错档位。**不连数据库、不起容器** —— 只做类型与元数据的断言。
"""

from __future__ import annotations

import ast
import importlib
import inspect
import textwrap

import pytest

from app.agents.base import AgentDeps, BaseAgent, FaultTolerance
from app.models.enums import StageName
from app.orchestrator import registry
from app.orchestrator.broadcaster import LogBroadcaster
from app.orchestrator.engine import STAGE_ORDER

#: 设计文档 §6 钉死的容错档位。**改这里之前先改设计文档** ——
#: 这五个值决定了「哪种失败会让整轮评估作废」，是产品行为不是实现细节。
#:
#: `recon` / `code_audit` / `report_gen` 为致命：没有技术栈就没有审计，
#: 没有审计就没有报告，没有报告就没有交付物。
#: `poc_verify` / `exploit_chain` 为降级：基础设施（沙箱）不可用不该
#: 让已完成的静态分析作废，且「没验证出来」不等于「不存在」。
EXPECTED_TOLERANCE = {
    StageName.RECON: FaultTolerance.FATAL,
    StageName.CODE_AUDIT: FaultTolerance.FATAL,
    StageName.POC_VERIFY: FaultTolerance.SKIPPABLE,
    StageName.EXPLOIT_CHAIN: FaultTolerance.SKIPPABLE,
    StageName.REPORT_GEN: FaultTolerance.FATAL,
}


@pytest.fixture
def loaded_registry():
    """让 `_ensure_defaults` **真正执行一次**（与 core 测试相反）。

    跑完还原，避免污染其它用例 —— `_defaults_loaded` 是个模块级全局，
    留着它会改变 `test_orchestrator_core.py` 里那些用例的前提。
    """
    registry.reset_for_tests()
    registry._ensure_defaults()
    yield registry
    registry.reset_for_tests()


def test_all_five_agents_import_and_register(loaded_registry) -> None:
    """五个阶段的 Agent 都要能被 import 并注册。

    失败信息里带上「缺哪个阶段」比一句「注册不完整」有用得多 ——
    这正是 `assert_complete` 的设计意图，这里复用它。
    """
    loaded_registry.assert_complete(STAGE_ORDER)

    assert set(loaded_registry.registered_stages()) == set(STAGE_ORDER)


def test_registered_agent_declares_matching_stage(loaded_registry) -> None:
    """注册在哪个阶段，类上就得声明哪个阶段。

    `registry.register` 已经会校验这一点，但那是**注册时**的检查；
    这里从「按阶段取到的东西」反过来验一次，覆盖的是
    「`register(cls.stage, cls)` 这种写法把类自己的声明当成键」的情形。
    """
    for stage in STAGE_ORDER:
        agent_cls = loaded_registry.agent_class(stage)
        assert agent_cls.stage is stage, f"{stage.value} 取到的 Agent 声明的是 {agent_cls.stage}"


def test_fault_tolerance_matches_design(loaded_registry) -> None:
    """容错档位决定「哪种失败会让整轮评估作废」，是产品行为不是实现细节。

    断言的是**类属性**而不是实例属性：这个值必须在构造之前就定下来，
    否则引擎没法在起容器之前决定「这个阶段挂了要不要继续」。
    """
    for stage, expected in EXPECTED_TOLERANCE.items():
        actual = loaded_registry.agent_class(stage).fault_tolerance
        assert actual is expected, (
            f"{stage.value} 的容错档位与设计不符：期望 {expected.value}，实际 {actual.value}"
        )


def test_every_agent_has_a_human_readable_name(loaded_registry) -> None:
    """`name` 会出现在阶段日志与报告里。空字符串或默认值 `agent` 说明忘了写。

    这不是洁癖：用户看到「agent 正在执行」时无从知道在等什么。
    """
    for stage in STAGE_ORDER:
        name = loaded_registry.agent_class(stage).name
        assert name and name != BaseAgent.name, f"{stage.value} 没有中文名"


def test_build_injects_deps_into_real_agents(loaded_registry) -> None:
    """`build` 要能把依赖真的注入进去。

    用 `session=None` 是刻意的：本用例只验注入路径，不验 Agent 行为。
    Agent 的 `__init__` 只存引用，不碰 session —— 真碰了会在这里炸，
    而那恰好是我们要挡的（构造函数里做 IO 会让 worker 启动期不可控）。
    """
    deps = AgentDeps(session=None, broadcaster=LogBroadcaster())  # type: ignore[arg-type]

    for stage in STAGE_ORDER:
        agent = loaded_registry.build(stage, deps)
        assert isinstance(agent, BaseAgent)
        assert agent.deps is deps


def test_gather_input_default_is_identity(loaded_registry) -> None:
    """五个 Agent 都不覆盖 `gather_input`，输入就是整个上下文。

    钉住它的意义：`engine` 调用的是 `agent.run(ctx, agent.gather_input(ctx))`，
    若某个 Agent 改成返回一个**不是** `ctx` 的东西，`run(self, ctx, inp)` 的
    两个参数就不再是同一个对象 —— 而现有实现全都假设它们是。
    """
    deps = AgentDeps(session=None, broadcaster=LogBroadcaster())  # type: ignore[arg-type]
    sentinel = object()

    for stage in STAGE_ORDER:
        agent = loaded_registry.build(stage, deps)
        assert agent.gather_input(sentinel) is sentinel, stage.value  # type: ignore[arg-type]


def test_no_agent_commits(loaded_registry) -> None:
    """**Agent 不得 commit**（T4：阶段边界是唯一原子提交点）。

    用源码扫描而不是运行时断言：一个 Agent 只在某条分支上 commit 的话，
    运行时测试要覆盖到那条分支才能发现。这里扫的是「有没有调用」这个事实。

    允许 `flush()` —— 阶段内需要中间态拿到自增 id，那是合法的。
    """

    for stage in STAGE_ORDER:
        agent_cls = loaded_registry.agent_class(stage)
        source = inspect.getsource(agent_cls)
        assert "session.commit()" not in source, f"{agent_cls.__name__} 里有 session.commit()"


# ---------------------------------------------------------------------------
# 配置 → 分析引擎的接线
# ---------------------------------------------------------------------------


async def test_code_audit_把配置里的规模闸传给分析引擎(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """三个 `analysis_*` 限额必须**真的**被传进 `analyze()`。

    为什么值得单测：`analyze()` 的这三个参数都有模块内默认值，所以
    把 `max_files=settings.analysis_max_files` 整行删掉之后，
    **没有任何测试会红** —— 引擎照跑，只是悄悄用回了硬编码的 2000。
    于是 `Settings` 里那三个字段变成一句谎话：改配置不生效，
    而「为什么我把上限调到 100 还是扫了 2000 个文件」要查很久。

    这里拦住的是那条「参数还在、接线断了」的路径。
    """
    from app.agents.code_audit import CodeAuditAgent
    from app.analysis.types import AnalysisResult
    from app.core.config import settings

    captured: dict[str, object] = {}

    async def fake_analyze(manifest, read_source, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return AnalysisResult(
            findings=(),
            files_scanned=0,
            total_loc=0,
            duration_ms=0,
            truncated=False,
        )

    class _Manifest:
        total_files = 0
        total_loc = 0
        truncated = False

    async def fake_manifest(project_id: int) -> object:
        return _Manifest()

    monkeypatch.setattr("app.analysis.analyze", fake_analyze, raising=True)
    monkeypatch.setattr("app.projects.workspace.read_manifest_async", fake_manifest, raising=True)
    # 值改成与默认值都不同，否则「接线断了」也会因为恰好等于默认值而通过
    monkeypatch.setattr(settings, "analysis_max_files", 7)
    monkeypatch.setattr(settings, "analysis_max_seconds", 3.5)
    monkeypatch.setattr(settings, "analysis_max_file_bytes", 4096)

    class _Ctx:
        project_id = 1
        assessment_id = 1
        stage_outputs: dict[str, object] = {}

    agent = CodeAuditAgent(_deps())
    agent.bind(_Ctx())  # type: ignore[arg-type]
    monkeypatch.setattr(agent, "_persist", _noop_persist)
    await agent.run(_Ctx(), _Ctx())  # type: ignore[arg-type]

    assert captured["max_files"] == 7
    assert captured["max_seconds"] == 3.5
    assert captured["max_file_bytes"] == 4096


async def _noop_persist(ctx: object, result: object) -> list[object]:
    """跳过落库：本用例只验「配置传进去了」，不验写库。"""
    return []


def _deps() -> AgentDeps:
    return AgentDeps(session=None, broadcaster=LogBroadcaster())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ORM 落库：Agent 传的关键字必须真的是表上的列
# ---------------------------------------------------------------------------


def test_落库关键字都是真实的_ORM_列() -> None:
    """扫 Agent 源码里所有 `Model(...)` 的关键字实参，逐个核对是不是真列。

    ## 为什么值得用 AST 扫而不是跑一遍

    这条守的是一类**只在实际落库那一刻才炸**的错误：B4/B5/B6 的 DTO 按契约 2
    的要求「字段名逐字照抄 ORM 列名」，所以两边一旦漂移（比如 B5 的
    `PocAttempt` 多了 `probe_id` / `failed_gate` / `reason_code`，而表上没有），
    症状是 `TypeError: 'probe_id' is an invalid keyword argument`。

    单元测试抓不到它：测试全都 mock 掉 session、或根本不走到有数据的那条分支
    （`poc_verify._persist` 只在**真有漏洞验证过**时才构造 `PocAttempt`）。
    真实后果是「端到端跑到动态验证阶段才崩」。

    这里不跑代码，直接扫源码 —— 无论那条分支有没有被测到，字段名都在。
    """

    from app.models import chain as chain_models
    from app.models import report as report_models
    from app.models import vulnerability as vuln_models

    # 表上真实存在的列名
    real: dict[str, set[str]] = {}
    for mod in (vuln_models, chain_models, report_models):
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            table = getattr(obj, "__table__", None)
            if table is not None:
                real[obj.__name__] = {c.name for c in table.columns}

    names = _agent_class_names()
    assert names, "没扫到任何 Agent 类，测试本身失效了"

    problems: list[str] = []
    for cls_name in names:
        src = inspect.getsource(_import_agent(cls_name))
        for node in ast.walk(ast.parse(_dedent(src))):
            if not isinstance(node, ast.Call):
                continue
            model = _callee_name(node.func)
            if model not in real:
                continue
            for kw in node.keywords:
                if kw.arg and kw.arg not in real[model]:
                    problems.append(
                        f"{cls_name} 给 {model} 传了不存在的列 `{kw.arg}`（第 {node.lineno} 行）"
                    )

    assert not problems, (
        "Agent 落库传了表上没有的字段，运行到那条分支会抛 TypeError：\n  "
        + "\n  ".join(problems)
        + "\n要么改 Agent，要么先改 PRD §6 的列清单再加迁移 —— "
        "PRD §6 是列名的唯一来源。"
    )


def _agent_class_names() -> list[str]:
    from app.orchestrator import registry
    from app.orchestrator.engine import STAGE_ORDER

    registry.reset_for_tests()
    registry._ensure_defaults()
    names = [registry.agent_class(s).__name__ for s in STAGE_ORDER]
    registry.reset_for_tests()
    return names


def _import_agent(cls_name: str) -> type:
    for mod in (
        "app.agents.recon",
        "app.agents.code_audit",
        "app.agents.poc_verify",
        "app.agents.exploit_chain",
        "app.agents.report_gen",
    ):
        obj = getattr(importlib.import_module(mod), cls_name, None)
        if obj is not None:
            return obj
    raise AssertionError(f"找不到 Agent 类 {cls_name}")


def _dedent(src: str) -> str:
    return textwrap.dedent(src)


def _callee_name(func: ast.expr) -> str:
    """取被调用者的**末段名**：`m.PocAttempt(...)` 与 `PocAttempt(...)` 归一。"""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""
