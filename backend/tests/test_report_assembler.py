"""装配层端到端：**在 LLM 完全不可用时把报告从头到尾走一遍**。

## 为什么要有这一组，而不是只测渲染

渲染测试喂的是手搓的 `ReportData`，它能证明「模板没问题」，但证明不了
「数据真的能装配成那个形状」。中间那一段 —— `load_snapshot` 取数、
`_latest_patch` 挑补丁、`_poc_evidence` 选探针、`build_report_data` 派生字段 ——
恰恰是最容易漏的地方，而它一旦漏了，症状是**报告照常生成、只是少了一块**。

这一组用真 SQLAlchemy 会话（SQLite 内存库）跑 `build_report()`，
断言的是**契约 4 的返回物**：报告出来了、章节齐了、结论字段一个不少。

## 为什么用 SQLite 而不是 MySQL

不为「像生产」付代价：本组的断言全部是**行与行之间的关系**（关联有没有被
取出来、排序对不对、状态怎么映射），与方言无关。跑 MySQL 只会让这套测试
在本地跑不起来，从而慢慢变成没人跑的那一组。

## 注入的是「未配 key」的假客户端

`NoKeyCompleter` 的 `is_configured=False` 走的正是「开发态没配 key」那条路，
与生产降级是**同一个分支**，所以它测出来的就是真实降级行为，
而不是一个只在测试里存在的假路径。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.llm.types import TEMPLATE_MODEL
from app.models.assessment import Assessment, AssessmentStage
from app.models.chain import AttackChain, AttackChainNode
from app.models.enums import (
    AssessmentStatus,
    ChainNodeType,
    DetectionMethod,
    PatchSource,
    PatchStatus,
    ProjectStatus,
    ReportFormat,
    SecurityGrade,
    Severity,
    StageName,
    StageStatus,
    TaintStepType,
    VerificationStatus,
    VulnStatus,
)
from app.models.project import Project
from app.models.vulnerability import Patch, PocAttempt, TaintPath, Vulnerability
from app.report.assembler import build_report, build_summary, load_snapshot
from app.report.errors import ReportSnapshotError
from tests.llm_fakes import NoKeyCompleter

#: 固定时间戳：报告里有 `generated_at`，用 `now()` 会让断言依赖运行时刻。
GENERATED_AT = datetime(2026, 10, 16, 12, 0, 0)


@asynccontextmanager
async def memory_session() -> AsyncIterator[AsyncSession]:
    """一次性内存库。

    `StaticPool` 是必需的：`:memory:` 库的生命周期绑定在**连接**上，
    用默认连接池时第二个连接会看到一张空库 —— 而症状是「测试偶发失败」，
    取决于哪个协程先拿到连接。

    **抽成上下文管理器而不是只写成 fixture**：`test_report_export.py` 需要同一个
    库，但它自己还要叠一层「把报告根目录挪进 tmp」的 fixture。跨模块复用 fixture
    会遇到 pytest 的 fixture 名与 ruff 的 F811 打架（导入的 fixture 名会被当成
    重复定义），而一个普通的 async 上下文管理器两边都能直接用。
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """本文件用的库。"""
    async with memory_session() as sess:
        yield sess


async def seed(session: AsyncSession, *, with_llm_patch: bool = True) -> int:
    """造一次「有漏洞、有链、有验证记录」的评估，返回 assessment_id。"""
    project = Project(
        name="靶场订单系统",
        description="用于演示注入类漏洞的靶场。",
        source_type="git",
        source_url="https://example.invalid/target.git",
        source_branch="main",
        tech_stack={"python": "3.12", "flask": "3.0"},
        total_loc=1200,
        status=ProjectStatus.COMPLETED,
    )
    session.add(project)
    await session.flush()

    assessment = Assessment(
        project_id=project.id,
        status=AssessmentStatus.COMPLETED,
        current_stage=StageName.REPORT_GEN,
        progress=100,
        started_at=datetime(2026, 10, 16, 10, 0, 0),
        finished_at=datetime(2026, 10, 16, 10, 3, 30),
    )
    assessment.stages = [
        AssessmentStage(
            stage=StageName.RECON,
            status=StageStatus.COMPLETED,
            started_at=datetime(2026, 10, 16, 10, 0, 0),
            finished_at=datetime(2026, 10, 16, 10, 0, 30),
        ),
        AssessmentStage(
            stage=StageName.POC_VERIFY,
            status=StageStatus.SKIPPED,
            note="沙箱不可达，已跳过动态验证",
        ),
    ]
    session.add(assessment)
    await session.flush()

    # ① 已验证的严重漏洞：有污点路径、有通过无害闸门的探针、有已过四道校验的补丁
    verified = Vulnerability(
        assessment_id=assessment.id,
        code="VULN-2026-0001",
        title="订单查询接口存在 SQL 注入",
        vuln_type="sql_injection",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        status=VulnStatus.VERIFIED,
        file_path="app/api/order.py",
        line_start=40,
        line_end=48,
        code_snippet="cursor.execute(sql)",
        sink_symbol="cursor.execute",
        description="外部输入被直接拼接进 SQL 语句。",
        detection_method=DetectionMethod.TAINT_INTER,
    )
    verified.taint_paths = [
        TaintPath(
            step_index=0,
            step_type=TaintStepType.SOURCE,
            file_path="app/api/order.py",
            line=12,
            symbol="request.args",
            code_snippet="order_id = request.args.get('order_id')",
        ),
        TaintPath(
            step_index=1,
            step_type=TaintStepType.SINK,
            file_path="app/api/order.py",
            line=44,
            symbol="cursor.execute",
            code_snippet="cursor.execute(sql)",
        ),
    ]
    verified.poc_attempts = [
        PocAttempt(
            payload="1' AND 1=1-- ",
            technique="boolean_blind",
            matched=True,
            http_status=200,
            elapsed_ms=120,
            harmless_guard_passed=True,
        ),
    ]
    verified.patches = [
        Patch(
            target_file="app/api/order.py",
            diff_content=(
                "--- a/app/api/order.py\n+++ b/app/api/order.py\n@@ -40,1 +40,2 @@\n-old\n+new\n"
            ),
            status=PatchStatus.SUGGESTED,
            source=PatchSource.LLM if with_llm_patch else PatchSource.TEMPLATE,
            llm_model="deepseek-chat" if with_llm_patch else None,
            rationale="改为参数化查询。",
            valid_diff=True,
            window_ok=True,
            apply_check_ok=True,
            taint_cleared=True,
        )
    ]

    # ② 未验证的高危：没有探针记录 —— 报告里必须如实标出来
    unverified = Vulnerability(
        assessment_id=assessment.id,
        code="VULN-2026-0002",
        title="用户中心存在存储型跨站脚本",
        vuln_type="xss",
        severity=Severity.HIGH,
        cvss_score=8.0,
        status=VulnStatus.UNVERIFIED,
        file_path="app/views/profile.py",
        line_start=88,
        line_end=90,
        description="用户昵称未做输出编码。",
        detection_method=DetectionMethod.TAINT_INTRA,
    )
    unverified.taint_paths = [
        TaintPath(
            step_index=0,
            step_type=TaintStepType.SOURCE,
            file_path="app/views/profile.py",
            line=20,
            symbol="request.form",
        ),
        TaintPath(
            step_index=1,
            step_type=TaintStepType.SINK,
            file_path="app/views/profile.py",
            line=88,
            symbol="render_template_string",
        ),
    ]
    # 被无害闸门拦下的一次尝试：可以用来说明「这里试过但没打」
    unverified.poc_attempts = [
        PocAttempt(
            payload="<img src=x onerror=alert(1)>",
            technique="reflected",
            matched=False,
            harmless_guard_passed=False,
            failure_reason="载荷命中无害化闸门，已拦下",
        )
    ]

    session.add_all([verified, unverified])
    await session.flush()

    chain = AttackChain(
        assessment_id=assessment.id,
        name="SQL 注入 → 管理员凭证 → 上传 WebShell",
        description="自订单查询接口注入开始，逐级取得更高权限。",
        severity=Severity.CRITICAL,
        entry_point="订单查询接口",
        target_asset="ECS 宿主机",
        confidence=0.85,
    )
    chain.nodes = [
        AttackChainNode(
            order_index=0,
            node_type=ChainNodeType.VULN,
            vuln_id=verified.id,
            label="SQL 注入获取数据库读写",
            rule_id="R1",
            verification_status=VerificationStatus.VERIFIED,
        ),
        AttackChainNode(
            order_index=1,
            node_type=ChainNodeType.CREDENTIAL,
            label="弱哈希离线破解得到明文口令",
            rule_id="R5",
            verification_status=VerificationStatus.INFERRED,
        ),
    ]
    session.add(chain)
    await session.flush()
    await session.commit()
    return assessment.id


# ---------------------------------------------------------------------------
# 一、LLM 完全不可用时，报告仍然完整
# ---------------------------------------------------------------------------


async def test_未配_key_时报告仍然完整(session: AsyncSession) -> None:
    """**这是本模块最重要的一条断言。**

    判据（PRD §7.6.2 L4）：拿掉 LLM，系统的**结论**必须一字不变，只有措辞会变。
    所以这里断言的不是「有内容」，而是逐项的具体事实：
    评分、等级、排序、状态、CVSS、污点路径 —— 一项都不能因为模型不说话而消失。
    """
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())

    data = draft.data
    # 结论字段：全部来自确定性代码
    assert data.score.score == pytest.approx(100 - 9.8 - 8.0 * 0.1, abs=0.01)
    assert data.score.grade == SecurityGrade.CRITICAL
    assert data.score.veto is True, "已验证的严重漏洞必须一票否决"

    # 清单按「严重度 → CVSS → 编号」排，与输入顺序无关
    assert [v.code for v in data.vulnerabilities] == ["VULN-2026-0001", "VULN-2026-0002"]
    assert [v.status for v in data.vulnerabilities] == [VulnStatus.VERIFIED, VulnStatus.UNVERIFIED]

    # 两条漏洞的 CVSS 与污点路径都在（这就是「信息量不缩水」）
    assert data.vulnerabilities[0].cvss_score == pytest.approx(9.8)
    assert data.vulnerabilities[0].cvss_estimated is False
    assert [s.step_index for s in data.vulnerabilities[0].taint_path] == [0, 1]
    assert data.vulnerabilities[0].taint_path[0].symbol == "request.args"

    # 第 3 章标题：清单里有未验证条目 → 不能写「已验证漏洞清单」
    assert data.chapter3_title == "漏洞清单（含未经验证条目）"
    assert data.has_verified is True

    # 攻击链与整改建议
    assert len(data.chains) == 1
    assert data.chains[0].verified_count == 1
    assert data.chains[0].inferred_count == 1
    assert [r.code for r in data.recommendations] == ["VULN-2026-0001", "VULN-2026-0002"]
    assert [r.rank for r in data.recommendations] == [1, 2]


async def test_未配_key_时全部文案走模板且标为_template(session: AsyncSession) -> None:
    """`llm_model` 必须能区分「模型写的」与「模板写的」。

    这个字段是整条降级链路的**唯一凭证**：报告页面上要据此打「模板生成」标，
    事后审计时要能回答「这句话是谁说的」。写错它，降级就成了静默的。
    """
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())

    for chain in draft.data.chains:
        assert chain.narrative_model == TEMPLATE_MODEL
        assert chain.narrative_degraded is True
    for rec in draft.data.recommendations:
        assert rec.note_model == TEMPLATE_MODEL
        assert rec.note_degraded is True

    assert draft.data.notes_template_count == 2
    assert "llm" in draft.data.degraded


async def test_未配_key_时降级文案非空且无占位符(session: AsyncSession) -> None:
    """防 `return ""`。

    降级路径最容易的糊弄方式就是返回空串或「TODO」，而此时**不报错、不崩溃**，
    只有打开报告才发现第五组建议在那儿写着「描述漏洞」。所以这里卡长度与关键词。
    """
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())

    placeholders = ("TODO", "FIXME", "占位", "待补充", "undefined", "None", "该字段缺失")
    texts = [c.narrative for c in draft.data.chains] + [r.note for r in draft.data.recommendations]
    assert texts
    for text in texts:
        assert len(text.strip()) >= 30, f"降级文案过短，可疑：{text!r}"
        for token in placeholders:
            assert token not in text, f"降级文案含占位符 {token!r}：{text!r}"

    # 降级文案必须落到**具体事实**上，而不是泛泛而谈
    note = draft.data.recommendations[0].note
    assert "app/api/order.py" in note
    assert "9.8" in note


async def test_未配_key_时报告正文两个格式都渲染得出来(session: AsyncSession) -> None:
    """渲染是装配的最后一步，它炸了前面的完整性都白搭。"""
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())

    for text in (draft.html, draft.markdown):
        assert "1. 项目概况与执行信息" in text
        assert "2. 安全评分与风险大盘" in text
        assert "4. 多步攻击路径推演" in text
        assert "5. 安全整改建议" in text
        assert "VULN-2026-0001" in text
        assert "9.8" in text, "CVSS 没进正文"
        assert "app/api/order.py:12" in text, "污点路径没进正文"
    assert "模板生成" in draft.html


async def test_摘要与正文取同一份事实(session: AsyncSession) -> None:
    """`reports.summary` 是报告列表页直接展示的那一份。

    列表页另立一套统计是报告类产品的经典事故：列表说「严重 3 条」，
    点进去正文说 2 条 —— 两边都没错，只是各算各的。
    """
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())
    summary = draft.summary

    assert summary.total == len(draft.data.vulnerabilities) == 2
    assert summary.score == draft.data.score.score
    assert summary.grade == draft.data.score.grade
    assert summary.chain_count == len(draft.data.chains)
    # top_codes 必须与正文第 3 章同序
    assert summary.top_codes == [v.code for v in draft.data.vulnerabilities][:5]
    assert summary.formats == [ReportFormat.HTML, ReportFormat.MD]
    assert "llm" in summary.degraded


async def test_build_report_不落盘不写库(session: AsyncSession) -> None:
    """契约 4：装配与导出分开 —— 事务边界属于调用方。

    这条断言的存在理由：一旦 `build_report` 内部偷偷 `commit()`，
    `report_gen` 阶段就再也没法把「生成报告」与「回写评分」放进同一个事务，
    失败时会出现「报告写好了但评分没落库」的半成品。
    """
    from sqlalchemy import func, select

    from app.models.report import Report

    assessment_id = await seed(session)
    await build_report(assessment_id, session, client=NoKeyCompleter())

    count = (await session.execute(select(func.count()).select_from(Report))).scalar_one()
    assert count == 0
    assessment = await session.get(Assessment, assessment_id)
    assert assessment is not None
    assert assessment.security_score is None, "评分回写是 exporter 的事，不是装配的事"


# ---------------------------------------------------------------------------
# 二、如实标注：三种「不确定」不能混成一种
# ---------------------------------------------------------------------------


async def test_被闸门拦下的探针不进证据位但留痕(session: AsyncSession) -> None:
    """`harmless_guard_passed=False` 的记录证明的是「这次尝试被拦下了」。

    把它摆进证据位，等于用一条失败记录支撑「这里能打」；直接丢掉，
    又会让读者以为「根本没试过」。正确做法是：不进证据位，但在报告里标出
    「这一条被闸门拦过」——两种事实各有各的位置。
    """
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())
    by_code = {v.code: v for v in draft.data.vulnerabilities}

    assert by_code["VULN-2026-0001"].poc is not None
    assert by_code["VULN-2026-0001"].poc.matched is True
    # 只有被拦下的那次尝试 → 没有可用证据，但要标出「被拦过」
    assert by_code["VULN-2026-0002"].poc is None
    assert by_code["VULN-2026-0002"].guard_blocked is True

    assert "被无害化闸门拦下" in draft.html
    assert "被无害化闸门拦下" in draft.markdown


async def test_已通过验证但没有探针记录标为数据缺口(session: AsyncSession) -> None:
    """「验证过了」与「证据在哪」是两件事。

    结论说已验证、证据却不在，说明数据链路上有缺口 —— 标出来，
    而不是让它看起来与「有完整证据的已验证」一模一样。
    """
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())
    verified = next(v for v in draft.data.vulnerabilities if v.code == "VULN-2026-0001")

    assert verified.data_incomplete is False, "这条证据是齐的"

    # 把探针拆掉后同一条漏洞必须被标为数据不完整
    snapshot = await load_snapshot(session, assessment_id)
    for vuln in snapshot.vulnerabilities:
        vuln.poc_attempts = []
    from app.report.assembler import build_report_data

    data = build_report_data(snapshot, generated_at=GENERATED_AT)
    verified = next(v for v in data.vulnerabilities if v.code == "VULN-2026-0001")
    assert verified.data_incomplete is True


async def test_跳过的阶段原样带进报告(session: AsyncSession) -> None:
    """`skipped` 阶段必须带着 note 进报告，且**不得**被当成 completed。

    这是「一份诚实标注局限的报告比一份看起来很全的报告有价值」最直接的一处。
    """
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())
    stages = {s.stage: s for s in draft.data.meta.stages}

    assert stages[StageName.POC_VERIFY].status == StageStatus.SKIPPED
    assert stages[StageName.POC_VERIFY].note == "沙箱不可达，已跳过动态验证"
    assert "已跳过" in draft.html


async def test_未验证条目多时第3章标题如实改写(session: AsyncSession) -> None:
    """只要清单里有未验证条目，标题就不能写「已验证漏洞清单」。"""
    from app.models.enums import VulnStatus as VS

    assessment_id = await seed(session)
    snapshot = await load_snapshot(session, assessment_id)
    for vuln in snapshot.vulnerabilities:
        vuln.status = VS.UNVERIFIED

    from app.report.assembler import build_report_data

    data = build_report_data(snapshot, generated_at=GENERATED_AT)
    assert data.has_verified is False
    assert data.chapter3_title == "漏洞清单（含未经验证条目）"
    assert "没有任何一条通过动态验证" in data.chapter3_note


# ---------------------------------------------------------------------------
# 三、边界：空评估、不存在的评估
# ---------------------------------------------------------------------------


async def test_全部已验证时标题才写已验证(session: AsyncSession) -> None:
    """标题的判据是「**全部**条目都已验证」，不是「有没有一条已验证」。

    差一个字的代价：「9 条未验证 + 1 条已验证」挂上「已验证漏洞清单」的标题，
    读者会把整份静态结论当成已确认事实。**混着的时候必须说混着。**
    """
    from app.models.enums import VulnStatus as VS
    from app.report.assembler import build_report_data

    assessment_id = await seed(session)
    snapshot = await load_snapshot(session, assessment_id)
    for vuln in snapshot.vulnerabilities:
        vuln.status = VS.VERIFIED
    data = build_report_data(snapshot, generated_at=GENERATED_AT)
    assert data.chapter3_title == "已验证漏洞清单"

    # 只把其中一条降回未验证 —— 标题必须立刻改口
    snapshot.vulnerabilities[0].status = VS.UNVERIFIED
    mixed = build_report_data(snapshot, generated_at=GENERATED_AT)
    assert mixed.chapter3_title == "漏洞清单（含未经验证条目）"

    # `rejected` 是「已判定不是漏洞」，它不该把标题拉回混合态
    for vuln in snapshot.vulnerabilities:
        vuln.status = VS.VERIFIED
    snapshot.vulnerabilities[0].status = VS.REJECTED
    assert build_report_data(snapshot, generated_at=GENERATED_AT).chapter3_title == "已验证漏洞清单"


async def test_没有漏洞的评估也能出报告(session: AsyncSession) -> None:
    """空态是一份**结论**（「本次未命中」），不是一份失败的报告。"""
    project = Project(name="干净项目", source_type="upload", status=ProjectStatus.COMPLETED)
    session.add(project)
    await session.flush()
    assessment = Assessment(project_id=project.id, status=AssessmentStatus.COMPLETED, progress=100)
    session.add(assessment)
    await session.commit()

    draft = await build_report(assessment.id, session, client=NoKeyCompleter())

    assert draft.data.empty_state is True
    assert draft.data.score.score == 100.0
    assert draft.data.score.grade == SecurityGrade.SAFE
    assert draft.data.chapter4_placeholder, "没有链时必须给出解释性占位，而不是空白章节"
    assert "未发现漏洞" in draft.html
    # 空态同样要有降级横幅：tech_stack / loc 都没有
    assert "tech_stack" in draft.data.degraded


async def test_评估不存在时抛快照错误而不是空报告(session: AsyncSession) -> None:
    """**L5 不可降级**：没有快照就没有报告。

    编一份「部分数据」的报告比不出报告危险得多 —— 它会看起来是完整的。
    """
    with pytest.raises(ReportSnapshotError) as exc:
        await build_report(999, session, client=NoKeyCompleter())

    assert exc.value.error_code == "REPORT_SNAPSHOT_FAILED"
    # 5xx + retryable：快照失败归在「存储类依赖」下，MySQL 恢复后重跑是有意义的；
    # 关键不是重试与否，而是它**不会**被当成 L3 的降级项吞掉
    assert exc.value.http_status == 503
    assert "降级" not in exc.value.remediation


async def test_补丁取最新且跳过已拒绝的(session: AsyncSession) -> None:
    """`rejected` 的补丁不能作为「参考补丁」出现在报告里。

    它是被判定不可用的那一版 —— 展示它等于给读者一份已知有问题的方案。
    """
    assessment_id = await seed(session)
    snapshot = await load_snapshot(session, assessment_id)
    vuln = next(v for v in snapshot.vulnerabilities if v.code == "VULN-2026-0001")
    session.add(
        Patch(
            vulnerability_id=vuln.id,
            target_file="app/api/order.py",
            diff_content="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
            status=PatchStatus.REJECTED,
            source=PatchSource.LLM,
            failure_reason="打上后污点路径仍然存在",
        )
    )
    await session.commit()

    draft = await build_report(assessment_id, session, client=NoKeyCompleter())
    entry = next(v for v in draft.data.vulnerabilities if v.code == "VULN-2026-0001")

    assert entry.patch is not None
    assert entry.patch.status == PatchStatus.SUGGESTED, "取到了被拒绝的那一版"
    assert "打上后污点路径仍然存在" not in draft.html


async def test_同一份数据两次生成的结论逐字相同(session: AsyncSession) -> None:
    """**可复现是本项目的卖点之一，必须能被当场验证。**

    只比对一份手写的时间戳之外的正文 —— `generated_at` 本来就不该相同。
    """
    assessment_id = await seed(session)
    first = await build_report(
        assessment_id, session, client=NoKeyCompleter(), generated_at=GENERATED_AT
    )
    second = await build_report(
        assessment_id, session, client=NoKeyCompleter(), generated_at=GENERATED_AT
    )

    assert first.html == second.html
    assert first.markdown == second.markdown
    assert first.summary == second.summary


async def test_摘要单独构建时不需要数据库(session: AsyncSession) -> None:
    """`build_summary` 是纯函数：列表页刷新摘要时不必把报告重新渲染一遍。"""
    assessment_id = await seed(session)
    draft = await build_report(assessment_id, session, client=NoKeyCompleter())
    assert build_summary(draft.data, formats=draft.summary.formats) == draft.summary
