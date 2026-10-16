"""验证闭环的测试：**三态判定、降级不阻断、隔离参数、配额记账**。

这个文件回答的是 B5 最容易被追问的一个问题：
「跑出来的那个 `verified`，凭什么？」—— 每一类结论都有一条测试钉住，
并且都经过一次**真的把探针计划塞进容器、再把证据解回来**的往返，
不是直接往结果对象上赋一个 `matched=True`。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from verify_chain_fakes import (
    BINDABLE_SINK_LINE,
    BINDABLE_SOURCE_LINE,
    BoomSandbox,
    FakeFinding,
    FakeHandle,
    FakeSandbox,
    FakeTaintStep,
    decode_plan,
    vuln_for,
)

from app.models.enums import VulnStatus as OrmVulnStatus
from app.verify.guard import HarmlessGuard
from app.verify.runner import (
    CVSS_UPLIFT,
    SANDBOX_RETRY_ATTEMPTS,
    PocVerifier,
    cvss_after_verification,
    verify_finding,
)
from app.verify.types import (
    GateName,
    GuardVerdict,
    Probe,
    ReasonCode,
    SandboxConfig,
    SkipReason,
    Verdict,
    VulnStatus,
)

#: 可绑定夹具的源码根。`bind_route` 要读**真实文件**才能反查出端点 ——
#: 喂内存里的字符串是做不到的（那正是它要读源码的原因）。
BINDABLE_ROOT = Path(__file__).parent / "fixtures" / "bindable_app"


@pytest.fixture()
def handle() -> FakeHandle:
    return FakeHandle(src_root=BINDABLE_ROOT)


def _sqli_finding(vuln_id: int = 1) -> FakeFinding:
    """一条**能绑上端点**的 SQL 注入。

    ⚠️ 行号与 `tests/fixtures/bindable_app/app.py` 是**契约**：
    20 = `q = request.args.get("q", "1")`，22 = `cursor.execute("… " + q)`。
    改夹具的行数就要改这里，否则绑定会静默失败、用例集体落进
    "未绑定 → potential" 那一支（仍然变绿，但测的东西变了）。
    """
    return FakeFinding(
        vuln_id=vuln_id,
        vuln_type="sql_injection",
        cvss_score=7.5,
        taint_path=(
            FakeTaintStep("request.args.get('q')", step_kind="source", line=BINDABLE_SOURCE_LINE),
            FakeTaintStep("cursor.execute", step_kind="sink", line=BINDABLE_SINK_LINE),
        ),
    )


# ---------------------------------------------------------------------------
# verified：探针真的发出去了，且观察到了锚点
# ---------------------------------------------------------------------------


def test_verified_when_probe_hits(handle: FakeHandle) -> None:
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    verifier = PocVerifier(sandbox=sandbox)
    result = asyncio.run(verifier.verify_finding(_sqli_finding(), handle))

    assert result.verdict is Verdict.VERIFIED
    assert result.status is VulnStatus.VERIFIED
    assert result.matched_probe_id
    assert result.executed_probe_count > 0
    assert result.unverified_reason is None
    # CVSS 按漏洞类型上调，但**封顶 10**：上调是"已在动态层面证实"的代价，
    # 不是重新评分。
    assert result.cvss_before == 7.5
    assert result.cvss_after == round(7.5 + CVSS_UPLIFT["sqli"], 1)
    assert result.cvss_after <= 10.0


def test_未绑定端点的命中只落_potential(handle: FakeHandle) -> None:
    """**本次修正的核心语义。**

    探针命中了，但它打在模板的**固定路由**上（这条 finding 的污点步骤指向一个
    读不到的文件，反查端点失败）—— 那证明的是「这一类漏洞在本目标上存在」，
    不是「这一行所在的端点被跑通了」。

    靶场实测 15 条 finding 里 10 条属于这种：`config.py:26` 的硬编码密钥
    靠读 `/.env` "通过"了动态验证。把它们记成 `verified`，报告里就会出现
    一句读起来像"这行代码被证明有问题"、实际不是的话。

    ⚠️ 落 `potential` 而**不是** `rejected`：静态结论不动（那条 finding 仍然成立），
    只是动态证据不够。这是"没测到这一条"，与"测了、不存在"是两件事。
    """
    finding = FakeFinding(
        vuln_id=7,
        vuln_type="sql_injection",
        cvss_score=7.5,
        taint_path=(
            FakeTaintStep("request.args.get('order_id')", file_path="读不到.py"),
            FakeTaintStep("cursor.execute", step_kind="sink", file_path="读不到.py"),
        ),
    )
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    result = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(finding, handle))

    assert result.status is VulnStatus.POTENTIAL
    assert result.matched_probe_id, "命中是事实，要如实记下来"
    assert result.cvss_before == result.cvss_after, "未逐点确认就不上调 CVSS"
    assert result.unverified_reason and "标准形态" in result.unverified_reason


def test_verified_result_explains_itself(handle: FakeHandle) -> None:
    """命中那条 attempt 必须带上**判定依据**：载荷、期望特征、响应、耗时。"""
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    result = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(_sqli_finding(), handle))

    hit = next(a for a in result.attempts if a.probe_id == result.matched_probe_id)
    assert hit.matched is True
    assert hit.harmless_guard_passed is True
    assert hit.payload and hit.expected_pattern
    assert hit.response_raw
    assert hit.http_status == 200
    assert hit.technique == "union_extract"


def test_sql_injection_upgrades_cvss_by_the_documented_delta() -> None:
    assert cvss_after_verification("sql_injection", 7.5) == 9.8
    assert cvss_after_verification("sql_injection", 9.5) == 10.0  # 封顶
    # 表外类型兜底 +1.0 而不是 +0：「已验证」这件事本身就抬高分数
    assert cvss_after_verification("some_unknown_type", 5.0) == 6.0


# ---------------------------------------------------------------------------
# unverified：跑过了，但没看到锚点 —— **不是"不存在"**
# ---------------------------------------------------------------------------


def test_unverified_when_probe_runs_but_does_not_match(handle: FakeHandle) -> None:
    """探针执行了、目标也答了，但响应体里没有锚点 → unverified/potential。

    用文件上传：它的探针没有对照组（"没回显"只是没回显），所以既不能证实、
    也不能证伪 —— 这正是"我们测了，没测出来"该有的样子。
    """
    finding = FakeFinding(vuln_id=21, vuln_type="file_upload", cvss_score=6.5)
    result = asyncio.run(PocVerifier(sandbox=FakeSandbox()).verify_finding(finding, handle))

    assert result.executed_probe_count > 0, "探针必须真的跑过"
    assert result.verdict is Verdict.UNVERIFIED
    assert result.status is VulnStatus.POTENTIAL
    assert result.matched_probe_id is None
    assert result.unverified_reason and "未观察到命中特征" in result.unverified_reason
    # 关键措辞：**维持 potential 而非否定**
    assert "potential" in result.unverified_reason


def test_unverified_is_not_rejected_without_negating_power(handle: FakeHandle) -> None:
    """没有否证力的探针跑完没命中 → 只能 potential ——「没验证出来」不等于「不存在」。"""
    finding = FakeFinding(vuln_id=22, vuln_type="file_upload", cvss_score=6.5)
    result = asyncio.run(PocVerifier(sandbox=FakeSandbox()).verify_finding(finding, handle))

    assert result.verdict is Verdict.UNVERIFIED
    assert result.status is VulnStatus.POTENTIAL
    assert result.status is not VulnStatus.REJECTED
    assert result.cvss_after == result.cvss_before


def test_rejected_when_access_is_explicitly_denied(handle: FakeHandle) -> None:
    """未授权访问类：靶场回 401 → **有否证力**的否定 → 判 rejected。

    这是全系统里最硬的一条"证伪"路径：鉴权层答了话，说明端点存在且守住了。
    """
    finding = FakeFinding(vuln_id=2, vuln_type="unauth_access", cvss_score=8.0)
    sandbox = FakeSandbox()  # unauth_probe 未命中 → 回 401
    result = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(finding, handle))

    assert result.executed_probe_count > 0
    assert result.verdict is Verdict.UNVERIFIED
    assert result.status is VulnStatus.REJECTED
    assert "静态判断被证伪" in (result.unverified_reason or "")
    assert result.cvss_after == result.cvss_before, "证伪不动 CVSS"


def test_probe_that_got_no_response_cannot_negate(handle: FakeHandle) -> None:
    """探针被容器超时杀掉（无响应）→ 一定不能是 rejected，只能是 potential。"""
    finding = FakeFinding(vuln_id=3, vuln_type="unauth_access", cvss_score=8.0)
    sandbox = FakeSandbox()
    # 先跑一次拿到 probe_id，再让假沙箱吞掉它们的证据
    first = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(finding, handle))
    probe_ids = {a.probe_id for a in first.attempts}
    assert probe_ids
    assert first.status is VulnStatus.REJECTED  # 前提：正常情况下这条会证伪

    sandbox.drop_evidence = probe_ids
    result = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(finding, handle))
    assert result.executed_probe_count == 0
    assert result.status is VulnStatus.POTENTIAL, "没有响应的探针不能被当成「打不穿」"
    assert result.skipped_probe_count >= len(probe_ids)


def test_probe_without_negating_power_does_not_vote(handle: FakeHandle) -> None:
    """无否证力的探针**不进证伪表决**：它既不能证实、也不能证伪。"""
    # sqli 的 UNION 探针（CONTENT_NONCE）无否证力，布尔盲注探针有 ——
    # 靶场干净时，布尔那条给出否定，于是判 rejected；而 UNION 那条只是没看到痕迹。
    finding = FakeFinding(vuln_id=4, vuln_type="sql_injection", cvss_score=7.5)
    result = asyncio.run(PocVerifier(sandbox=FakeSandbox()).verify_finding(finding, handle))

    assert result.status is VulnStatus.REJECTED
    assert "无否证力" in (result.unverified_reason or "")


# ---------------------------------------------------------------------------
# skipped：沙箱不可达 —— **降级，不阻断**（L4）
# ---------------------------------------------------------------------------


def test_sandbox_unreachable_yields_skipped_not_exception(handle: FakeHandle) -> None:
    """沙箱连不上 → `skipped`，**不抛异常**。这是 L4 的核心断言。"""
    sandbox = BoomSandbox()
    result = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(_sqli_finding(), handle))

    assert result.verdict is Verdict.SKIPPED
    assert result.skip_reason is SkipReason.SANDBOX_UNREACHABLE
    assert result.status is VulnStatus.POTENTIAL
    assert sandbox.calls == SANDBOX_RETRY_ATTEMPTS, "必须重试而不是一次就放弃"


def test_transient_failure_is_retried_and_succeeds(handle: FakeHandle) -> None:
    """前两次连不上、第三次成功 → 仍然拿到 verified（瞬断不该毁掉结论）。"""
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"), fail_times=2)
    result = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(_sqli_finding(), handle))
    assert result.verdict is Verdict.VERIFIED
    assert sandbox.calls == 3


def test_batch_marks_sandbox_unreachable_and_stops(handle: FakeHandle) -> None:
    """一个批次里沙箱挂了：`sandbox_reachable=False`，且**立刻停止后续 Finding**。"""
    sandbox = BoomSandbox()
    findings = [_sqli_finding(vuln_id=i) for i in (1, 2, 3, 4)]
    outcome = asyncio.run(PocVerifier(sandbox=sandbox).verify_findings(findings, handle=handle))

    assert outcome.sandbox_reachable is False
    assert len(outcome.results) == 1, "沙箱不可达是阶段级事件，剩下的不必再试"
    assert outcome.skipped_count == 1
    assert outcome.results[0].verdict is Verdict.SKIPPED


def test_batch_keeps_static_findings_intact(handle: FakeHandle) -> None:
    """降级时静态成果必须原样保留：结果里带着 vuln_id 与保持不变的 CVSS。"""
    outcome = asyncio.run(
        PocVerifier(sandbox=BoomSandbox()).verify_findings([_sqli_finding()], handle=handle)
    )
    degraded = outcome.results[0]
    assert degraded.vuln_id == 1
    assert degraded.cvss_after == degraded.cvss_before == 7.5


def test_env_deploy_failed_is_unverified_not_skipped(handle: FakeHandle) -> None:
    """靶场起不来 = 环境问题（可重跑），与"沙箱连不上"（阶段级）分开归因。"""
    sandbox = FakeSandbox(ready=False)
    result = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(_sqli_finding(), handle))

    assert result.verdict is Verdict.UNVERIFIED
    assert result.skip_reason is None
    assert "ENV_DEPLOY_FAILED" in (result.unverified_reason or "")
    assert result.status is VulnStatus.POTENTIAL


def test_consecutive_env_failures_stop_the_batch(handle: FakeHandle) -> None:
    """连续 3 个部署失败 → 判定为 daemon 级问题，停止剩余验证（设计 §6）。"""
    sandbox = FakeSandbox(ready=False)
    findings = [_sqli_finding(vuln_id=i) for i in range(1, 8)]
    outcome = asyncio.run(PocVerifier(sandbox=sandbox).verify_findings(findings, handle=handle))

    assert len(outcome.results) == 3
    assert outcome.sandbox_reachable is False


# ---------------------------------------------------------------------------
# 配额与闸门：被拦下的都要**记账**
# ---------------------------------------------------------------------------


def test_quota_overflow_is_recorded_in_the_result(handle: FakeHandle) -> None:
    """一条 Finding 造出 60 条候选探针 → 只跑 20 条，其余**计入 skipped**。

    ⚠️ 这条用例走的是**未绑定**那条路径，所以污点步骤的 `file_path` 指向一个
    不存在的文件 —— 绑定失败正是它要测的前提。绑定成功时候选集会塌缩成
    「每个模板一条」（路由和参数都是反查出来的事实，没有张量积可言），
    那条路径由 `tests/test_verify_binding.py` 覆盖，配额在这里无从谈起。
    """
    points = tuple(
        FakeTaintStep(f"request.args.get('p{i}')", file_path="不存在.py") for i in range(30)
    )
    finding = FakeFinding(vuln_id=9, vuln_type="sql_injection", taint_path=points)
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    result = asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(finding, handle))

    executed = sum(1 for a in result.attempts if a.harmless_guard_passed)
    assert executed == 20
    assert result.skipped_probe_count >= 40, "被裁掉的探针数必须出现在结果里"
    # 容器里也真的只有 20 条探针（配额在**发送前**生效，不是发送后再筛）
    plan = decode_plan(sandbox.specs[0])
    assert len(plan["probes"]) == 20


def test_guard_blocked_probes_are_recorded_with_their_gate(handle: FakeHandle) -> None:
    """被闸门拦下的探针要留下 `harmless_guard_passed=False` + 闸门名，**且不发出去**。"""

    class HalfRejectingGuard(HarmlessGuard):
        """把第 0 条探针拦下 —— 模拟「模板里混进了一条不合规的探针」。"""

        def check(self, probe: Probe, *, probe_index: int = 0) -> GuardVerdict:
            if probe_index == 0:
                return GuardVerdict(
                    passed=False,
                    failed_gate=GateName.PAYLOAD,
                    reason_code=ReasonCode.BEHAVIOR_MISMATCH,
                    reason="测试替身：第 0 条探针被判不合规",
                    # `matched_token` 是"命中的那截载荷"，不是口令：S106 在这里是误报
                    matched_token="<stub>",  # noqa: S106
                )
            return super().check(probe, probe_index=probe_index)

    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    finding = _sqli_finding()
    verifier = PocVerifier(sandbox=sandbox, guard=HalfRejectingGuard())
    result = asyncio.run(verifier.verify_finding(finding, handle))

    blocked = [a for a in result.attempts if not a.harmless_guard_passed]
    assert blocked, "被拦下的探针必须留下记录"
    assert blocked[0].failed_gate is GateName.PAYLOAD
    assert blocked[0].failure_reason
    # 被拦下的那条**不能出现在出网报文里**
    sent_ids = {p["probe_id"] for p in decode_plan(sandbox.specs[0])["probes"]}
    assert blocked[0].probe_id not in sent_ids
    assert result.skipped_probe_count >= 1


def test_no_template_means_skipped_not_crash(handle: FakeHandle) -> None:
    """没有探针模板 → 空计划，且结果里说明原因。"""
    finding = FakeFinding(vuln_id=11, vuln_type="quantum_entanglement")
    result = asyncio.run(PocVerifier(sandbox=FakeSandbox()).verify_finding(finding, handle))
    assert result.verdict in (Verdict.SKIPPED, Verdict.UNVERIFIED)
    assert result.status is VulnStatus.POTENTIAL
    assert result.unverified_reason
    assert result.cvss_after == result.cvss_before


# ---------------------------------------------------------------------------
# 隔离：容器参数是安全侧的不变量
# ---------------------------------------------------------------------------


def test_container_spec_is_locked_down(handle: FakeHandle) -> None:
    """**无出网、只读根、源码只读挂载** —— 三个参数硬编码，没有配置项。"""
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(_sqli_finding(), handle))
    spec = sandbox.specs[0]

    assert spec.network_disabled is True
    assert spec.read_only_root is True
    assert spec.source_mount == handle.mount_host_path, "挂载必须用数据面宿主路径"
    assert spec.timeout_seconds >= 30
    assert spec.env["ASA_MISSION_B64"]


def test_no_destructive_payload_reaches_the_container(handle: FakeHandle) -> None:
    """把容器里真正收到的每一条请求原文捞出来，逐条过破坏性词表。

    这是「绝不执行破坏性 payload」在**端到端路径**上的断言：
    不是"闸门函数返回了 False"，而是"出网报文里没有这些东西"。
    """
    forbidden = (
        "drop ",
        "delete ",
        "rm -rf",
        "nc -e",
        "/dev/tcp/",
        "curl ",
        "wget ",
        "into outfile",
    )
    for vuln_type in ("sql_injection", "command_injection", "file_read", "deserialization"):
        sandbox = FakeSandbox(vulnerable=vuln_for(vuln_type))
        finding = FakeFinding(vuln_id=1, vuln_type=vuln_type)
        asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(finding, handle))
        payload_text = decode_plan(sandbox.specs[0]).__repr__().lower()
        for token in forbidden:
            assert token not in payload_text, (vuln_type, token)


def test_serial_single_container_per_finding(handle: FakeHandle) -> None:
    """一个 Finding 只起一个容器（并发恒为 1），探针在容器内串行——设计硬规则。"""
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    asyncio.run(PocVerifier(sandbox=sandbox).verify_finding(_sqli_finding(), handle))
    assert sandbox.calls == 1


def test_progress_callback_failure_does_not_change_the_verdict(handle: FakeHandle) -> None:
    """进度回调是表达层：它炸了，结论不能变。"""

    async def boom(_result: object) -> None:
        raise RuntimeError("websocket closed")

    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    result = asyncio.run(
        PocVerifier(sandbox=sandbox).verify_finding(_sqli_finding(), handle, on_progress=boom)
    )
    assert result.verdict is Verdict.VERIFIED


def test_contract_entry_point_signature(handle: FakeHandle) -> None:
    """契约 4 的形状：`verify_finding(finding, sandbox, handle)`。"""
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    result = asyncio.run(verify_finding(_sqli_finding(), sandbox, handle))
    assert result.verdict is Verdict.VERIFIED
    assert result.status is OrmVulnStatus.VERIFIED, "status 必须能直接落 vulnerabilities.status"


def test_config_defaults_come_from_settings() -> None:
    cfg = SandboxConfig.from_settings()
    assert cfg.max_probes_per_vuln == 20
    assert cfg.probe_timeout_s == 30
    assert cfg.allowed_hosts == frozenset({"127.0.0.1", "localhost", "::1"})


def test_multiple_findings_are_verified_serially(handle: FakeHandle) -> None:
    sandbox = FakeSandbox(vulnerable=vuln_for("sql_injection"))
    findings = [_sqli_finding(vuln_id=i) for i in (1, 2)]
    outcome = asyncio.run(PocVerifier(sandbox=sandbox).verify_findings(findings, handle=handle))

    assert outcome.sandbox_reachable is True
    assert outcome.verified_count == 2
    assert outcome.results[0].vuln_id == 1 and outcome.results[1].vuln_id == 2
    assert sandbox.calls == 2, "串行：每个 Finding 各起一次容器"
