"""攻击链推演的测试（L1：节点与边由规则算出；Q24：逐环标实测/推演）。

本文件里有三条断言是**不可替代**的：

1. `test_chain_is_deterministic_*` —— 同一批 finding 推两次、打乱顺序再推一次，
   结果必须逐字段相同。链是要落库、要进报告、要被人工复核的东西，
   "这次推出来是这样，下次未必"会让整条链失去作为证据的资格。
2. `test_inferred_rings_are_marked_per_ring` —— Q24 方案 A 的落点。
   设计 §4.7 的演示表把"凭证登录后台"标成已验证，但那需要一条本模块
   并未提供的探针；**没有实测依据的环必须逐环标出来**，否则报告会读成
   "整条链都验过了"。
3. `test_unverified_findings_do_not_enter_the_chain` —— 链的每一条边都要踩在
   实测的支撑点上。让 `potential` 进来，链就退化成推测文。
"""

from __future__ import annotations

import random

from app.chain.builder import MAX_CHAIN_DEPTH, MAX_CHAINS, ChainBuilder, build_chain
from app.chain.types import ChainDraft
from app.models.enums import ChainNodeType, Severity, VerificationStatus, VulnStatus


class _Finding:
    """`Vulnerability` / B4 `Finding` 的最小视图。"""

    def __init__(
        self,
        vuln_id: int,
        vuln_type: str,
        *,
        file_path: str = "app/api/order.py",
        symbol: str = "cursor.execute",
        cvss: float = 7.5,
        code: str | None = None,
        status: object = None,
    ) -> None:
        self.vuln_id = vuln_id
        self.vuln_type = vuln_type
        self.file_path = file_path
        self.symbol = symbol
        self.cvss_score = cvss
        self.code = code or f"VULN-2026-{vuln_id:04d}"
        self.status = status
        self.line_start = 10
        self.line_end = 10


def _demo_findings() -> list[_Finding]:
    """设计 §4.7 的演示场景：SQL 注入（够得着 users 表）+ 后台可上传。"""
    return [
        _Finding(1, "sql_injection", file_path="app/api/order.py", cvss=9.1, code="VULN-2026-0001"),
        _Finding(
            2,
            "file_upload",
            file_path="app/api/admin/upload.py",
            symbol="save_upload",
            cvss=8.1,
            code="VULN-2026-0004",
        ),
    ]


def _flagship_findings() -> list[_Finding]:
    """更丰富的一批：能同时推出多环链与若干条单节点链。"""
    return [
        *_demo_findings(),
        _Finding(
            3,
            "command_injection",
            file_path="app/utils/export.py",
            symbol="os.system",
            cvss=9.8,
            code="VULN-2026-0003",
        ),
        _Finding(
            4,
            "unauth_access",
            file_path="app/api/admin/users.py",
            symbol="list_users",
            cvss=6.5,
            code="VULN-2026-0002",
        ),
        _Finding(
            5,
            "file_read",
            file_path="app/api/files.py",
            symbol="open",
            cvss=5.3,
            code="VULN-2026-0005",
        ),
    ]


# ---------------------------------------------------------------------------
# 演示链：R1 → R2 → R3
# ---------------------------------------------------------------------------


def test_demo_chain_is_built_from_the_rules() -> None:
    """设计 §4.7 那条链：SQLi → 凭证 → 后台会话 → 上传点 RCE。"""
    draft = build_chain(_demo_findings())
    assert draft.chains, draft.note

    chain = draft.chains[0]
    assert chain.rule_ids == ["R1", "R2", "R3"]
    assert chain.severity is Severity.CRITICAL
    assert chain.entry_point == "app/api/order.py"


def test_chain_nodes_form_a_single_chain() -> None:
    """节点用 `parent_index` 连成一条链：第 i 环的父节点是 i-1（DAG 的边由此派生）。"""
    chain = build_chain(_demo_findings()).chains[0]
    assert chain.nodes[0].parent_index is None
    for index, node in enumerate(chain.nodes[1:], start=1):
        assert node.parent_index == index - 1
        assert node.order_index == index


def test_inferred_rings_are_marked_per_ring() -> None:
    """**Q24 方案 A**：哪几环实测、哪几环推演，逐环标注。

    R2（登录后台）与 R3（投放 WebShell）没有实测依据 —— 它们需要主动利用，
    而本系统的探针只做只读无害验证。它们能进链，但必须标成 `inferred`。
    """
    chain = build_chain(_demo_findings()).chains[0]
    by_rule = {node.rule_id: node for node in chain.nodes if node.rule_id}

    assert by_rule["R1"].verification_status is VerificationStatus.VERIFIED
    assert by_rule["R2"].verification_status is VerificationStatus.INFERRED
    assert by_rule["R3"].verification_status is VerificationStatus.INFERRED
    # 入口节点承接起始漏洞的实测结论
    assert chain.nodes[0].verification_status is VerificationStatus.VERIFIED
    # 收尾的影响节点是推演出来的（它是"这些能力合起来意味着什么"）
    assert chain.nodes[-1].node_type is ChainNodeType.IMPACT
    assert chain.nodes[-1].verification_status is VerificationStatus.INFERRED

    assert chain.verified_ring_count + chain.inferred_ring_count == len(chain.nodes)
    assert chain.verified_ring_count == 2
    assert chain.inferred_ring_count == 3


def test_confidence_is_derived_from_the_measured_rings() -> None:
    """可达性置信度 = 实测环占比（确定性算出，不是模型给的）。"""
    chain = build_chain(_demo_findings()).chains[0]
    expected = round(chain.verified_ring_count / len(chain.nodes), 3)
    assert chain.confidence == expected == 0.4


def test_inferred_nodes_say_so_in_their_text() -> None:
    """推演的环在文字里也要说清楚 —— 读者是跳着看的，只看标记不够。"""
    chain = build_chain(_demo_findings()).chains[0]
    r2 = next(n for n in chain.nodes if n.rule_id == "R2")
    assert "未实测" in r2.detail or "推演" in r2.detail
    r3 = next(n for n in chain.nodes if n.rule_id == "R3")
    assert "未实际执行" in r3.detail
    r1 = next(n for n in chain.nodes if n.rule_id == "R1")
    assert "已验证" in r1.detail


def test_nodes_carry_the_supporting_vuln_code() -> None:
    chain = build_chain(_demo_findings()).chains[0]
    codes = {n.vuln_code for n in chain.nodes if n.vuln_code}
    assert codes == {"VULN-2026-0001", "VULN-2026-0004"}
    assert chain.vuln_codes == frozenset(codes)


def test_template_narrative_marks_every_ring() -> None:
    """模板叙事（LLM 不可用时的降级产出）逐环标「沙箱实测 / 推演」。"""
    chain = build_chain(_demo_findings()).chains[0]
    assert chain.narrative_source == "template"
    assert chain.narrative.count("（沙箱实测）") == 2
    assert chain.narrative.count("（推演，未实际执行）") == 3
    assert "小结：" in chain.narrative


# ---------------------------------------------------------------------------
# 确定性
# ---------------------------------------------------------------------------


def test_chain_is_deterministic_for_the_same_input() -> None:
    """同一批 finding 推两次 → 逐字段相同。"""
    first = build_chain(_flagship_findings())
    second = build_chain(_flagship_findings())
    assert first.model_dump() == second.model_dump()


def test_chain_is_independent_of_input_order() -> None:
    """打乱输入顺序 → 结果不变（调用方传进来的顺序不该影响结论）。"""
    findings = _flagship_findings()
    baseline = build_chain(findings).model_dump()
    for seed in (1, 7, 99):
        shuffled = findings[:]
        # 这里要的是"随机打乱"本身，不是密码学随机：S311 是误报
        random.Random(seed).shuffle(shuffled)  # noqa: S311
        assert build_chain(shuffled).model_dump() == baseline, seed


def test_rule_ids_are_stable_across_instances() -> None:
    draft = build_chain(_flagship_findings())
    assert [c.rule_ids for c in draft.chains] == [
        c.rule_ids for c in build_chain(_flagship_findings()).chains
    ]


# ---------------------------------------------------------------------------
# 输入过滤
# ---------------------------------------------------------------------------


def test_unverified_findings_do_not_enter_the_chain() -> None:
    """只有 `verified` 能进链：链的每条边都要踩在实测的支撑点上。"""
    findings = _demo_findings()
    findings[0].status = VulnStatus.POTENTIAL
    draft = build_chain(findings)

    assert all(atom.verified for atom in draft.atoms)
    assert draft.skipped_finding_count == 1
    assert all(c.rule_ids != ["R1", "R2", "R3"] for c in draft.chains)


def test_rejected_and_unverified_are_also_excluded() -> None:
    for status in (VulnStatus.REJECTED, VulnStatus.UNVERIFIED):
        findings = _demo_findings()
        findings[0].status = status
        draft = build_chain(findings)
        assert draft.skipped_finding_count == 1, status


def test_require_verified_can_be_relaxed_explicitly() -> None:
    """显式关掉过滤时，未验证的 finding 也能参与 —— 但那是调用方的选择。"""
    findings = _demo_findings()
    findings[0].status = VulnStatus.POTENTIAL
    draft = ChainBuilder(require_verified=False).build(findings)
    assert draft.skipped_finding_count == 0
    assert len(draft.atoms) == 2


def test_findings_without_status_are_treated_as_verified() -> None:
    """B4 的 `Finding` 落库前压根没有 `status`；默认"未验证"会让链恒为空。

    这是一个**刻意选择**：把"没有状态"当成"未验证"，故障表现是"什么都没发生"，
    比报错难查得多；而调用方若确实要传全量 findings，可以显式要求过滤。
    """
    draft = build_chain(_demo_findings())  # status 全为 None
    assert draft.atoms and draft.chains


def test_finding_without_primary_key_is_skipped() -> None:
    """没有主键 → 进不了 `nodes.vuln_id` 外键 → 拦掉并计数。"""
    findings = _demo_findings()
    findings[0].vuln_id = 0
    draft = build_chain(findings)
    assert draft.skipped_finding_count == 1


def test_unknown_vuln_type_is_skipped_without_crash() -> None:
    findings = [*_demo_findings(), _Finding(9, "quantum_entanglement", file_path="x.py")]
    draft = build_chain(findings)
    assert draft.skipped_finding_count == 1
    assert all(atom.vuln_id != 9 for atom in draft.atoms)


def test_empty_input_produces_an_explained_draft() -> None:
    draft = build_chain([])
    assert isinstance(draft, ChainDraft)
    assert draft.chains == []
    assert draft.note == "没有可用于推演的已验证漏洞"
    assert draft.chain_count == 0


# ---------------------------------------------------------------------------
# 边界的显式化：深度、条数、单节点链
# ---------------------------------------------------------------------------


def test_depth_cap_is_enforced() -> None:
    """深度上限：链不会无限长下去（设计 §4.4 的深度上限）。"""
    deep = ChainBuilder(max_depth=2).build(_flagship_findings())
    assert deep.chains
    for chain in deep.chains:
        assert len(chain.rule_ids) <= 2
    assert MAX_CHAIN_DEPTH == 6  # 默认上限：再长就不是"演示一条链"，是穷举


def test_chain_count_cap_records_a_note() -> None:
    """展示条数被截断时**必须留痕**：报告要能写出"另有 N 条未展示"。

    "没输出"与"输出被截断"是两件事 —— 前者是"没有攻击面"，后者是"只看了一部分"。
    """
    draft = ChainBuilder(max_chains=1).build(_flagship_findings())
    assert len(draft.chains) == 1
    assert draft.note and "仅展示前 1 条" in draft.note
    assert MAX_CHAINS == 5


def test_single_node_chains_cover_leftover_atoms() -> None:
    """没有边可走的已验证漏洞仍要出现在报告里（单节点链），不能被悄悄丢掉。"""
    draft = build_chain(_flagship_findings())
    singles = [c for c in draft.chains if len(c.nodes) == 1]
    assert singles, "剩余漏洞必须各自成链"
    for chain in singles:
        node = chain.nodes[0]
        assert node.vuln_id is not None
        assert node.verification_status is VerificationStatus.VERIFIED
        assert node.node_type is ChainNodeType.VULN


def test_single_node_chains_can_be_disabled() -> None:
    draft = ChainBuilder(include_single_node_chains=False).build(_flagship_findings())
    assert all(len(c.nodes) > 1 for c in draft.chains)


def test_one_chain_does_not_reuse_the_same_vuln_twice() -> None:
    """一条链里，同一个漏洞最多支撑**一环** —— 用了就"消耗"掉，否则链会自己绕圈。

    链首的入口节点是个例外，而且是**有意的**：它写的是"从哪个漏洞进去"
    （`entry` 节点，无 `rule_id`），紧接着的第一环写的是"这个漏洞能换来什么"。
    两处指的是同一个漏洞的**两种角色**，不是把一条证据数了两遍 ——
    把入口去掉会让链读起来没有起点，把第一环去掉会让入口悬空。
    """
    for chain in build_chain(_flagship_findings()).chains:
        rules = [n for n in chain.nodes if n.rule_id]
        hop_ids = [n.vuln_id for n in rules if n.vuln_id]
        assert len(hop_ids) == len(set(hop_ids)), chain.chain_id
        assert len(chain.nodes) <= MAX_CHAIN_DEPTH + 2  # 上限 + 入口/影响节点

        entry = chain.nodes[0]
        if entry.node_type is ChainNodeType.ENTRY and rules:
            # 入口与第一环指向同一个漏洞时，只有第一环带规则编号
            assert entry.rule_id is None
            assert rules[0].parent_index == 0


def test_a_vuln_cannot_back_two_rings_of_one_chain() -> None:
    """构造一个会踩到这个坑的场景：同一个上传点同时满足 R3 与 R7 的前置。

    若允许复用，同一条证据会被数成两环"利用"，链长从 3 变成 4 ——
    报告里读起来像是打了两个上传点，实际只有一个。
    """
    findings = [
        _Finding(1, "sql_injection", file_path="app/api/order.py", cvss=9.1),
        _Finding(2, "unauth_access", file_path="app/api/upload.py", symbol="upload"),
        _Finding(
            3,
            "file_upload",
            file_path="app/api/upload.py",
            symbol="save_upload",
            cvss=9.0,
        ),
    ]
    for chain in build_chain(findings).chains:
        rule_nodes = [n for n in chain.nodes if n.rule_id]
        ids = [n.vuln_id for n in rule_nodes if n.vuln_id]
        assert len(ids) == len(set(ids)), (chain.chain_id, ids)


def test_impact_node_closes_the_chain_with_a_reason() -> None:
    """多环链结尾要有一句"这些能力合起来意味着什么"，而不是停在中途。"""
    draft = build_chain(_flagship_findings())
    multi = next(c for c in draft.chains if len(c.rule_ids) >= 2)
    last = multi.nodes[-1]
    assert last.node_type is ChainNodeType.IMPACT
    assert last.detail
    assert multi.target_asset


def test_chain_severity_reflects_the_worst_ring() -> None:
    """链的严重度取最严重的一环（不是平均）—— 一条 RCE 链不会因为
    中间夹了一环中危而变成中危。"""
    draft = build_chain(_flagship_findings())
    multi = next(c for c in draft.chains if len(c.rule_ids) >= 2)
    assert multi.severity in (Severity.CRITICAL, Severity.HIGH)
    assert any(c.severity is Severity.CRITICAL for c in draft.chains)
