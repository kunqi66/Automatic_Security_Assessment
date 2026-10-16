"""链规则表与匹配语义的测试（L1：节点与边由**确定性规则**决定，不是 LLM）。

规则表是"哪些边成立"的唯一来源，所以这里测的是**边界条件**：
权限用的是集合包含而不是等级比较、类别要有一个"我现在够得着"的实例、
资产要同时看工程级与漏洞自身。这三条任何一条被写成"差不多就行"，
推出来的链就会变成一堆听起来合理的边 —— 而听起来合理的边正是最该被拒的。
"""

from __future__ import annotations

from app.chain.atom import CATEGORY_ATOMS, to_atom
from app.chain.rules import (
    CHAIN_RULES,
    RULES_BY_ID,
    SEVERITY_SCORE,
    describe_rules,
    match,
    state_rank,
)
from app.chain.types import Priv, VulnAtom
from app.models.enums import Severity


class _Finding:
    def __init__(
        self,
        vuln_id: int,
        vuln_type: str,
        *,
        file_path: str = "app/api/order.py",
        symbol: str = "cursor.execute",
        cvss: float = 8.0,
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


def _atom(vuln_id: int, vuln_type: str, **kwargs: object) -> VulnAtom:
    atom = to_atom(_Finding(vuln_id, vuln_type, **kwargs))  # type: ignore[arg-type]
    assert atom is not None
    return atom


def _by_category(*atoms: VulnAtom) -> dict[str, list[VulnAtom]]:
    buckets: dict[str, list[VulnAtom]] = {}
    for atom in atoms:
        buckets.setdefault(atom.category, []).append(atom)
    return buckets


# ---------------------------------------------------------------------------
# 规则表本身
# ---------------------------------------------------------------------------


def test_there_are_exactly_eight_rules_with_unique_ids() -> None:
    """R1–R8，编号唯一 —— 设计 §4.4 的八条边一条不少、一条不多。"""
    ids = [rule.rule_id for rule in CHAIN_RULES]
    assert ids == [f"R{i}" for i in range(1, 9)]
    assert set(RULES_BY_ID) == set(ids)


def test_every_rule_declares_its_evidence_backing() -> None:
    """每条边都必须说清"它凭什么成立"：一个支撑类别，或显式声明这是推演。

    `backed_by_category=None` 而 `outcome_inferred=False` 是**不允许**的组合 ——
    那意味着一条既没有实测支撑、又不承认自己是推演的边，
    它在报告里会被当成实测结论展示。
    """
    for rule in CHAIN_RULES:
        if rule.backed_by_category is None:
            assert rule.outcome_inferred is True, rule.rule_id
        else:
            assert rule.backed_by_category in CATEGORY_ATOMS, rule.rule_id


def test_inferred_rules_are_exactly_the_ones_we_cannot_measure() -> None:
    """只有 R2/R3/R7 是推演：登录、投放 WebShell、无凭证直达上传点。

    这三条的共同点：需要**主动利用**（真登录、真传 shell），而本系统的探针
    只做只读无害验证。它们能进链，但必须逐环标成 `inferred`。
    """
    inferred = {rule.rule_id for rule in CHAIN_RULES if rule.outcome_inferred}
    assert inferred == {"R2", "R3", "R7"}


def test_require_priv_and_gain_priv_are_sets() -> None:
    for rule in CHAIN_RULES:
        assert rule.require_priv and rule.gain_priv, rule.rule_id
        assert all(isinstance(p, Priv) for p in rule.require_priv), rule.rule_id


def test_severity_scores_cover_all_four_levels() -> None:
    """排序折算表覆盖 Severity 的全部四档 —— 少一档会让 KeyError 落在推演里。"""
    assert set(SEVERITY_SCORE) == set(Severity)


def test_describe_rules_is_human_readable() -> None:
    lines = describe_rules()
    assert len(lines) == 8
    assert lines[0].startswith("R1 ")
    assert "→" in lines[0]


def test_state_rank_is_monotonic_in_privilege() -> None:
    """`state_rank` 只用于排序，但必须是单调的：权限越多，排名越高。"""
    low = state_rank(frozenset({Priv.ANONYMOUS}))
    mid = state_rank(frozenset({Priv.ANONYMOUS, Priv.USER}))
    high = state_rank(frozenset({Priv.ANONYMOUS, Priv.USER, Priv.ADMIN, Priv.HOST}))
    assert low < mid < high


# ---------------------------------------------------------------------------
# 匹配语义
# ---------------------------------------------------------------------------


def test_r1_matches_when_anonymous_and_sqli_present() -> None:
    atoms = _by_category(_atom(1, "sql_injection", file_path="app/api/order.py"))
    hits = match(
        priv=frozenset({Priv.ANONYMOUS}),
        artifacts=frozenset(),
        project_assets=frozenset(),
        atoms_by_category=atoms,
    )
    assert [h.rule.rule_id for h in hits] == ["R1"]
    assert hits[0].primary_atom is not None and hits[0].primary_atom.vuln_id == 1


def test_privilege_check_is_set_containment_not_ranking() -> None:
    """`require_priv ⊆ priv` —— **集合包含**，不是"等级够了就行"。

    设计 §4.5 的 `Priv` 是偏序而不是全序：`admin` 并不蕴含 `user`
    （一个只拿到后台会话的人并不因此拥有一份普通用户的凭证）。
    用等级比较会凭空多出几条边，而且多出来的恰好是"看起来很顺"的那几条。
    """
    atoms = _by_category(_atom(1, "sql_injection"))
    hits = match(
        priv=frozenset({Priv.ADMIN}),
        artifacts=frozenset(),
        project_assets=frozenset(),
        atoms_by_category=atoms,
    )
    assert hits == [], "admin 不蕴含 anonymous，R1 不该命中"


def test_category_requires_an_instance_reachable_from_current_privilege() -> None:
    """ "存在一个已验证的 idor"不够，还要"我现在够得着它"（`atom.requires ⊆ priv`）。"""
    idor = _atom(1, "idor", file_path="app/api/users.py", symbol="get_user")
    assert idor.requires == frozenset({Priv.USER})

    anonymous = match(
        priv=frozenset({Priv.ANONYMOUS}),
        artifacts=frozenset(),
        project_assets=frozenset(),
        atoms_by_category=_by_category(idor),
    )
    assert anonymous == []

    user = match(
        priv=frozenset({Priv.ANONYMOUS, Priv.USER}),
        artifacts=frozenset(),
        project_assets=frozenset(),
        atoms_by_category=_by_category(idor),
    )
    assert "R4" in [h.rule.rule_id for h in user]


def test_artifact_precondition_is_enforced() -> None:
    """R2 需要上一步产出的 `credential`；没有它就不该有这条边。"""
    sqli = _atom(1, "sql_injection")
    without = match(
        priv=frozenset({Priv.USER}),
        artifacts=frozenset(),
        project_assets=frozenset({"admin_login"}),
        atoms_by_category=_by_category(sqli),
    )
    assert all(h.rule.rule_id != "R2" for h in without)

    with_cred = match(
        priv=frozenset({Priv.USER}),
        artifacts=frozenset({"credential"}),
        project_assets=frozenset({"admin_login"}),
        atoms_by_category=_by_category(sqli),
    )
    assert "R2" in [h.rule.rule_id for h in with_cred]


def test_project_asset_precondition_is_enforced() -> None:
    """R2 还要求工程里**确实存在**后台登录接口 —— 资产表为空时不该推这条边。"""
    hits = match(
        priv=frozenset({Priv.USER}),
        artifacts=frozenset({"credential"}),
        project_assets=frozenset(),
        atoms_by_category=_by_category(_atom(1, "sql_injection")),
    )
    assert "R2" not in [h.rule.rule_id for h in hits]


def test_atom_assets_count_towards_the_precondition() -> None:
    """R1 的 "users 表" 是**漏洞自己的资产**（sqli 原子的 assets 含 users）。

    设计 §4.6 只有一个 `require_assets` 字段，把工程级资产（"存在后台登录接口"）
    与漏洞级资产（"这个注入点够得着 users 表"）混在同一列里。
    匹配时取并集，两种写法都能成立 —— 否则 R1 永远不命中。
    """
    assert "users" in CATEGORY_ATOMS["sqli"].assets
    hits = match(
        priv=frozenset({Priv.ANONYMOUS}),
        artifacts=frozenset(),
        project_assets=frozenset(),  # 工程资产为空，只能靠原子自带的 users
        atoms_by_category=_by_category(_atom(1, "sql_injection")),
    )
    assert "R1" in [h.rule.rule_id for h in hits]


def test_match_order_follows_rule_declaration() -> None:
    """命中顺序 = 规则声明顺序，与集合迭代序无关（确定性）。"""
    atoms = _by_category(_atom(1, "sql_injection"), _atom(2, "cmdi"), _atom(3, "info_disclosure"))
    kwargs = {
        "priv": frozenset({Priv.ANONYMOUS}),
        "artifacts": frozenset(),
        "project_assets": frozenset({"config"}),
        "atoms_by_category": atoms,
    }
    first = [h.rule.rule_id for h in match(**kwargs)]  # type: ignore[arg-type]
    second = [h.rule.rule_id for h in match(**kwargs)]  # type: ignore[arg-type]
    assert first == second
    assert first == sorted(first, key=lambda r: int(r[1:]))


def test_primary_atom_is_the_smallest_vuln_id() -> None:
    """同一类别有多个实例时，记在节点上的是 `vuln_id` 最小者 —— 确定性。"""
    atoms = _by_category(_atom(7, "cmdi", file_path="b.py"), _atom(3, "cmdi", file_path="a.py"))
    hits = match(
        priv=frozenset({Priv.ANONYMOUS}),
        artifacts=frozenset(),
        project_assets=frozenset(),
        atoms_by_category=atoms,
    )
    r6 = next(h for h in hits if h.rule.rule_id == "R6")
    assert r6.primary_atom is not None
    assert r6.primary_atom.vuln_id == 3


def test_every_category_appears_in_a_rule_except_the_documented_standalone_one() -> None:
    """每个原子类别都该有边 —— 唯一的例外要**显式写出来**，不能靠"没人发现"。

    `deserialization` 在设计 §4.5 的原子表里有（匿名 → host），但设计 §4.4 的
    规则表只给了 R1–R8，没有任何一条以它为前提。于是它只能作为**单节点链**
    （"反序列化 → RCE"）出现在报告里。本实现不擅自加 R9 去补这个洞 ——
    加一条设计里没有的边，等于替设计做了决定；这里把差额钉在测试里，
    让它出现在报告的分歧清单上，而不是变成一个"看起来规则挺全"的假象。
    """
    used = {rule.backed_by_category for rule in CHAIN_RULES if rule.backed_by_category}
    for rule in CHAIN_RULES:
        used |= set(rule.require_categories)
    standalone = {"deserialization"}
    assert set(CATEGORY_ATOMS) - used == standalone


def test_any_mode_fires_on_either_category() -> None:
    """R4 是 `any`：只要 idor 或 unauth_access 有一个就成立（规则名里只有一个箭头）。"""
    assert RULES_BY_ID["R4"].category_mode.value == "any"

    for vuln_type in ("idor", "unauth_access"):
        atom = _atom(1, vuln_type, file_path="app/api/users.py")
        hits = match(
            priv=frozenset({Priv.ANONYMOUS, Priv.USER}),
            artifacts=frozenset(),
            project_assets=frozenset(),
            atoms_by_category=_by_category(atom),
        )
        assert "R4" in [h.rule.rule_id for h in hits], vuln_type


def test_all_mode_still_requires_every_category() -> None:
    """R7 是 `all`：未授权访问与上传点**都要**有，缺一个就不是那条边。"""
    assert RULES_BY_ID["R7"].category_mode.value == "all"
    only_upload = _atom(1, "file_upload", file_path="app/api/upload.py")
    hits = match(
        priv=frozenset({Priv.ANONYMOUS}),
        artifacts=frozenset(),
        project_assets=frozenset(),
        atoms_by_category=_by_category(only_upload),
    )
    assert "R7" not in [h.rule.rule_id for h in hits]


def test_deserialization_only_chains_with_admin_or_upload() -> None:
    """反序列化单独出现时推不出多环链 —— 它需要落点（`deser` 资产不在任何前置里）。"""
    atoms = _by_category(_atom(1, "deserialization", file_path="app/api/data.py"))
    hits = match(
        priv=frozenset({Priv.ANONYMOUS}),
        artifacts=frozenset(),
        project_assets=frozenset(),
        atoms_by_category=atoms,
    )
    assert [h.rule.rule_id for h in hits] == []
