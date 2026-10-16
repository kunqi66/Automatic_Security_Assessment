"""规则表 R1–R8 与通用匹配器（B5 设计 §4.6）。

## 一切都是数据

`CHAIN_RULES` 是一个元组，`match()` 是一个**与规则内容无关**的匹配器。
新增一条规则只需往元组里追加一个 `ChainRule`；匹配器、构建器、叙事、测试
一个字都不用改。反过来，如果写成 `if finding.vuln_type == "sqli": ...`，
规则表就会散落在控制流里，"一共几条规则、分别是什么"变成要去读代码才知道的事。

## 权限匹配用集合包含，不是等级比较

`require_priv ⊆ 当前可达权限`。这条写成 `<=` 就会错：`admin` 与 `db` 不可比
（设计 §4.5）。`PRIV_RANK` 只用于**最终选路径时排序**，不参与任何匹配判定 ——
它被放在文件末尾并加了警示注释，就是为了防止有人顺手拿它来写匹配。
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from app.chain.types import CategoryMode, ChainRule, Priv, VulnAtom
from app.models.enums import ChainNodeType, Severity

#: 权重最高的权限…… 不，**这不是权重**。它只是把"哪条链的终点更值得展示"
#: 排出一个全序，用于 `builder` 在多条候选路径里挑一条。
#:
#: ⚠️ **不要用它做匹配判定。** 权限是偏序集合，`host` 与 `db` 之间没有大小关系；
#: 这里的 6 > 5 只表示"演示时先把拿下宿主机的那条链摆在前面"。
PRIV_RANK: dict[Priv, int] = {
    Priv.HOST: 6,
    Priv.DB: 5,
    Priv.ADMIN: 4,
    Priv.KEYS: 3,
    Priv.USER: 2,
    Priv.ANONYMOUS: 1,
}


def state_rank(priv: frozenset[Priv]) -> int:
    """一个状态"走到了多远"——取最高分量的名次。**仅用于排序。**"""
    return max((PRIV_RANK.get(p, 0) for p in priv), default=0)


CHAIN_RULES: tuple[ChainRule, ...] = (
    ChainRule(
        rule_id="R1",
        name="SQLi → 凭证泄露",
        require_priv=frozenset({Priv.ANONYMOUS}),
        require_categories=frozenset({"sqli"}),
        require_assets=frozenset({"users"}),
        gain_priv=frozenset({Priv.USER}),
        exit_artifact="credential",
        severity=Severity.HIGH,
        node_type=ChainNodeType.CREDENTIAL,
        backed_by_category="sqli",
        narrative_template="利用 {file} 的 SQL 注入读取 users 表，得到可用于登录的账号凭证。",
        label_template="读取 users 表得到账号凭证",
        stage_name="凭证获取",
        precondition_template="匿名可达的 SQL 注入点（{file}）",
        postcondition_template="持有一组有效账号凭证",
        detail_template="由已验证的 SQL 注入（{vuln_code}）推得：注入点可直接读取 users 表。",
    ),
    ChainRule(
        rule_id="R2",
        name="凭证泄露 → 后台登录",
        require_priv=frozenset({Priv.USER}),
        require_artifacts=frozenset({"credential"}),
        require_assets=frozenset({"admin_login"}),
        gain_priv=frozenset({Priv.ADMIN}),
        exit_artifact="session",
        severity=Severity.HIGH,
        node_type=ChainNodeType.CREDENTIAL,
        # ⚠️ 这一环**没有实测依据**：设计 §4.2 的探针表里没有"登录接口探针"，
        # 因此没有任何东西能证明这组凭证真的能登进后台。设计 §4.7 的演示表把
        # 第 2 环标成「✅ 已验证」，但那需要一条本模块并未提供的探针 ——
        # 见报告里的"设计与契约/实现的分歧"。这里按事实标 `inferred`。
        backed_by_category=None,
        outcome_inferred=True,
        narrative_template="工程存在后台登录接口，用上一步的凭证登录，取得管理员会话。",
        label_template="凭证登录后台，取得管理员会话",
        stage_name="权限提升",
        precondition_template="持有账号凭证 ∧ 工程存在后台登录接口",
        postcondition_template="持有管理员会话（admin）",
        detail_template="**未实测**：由「已持有凭证」+「工程存在后台登录接口」推演得出登录成功。",
    ),
    ChainRule(
        rule_id="R3",
        name="管理员 + 文件上传 → RCE",
        require_priv=frozenset({Priv.ADMIN}),
        require_categories=frozenset({"file_upload"}),
        require_artifacts=frozenset({"session"}),
        gain_priv=frozenset({Priv.HOST}),
        exit_artifact="rce",
        severity=Severity.CRITICAL,
        node_type=ChainNodeType.SHELL,
        backed_by_category="file_upload",
        # 上传验证只传了 `<nonce>.txt` 并回读成功（证明上传点可达、无后缀白名单），
        # **没有传 WebShell，更没有执行它**。所以"宿主机 RCE"是推演。
        outcome_inferred=True,
        narrative_template="以管理员会话调用 {file} 的上传点投放 WebShell，取得宿主机执行权。",
        label_template="上传 WebShell 并取得宿主机执行权",
        stage_name="主机失陷",
        precondition_template="持有管理员会话 ∧ 上传点可达且无后缀白名单（{file}）",
        postcondition_template="宿主机命令执行（rce）",
        detail_template="**推演，未实际执行**：实测只证明了上传点可达（{vuln_code}），未投放任何可执行文件。",
    ),
    ChainRule(
        rule_id="R4",
        name="IDOR → 敏感数据泄露",
        require_priv=frozenset({Priv.USER}),
        # 「或」不是「与」：越权对象引用与未授权接口**任一**都能横读数据，
        # 规则名里也只有一个箭头。写成 AND 会让 R4 静默地要求两者同时存在。
        require_categories=frozenset({"idor", "unauth_access"}),
        category_mode=CategoryMode.ANY,
        gain_priv=frozenset({Priv.USER}),
        exit_artifact="pii_bulk",
        severity=Severity.HIGH,
        node_type=ChainNodeType.IMPACT,
        backed_by_category="idor",
        narrative_template="遍历 {file} 的用户接口标识，横向读取全量用户数据。",
        label_template="横向遍历读取全量用户数据",
        stage_name="数据泄露",
        precondition_template="持有普通用户身份 ∧ 存在越权对象引用（{file}）",
        postcondition_template="全量用户数据（pii_bulk）",
        detail_template="由已验证的越权（{vuln_code}）推得：同一接口按 id 遍历即可覆盖全量用户。",
    ),
    ChainRule(
        rule_id="R5",
        name="敏感信息泄露 → 数据库直连",
        require_priv=frozenset({Priv.ANONYMOUS}),
        require_categories=frozenset({"info_disclosure"}),
        require_assets=frozenset({"config"}),
        gain_priv=frozenset({Priv.DB}),
        exit_artifact="db_access",
        severity=Severity.HIGH,
        node_type=ChainNodeType.IMPACT,
        backed_by_category="info_disclosure",
        narrative_template="从 {file} 的配置探测结果里取得数据库口令，直接连接数据库。",
        label_template="取得数据库口令并直连",
        stage_name="数据层失陷",
        precondition_template="匿名可达的配置/调试接口（{file}）",
        postcondition_template="数据库直连能力（db_access）",
        detail_template="由已验证的信息泄露（{vuln_code}）推得：泄露内容包含数据库连接口令模式。",
    ),
    ChainRule(
        rule_id="R6",
        name="命令注入 → RCE",
        require_priv=frozenset({Priv.ANONYMOUS}),
        require_categories=frozenset({"cmdi"}),
        gain_priv=frozenset({Priv.HOST}),
        exit_artifact="rce",
        severity=Severity.CRITICAL,
        node_type=ChainNodeType.HOST,
        backed_by_category="cmdi",
        # 这一环**是实测的**：时间盲注的 `sleep 3` 真的被执行了，
        # 命令执行能力已被证实（设计 §4.7 的演示表把命令注入那一环标为 ✅）。
        outcome_inferred=False,
        narrative_template="利用 {file} 的命令注入执行任意系统命令，取得宿主机执行权。",
        label_template="命令注入取得宿主机执行权",
        stage_name="主机失陷",
        precondition_template="匿名可达的命令注入点（{file}）",
        postcondition_template="宿主机命令执行（rce）",
        detail_template="由已验证的命令注入（{vuln_code}）推得：时间盲注已证明命令被真实执行。",
    ),
    ChainRule(
        rule_id="R7",
        name="未授权访问 + 文件上传 → RCE（R3 的无 admin 变体）",
        require_priv=frozenset({Priv.ANONYMOUS}),
        require_categories=frozenset({"unauth_access", "file_upload"}),
        gain_priv=frozenset({Priv.HOST}),
        exit_artifact="rce",
        severity=Severity.CRITICAL,
        node_type=ChainNodeType.SHELL,
        backed_by_category="file_upload",
        outcome_inferred=True,
        narrative_template="借未授权访问直达 {file} 的上传点投放 WebShell，取得宿主机执行权。",
        label_template="无凭证直达上传点并投放 WebShell",
        stage_name="主机失陷",
        precondition_template="存在未授权可达的上传点（{file}）",
        postcondition_template="宿主机命令执行（rce）",
        detail_template="**推演，未实际执行**：实测只证明了上传点无需鉴权即可到达（{vuln_code}）。",
    ),
    ChainRule(
        rule_id="R8",
        name="任意文件读取 → 源码/密钥泄露",
        require_priv=frozenset({Priv.ANONYMOUS}),
        require_categories=frozenset({"file_read"}),
        gain_priv=frozenset({Priv.KEYS}),
        exit_artifact="secret",
        severity=Severity.MEDIUM,
        node_type=ChainNodeType.IMPACT,
        backed_by_category="file_read",
        narrative_template="利用 {file} 的路径穿越读取配置文件，取得密钥材料。",
        label_template="路径穿越读取配置/密钥文件",
        stage_name="密钥泄露",
        precondition_template="匿名可达的文件读取入口（{file}）",
        postcondition_template="密钥 / 源码（secret）",
        detail_template="由已验证的文件读取（{vuln_code}）推得：可读到配置类文件。",
    ),
)

#: 规则编号 → 规则，便于按 id 取回（叙事与测试都常用）
RULES_BY_ID: Mapping[str, ChainRule] = {rule.rule_id: rule for rule in CHAIN_RULES}

#: 严重度档位折算成分值，**只用于链之间的排序**（设计 §4.4 的 PICK 第 ② 条）。
#:
#: 这不是在算 CVSS —— 它只是把"这条边有多严重"折算到与 CVSS 同一个量纲上，
#: 好让「四环打到宿主机」不会被「一环打到宿主机」在排序上盖过去。
#: 若只累加原子的 CVSS，一条从 SQL 注入一路推到 RCE 的长链（原子只有 7.5）
#: 会输给一条单环命令注入（原子 9.0）—— 而报告最该展示的恰恰是前者。
SEVERITY_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
}


class RuleHit:
    """一次命中：规则 + 支撑它的原子实例（可能没有，如 R2）。"""

    __slots__ = ("atoms", "rule")

    def __init__(self, rule: ChainRule, atoms: tuple[VulnAtom, ...]) -> None:
        self.rule = rule
        self.atoms = atoms

    @property
    def primary_atom(self) -> VulnAtom | None:
        """记在节点上的那个原子。多个实例时取 `vuln_id` 最小者 —— **确定性**。"""
        return min(self.atoms, key=lambda a: a.vuln_id) if self.atoms else None

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<RuleHit {self.rule.rule_id} atoms={[a.vuln_id for a in self.atoms]}>"


def match(
    *,
    priv: frozenset[Priv],
    artifacts: frozenset[str],
    project_assets: frozenset[str],
    atoms_by_category: Mapping[str, Sequence[VulnAtom]],
    rules: Sequence[ChainRule] = CHAIN_RULES,
) -> list[RuleHit]:
    """对当前状态做一次全规则匹配（B5 设计 §4.4 的 MATCH 步骤）。

    四个前置条件全部满足才算命中：

    1. `require_priv ⊆ priv` —— 用**集合包含**，不是等级比较；
    2. `require_categories` 里的每个类别**都要有一个实例**，且该实例自身的
       `requires ⊆ priv`（"存在已验证的 idor"之外，还要"我现在够得着它"）；
    3. `require_artifacts ⊆ artifacts` —— 上一步的产出物；
    4. `require_assets ⊆ project_assets` —— 工程里确实存在这个资产。

    返回顺序 = `rules` 的声明顺序，因此调用方的遍历顺序天然确定。
    """
    hits: list[RuleHit] = []
    for rule in rules:
        if not rule.require_priv <= priv:
            continue
        if not rule.require_artifacts <= artifacts:
            continue

        matched_atoms: list[VulnAtom] = []
        ok = True
        for category in sorted(rule.require_categories):  # 排序 ⇒ 结果与集合迭代序无关
            candidates = [
                atom for atom in atoms_by_category.get(category, ()) if atom.requires <= priv
            ]
            if candidates:
                matched_atoms.append(min(candidates, key=lambda a: a.vuln_id))
                if rule.category_mode is CategoryMode.ANY:
                    break
                continue
            if rule.category_mode is CategoryMode.ALL:
                ok = False
                break
        if not ok or (rule.require_categories and not matched_atoms):
            continue

        # 资产检查放在最后：它要同时看**工程级资产**（R2 的"存在后台登录接口"）
        # 与**支撑这一环的漏洞自己的资产**（R1 的"其资产含 users 表"）。
        # 设计 §4.6 只给了一个 `require_assets` 字段，两种资产混在同一列里
        # （"users 表 / 后台登录接口"）—— 用并集匹配，两种写法都能成立。
        available = set(project_assets)
        for atom in matched_atoms:
            available |= atom.assets
        if not rule.require_assets <= available:
            continue

        hits.append(RuleHit(rule, tuple(matched_atoms)))
    return hits


def describe_rules(rules: Sequence[ChainRule] = CHAIN_RULES) -> list[str]:
    """人类可读的规则清单（报告附录用，也便于测试断言"一共八条"）。"""
    return [
        f"{r.rule_id} {r.name}：{'/'.join(sorted(p.value for p in r.require_priv)) or '任意'}"
        f" → {'/'.join(sorted(p.value for p in r.gain_priv))} ({r.exit_artifact})"
        for r in rules
    ]
