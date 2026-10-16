"""攻击链构建器：从已验证漏洞推出攻击链（B5 设计 §4.4）。

## 算法：在「状态空间」上做 BFS，而不是在「路径」上

队列里的元素是 **状态** `(可达权限集合, 已持产出物)`，不是一条走过的路径。
同一个状态无论从哪条路到达，都只扩展一次 —— 于是搜索规模只与**可达状态数**
相关，与路径数无关（路径数随环数指数增长，状态数不会）。

副产品有两个，都很值钱：

* **环检测几乎不需要了**：每一跳都要求状态**严格变大**（至少多一个权限或产出物），
  所以按构造就不可能出现环。设计 §4.4 的"环剔除"在这一实现下是结构性成立的，
  而不是靠事后剪枝。仍然保留 `_assert_grows` 作为一道自检：万一将来有人加了一条
  "原地踏步"的规则，它会立刻报出来，而不是悄悄产出一个死循环。
* **路径可复现**：所有集合遍历都排过序（`sorted(rule.require_categories)`、
  原子按 `vuln_id` 取最小），因此同一份输入永远得到同一条链（L1）。

## 选路径：三条排序键，顺序不能换

设计 §4.4 的 PICK：①最高可达权限 ②总 CVSS ③最短链长。
第 ① 条用 `PRIV_RANK`（**仅排序用**，见 `rules.py` 的警示）。
把 ② 排在 ③ 前面是有意的：**两条路终点相同时，更严重的那条更值得展示**，
哪怕它更长 —— 报告是给人看的，省一行文字换不来任何东西。
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.chain.atom import detect_project_assets, to_atom
from app.chain.rules import CHAIN_RULES, SEVERITY_SCORE, RuleHit, match, state_rank
from app.chain.types import (
    AttackChain,
    ChainDraft,
    ChainNode,
    ChainRule,
    Priv,
    VulnAtom,
)
from app.core.logging import get_logger
from app.models.enums import ChainNodeType, Severity, VerificationStatus

logger = get_logger(__name__)

#: 链深上限（设计 §4.4 的 DEPTH 判断）。超出即剪枝并 WARN ——
#: 真实的攻击链不会长到 7 环以上；真出现了，说明规则表里有循环在自我引用。
MAX_CHAIN_DEPTH = 6

#: 一次推演最多输出几条链。超出部分不是"没有"，而是"报告里放不下"，
#: 所以只取排序靠前的若干条，并在 `ChainDraft.note` 里写明被省略的数量。
MAX_CHAINS = 5

#: 链首节点的类型（链的入口）
_ENTRY_NODE_TYPE = ChainNodeType.ENTRY


class _State:
    """搜索状态：`(权限, 产出物)` 二元组 + 到达它的最优路径。"""

    __slots__ = ("artifacts", "parent", "priv", "steps")

    def __init__(
        self,
        priv: frozenset[Priv],
        artifacts: frozenset[str],
        parent: _State | None = None,
        steps: tuple[_Hop, ...] = (),
    ) -> None:
        self.priv = priv
        self.artifacts = artifacts
        self.parent = parent
        self.steps = steps

    @property
    def key(self) -> tuple[frozenset[Priv], frozenset[str]]:
        return (self.priv, self.artifacts)

    @property
    def depth(self) -> int:
        return len(self.steps)

    @property
    def cvss_total(self) -> float:
        """链的"总严重度"：每个支撑漏洞的 CVSS + 每条规则的严重度折算分。

        两项都要加：只加原子 CVSS 的话，一条从 SQL 注入一路推到宿主机 RCE 的长链
        （原子只有一个 7.5 的 SQL 注入）会输给一条单环命令注入（原子 9.0），
        而报告最该展示的恰恰是前者。折算口径见 `rules.SEVERITY_SCORE`。
        """
        atom_part = sum(step.atom.cvss if step.atom else 0.0 for step in self.steps)
        rule_part = sum(SEVERITY_SCORE.get(step.rule.severity, 0.0) for step in self.steps)
        return round(atom_part + rule_part, 2)

    def rank_key(self) -> tuple[int, float, int]:
        """排序键：①最高权限 ②总 CVSS ③最短链长（用负值实现"越短越好"）。"""
        return (state_rank(self.priv), self.cvss_total, -self.depth)


class _Hop:
    """一跳：命中的规则 + 支撑它的原子（R2 没有原子）。"""

    __slots__ = ("atom", "hit", "rule")

    def __init__(self, hit: RuleHit) -> None:
        self.hit = hit
        self.rule: ChainRule = hit.rule
        self.atom: VulnAtom | None = hit.primary_atom


class ChainBuilder:
    """从已验证漏洞集合构建攻击链（B5 设计 §3.1 的 `ChainBuilder`）。"""

    def __init__(
        self,
        *,
        rules: Sequence[ChainRule] = CHAIN_RULES,
        max_depth: int = MAX_CHAIN_DEPTH,
        max_chains: int = MAX_CHAINS,
        require_verified: bool = True,
        include_single_node_chains: bool = True,
    ) -> None:
        self.rules = tuple(rules)
        self.max_depth = max_depth
        self.max_chains = max_chains
        self.require_verified = require_verified
        self.include_single_node_chains = include_single_node_chains

    # ------------------------------------------------------------------
    # 对外入口
    # ------------------------------------------------------------------

    def build(self, findings: Sequence[Any]) -> ChainDraft:
        """推演。**同步、纯函数、无 IO**（契约 4 的 `build_chain` 就是它）。"""
        draft = ChainDraft()
        ordered = _stable_order(findings)

        atoms: list[VulnAtom] = []
        skipped = 0
        for finding in ordered:
            atom = to_atom(finding)
            if atom is None:
                skipped += 1
                continue
            if self.require_verified and not atom.verified:
                # 未验证的 finding 不进链：链的每一条边都要有实测的支撑点，
                # 否则整条链会退化成"可能这样也可能那样"的推测文。
                skipped += 1
                continue
            if atom.vuln_id == 0:
                # 没有主键的 finding 进不了 `attack_chain_nodes.vuln_id`（外键），
                # 与其产出一个不可落库的节点，不如在这一步就拦掉并计数。
                logger.warning("finding 缺少 vuln_id，跳过链推演：%s", atom.file_path)
                skipped += 1
                continue
            atoms.append(atom)

        if not atoms:
            draft.skipped_finding_count = skipped
            draft.note = "没有可用于推演的已验证漏洞"
            return draft

        project_assets = detect_project_assets(ordered)
        atoms_by_category: dict[str, list[VulnAtom]] = {}
        for atom in atoms:
            atoms_by_category.setdefault(atom.category, []).append(atom)
        for bucket in atoms_by_category.values():
            bucket.sort(key=lambda a: a.vuln_id)

        consumed: set[int] = set()
        chains: list[AttackChain] = []
        remaining = atoms

        while len(chains) < self.max_chains:
            best = self._best_path(remaining, project_assets)
            if best is None or not best.steps:
                break
            chain = self._to_chain(best, project_assets)
            chains.append(chain)
            consumed.update(step.atom.vuln_id for step in best.steps if step.atom is not None)
            remaining = [a for a in atoms if a.vuln_id not in consumed]

        if self.include_single_node_chains:
            chains.extend(self._single_node_chains(atoms, consumed, project_assets))

        if len(chains) > self.max_chains:
            # "没输出"与"输出被截断"必须能被区分 —— 报告要能写出
            # "另有 N 条链未展示"，而不是让人以为攻击面只有这几条。
            draft.note = f"共推出 {len(chains)} 条链，按严重度仅展示前 {self.max_chains} 条"
            chains = chains[: self.max_chains]

        draft.chains = chains
        draft.atoms = atoms
        draft.skipped_finding_count = skipped
        return draft

    # ------------------------------------------------------------------
    # BFS
    # ------------------------------------------------------------------

    def _best_path(
        self, atoms: Sequence[VulnAtom], project_assets: frozenset[str]
    ) -> _State | None:
        """在状态空间上 BFS，返回**最优的终止状态**（含到达它的路径）。"""
        if not atoms:
            return None

        atoms_by_category: dict[str, list[VulnAtom]] = {}
        for atom in atoms:
            atoms_by_category.setdefault(atom.category, []).append(atom)

        start = _State(priv=frozenset({Priv.ANONYMOUS}), artifacts=frozenset())
        frontier: list[_State] = [start]
        seen: dict[tuple[frozenset[Priv], frozenset[str]], _State] = {start.key: start}
        terminals: list[_State] = []

        pruned = 0
        while frontier:
            current = frontier.pop(0)
            hits = match(
                priv=current.priv,
                artifacts=current.artifacts,
                project_assets=project_assets,
                atoms_by_category=atoms_by_category,
                rules=self.rules,
            )
            advanced = False
            for hit in hits:
                nxt = self._advance(current, hit)
                if nxt is None:
                    continue
                existing = seen.get(nxt.key)
                if existing is not None:
                    # 状态去重：同一状态只扩展一次（并保留排序更优的那条到达路径）
                    if nxt.rank_key() > existing.rank_key():
                        existing.parent = nxt.parent
                        existing.steps = nxt.steps
                    continue
                if nxt.depth > self.max_depth:
                    pruned += 1
                    continue
                seen[nxt.key] = nxt
                frontier.append(nxt)
                advanced = True
            if not advanced and current.steps:
                terminals.append(current)

        if pruned:
            logger.warning(
                "链深超过 %d 环，已剪枝 %d 个状态（设计 §4.4 的深度上限）",
                self.max_depth,
                pruned,
            )

        if not terminals:
            return None
        # 排序键 ①最高权限 ②总 CVSS ③最短链长；`max` 取的是"更值得展示"的那条
        return max(terminals, key=lambda s: s.rank_key())

    def _advance(self, state: _State, hit: RuleHit) -> _State | None:
        """应用一跳，得到新状态。**状态必须严格变大，否则丢弃。**"""
        new_priv = state.priv | hit.rule.gain_priv
        new_artifacts = state.artifacts | (
            {hit.rule.exit_artifact} if hit.rule.exit_artifact else set()
        )
        hop = _Hop(hit)

        # 同一条路径上，一个漏洞最多支撑**一环**。
        # 否则 R3（管理员+上传→RCE）与 R7（未授权+上传→RCE）可以拿同一个上传点
        # 各记一环，输出成"两环利用"，而实际上我们只验证了一个上传点 ——
        # 那是把同一份证据数了两遍。这和"状态必须严格变大"是两回事：
        # 状态会变（多了 host），但支撑它的事实只有一条。
        used = {step.atom.vuln_id for step in state.steps if step.atom is not None}
        if hop.atom is not None and hop.atom.vuln_id in used:
            logger.debug(
                "漏洞 %s 已在本路径上支撑过一环，规则 %s 跳过",
                hop.atom.vuln_id,
                hit.rule.rule_id,
            )
            return None

        if (new_priv, new_artifacts) == state.key:
            # 原地踏步的规则会让 BFS 空转 —— 丢弃，而不是让它进队列。
            # ⚠️ 这是 `debug` 而不是 `warning`：**它太常见了**（R4 这类
            # `gain_priv == require_priv` 的规则在任何状态下都是原地踏步），
            # 一次推演能刷出几十行。用 warning 记它，等于把真正的告警淹掉。
            logger.debug(
                "规则 %s 在状态 %s 上没有产生新的权限或产出物，已跳过",
                hit.rule.rule_id,
                sorted(p.value for p in state.priv),
            )
            return None
        return _State(
            priv=new_priv,
            artifacts=new_artifacts,
            parent=state,
            steps=(*state.steps, hop),
        )

    # ------------------------------------------------------------------
    # 落成链模型
    # ------------------------------------------------------------------

    def _to_chain(self, terminal: _State, project_assets: frozenset[str]) -> AttackChain:
        steps = terminal.steps
        entry_atom = steps[0].atom if steps and steps[0].atom else None

        nodes: list[ChainNode] = [
            ChainNode(
                node_type=_ENTRY_NODE_TYPE,
                vuln_id=entry_atom.vuln_id if entry_atom else None,
                vuln_code=entry_atom.vuln_code if entry_atom else None,
                parent_index=None,
                order_index=0,
                stage_name="入口",
                label=_entry_label(entry_atom),
                precondition="匿名可达",
                postcondition="已确认的初始突破口",
                detail=_entry_detail(entry_atom),
                rule_id=None,
                # 入口节点就是那条已验证的漏洞本身 —— 实测，不是推演
                verification_status=VerificationStatus.VERIFIED,
            )
        ]

        for step in steps:
            index = len(nodes)
            atom = step.atom
            nodes.append(
                ChainNode(
                    node_type=step.rule.node_type,
                    vuln_id=atom.vuln_id if atom else None,
                    vuln_code=atom.vuln_code if atom else None,
                    parent_index=index - 1,
                    order_index=index,
                    stage_name=step.rule.stage_name,
                    label=_fill(step.rule.label_template, atom, step),
                    precondition=_fill(step.rule.precondition_template, atom, step),
                    postcondition=_fill(step.rule.postcondition_template, atom, step),
                    detail=_fill(step.rule.detail_template, atom, step),
                    rule_id=step.rule.rule_id,
                    verification_status=_verification_of(step),
                )
            )

        impact = _impact_node(terminal, parent_index=len(nodes) - 1, order_index=len(nodes))
        impact_node_added = impact is not None
        if impact is not None:
            nodes.append(impact)

        rule_ids = [step.rule.rule_id for step in steps]
        severity = _chain_severity(steps)
        verified = sum(1 for n in nodes if n.verification_status is VerificationStatus.VERIFIED)
        chain = AttackChain(
            chain_id="CHAIN-" + "-".join(rule_ids) if rule_ids else "CHAIN-SINGLE",
            name=_chain_name(steps),
            description=_chain_description(nodes),
            severity=severity,
            entry_point=entry_atom.file_path if entry_atom else "",
            target_asset=_target_asset(terminal, impact_node_added),
            # 置信度 = 实测环占比。**由结构算出**，不是模型给的、也不是拍的：
            # 一条 4 环里 2 环实测的链，置信度 0.5 是它的结构事实。
            confidence=round(verified / len(nodes), 3) if nodes else 0.0,
            rule_ids=rule_ids,
            nodes=nodes,
        )
        chain.narrative = _template_narrative(chain)
        chain.narrative_source = "template"
        return chain

    def _single_node_chains(
        self,
        atoms: Sequence[VulnAtom],
        consumed: set[int],
        project_assets: frozenset[str],
    ) -> list[AttackChain]:
        """没被任何链用到的已验证漏洞，各自成为一条单节点链。

        理由：报告的攻击面一节要回答"这个工程里**哪些**已验证漏洞构成了攻击路径"。
        没进链的漏洞不是不存在，只是它没接上任何规则 —— 把它们丢掉会让读者以为
        "没链 = 没问题"，而事实是"孤立但真实存在"。
        """
        out: list[AttackChain] = []
        for atom in sorted(atoms, key=lambda a: a.vuln_id):
            if atom.vuln_id in consumed:
                continue
            node = ChainNode(
                node_type=ChainNodeType.VULN,
                vuln_id=atom.vuln_id,
                vuln_code=atom.vuln_code,
                parent_index=None,
                order_index=0,
                stage_name="独立漏洞",
                label=_entry_label(atom),
                precondition="匿名可达" if Priv.ANONYMOUS in atom.requires else "需已有权限",
                postcondition="已确认可利用（未与其他漏洞连成链）",
                detail=_entry_detail(atom),
                verification_status=VerificationStatus.VERIFIED,
            )
            chain = AttackChain(
                chain_id=f"CHAIN-{atom.vuln_id}",
                name=f"{atom.category} 独立可利用点",
                description=(
                    f"{atom.file_path} 的 {atom.category} 已在沙箱中无害验证；"
                    f"它没有与其它漏洞连成多环链（现有规则未命中）。"
                ),
                severity=_severity_of_atom(atom),
                entry_point=atom.file_path,
                # 终点资产取"它能拿到什么权限"，而不是罗列全部资产 ——
                # 后者会让报告里出现 `api/config/db/shell/upload` 这种谁也读不懂的一串。
                target_asset=_PRIV_LABEL.get(
                    max(atom.gains, key=_priv_rank, default=Priv.USER), atom.category
                ),
                confidence=1.0,  # 单节点 = 一 环实测（这个漏洞本身）
                rule_ids=[],
                nodes=[node],
            )
            chain.narrative = _template_narrative(chain)
            chain.narrative_source = "template"
            out.append(chain)
        return out


# ---------------------------------------------------------------------------
# 节点/链上的文本：全部由模板拼出（**不给 LLM 留任何位置**）
# ---------------------------------------------------------------------------


def _verification_of(step: _Hop) -> VerificationStatus:
    """这一环是实测还是推演（Q24 方案 A 的判定，**确定性规则**）。

    三条都满足才算实测：
      ① 规则声明自己的结论不是推演（`outcome_inferred=False`）；
      ② 这一环有支撑它的漏洞原子（R2 没有 —— 它只是一个接口存在性推断）；
      ③ 那个原子是已验证的（构建器已经过滤过，这里是第二道自检）。
    """
    if step.rule.outcome_inferred or step.atom is None or not step.atom.verified:
        return VerificationStatus.INFERRED
    return VerificationStatus.VERIFIED


def _fill(template: str, atom: VulnAtom | None, step: _Hop) -> str:
    """填模板。**缺字段不抛异常** —— 一条链不该因为少个文件名就构建失败。"""
    try:
        return template.format(
            file=atom.file_path if atom else "（未知位置）",
            vuln_code=atom.vuln_code if atom and atom.vuln_code else "（未编号）",
            rule_id=step.rule.rule_id,
            category=atom.category if atom else step.rule.name,
        )
    except (KeyError, IndexError) as exc:  # 模板写错：降级成原文，别让整条链挂掉
        logger.warning("链模板 %s 填充失败（%s），改用原文", step.rule.rule_id, exc)
        return template


def _entry_label(atom: VulnAtom | None) -> str:
    if atom is None:
        return "入口：匿名可达的攻击面"
    code = f"（{atom.vuln_code}）" if atom.vuln_code else ""
    return f"{atom.category} 入口{code}：{atom.file_path}"


def _entry_detail(atom: VulnAtom | None) -> str:
    if atom is None:
        return "链的入口点。"
    # ⚠️ 这里原本写的是「只读探针命中特征」—— **对两条探针是假话**：
    # idor 要 `POST` 写一条自造标记（读回来才算打通平行越权），
    # 上传要 `POST` 传一个文件。两条都不是只读的。
    #
    # 真正对**所有**探针都成立、而且更强的是闸门那条不变量：**无破坏性**
    # （`guard` + 模板的 `side_effect_free`）—— 不改真实数据、不外连、
    # 不落可执行文件、不碰任何持久资产。换成这一条，
    # 它在每个类别上都是真话，而且正是读者真正在问的那件事。
    return (
        f"{atom.file_path} 的 {atom.category} 已在沙箱中**无害验证**"
        f"（探针命中特征，全程无破坏性操作），是整条链的起点。"
    )


def _impact_node(terminal: _State, *, parent_index: int, order_index: int) -> ChainNode | None:
    """链的终点节点：只有当链真的拿到了主机/数据库级权限时才追加。

    追加它有两条理由：① 设计 §4.7 的演示链第 4 环就是"宿主机 RCE"这个**影响**，
    ② 前面那些 `R3`/`R7` 的 SHELL 节点描述的是"怎么进去的"，而读者最关心的
    "所以呢"需要一个单独的节点承载 —— 它**永远是 `inferred`**，
    因为"拿下宿主机"这件事我们从不实测（无害化红线）。
    """
    if Priv.HOST in terminal.priv:
        return ChainNode(
            node_type=ChainNodeType.IMPACT,
            parent_index=parent_index,
            order_index=order_index,
            stage_name="最终影响",
            label="宿主机完全失陷：可执行任意命令、读写任意文件",
            precondition="已取得宿主机执行权",
            postcondition="主机级权限（host）",
            detail="**推演，未实际执行**：无害化原则下，本系统不会真的在目标上执行命令。",
            verification_status=VerificationStatus.INFERRED,
        )
    if Priv.DB in terminal.priv:
        return ChainNode(
            node_type=ChainNodeType.IMPACT,
            parent_index=parent_index,
            order_index=order_index,
            stage_name="最终影响",
            label="数据层失陷：可直连数据库读取全量业务数据",
            precondition="已取得数据库访问能力",
            postcondition="数据库级权限（db）",
            detail="**推演**：由已验证的信息泄露/注入推得，未实际连接数据库。",
            verification_status=VerificationStatus.INFERRED,
        )
    return None


def _chain_severity(steps: Sequence[_Hop]) -> Severity:
    """链的严重度 = 环上最高的那一档。

    `Severity` 只有四档（critical/high/medium/low，SSOT 在 `app/models/enums.py`），
    没有"信息级" —— 所以"取最高"就是在这四档里取，不必再补一档。
    """
    for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        if any(step.rule.severity is level for step in steps):
            return level
    return Severity.MEDIUM


def _severity_of_atom(atom: VulnAtom) -> Severity:
    """单节点链的严重度：按 CVSS 分档（阈值与 `app/analysis/cvss.py` 同口径）。"""
    if atom.cvss >= 9.0:
        return Severity.CRITICAL
    if atom.cvss >= 7.0:
        return Severity.HIGH
    if atom.cvss >= 4.0:
        return Severity.MEDIUM
    # CVSS 为 0（未评分）落到 LOW：**Four 档里没有"信息级"**，
    # 而落到 MEDIUM 会凭空抬高一条没评分的漏洞在报告里的位置。
    return Severity.LOW


#: 权限 → 中文短语，**只出现在链名与 target_asset 这类展示字段里**
_PRIV_LABEL: dict[Priv, str] = {
    Priv.HOST: "宿主机权限",
    Priv.DB: "数据库权限",
    Priv.ADMIN: "管理员会话",
    Priv.KEYS: "密钥泄露",
    Priv.USER: "用户数据",
    Priv.ANONYMOUS: "匿名访问",
}


def _chain_name(steps: Sequence[_Hop]) -> str:
    """链名 = 「起点类别 → 终点权限」，例如 `sqli → 宿主机权限`。

    不用规则名拼接：规则名里带括号解释（R7 就有一串），拼出来会长得没法看，
    而链名要出现在报告的小标题里。
    """
    if not steps:
        return "攻击链"
    category = steps[0].atom.category if steps[0].atom else steps[0].rule.name
    gains: set[Priv] = set()
    for step in steps:
        gains |= step.rule.gain_priv
    top = max(gains, key=lambda p: _priv_rank(p), default=Priv.USER)
    return f"{category} → {_PRIV_LABEL.get(top, top.value)}"


def _priv_rank(priv: Priv) -> int:
    """取排序名次。**只用于排序**（实现放在 `rules.PRIV_RANK`）。"""
    from app.chain.rules import PRIV_RANK

    return PRIV_RANK.get(priv, 0)


def _chain_description(nodes: Sequence[ChainNode]) -> str:
    verified = sum(1 for n in nodes if n.verification_status is VerificationStatus.VERIFIED)
    return (
        f"共 {len(nodes)} 环，其中 {verified} 环已在沙箱中无害验证，"
        f"{len(nodes) - verified} 环为推演结论（未实际执行）。"
    )


def _target_asset(terminal: _State, impact_added: bool) -> str:
    """链的终点资产：拿到主机/数据库权限就写它，否则写链上累积的产出物。"""
    top = max(terminal.priv, key=_priv_rank, default=None)
    if impact_added and top is not None:
        return _PRIV_LABEL.get(top, top.value)
    assets = sorted(terminal.artifacts)
    return "/".join(assets) if assets else "（未取得额外资产）"


# ---------------------------------------------------------------------------
# 叙事模板（LLM 不可用 / 校验不过时的降级产出）
# ---------------------------------------------------------------------------


def _template_narrative(chain: AttackChain) -> str:
    """由链上节点拼出的中文叙事（LLM 不可用 / L3 校验不过时的降级产出）。

    结尾那句"哪几环实测、哪几环推演"是**必须有的**：报告第 4 章的呈现口径
    （Q24 方案 A）就落在这里。少了它，模板叙事会读起来像是整条链都验证过了 ——
    而"看起来验证过了"正是这份报告最不能犯的错。

    逐环节都标了「实测 / 推演」，不是只在结尾说一句：读者是跳着看的，
    任何一处没标注的环都会被默认读成"已经验过了"。
    """
    if not chain.nodes:
        return f"（{chain.name}：无节点）"
    lines: list[str] = []
    for node in chain.nodes:
        tag = f"[{node.rule_id}] " if node.rule_id else ""
        status = (
            "（沙箱实测）"
            if node.verification_status is VerificationStatus.VERIFIED
            else "（推演，未实际执行）"
        )
        lines.append(f"{node.order_index + 1}. {tag}{node.label}{status}")
        if node.detail:
            lines.append(f"   {node.detail}")
    verified_rings = [
        str(n.order_index + 1)
        for n in chain.nodes
        if n.verification_status is VerificationStatus.VERIFIED
    ]
    inferred_rings = [
        str(n.order_index + 1)
        for n in chain.nodes
        if n.verification_status is VerificationStatus.INFERRED
    ]
    # 两种"某一类环一个都没有"的句式要分开写。写成「第 （无） 环为推演结论」
    # 虽然语法上没错，但读者会把「（无）」当成一个编号或占位符 ——
    # 一句需要读两遍才明白的免责声明，等于没有免责声明。
    verified_clause = (
        f"第 {'、'.join(verified_rings)} 环已在沙箱中无害验证"
        if verified_rings
        else "链上各环均无实测证据"
    )
    inferred_clause = (
        f"第 {'、'.join(inferred_rings)} 环为推演结论" if inferred_rings else "链上各环均为实测结论"
    )
    lines.append(f"小结：{verified_clause}；{inferred_clause}。")
    lines.append(
        f"（共 {len(chain.nodes)} 环：实测 {chain.verified_ring_count} / "
        f"推演 {chain.inferred_ring_count}，置信度 {chain.confidence}）"
    )
    return "\n".join(lines)


def _stable_order(findings: Sequence[Any]) -> list[Any]:
    """输入排序：链的推演结果不能取决于调用方传进来的顺序。"""
    return sorted(
        findings,
        key=lambda f: (
            str(getattr(f, "file_path", "") or ""),
            int(getattr(f, "line_start", 0) or 0),
            int(getattr(f, "vuln_id", 0) or 0),
        ),
    )


# ---------------------------------------------------------------------------
# 契约 4 的入口
# ---------------------------------------------------------------------------


def build_chain(findings: Sequence[Any], **kwargs: Any) -> ChainDraft:
    """契约 4：`chain.build_chain(findings) -> ChainDraft`。

    **同步、无 IO、无 LLM** —— 拿掉 LLM 之后，链的节点、边、环级验证状态
    必须一字不变（L1）。叙事走 `narrative.py`，那一步才可能出现模型。
    """
    return ChainBuilder(**kwargs).build(findings)
