"""攻击链推演的数据契约（B5 设计 §3.3 的 (B) 部分 + §4.5/§4.6）。

## 三处与设计文档的**有意偏离**（都在这里写清楚，免得被当成抄漏了）

1. **`Priv` 是偏序集合，不是等级。** 设计 §4.5 说得很对：`admin`（管理员会话）
   与 `db`（数据库口令）不可比。所以匹配用的是集合包含（`⊆`），
   任何"哪条路更厉害"的排序都只发生在**展示层**（`PRIV_RANK`，见 `rules.py`），
   且被显式标注为"仅用于排序"。把排序混进匹配会让 R2 与 R5 的判定出错。

2. **`ChainNode.node_type` 用 `ChainNodeType` 而不是设计 §3.3 写的
   `vuln|asset|goal`。** ORM（`app/models/chain.py`）已经冻结了六值枚举
   （`entry/vuln/credential/shell/host/impact`），并给了理由：F4 要按它着色。
   枚举值是 SSOT，这里照抄。

3. **`ChainNode.parent_index` 不叫 `parent_node_id`。** 推演发生时，节点还没有
   数据库主键（`parent_node_id` 是自引用外键）。草稿里存的是**节点数组下标**，
   由 B3 落库时按下标顺序插入并回填真实 id —— 存一个"未来的 id"是存不出来的。
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from app.models.enums import ChainNodeType, Severity, VerificationStatus


class Priv(StrEnum):
    """权限三轴偏序集合（B5 设计 §4.5）。

    身份轴：`anonymous < user < admin`；
    数据轴：`self < all_users < db`；
    主机轴：`host`；密钥轴：`keys`。

    **三条轴不可比**：管理员会话不能推出数据库口令，反之亦然。用集合而不是
    分值，就是为了让"不可比"这件事在类型上成立。
    """

    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"
    DB = "db"
    KEYS = "keys"
    HOST = "host"


class CategoryMode(StrEnum):
    """`require_categories` 的匹配模式（见 `ChainRule.category_mode` 的注释）。"""

    ALL = "all"
    ANY = "any"


def as_priv_set(values: object) -> frozenset[Priv]:
    """把字符串/枚举集合归一成 `frozenset[Priv]`，非法值直接丢弃。"""
    if values is None:
        return frozenset()
    items = values if isinstance(values, (set, frozenset, list, tuple)) else [values]
    out: set[Priv] = set()
    for item in items:
        try:
            out.add(item if isinstance(item, Priv) else Priv(str(item)))
        except ValueError:
            continue
    return frozenset(out)


class VulnAtom(BaseModel):
    """一个已验证漏洞在权限图里的"原子"（B5 设计 §4.5）。

    `requires` / `gains` / `assets` / `produces` 四元组**由类别静态映射表给出**，
    不经 LLM、不做推断 —— 这是整条链可复现的前提。
    """

    vuln_id: int
    vuln_code: str | None = None
    category: str
    requires: frozenset[Priv] = frozenset()
    gains: frozenset[Priv] = frozenset()
    assets: frozenset[str] = frozenset()
    produces: frozenset[str] = frozenset()
    cvss: float = 0.0
    verified: bool = False
    file_path: str = ""


class ChainRule(BaseModel):
    """R1–R8：**声明式数据，不是代码分支**（B5 设计 §4.6）。

    新增一条规则 = 往 `rules.CHAIN_RULES` 里追加一个实例，匹配器与构建器
    一个字都不用改。这是 `PRD §7.4`「规则引擎，不是 if-else 硬编码」的落点。
    """

    rule_id: str
    name: str
    #: 前置条件（四元组，全部满足才算命中）
    require_priv: frozenset[Priv] = frozenset()
    require_categories: frozenset[str] = frozenset()
    #: `require_categories` 怎么读：`all` = 每个类别都要有一个实例；
    #: `any` = 任一个类别有实例即可。
    #:
    #: 为什么需要这个开关：R4「IDOR → 敏感数据泄露」的落点是**横向读取**，
    #: 越权对象引用（idor）与未授权接口（unauth_access）**任一**都能走到那一步 ——
    #: 而它的规则名里只有一个箭头。若按"集合里的类别全都要"读，R4 会静默地
    #: 要求两者同时存在，表现为"明明有 IDOR 却没有这条边"，而规则表上完全看不出来。
    #: R3/R7 的名字里写着「+」（管理员**加**上传点、未授权访问**加**上传点），
    #: 那两个才是真正的 `all`。
    category_mode: CategoryMode = CategoryMode.ALL
    require_artifacts: frozenset[str] = frozenset()
    require_assets: frozenset[str] = frozenset()
    #: 出口
    gain_priv: frozenset[Priv] = frozenset()
    exit_artifact: str = ""
    severity: Severity = Severity.MEDIUM
    #: 该环在链上落成什么类型的节点（六值枚举，见模块头第 2 条）
    node_type: ChainNodeType = ChainNodeType.VULN
    #: 支撑这条规则的漏洞类别（`None` 表示该环**没有任何实测依据**，
    #: 只能由上游产出物推得，例如 R2 的"用凭证登录后台"）。
    backed_by_category: str | None = None
    #: **这一环的结论本身是不是推演**。True ⇒ 节点 `verification_status=inferred`。
    #:
    #: R3 / R7 是仅有的两个 True：它们从"上传点可达"推出"宿主机 RCE"，
    #: 而按无害化原则我们**不会真去传一个 WebShell 验证它**（B5 设计 §4.7）。
    #: 这个字段就是 Q24 方案 A 在数据层的落点。
    outcome_inferred: bool = False
    #: 中文模板：LLM 不可用时的叙事降级产出（`str.format` 的具名占位符）
    narrative_template: str = ""
    label_template: str = ""
    stage_name: str = ""
    precondition_template: str = ""
    postcondition_template: str = ""
    detail_template: str = ""


class ChainNode(BaseModel):
    """链上的一环（↔ `attack_chain_nodes`）。字段名与 ORM 逐一对应。"""

    node_type: ChainNodeType
    vuln_id: int | None = None
    #: 漏洞编码（`VULN-2026-0001`）。推演阶段可能还没有（B3 落库时才生成），
    #: 所以可空 —— 但它是叙事 L3 校验（节点集合比对）的锚点，有就要带上。
    vuln_code: str | None = None
    #: 父节点在 `AttackChain.nodes` 里的下标；`None` 表示链首（DAG 的边由此派生）
    parent_index: int | None = None
    order_index: int = 0
    stage_name: str = ""
    label: str = ""
    precondition: str = ""
    postcondition: str = ""
    detail: str = ""
    #: 命中的规则编号 —— 让"这条边是怎么推出来的"可被追问、可被复查
    rule_id: str | None = None
    #: Q24 方案 A：这一环是实测出来的，还是推演出来的（**每环独立标注**）
    verification_status: VerificationStatus = VerificationStatus.INFERRED


class AttackChain(BaseModel):
    """一条攻击链（↔ `attack_chains`）。"""

    chain_id: str
    name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    entry_point: str = ""
    target_asset: str = ""
    #: 可达性置信度：由"链上有多少环是实测的"确定性算出（见 builder），
    #: **不是模型给的**，也不是拍脑袋给的。
    confidence: float = 0.0
    narrative: str = ""
    #: `llm` 或 `template` —— 报告与前端据此标注"模板生成"（契约 3）
    narrative_source: str = "template"
    #: 链上命中的规则编号序列，如 `["R1", "R2", "R3"]`
    rule_ids: list[str] = Field(default_factory=list)
    nodes: list[ChainNode] = Field(default_factory=list)

    @property
    def vuln_codes(self) -> frozenset[str]:
        """链上出现过的漏洞编码集合 —— **叙事 L3 校验的白名单**（设计 §4.8）。"""
        return frozenset(n.vuln_code for n in self.nodes if n.vuln_code)

    @property
    def verified_ring_count(self) -> int:
        return sum(1 for n in self.nodes if n.verification_status is VerificationStatus.VERIFIED)

    @property
    def inferred_ring_count(self) -> int:
        return sum(1 for n in self.nodes if n.verification_status is VerificationStatus.INFERRED)


class ChainDraft(BaseModel):
    """攻击链推演的完整产出（契约 4：`chain.build_chain(findings) -> ChainDraft`）。"""

    chains: list[AttackChain] = Field(default_factory=list)
    #: 参与推演的已验证漏洞原子（供报告"本次有哪些前置条件已证实"一节使用）
    atoms: list[VulnAtom] = Field(default_factory=list)
    #: 被跳过的 finding 数（未验证的、或类型无原子映射的）
    skipped_finding_count: int = 0
    #: 深度上限剪枝等情况的说明，为空表示未发生
    note: str = ""

    @property
    def chain_count(self) -> int:
        return len(self.chains)
