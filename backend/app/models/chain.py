"""攻击链与链上节点（B5 推演产物）。

**关键设计：不建边表。** DAG 的边完全由 `parent_node_id` 自引用派生 ——
节点数远少于边数，一张自引用表就够，且天然不会出现「边指向不存在的节点」。
"""

from __future__ import annotations

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import ChainNodeType, Severity, VerificationStatus, sa_enum


class AttackChain(Base, TimestampMixin):
    __tablename__ = "attack_chains"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity | None] = mapped_column(sa_enum(Severity), nullable=True)
    entry_point: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_asset: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    #: 链叙事，LLM 生成；降级时用模板。**表达层，不影响图结构**（总纲 §8.5 L1）
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)

    nodes: Mapped[list[AttackChainNode]] = relationship(
        back_populates="chain",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="AttackChainNode.order_index",
    )


class AttackChainNode(Base):
    __tablename__ = "attack_chain_nodes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(
        ForeignKey("attack_chains.id", ondelete="CASCADE"), nullable=False, index=True
    )

    node_type: Mapped[ChainNodeType] = mapped_column(sa_enum(ChainNodeType), nullable=False)
    vuln_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True
    )

    #: DAG 的边由此派生。**自引用，不单独建边表。**
    parent_node_id: Mapped[int | None] = mapped_column(
        ForeignKey("attack_chain_nodes.id", ondelete="SET NULL"), nullable=True
    )

    order_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stage_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    precondition: Mapped[str | None] = mapped_column(Text, nullable=True)
    postcondition: Mapped[str | None] = mapped_column(Text, nullable=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: 命中的推演规则编号 R1–R8 —— 让「这条边是怎么推出来的」可被追问、可被复查
    rule_id: Mapped[str | None] = mapped_column(String(16), nullable=True)

    #: ★ Q24 定案：标注该环是「沙箱已验证」还是「推演推断」。
    #: 链的最后一环通常是 inferred —— 扫描器可以推断「这里能打穿」，但不该自己打穿。
    verification_status: Mapped[VerificationStatus] = mapped_column(
        sa_enum(VerificationStatus), nullable=False, default=VerificationStatus.INFERRED
    )

    chain: Mapped[AttackChain] = relationship(back_populates="nodes")
