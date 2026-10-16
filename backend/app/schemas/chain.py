"""攻击链 DTO（B5）。"""

from __future__ import annotations

from pydantic import field_validator

from app.models.enums import ChainNodeType, VerificationStatus
from app.schemas.common import ORMModel


class AttackChainNodeOut(ORMModel):
    """攻击链上的一个节点。

    ⚠️ **响应里没有独立的边数组**：DAG 的边由 `parent_node_id` 自引用派生。
    前端 `buildGraph()` 据此展开 —— 多返回一份边数组就等于让同一事实有两个来源，
    迟早会出现「节点变了边没变」。

    字段名一律照抄 PRD §6 的表列名（`chain_id` / `vuln_id`），**不做二次改名** ——
    「DTO 叫 vulnerability_id、列叫 vuln_id」这种映射是纯粹的翻译税，
    而且是字段错位最容易被藏住的地方。
    """

    id: int
    #: 所属攻击链。节点挂在**链**下而不是评估下 —— 一次评估可以推演出多条链
    chain_id: int
    parent_node_id: int | None
    node_type: ChainNodeType
    label: str
    detail: str
    #: `inferred` 表示该环是**推演结论而非实测结果**，报告必须声明它未实际执行（Q24 定案）
    verification_status: VerificationStatus
    #: 该节点坐实的漏洞；`credential` / `shell` / `host` / `impact` 这类节点为 null
    vuln_id: int | None
    #: 命中的推演规则编号 R1–R8，让「这条边怎么来的」可被追问
    rule_id: str | None

    @field_validator("detail", mode="before")
    @classmethod
    def _null_to_empty(cls, v: str | None) -> str:
        return v or ""
