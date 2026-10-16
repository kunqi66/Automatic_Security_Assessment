"""攻击链查询（L1 接口层）。

**返回的是扁平的节点列表，不是嵌套的树**。前端拿到 `chain_id` +
`parent_node_id` 自己构图 —— 服务端不做图布局，那是渲染的事。
嵌套结构还会带来一个服务端问题：节点的父子关系在 `builder` 里已经定了，
再套一层只会让人以为「顺序是接口决定的」，而实际上是 B5 决定的。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.api.deps import DBSession, Permission, require
from app.core.exceptions import NotFoundError
from app.models.assessment import Assessment
from app.models.chain import AttackChain, AttackChainNode
from app.models.user import User
from app.schemas.chain import AttackChainNodeOut

router = APIRouter(tags=["攻击链"])

Viewer = Annotated[User, Depends(require(Permission.ASSESSMENT_VIEW))]


@router.get(
    "/assessments/{assessment_id}/chains",
    response_model=list[AttackChainNodeOut],
    summary="攻击链节点（前端据此自建图）",
)
async def list_chain_nodes(
    assessment_id: int, session: DBSession, _: Viewer
) -> list[AttackChainNodeOut]:
    if await session.get(Assessment, assessment_id) is None:
        raise NotFoundError(f"评估 {assessment_id} 不存在")

    rows = (
        (
            await session.execute(
                select(AttackChainNode)
                .join(AttackChain, AttackChain.id == AttackChainNode.chain_id)
                .where(AttackChain.assessment_id == assessment_id)
                # 排序是**渲染顺序**，不是「重要程度」：前端按这个顺序逐跳展开。
                # 按 (链, 层内序号) 排，多条链时才不会交错在一起。
                .order_by(
                    AttackChain.severity.desc(),
                    AttackChainNode.chain_id.asc(),
                    AttackChainNode.order_index.asc(),
                )
            )
        )
        .scalars()
        .all()
    )

    return [AttackChainNodeOut.model_validate(row) for row in rows]
