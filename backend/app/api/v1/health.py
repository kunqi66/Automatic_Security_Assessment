"""存活探针。

**刻意不带鉴权**：它只回答「进程起来了吗、能不能连库」，不返回任何业务数据。
启动脚本靠它判断「端口开了」还是「真的可用了」—— 端口占用 ≠ 应用就绪。
"""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.api.deps import DBSession
from app.core.config import settings

router = APIRouter(tags=["健康检查"])


@router.get("/health", summary="存活与依赖探针")
async def health(session: DBSession) -> dict[str, object]:
    await session.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "database": "up",
        # 只报告「配没配 key」，**绝不回显密钥本身**
        "llm_available": settings.llm_available,
    }
