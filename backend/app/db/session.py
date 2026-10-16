"""异步数据库会话。

总纲 §8.2 的原则是「**存储类依赖不可降级**」：MySQL 连不上时**启动即失败并快速退出**，
绝不静默降级成一个假装能跑的服务。这里的启动自检（`verify_connection`）就是这个意思。
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.core.exceptions import DependencyDownError
from app.core.logging import get_logger

logger = get_logger(__name__)

engine: AsyncEngine = create_async_engine(
    settings.mysql_dsn,
    echo=settings.mysql_echo,
    pool_size=settings.mysql_pool_size,
    max_overflow=settings.mysql_pool_size,
    # 连接被中间件/服务端悄悄掐断后，拿出来先用一下，避免把死连接交给请求
    pool_pre_ping=True,
    # MySQL 默认 wait_timeout=28800s；回收周期取短一些，免得踩到服务端先行关闭
    pool_recycle=1800,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    # 关掉 expire_on_commit：提交后再读属性会触发一次隐式 IO，
    # 在 async 场景里这不是「慢一点」，而是直接抛 MissingGreenlet。
    expire_on_commit=False,
    autoflush=False,
)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI 依赖：每个请求一个会话，请求结束自动关闭。

    **不在依赖里 commit**：提交点由业务代码显式控制（总纲 §9.3 —— 阶段边界才是提交点），
    隐式提交会让「部分成功」的中间态落库，破坏断点续跑。
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def verify_connection() -> None:
    """启动自检：连不上就抛，让应用起不来。"""
    from sqlalchemy import text

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 —— 任何连接层异常都归为依赖不可用
        raise DependencyDownError(
            f"无法连接 MySQL（{settings.mysql_host}:{settings.mysql_port}/"
            f"{settings.mysql_database}）",
            remediation="检查数据库连通性、账号权限，以及该 database 是否已创建",
        ) from exc
    logger.info(
        "MySQL 连接正常：%s:%s/%s",
        settings.mysql_host,
        settings.mysql_port,
        settings.mysql_database,
    )


async def dispose_engine() -> None:
    await engine.dispose()
