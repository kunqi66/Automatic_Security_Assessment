"""Alembic 环境。

两个刻意的选择：

1. **连接串不写进 alembic.ini**，而是从 `app.core.config` 取。写两份的结果是
   「迁移跑在 A 库、应用连的是 B 库」，而这两件事都不会报错。

2. **不用 `config.set_main_option("sqlalchemy.url", ...)`**。ConfigParser 会对 `%`
   做插值，而 URL 编码后的口令里 `%` 很常见 —— 一旦命中，报的错是
   `InterpolationSyntaxError`，和数据库毫无关系，很难往这上面想。
   直接把 URL 交给 `create_async_engine` 就绕开了整个问题。
"""

from __future__ import annotations

import asyncio
from typing import Any

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import settings
from app.core.logging import setup_logging
from app.models import Base  # noqa: F401 —— 必须 import，否则 Base.metadata 是空的

target_metadata = Base.metadata


def _include_object(
    _object: Any, name: str | None, type_: str, _reflected: bool, _compare_to: Any
) -> bool:
    """忽略 Alembic 自己的版本表。"""
    return not (type_ == "table" and name == "alembic_version")


def _configure(connection: Connection | None = None, url: str | None = None) -> None:
    context.configure(
        connection=connection,
        url=url,
        target_metadata=target_metadata,
        include_object=_include_object,
        compare_type=True,  # 列类型变化也要生成迁移，否则改类型会被静默忽略
        compare_server_default=True,
        # 迁移脚本里渲染成 sa.Enum(...) 等抽象类型，由目标方言在真正执行时决定 DDL
        render_as_batch=False,
    )


def run_migrations_offline() -> None:
    _configure(url=settings.effective_dsn)
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    _configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    engine = create_async_engine(settings.effective_dsn, poolclass=pool.NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


setup_logging()
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
