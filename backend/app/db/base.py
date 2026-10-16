"""SQLAlchemy 声明式基类。

**命名约定是必须的**：不显式约定时，MySQL 会自动给索引/约束起名，而 Alembic
autogenerate 依赖名字比对来判断「约束是否变化」。名字随机生成的结果是每次
`alembic revision --autogenerate` 都产出一堆「删了又建」的空迁移。
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, MetaData, func, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    #: 🔴 **必须显式设 True，不能用默认的 "auto"。**
    #:
    #: `TimestampMixin` 的时间戳都是 `server_default`（值由数据库生成），
    #: 而 MySQL **不支持 `INSERT ... RETURNING`**。SQLAlchemy 2.0 的
    #: `eager_defaults` 默认是 `"auto"` = 「后端支持 RETURNING 才取回」——
    #: 于是在 MySQL 上，INSERT 之后 `created_at` / `updated_at` 处于
    #: **未加载**状态。
    #:
    #: 后果不是「值是 None」，而是更隐蔽的：下一次访问这两个属性会触发
    #: 一次**隐式 SELECT**。在同步代码里那只是一次多余查询，但在
    #: `async` 里它发生在 greenlet 之外，直接抛
    #: `MissingGreenlet: greenlet_spawn has not been called`。
    #:
    #: 实际症状（2026-10-16 实测）：`POST /api/v1/projects` 返回 500，
    #: 栈顶是 `ProjectOut.model_validate(project)` —— **报错位置与病因
    #: 隔了三层**（序列化 ← 属性未加载 ← MySQL 无 RETURNING），
    #: 而单测结构上碰不到它：要先真连一个 MySQL、真插一行、再序列化。
    #:
    #: 代价是每次 INSERT 多一条 `SELECT`（在 flush 内、greenlet 里，
    #: 是合法 IO），换掉上述整类 bug。
    __mapper_args__ = {"eager_defaults": True}


#: DDL 里的默认值表达式。
#:
#: ⚠️ **必须用 `text("CURRENT_TIMESTAMP")`，不能用 `func.now()`**：
#: SQLAlchemy 的 MySQL 方言会把函数默认值渲染成 `DEFAULT (now())` ——
#: 那是 MySQL 8.0.13 才引入的「表达式默认值」语法，低版本直接建表失败，
#: 而且是不可移植的写法。`CURRENT_TIMESTAMP` 在 MySQL 与 SQLite 上都是标准形式。
#:
#: 还有第二个理由：迁移文件里的 `server_default` 必须和模型这里**逐字一致**，
#: 否则 `compare_server_default=True` 会让每次 autogenerate 都吐出一份
#: 「把默认值改了又改回去」的空迁移。
#: 公开名（不带下划线）是刻意的：独立定义时间戳列的模型要 import 它。
#: 只要有一个地方手写 `func.now()`，autogenerate 就会永远吐出一份
#: 「把默认值改来改去」的空迁移，而且它看起来完全像是真的变更。
DDL_NOW = text("CURRENT_TIMESTAMP")


class TimestampMixin:
    """创建/更新时间。

    用数据库的 `CURRENT_TIMESTAMP` 而不是 Python 的 `datetime.now()`：
    多个进程（API + worker）写同一张表时，应用侧时钟不一致会让「谁先谁后」失真。
    """

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=DDL_NOW, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=DDL_NOW,
        # onupdate 只影响 SQLAlchemy 发的 UPDATE 语句，不进 DDL，
        # 所以这里用 func.now() 无妨 —— 它同样由数据库求值，不是 Python 时钟。
        onupdate=func.now(),
        nullable=False,
    )
