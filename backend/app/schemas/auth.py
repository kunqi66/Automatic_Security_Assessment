"""认证相关 DTO。"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import UserRole
from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(ORMModel):
    """对外暴露的用户视图。

    ⚠️ **刻意不含 `password_hash`**：ORM 模型上没有做字段级隐藏，
    所以绝不能直接把 `User` 返回出去 —— 必须经这个 schema 过滤一次。
    """

    id: int
    username: str
    role: UserRole
    created_at: datetime

    #: 该角色拥有的功能权限码，如 `["assessment:create", "vuln:view"]`。
    #:
    #: 由 `api/deps.py` 的 `permissions_for()` 从 `ROLE_PERMISSIONS` 派生 ——
    #: **不是数据库列**，所以下面是 `default_factory` 而不是从 ORM 读
    #: （`User` 上没有这个属性，`model_validate` 也变不出来）。
    #:
    #: 类型写成 `list[str]` 而不是 `list[Permission]`：`Permission` 定义在
    #: `api/deps.py`，而 `schemas/` 是更低的层 —— 本项目所有 `schemas/*.py`
    #: 都只从 `app.models.enums` 取枚举，没有一个 import `api`，不该由这里破例。
    #: 何况 DTO 描述的就是**线上形状**，而权限码在线上就是字符串。
    #:
    #: **为什么要返回给前端**：前端要据此决定「新建评估」按钮显不显示。
    #: 若让它拿 `role` 自己映射一份，那份表就成了第二份实现 ——
    #: 后端调整权限后前端会**静默**分叉成「按钮在、点了 403」，
    #: 或者更糟：按钮没了，功能其实还能用。
    #: 只返回**本人的**权限，不泄露任何他人信息。
    permissions: list[str] = Field(default_factory=list)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 —— OAuth2 RFC 6749 规定的固定值，不是凭据
    #: 顺带返回用户信息，前端登录后不必再打一次 /auth/me
    user: UserOut
