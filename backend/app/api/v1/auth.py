"""认证接口（PRD §9）。"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
from sqlalchemy import select

from app.api.deps import CurrentUser, DBSession, permissions_for
from app.core.exceptions import UnauthorizedError
from app.core.logging import get_logger
from app.core.security import create_access_token, verify_password
from app.db.audit import record
from app.models.user import User
from app.schemas.auth import LoginRequest, LoginResponse, UserOut

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["认证"])


def _to_out(user: User) -> UserOut:
    """ORM 用户 → 对外视图，并补上 `permissions`。

    **必须在这里补**：`permissions` 不是列，`model_validate` 变不出来。
    两个接口都走这个函数，`/auth/me` 与登录返回的 `user` 才是同一份东西 ——
    否则前端会看到「刚登录时有权限、刷新一下没了」这种只能靠重启解释的现象。

    排序是为了让响应**稳定**：`ROLE_PERMISSIONS` 的底层是 `frozenset`，
    迭代顺序不保证跨进程一致，直接序列化会让响应体在两个进程间无谓地不同。
    """
    out = UserOut.model_validate(user)
    out.permissions = sorted(p.value for p in permissions_for(user.role))
    return out


@router.post("/login", response_model=LoginResponse, summary="登录")
async def login(payload: LoginRequest, session: DBSession) -> LoginResponse:
    """口令登录 → JWT。

    **用户名不存在与口令错误返回同一个错误**，不区分 ——
    区分开等于给攻击者一个「哪些用户名有效」的枚举接口。
    """
    user = (
        await session.execute(select(User).where(User.username == payload.username))
    ).scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.password_hash):
        logger.info("登录失败：username=%s", payload.username)
        raise UnauthorizedError("用户名或密码错误", remediation="请检查后重试")

    user.last_login_at = datetime.now()
    record(
        session,
        user=user,
        action="auth.login",
        target_type="user",
        target_id=user.id,
    )
    await session.commit()

    token, _expires_in = create_access_token(
        user_id=user.id, username=user.username, role=user.role.value
    )
    return LoginResponse(
        access_token=token,
        token_type="bearer",  # noqa: S106 —— OAuth2 的固定字段值，不是口令
        user=_to_out(user),
    )


@router.get("/me", response_model=UserOut, summary="当前用户")
async def me(user: CurrentUser) -> UserOut:
    return _to_out(user)
