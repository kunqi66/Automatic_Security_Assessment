"""认证与授权依赖（需求 2.5.2）。

**安全红线 1 的落地**：用户身份**一律从 JWT 解析后回库重取**，
绝不采用客户端传参里的任何 `user_context` / `role`。
把 `role` 放进 token 只是为了少查一次库，**判定依据始终是数据库里的当前角色** ——
否则角色被降级或停用后，旧 token 就成了永久后门。
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.security import decode_access_token
from app.db.session import get_session
from app.models.enums import UserRole
from app.models.user import User

# auto_error=False：我们自己抛 401，才能带上统一错误载荷与 remediation
_bearer = HTTPBearer(auto_error=False, description="Bearer <access_token>")


class Permission(StrEnum):
    """权限点。

    **只读权限三角色共有**：需求 2.5.2 给每条角色描述的都是「能看到什么」，
    严格按字面解释会让管理员看不到任何页面 —— 那是需求的疏漏，不是设计意图。
    **写权限则严格按需求授予**，一个字都不多给。
    """

    # --- 只读（三角色共有）---
    PROJECT_VIEW = "project:view"
    ASSESSMENT_VIEW = "assessment:view"
    VULN_VIEW = "vuln:view"
    REPORT_VIEW = "report:view"

    # --- 写（严格按需求 2.5.2 授权）---
    #: 安全工程师：「创建评估任务」
    ASSESSMENT_CREATE = "assessment:create"
    #: 安全工程师：「核对漏洞验证证据」—— 人工复核是核对的一部分
    VULN_REVIEW = "vuln:review"
    #: 安全工程师：「审核修复建议并导出报告」
    REPORT_EXPORT = "report:export"
    #: 研发人员：「采纳 AI 修复补丁」
    PATCH_ACCEPT = "patch:accept"
    #: 系统管理员：「维护安全沙箱容器镜像、配置超时时间与资源配额」
    SANDBOX_MANAGE = "sandbox:manage"
    #: 系统管理员：「管理大语言模型推理参数」
    LLM_MANAGE = "llm:manage"
    #: 系统管理员：「系统审计日志」
    AUDIT_VIEW = "audit:view"


_READ_ONLY = frozenset(
    {
        Permission.PROJECT_VIEW,
        Permission.ASSESSMENT_VIEW,
        Permission.VULN_VIEW,
        Permission.REPORT_VIEW,
    }
)

#: 角色 → 权限。需求 2.5.2 三条职责逐条映射，不做任何自行扩张。
ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.SECURITY_ENGINEER: _READ_ONLY
    | {
        Permission.ASSESSMENT_CREATE,  # 创建评估任务
        Permission.VULN_REVIEW,  # 核对漏洞验证证据
        Permission.REPORT_EXPORT,  # 审核修复建议并导出报告
    },
    UserRole.DEVELOPER: _READ_ONLY
    | {
        Permission.PATCH_ACCEPT,  # 采纳 AI 修复补丁
    },
    UserRole.ADMIN: _READ_ONLY
    | {
        Permission.SANDBOX_MANAGE,
        Permission.LLM_MANAGE,
        Permission.AUDIT_VIEW,
    },
}


def permissions_for(role: UserRole) -> frozenset[Permission]:
    """角色 → 权限集合。

    **唯一的访问器**：`ROLE_PERMISSIONS` 只准从这里读，
    这样「鉴权」和「把权限告诉前端」用的是同一份，不会各自演化。

    未知角色返回空集而不是抛异常 —— 数据库里冒出一个没见过的 role 时，
    后果应该是「这个人什么都干不了」，而不是「所有接口 500」。
    """
    return ROLE_PERMISSIONS.get(role, frozenset())


def _role_label(role: UserRole) -> str:
    return {
        UserRole.SECURITY_ENGINEER: "安全工程师",
        UserRole.DEVELOPER: "研发人员",
        UserRole.ADMIN: "系统管理员",
    }[role]


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> User:
    if credentials is None or not credentials.credentials:
        raise UnauthorizedError("缺少访问令牌", remediation="请先登录")

    payload = decode_access_token(credentials.credentials)

    try:
        user_id = int(payload.sub)
    except ValueError as exc:
        raise UnauthorizedError("访问令牌载荷异常", remediation="请重新登录") from exc

    user = await session.get(User, user_id)
    if user is None:
        # 用户已被删除，但 token 还没过期 —— 必须在这里拦住
        raise UnauthorizedError("账号不存在或已被停用", remediation="请联系管理员")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
DBSession = Annotated[AsyncSession, Depends(get_session)]


def require(permission: Permission) -> Callable[..., Awaitable[User]]:
    """路由级功能权限校验工厂。

    **每个写接口都要独立挂它**，不得依赖前端隐藏按钮（安全红线 7）——
    前端隐藏只是不显示入口，直接调接口照样能过。
    """

    async def _guard(user: CurrentUser) -> User:
        if permission not in permissions_for(user.role):
            raise ForbiddenError(
                f"当前角色（{_role_label(user.role)}）无权执行该操作",
                remediation=f"该操作需要权限 {permission.value}，请联系管理员调整角色",
            )
        return user

    return _guard


async def get_optional_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> User | None:
    """可选认证。SSE 端点用 —— 浏览器 `EventSource` 不能自定义头，
    需要允许从 query 传 token；这条路径单独在 SSE 路由里处理，不混进正常鉴权。"""
    if credentials is None:
        return None
    try:
        return await get_current_user(credentials, session)
    except UnauthorizedError:
        return None


def request_ip(request: Request) -> str | None:
    return request.client.host if request.client else None
