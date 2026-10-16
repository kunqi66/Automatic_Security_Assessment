"""口令哈希与 JWT。

对应 PRD §8.3：JWT(HS256) + bcrypt 加盐哈希，secret 走环境变量。

**关于 bcrypt 的 72 字节上限**：bcrypt 只看前 72 字节，超长口令的尾部会被静默丢弃
（bcrypt>=4 干脆抛 ValueError）。这里先做一次 SHA-256 再 base64，把任意长度口令
压成固定 44 字节，既避开上限，也避开「两个长口令前 72 字节相同就等价」这个坑。
这就是常说的 bcrypt-sha256 方案。
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt
from pydantic import BaseModel

from app.core.config import settings
from app.core.exceptions import UnauthorizedError


def _prehash(plain_password: str) -> bytes:
    digest = hashlib.sha256(plain_password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(_prehash(plain_password), bcrypt.gensalt()).decode("ascii")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """校验口令。

    哈希串损坏时返回 False 而不是抛异常 —— 调用方只关心「能不能登进来」，
    让坏数据表现为登录失败、并留下日志，比抛 500 更不泄露信息。
    """
    try:
        return bcrypt.checkpw(_prehash(plain_password), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


class TokenPayload(BaseModel):
    """JWT 载荷。

    `role` 放进 token 是为了免去每个请求都查一次库；**但权限判定不能只信它** ——
    角色被降级后旧 token 仍然有效，因此写接口一律以数据库里的当前角色为准
    （见 `api/deps.py` 的 `require_role`）。
    """

    sub: str  # user_id（字符串，JWT 规范要求 sub 是字符串）
    username: str
    role: str
    exp: int


def create_access_token(*, user_id: int, username: str, role: str) -> tuple[str, int]:
    """返回 (token, 有效期秒数)。前端拿后者做本地过期提示。"""
    expires_in = settings.jwt_expire_minutes * 60
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires_in


def decode_access_token(token: str) -> TokenPayload:
    """解析并校验 token。任何失败都归一为 401，不向客户端区分「过期」与「签名错」。"""
    try:
        raw = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.ExpiredSignatureError as exc:
        raise UnauthorizedError(
            "登录已过期，请重新登录", remediation="重新登录以获取新的访问令牌"
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise UnauthorizedError("访问令牌无效", remediation="请重新登录") from exc

    try:
        return TokenPayload.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 —— 载荷结构不对同样只是「凭证不可用」
        raise UnauthorizedError("访问令牌载荷不完整", remediation="请重新登录") from exc
