"""建一个登录账号 —— 首次部署的**唯一**入口。

    uv run python -m app.scripts.create_user --username admin --role admin

## 为什么必须存在这个东西

系统的每条接口都要求登录（`app/api/deps.py` 的 `require_user`），而**没有任何
代码会创建 `User` 行** —— 没有注册接口，没有种子数据，`provision_app.sh` 也不建。
于是一个刚迁移完的库是**登不进去的**：密码再对也没用，因为根本没有账号。

这不是「少个便利功能」：没有它，整套系统在真实环境里跑不起来，
而症状是「登录返回 401」，看起来像密码错了。

## 口令怎么传

**只从终端交互输入**（`getpass`），不走 `--password` 参数。理由是参数会进两处
不该进的地方：shell 历史，以及 `ps aux` 的进程列表（同机器上任何用户都看得到）。
需要非交互（比如自动化部署）就用 `--password-stdin`，从标准输入读一行 ——
那种方式不会留下上述痕迹。
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import select

from app.core.logging import get_logger, setup_logging
from app.core.security import hash_password
from app.models.enums import UserRole
from app.models.user import User

logger = get_logger(__name__)

#: 口令长度下限。取 12 而不是 8：这套系统能起容器、能读任意上传的源码，
#: 账号被撞开的代价远高于一个普通后台。上限 256 与 `LoginRequest` 保持一致。
_MIN_PASSWORD_LEN = 12
_MAX_PASSWORD_LEN = 256


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.create_user",
        description="创建一个登录账号（本系统没有注册接口，这是唯一的建号方式）",
    )
    parser.add_argument("--username", required=True, help="登录名，1-64 字符")
    parser.add_argument(
        "--role",
        default=UserRole.SECURITY_ENGINEER.value,
        choices=[r.value for r in UserRole],
        help="角色（默认 security_engineer）",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="从标准输入读一行口令，而不是交互式输入（给自动化用）",
    )
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="账号已存在时改写它的口令，而不是报错退出",
    )
    return parser.parse_args(argv)


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        line = sys.stdin.readline()
        if not line:
            raise SystemExit("标准输入里没有读到口令")
        return line.rstrip("\n\r")
    first = getpass.getpass("口令：")
    second = getpass.getpass("再输一次：")
    if first != second:
        # 两次不一致就退出，而不是「以第一次为准」—— 打错一个字符就得到一个
        # 自己也不知道的账号，而当时的提示会被当成「只是确认一下」。
        raise SystemExit("两次输入不一致，未创建任何账号")
    return first


async def _run(args: argparse.Namespace) -> int:
    from app.db.session import AsyncSessionLocal, dispose_engine

    username = args.username.strip()
    if not username or len(username) > 64:
        raise SystemExit("用户名必须是 1-64 个字符")

    password = _read_password(args.password_stdin)
    if not _MIN_PASSWORD_LEN <= len(password) <= _MAX_PASSWORD_LEN:
        raise SystemExit(f"口令长度需在 {_MIN_PASSWORD_LEN}-{_MAX_PASSWORD_LEN} 之间")

    try:
        async with AsyncSessionLocal() as session:
            existing = await session.scalar(select(User).where(User.username == username))

            if existing is not None and not args.reset_password:
                # **不静默覆盖**：一个「重跑部署脚本就把管理员口令改了」的行为，
                # 会在某次例行操作后把所有人锁在门外，而且没人会怀疑到那一步。
                raise SystemExit(f"账号 {username!r} 已存在。要改写口令请显式加 --reset-password")

            if existing is not None:
                existing.password_hash = hash_password(password)
                existing.role = UserRole(args.role)
                action = "已更新口令与角色"
            else:
                session.add(
                    User(
                        username=username,
                        password_hash=hash_password(password),
                        role=UserRole(args.role),
                    )
                )
                action = "已创建"

            # 这是**一次性运维动作**，不是流水线里的阶段 —— 不适用「阶段边界才提交」
            # 那条规则（T4），那个规则管的是 Agent 不许自己 commit。
            await session.commit()
    finally:
        await dispose_engine()

    # 只回显用户名与角色，**绝不回显口令**
    print(f"{action}：{username}（{args.role}）")
    return 0


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    args = _parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except SystemExit as exc:
        # argparse 与上面各处都用 SystemExit 表达「用户输入有问题」，
        # 这里把它转成退出码，好让 shell 能判断成败。
        if exc.code not in (0, None):
            print(f"错误：{exc.code}", file=sys.stderr)
        return 1 if exc.code not in (0, None) else 0


if __name__ == "__main__":
    raise SystemExit(main())
