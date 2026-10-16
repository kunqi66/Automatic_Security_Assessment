"""靶场一的配置模块 —— **V3「配置硬编码密钥」的载体**（PRD §10.1）。

## 这个文件为什么长这样

它是靶场的一部分，不是"写坏的代码"：把凭据字面量写死在源码里，正是
PRD §10.1 的 V3 要考的那一类问题（真实事故里最常见的形态之一）。

`app.py` 的 `/.env` 与 `/debug/config` 两个路由会把这些值原样回给匿名请求 ——
**发现问题（硬编码）与利用问题（配置泄露路由）是两件事**，这个靶场把两件都摆上，
因为攻击链 R5「敏感信息泄露 → 数据库直连」要的是后者：光有硬编码，
没有泄露面，攻击者拿不到它。

## 为什么不做成读 .env 文件

沙箱把源码以**只读**方式挂到 `/workspace`（`SandboxService` 的
`volumes={...: {"mode": "ro"}}`），而上传的源码包里 dotfile 是否被保留
取决于打包实现 —— 让靶场的可复现性依赖"`.env` 有没有被 zip 进去"，
是把一个确定性实验绑到了打包细节上。值直接写在模块里，读法确定。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 凭据（V3：硬编码在源码里）
# ---------------------------------------------------------------------------
SECRET_KEY = "flask-session-8f3a1c9e2b7d4a60"
DB_PASSWORD = "shop_db_p4ssw0rd_2024"
API_KEY = "sk-live-3f9a2c7e1b8d4056"

#: 后台登录成功后签发的票据。同样是硬编码 —— 与 `admin_login.ADMIN_PASSWORD`
#: 一起构成"整个鉴权体系没有可轮换的密钥"这一现实。
ADMIN_TOKEN = "admin-session-token-2b7d4a608f3a1c9e"


def render_env_file() -> str:
    """`GET /.env` 的响应体：一份货真价实的 `.env` 内容。

    注意这里是**逐行拼接**而不是 `os.environ` —— 靶场要泄露的是源码里
    硬编码的那几个值（V3），所以泄露面与 V3 的载体是同一份数据。
    """
    lines = [
        "FLASK_ENV=production",
        f"SECRET_KEY={SECRET_KEY}",
        f"DB_PASSWORD={DB_PASSWORD}",
        f"DATABASE_URL=sqlite:////tmp/asa-range/shop.db",
        f"API_KEY={API_KEY}",
        f"ADMIN_TOKEN={ADMIN_TOKEN}",
    ]
    return "\n".join(lines) + "\n"


def render_debug_dump() -> str:
    """`GET /debug/config` 的响应体：调试接口把运行期配置整个倒出来。

    刻意用 `KEY=value` 的纯文本而不是 JSON：JSON 里键名带引号
    （`"SECRET_KEY": "..."`），而泄露判据要匹配的是 `KEY[:=]value` 这个形态 ——
    真实世界里"调试接口吐纯文本"也远比吐规整 JSON 常见。
    """
    lines = [
        "# runtime configuration dump",
        f"SECRET_KEY={SECRET_KEY}",
        f"DB_PASSWORD={DB_PASSWORD}",
        f"API_KEY={API_KEY}",
        "UPLOAD_DIR=/tmp/asa-range/uploads",
        "DEBUG=True",
    ]
    return "\n".join(lines) + "\n"
