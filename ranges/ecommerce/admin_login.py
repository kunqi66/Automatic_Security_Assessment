"""靶场一的后台鉴权 —— **V4「后台登录弱校验」的载体**（PRD §10.1）。

## 这个文件为什么单独存在

除了承载 V4，它还负责让攻击链 **R2「凭证泄露 → 后台登录」** 有前提可依。

R2 要求工程资产表里存在 `admin_login`。资产是从**已发现的漏洞**的
`file_path` / `symbol` / `title` 里按关键词（`login` / `admin` / `auth` …）
字面命中的 —— 也就是说，"这个工程有后台登录面"这件事必须由一个**漏洞**来举证，
而不是由一句自述。把后台登录的校验逻辑放进独立模块 `admin_login`，
它的路径本身就构成了这份举证：这个模块里只要有一条 finding，
`admin_login` 这个工程资产就成立。

若把 `check_login` 塞进 `app.py`，R2 就永远缺前提 —— 而症状是
"链推演少了一环"，既不报错也不告警，只是悄悄变短。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# V4：后台口令硬编码在源码里
# ---------------------------------------------------------------------------
ADMIN_PASSWORD = "Adm1n-Sup3r-S3cret-2024"

#: 允许登录后台的账号名。硬编码一份白名单本身也是"鉴权不可轮换"的一部分。
ADMIN_USERS = ("admin", "root")


def check_login(username: str, password: str) -> bool:
    """校验后台登录。**故意**用字符串拼接构造 SQL —— 这就是 V4。

    拼接的后果不只是"读到了不该读的行"，而是**认证绕过**：
    `username=' OR '1'='1' -- ` 会让 WHERE 恒真，于是不存在的账号也能登进后台。
    真实事故里这条路径通常被用来做"无凭证拿管理员会话"，正对应 R2 的
    `gain_priv=ADMIN` + `exit_artifact=session`。
    """
    from db import connect

    conn = connect()
    try:
        cursor = conn.cursor()
        # 注入点：username / password 未经转义直接拼进 SQL
        cursor.execute(
            "SELECT role FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        row = cursor.fetchone()
    finally:
        conn.close()
    return row is not None
