"""靶场二的配置 —— **V8「调试接口未关闭」的数据源**（PRD §10.2）。

与靶场一的 `config.py` 是同一个思路的两半：那边是"值硬编码"，这边是
"值硬编码 **且** 有个调试接口把它倒出来"。V8 考的是后者。

口令形态刻意用带连字符的随机串而不是 `password123`：
静态分析的凭据规则要求「值长度 ≥ 6 且不同字符数 > 2」，
`password123` 这种既像占位符又几乎全是重复模式的值，规则会（正确地）放它过去 ——
那样 V8 就只剩"调试接口暴露"这一半，而 PRD 把它记成"敏感信息泄露"是两半都算的。
"""

from __future__ import annotations

DB_PASSWORD = "usercenter_db_9f3a2b8c1d"
JWT_SECRET = "jwt-hs256-4c7e1b8d4056a2f9"
SMS_API_KEY = "sms-key-2a7f4c1e9b3d8056"


def render_debug_dump() -> str:
    """`GET /debug/config` 的响应体。

    纯文本 `KEY=value`，不是 JSON：泄露判据匹配的是 `KEY[:=]value`，
    而 JSON 的键名带引号（`"JWT_SECRET": "..."`）会让中间的 `"` 打断匹配。
    真实世界里"调试接口吐纯文本"也更常见。
    """
    lines = [
        "# usercenter runtime configuration",
        f"JWT_SECRET={JWT_SECRET}",
        f"DB_PASSWORD={DB_PASSWORD}",
        f"SMS_API_KEY={SMS_API_KEY}",
        "DB_HOST=127.0.0.1",
        "DB_USER=usercenter_app",
        "PHONE_MASKING=disabled",
    ]
    return "\n".join(lines) + "\n"
