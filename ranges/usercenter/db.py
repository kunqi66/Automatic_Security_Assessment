"""靶场二的存储层。

与靶场一同理落在 `/tmp`：容器的根文件系统只读、源码以 `ro` 挂进 `/workspace`，
整台容器里只有 `/tmp` 那块 tmpfs 可写。
"""

from __future__ import annotations

import os
import sqlite3

RUNTIME_DIR = "/tmp/asa-usercenter"
DB_PATH = os.path.join(RUNTIME_DIR, "usercenter.db")

#: 用户表。`phone` 是 V7 的载体 —— 接口把它**明文**返回，没有任何脱敏。
_USERS = [
    (1, "alice", "爱丽丝", "13800000001", "alice@example.com", "user"),
    (2, "bob", "鲍勃", "13800000002", "bob@example.com", "user"),
    (3, "carol", "卡罗尔", "13800000003", "carol@example.com", "user"),
    (4, "dave", "戴夫", "13800000004", "dave@example.com", "user"),
    (5, "admin", "管理员", "13800000005", "admin@example.com", "admin"),
]


def connect() -> sqlite3.Connection:
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def seed() -> None:
    """建表 + 造数（幂等）。"""
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY, username TEXT, nickname TEXT, "
            "phone TEXT, email TEXT, role TEXT)"
        )
        if cur.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None:
            cur.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", _USERS)
        conn.commit()
    finally:
        conn.close()
