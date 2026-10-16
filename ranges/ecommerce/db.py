"""靶场一的存储层：SQLite 建库、造数与连接。

## 为什么落在 /tmp

沙箱容器的根文件系统是**只读**的（`SandboxService` 起容器时 `read_only=True`），
源码又以 `mode: ro` 挂进 `/workspace`，整台容器里唯一可写的地方是挂在 `/tmp`
上的那块 tmpfs。所以数据库文件与上传目录都必须放在 `/tmp` 下面。

这一点值得写在代码里：写错位置时抛的是 `OSError: Read-only file system`，
看起来像"这段代码有 bug"，实际是沙箱隔离在按设计工作 —— 把结论写在
犯错的人会读到的地方。
"""

from __future__ import annotations

import os
import sqlite3

RUNTIME_DIR = "/tmp/asa-range"
DB_PATH = os.path.join(RUNTIME_DIR, "shop.db")
UPLOAD_DIR = os.path.join(RUNTIME_DIR, "uploads")

#: 商品描述刻意写长：SQL 布尔盲注的判据是"真/假分支的响应体长度差"，
#: 而真分支只命中一行（`WHERE id = 1 AND 1=1`）。一行若只有十几个字节，
#: 长度差就退化成噪声量级。描述长一些，差异是几百字节，判据才稳。
_PRODUCTS = [
    (1, "机械键盘", "87 键青轴机械键盘，支持全键无冲与热插拔，附赠腕托与拔键器，"
                   "键帽为 PBT 二色成型工艺，长时间码字不易打油。"),
    (2, "人体工学椅", "网布靠背，四级腰托，扶手可四向调节，坐深可调五档。"),
    (3, "显示器支架", "气弹簧单臂，支持 17-32 英寸，承重 2-9kg。"),
    (4, "降噪耳机", "主动降噪，续航 30 小时，支持多点连接。"),
]

_USERS = [
    (1, "alice", "alice_pw_2024", "user", "13800000001"),
    (2, "bob", "bob_pw_2024", "user", "13800000002"),
    (3, "admin", "admin_pw_2024", "admin", "13800000003"),
]

_ORDERS = [
    (1, 1, 2, 1099.00),
    (2, 2, 1, 2499.00),
    (3, 3, 3, 199.00),
]


def connect() -> sqlite3.Connection:
    """开一个连接。**每次都新建**：靶场追求的是行为可预测，
    不是吞吐 —— 连接池会让"某个请求把连接关了"这类问题变成偶发。"""
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def seed() -> None:
    """建表 + 造数。幂等：重复调用不会重复插入。"""
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS products "
            "(id INTEGER PRIMARY KEY, name TEXT, description TEXT)"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS users "
            "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, phone TEXT)"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS orders "
            "(id INTEGER PRIMARY KEY, product_id INTEGER, quantity INTEGER, amount REAL)"
        )
        if cur.execute("SELECT 1 FROM products LIMIT 1").fetchone() is None:
            cur.executemany("INSERT INTO products VALUES (?,?,?)", _PRODUCTS)
            cur.executemany("INSERT INTO users VALUES (?,?,?,?,?)", _USERS)
            cur.executemany("INSERT INTO orders VALUES (?,?,?,?)", _ORDERS)
        conn.commit()
    finally:
        conn.close()
