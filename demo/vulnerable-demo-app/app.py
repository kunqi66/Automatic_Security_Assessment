"""**故意有漏洞的示例应用** —— 给本系统的端到端演示用。

## 这个文件是干什么的

本系统要证明「能发现漏洞」，就得有一个**确定有漏洞**的目标。用真实开源项目
不行：它今天有、明天可能被修，而且「应该报几条」没有标准答案，回归测试没法写。
所以靶场必须自带、且漏洞清单是钉死的。

## 为什么文件名叫 `app.py` 且在根目录

不是随便起的：`app/verify/probe.py` 的 `render_mission_script` 把
`app_entry` 写死为 `"app.py"`、`workdir` 为 `/workspace`，容器起来后由探针
执行器启动它、等端口就绪（`port_ready_timeout_s = 30`）再发请求。
**改名或挪位置，动态验证就会在「等端口」那一步超时** ——
而报错只会说「目标未就绪」，看不出是入口点没找对。

同理端口必须是 **5000**：探针的 `target` 默认取 `5000`。

## 漏洞清单（与本仓库的规则集一一对应）

| 端点 | 类型 | 命中的 sink |
|---|---|---|
| `GET /user?id=` | SQL 注入 | `cursor.execute` |
| `GET /ping?host=` | 命令注入 | `os.system` |
| `GET /read?file=` | 路径穿越 | `open` |
| `POST /load` | 反序列化 | `pickle.loads` |
| `GET /order/<id>` | 越权（IDOR） | pattern 规则 |
| —— | 硬编码凭据 | pattern 规则 |

⚠️ **它是靶场，不是模板。** 里面的写法全是反面教材，别抄。
"""

import os
import pickle
import sqlite3

from flask import Flask, request

app = Flask(__name__)

# ⚠️ 故意的：硬编码凭据，命中 `patterns.py` 的 SECRET 规则。
# 用 `AKIA` 前缀是因为该规则要求「长得像真凭据」，一串随机值不会触发。
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DB_PATH = "/tmp/demo.db"


def _init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'alice', 'alice-secret')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'bob', 'bob-secret')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return {"ok": True, "endpoints": ["/user", "/ping", "/read", "/load", "/order/<id>"]}


@app.route("/user")
def get_user():
    """SQL 注入：用户输入直接拼进 SQL 字符串。

    污点链：`request.args.get("id")` → f-string → `cursor.execute`。
    """
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # 反面教材：应当用 execute("... WHERE id = ?", (user_id,))
    cursor.execute(f"SELECT id, name, secret FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    conn.close()
    return {"user": row}


@app.route("/ping")
def ping():
    """命令注入：用户输入拼进 shell 命令。

    污点链：`request.args.get("host")` → `os.system`。
    """
    host = request.args.get("host", "127.0.0.1")
    # 反面教材：应当用 subprocess 的 argv 形式，且对输入做白名单校验
    os.system(f"ping -c 1 {host}")
    return {"pinged": host}


@app.route("/read")
def read_file():
    """路径穿越：用户输入直接当文件路径。

    污点链：`request.args.get("file")` → `open`。
    """
    name = request.args.get("file", "readme.txt")
    # 反面教材：应当 realpath 归一化后校验是否落在允许目录内
    with open(os.path.join("/tmp", name)) as handle:
        return {"content": handle.read()}


@app.route("/load", methods=["POST"])
def load_object():
    """反序列化：把请求体直接喂给 pickle。

    污点链：`request.data` → `pickle.loads`。这条是真 RCE，
    但探针**不会**真的执行破坏性载荷（总纲 Q24）—— 它只验证「污点可达」。
    """
    # 反面教材：绝不应对不可信数据用 pickle
    return {"loaded": str(pickle.loads(request.data))}


@app.route("/order/<int:order_id>")
def get_order(order_id: int):
    """越权（IDOR）：按 id 取单，不校验归属。

    这条走 `patterns.py` 的 IDOR 规则，不是污点分析 —— 因为「有没有校验归属」
    是语义问题，数据流看不出来。
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    conn.close()
    return {"order": row}


if __name__ == "__main__":
    _init_db()
    # ⚠️ 必须 5000：探针默认打这个端口（见模块 docstring）
    app.run(host="0.0.0.0", port=5000)
