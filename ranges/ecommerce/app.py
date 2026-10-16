"""靶场一：电商后台（PRD §10.1）。

## 这是什么

一个**故意带漏洞**的 Flask 应用，用来给评估系统当被测目标。它的价值不在于
"能跑"，而在于**每一个漏洞都是可被判定的**：探针打过来时，响应里必须真的
出现那条漏洞的判据（nonce、时间差、长度差、状态码）。

所以下面每个路由都成对地写了两件事：**漏洞本身**，和**让这个漏洞可观测的响应形态**。
少了后者，漏洞依然存在，但评估系统只会得到"未验证" —— 而"未验证"与
"没这个漏洞"在报告上看起来很像，那正是本系统最想避免的含糊。

## 路由表与探针的对应关系

| 路由 | 漏洞 | 对应探针技术 | 判定依据 |
|---|---|---|---|
| `GET /search` | V1 SQL 注入 | `union_extract` | 响应里出现 nonce |
| `GET /search` | V1 SQL 注入 | `boolean_blind` | `1=1` 与 `1=2` 的长度差 |
| `GET /api/order/query` | V1 SQL 注入（PRD 记载的位置） | — | 静态分析 |
| `POST /api/upload` | V2 任意文件上传 | `upload_marker` | 上传后回读得到 nonce |
| `POST /admin/upload` | V2 任意文件上传（PRD 记载的位置） | — | 同一个处理函数 |
| `GET /api/ping` | 命令注入 | `time_blind` | `sleep 3` 造成的耗时增量 |
| `GET /api/ping` | 命令注入 | `echo_nonce` | 响应里出现 nonce |
| `GET /api/file` | 任意文件读取 | `path_traversal_read` | 读到 `/etc/passwd` 首行 |
| `GET /api/download` | 任意文件读取 | `path_traversal_read` | 读到 `/etc/hostname` |
| `GET /.env` | V3 配置泄露 | `read_config` | 响应里出现 `KEY=` 形态 |
| `GET /debug/config` | V3 配置泄露 | `read_config` | 同上 |
| `POST /api/deserialize` | 反序列化 | `deser_marker` | 异常信息回显 nonce |
| `POST /admin/login` | V4 登录弱校验 | — | 静态分析（无登录探针） |

**关于"PRD 记载的位置"那一列**：PRD §10.1 写的是 `/api/order/query` 与
`/admin/upload`，而探针模板打的是 `/search` 与 `/api/upload`。两者都是既成事实，
谁改谁都要动别处，所以这里让靶场**同时暴露两组路由**，指向同一段有漏洞的实现。
这样"文档描述的位置"与"探针可达的位置"同时成立，不必二选一。
"""

from __future__ import annotations

import base64
import json
import os
import pickle
import subprocess

from flask import Flask, Response, jsonify, request, send_file

import config
import db
from admin_login import check_login

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY


# ---------------------------------------------------------------------------
# V1：SQL 注入
# ---------------------------------------------------------------------------


@app.route("/search")
def search():
    """商品检索 —— V1 的注入点之一（探针打的就是这里）。

    **注入点必须落在数值上下文里**，这不是随便选的：探针的两种 SQL 技术
    都要求参数拼接后仍是合法 SQL 的表达式位。

    - `union_extract` 载荷是 `1 UNION SELECT '<nonce>','asa' -- `：
      若参数被塞进 `LIKE '%...%'` 这类的**字符串**里，第一个引号就会把
      字符串提前闭合，得到的是语法错误而不是注入；
    - `boolean_blind` 载荷是 `1 AND 1=1` / `1 AND 1=2`：
      在字符串里它只是被当成文本的一部分，两个分支结果**完全一样**，
      长度差为 0，探针会（正确地）判定"没有注入" —— 一个假阴性。

    所以 `q` 拼在 `WHERE id =` 后面。这也是真实世界里最常见的那种写法：
    拿一个本该是整数的主键当查询参数，顺手就用 `+` 拼了。

    ## 这里为什么查两列

    `UNION SELECT` 两侧列数必须一致。探针现在**按目标 SELECT 的列数**
    构造载荷（`probe._build_union_payload`），两列只是本端点的自然写法。
    旁边 `/api/order/query` 查三列：UNION 探针原先恒发两列，在那必然 500。
    """
    q = request.args.get("q", "1")
    conn = db.connect()
    try:
        cursor = conn.cursor()
        # ⚠️ 注入点：q 未经校验直接拼进 SQL（参数化查询应写成 execute(sql, (q,))）
        cursor.execute(
            "SELECT id, name || ' :: ' || description FROM products WHERE id = " + q
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    body = json.dumps(
        [{"id": row[0], "name": row[1]} for row in rows], ensure_ascii=False
    )
    return Response(body, mimetype="application/json")


@app.route("/api/order/query")
def order_query():
    """订单查询 —— V1 在 PRD §10.1 里记载的位置。

    与 `/search` 是同一个缺陷的第二个实例。刻意不做成"共用同一个函数"：
    真实工程里这类重复是常态，而静态分析要能在**两处**都报出来 ——
    如果共用，召回率就变成了"每类漏洞只找一个代表"，那是自欺。
    """
    order_id = request.args.get("id", "1")
    conn = db.connect()
    try:
        cursor = conn.cursor()
        # ⚠️ 注入点：同上
        cursor.execute(
            "SELECT id, product_id, amount FROM orders WHERE id = " + order_id
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    body = json.dumps(
        [{"id": r[0], "product_id": r[1], "amount": r[2]} for r in rows],
        ensure_ascii=False,
    )
    return Response(body, mimetype="application/json")


# ---------------------------------------------------------------------------
# V2：任意文件上传
# ---------------------------------------------------------------------------


@app.route("/api/upload", methods=["POST"])
@app.route("/admin/upload", methods=["POST"])
def upload():
    """上传点 —— V2。两个路径指向同一个处理函数。

    缺陷是**没有后缀白名单**，且落盘路径直接由客户端给的 `filename` 决定。
    这里刻意不接收 `.py` / `.phtml` 之类的可执行内容 —— 攻击链里"上传 WebShell
    并执行"那一环始终是**推演**（沙箱把 `/tmp` 挂成 `noexec`，
    写进去的二进制根本跑不起来）。

    换句话说：本靶场能证明"上传点可达且无后缀限制"，**不能**也**不应**
    证明"传上去能执行"。这个边界写在这里，是为了让报告里那条标注了
    「推演，未实际执行」的链环有据可依。
    """
    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"ok": False, "error": "缺少 file 字段"}), 400

    # ⚠️ 缺陷：filename 完全由客户端控制，且没有后缀白名单
    target = os.path.join(db.UPLOAD_DIR, uploaded.filename)
    uploaded.save(target)
    return jsonify({"ok": True, "path": "/uploads/" + uploaded.filename})


@app.route("/uploads/<path:name>")
def serve_upload(name: str):
    """上传文件的回读入口。

    上传探针的判定是"**回读得到** nonce"，而不是"上传返回 200" ——
    后者只能证明接口没报错。所以这个路由是把上传变成可判定漏洞的**必要**一环。
    """
    try:
        return send_file(os.path.join(db.UPLOAD_DIR, name), mimetype="text/plain")
    except OSError as exc:
        # 回读失败必须是一个**明确的 404**：探针的 upper bound 是"没有回读到
        # nonce 就等于上传点不可达"，500 与 404 在这一点上等价，
        # 但 404 让"文件确实不在"与"服务出错了"两件事在日志里能分开。
        return Response(f"not found: {exc}", status=404, mimetype="text/plain")


# ---------------------------------------------------------------------------
# 命令注入
# ---------------------------------------------------------------------------


@app.route("/api/ping")
def network_diagnostic():
    """网络诊断 —— 命令注入点。

    用 `subprocess.check_output` 而不是 `os.system`，理由是**判定**：
    `echo` 回显探针需要拿到命令的输出，而 `os.system` 只把输出直接写进程的
    stdout，HTTP 响应里什么都看不到。捕获输出既让漏洞更可观测，
    也是真实工程里更常见的写法（要把结果返回给页面）。

    沙箱给容器的时长预算很紧，`timeout` 是必须的：没有它，一个
    `; sleep 99999` 会把容器拖到被硬杀，连带同组的其他探针一起失去证据。
    """
    host = request.args.get("host", "127.0.0.1")
    # ⚠️ 注入点：host 直接拼进 shell 命令
    command = "ping -c 1 " + host
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, timeout=20
        )
    except subprocess.CalledProcessError as exc:
        output = exc.output or b""
    except subprocess.TimeoutExpired:
        output = b"command timed out"
    return Response(output.decode("utf-8", "replace"), mimetype="text/plain")


# ---------------------------------------------------------------------------
# 任意文件读取
# ---------------------------------------------------------------------------


@app.route("/api/file")
def read_file():
    """文件查看 —— 任意文件读取点。

    注入的是相对路径（`../../../../etc/passwd`）而不是绝对路径：探针载荷的
    形态闸门只放行相对路径，理由是绝对路径无法用一条正向白名单描述
    "它去哪了"。这里不做任何规范化，于是 `..` 一路穿透。
    """
    path = request.args.get("path", "readme.txt")
    try:
        # ⚠️ 注入点：path 未经规范化就交给 open
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        # 文件不存在／不可读时回 404，**不是 500**。这不只是为了好看：
        # 容器里那条连接在 500 之后会进入一个很别扭的状态（实测：同一连接上
        # 后续请求会挂到超时），而探针是复用同一条连接连发数次的。
        return Response(f"not found: {exc}", status=404, mimetype="text/plain")
    return Response(data, mimetype="text/plain")


@app.route("/api/download")
def download():
    """附件下载 —— 任意文件读取的第二个实例。

    这里用 `send_file`：除了是同一个缺陷的另一种写法，它还顺带说明了
    **"读文件"这个动作的危险性不取决于用哪个 API** —— `open` 与
    `send_file` 在静态分析里是两条独立规则，但根因是同一个。
    """
    name = request.args.get("file", "readme.txt")
    # ⚠️ 注入点：同上
    try:
        return send_file(name, mimetype="text/plain")
    except OSError as exc:
        return Response(f"not found: {exc}", status=404, mimetype="text/plain")


# ---------------------------------------------------------------------------
# V3：配置泄露
# ---------------------------------------------------------------------------


@app.route("/.env")
def dotenv():
    """把 `.env` 的内容暴露给匿名请求 —— V3 的利用面。

    点开头的路径通常是"本该不可达"的：Web 服务器不会主动把 `.env` 当静态资源
    发出去。但一个手写的路由可以，而"手写一个调试用的配置路由然后忘了摘"
    是真实项目里非常常见的形态。
    """
    return Response(config.render_env_file(), mimetype="text/plain")


@app.route("/debug/config")
def debug_config():
    """调试接口把运行期配置整个倒出来。"""
    return Response(config.render_debug_dump(), mimetype="text/plain")


# ---------------------------------------------------------------------------
# 反序列化
# ---------------------------------------------------------------------------


@app.route("/api/deserialize", methods=["POST"])
def deserialize():
    """反序列化点。

    探针递过来的是一个**只会失败、不会做事**的 pickle：`__reduce__` 指向
    `getattr("builtins", "<nonce>")` —— 一次必然失败的属性查找。
    它没有副作用，但异常信息里带着 nonce，于是"对象真的被反序列化了"
    这件事变得可观测。

    这个路由把异常原文回给调用方，既是为了可观测性，也**本身就是**一个
    真实缺陷（错误信息外泄内部结构）。
    """
    raw = request.form.get("data", "")
    try:
        envelope = json.loads(raw)
        blob = base64.b64decode(envelope["data"])
        # ⚠️ 注入点：不可信输入直接进 pickle.loads
        obj = pickle.loads(blob)
    except Exception as exc:  # noqa: BLE001 —— 回显异常是刻意行为
        return Response(f"deserialize failed: {exc}", status=500, mimetype="text/plain")
    return jsonify({"ok": True, "type": type(obj).__name__})


# ---------------------------------------------------------------------------
# V4：后台登录
# ---------------------------------------------------------------------------


@app.route("/admin/login", methods=["POST"])
def admin_login():
    """后台登录 —— V4 的入口。校验逻辑在 `admin_login.check_login`（带注入）。"""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if check_login(username, password):
        return jsonify({"ok": True, "role": "admin", "token": config.ADMIN_TOKEN})
    return jsonify({"ok": False, "error": "用户名或密码错误"}), 401


# ---------------------------------------------------------------------------


def main() -> None:
    db.seed()
    # 沙箱内的执行器连的是容器回环，绑 0.0.0.0 对两种访问都成立。
    # 关闭 debug：开着会启动 reloader，父进程会 fork 出一个子进程，
    # 而沙箱只等"端口就绪"，多出来的进程在容器被回收时会变成僵尸。
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
