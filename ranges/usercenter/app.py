"""靶场二：微服务用户中心（PRD §10.2）。

## 这个靶场考的是「本该有而没有被写出来的那一行」

靶场一的四个漏洞都是**写错了**（拼接了、没过滤、硬编码了）—— 有一个具体的
错误语句可以指给你看。靶场二的三个漏洞是**漏写了**：没有 owner 校验、
没有鉴权装饰器、没有脱敏。代码每一行单看都完全正常，缺陷是"少了一行"。

这个区别不是修辞，它决定了静态分析能做到什么程度：
「多了一句坏代码」可以靠模式匹配找，「少了一句好代码」只能靠推断 ——
所以本靶场的 IDOR 检出置信度是 0.55（`IDOR_CONFIDENCE`），
低于靶场一那些数据流规则的置信度。**报告里的置信度不同，是真实反映，
不是拍脑袋填的。**

## 路由表与探针的对应关系

| 路由 | 漏洞 | 对应探针技术 | 判定依据 |
|---|---|---|---|
| `GET /api/user/<user_id>/profile` | V5 平行越权 | `idor_horizontal` | 匿名写入的 nonce 被匿名读回 |
| `POST /api/user/profile` | V5 的写入侧 | `idor_horizontal` | 同上（探针先写后读） |
| `GET /api/user/list` | V6 未授权访问 | `unauth_probe` | 无凭证返回 200 + 非空 JSON |
| `GET /debug/config` | V8 调试接口未关闭 | `read_config` | 响应里出现 `KEY=` 形态 |
| （全部响应体） | V7 手机号明文 | — | 静态分析 / 人工复核 |

**V6 与 V7 是刻意留下的两个"不完整"**，它们标出了系统当前的能力边界：

- **V6**：探针**能验证**未授权访问（`unauth_probe` 打 `/api/user/list`），
  但静态分析**没有**发现它的规则 —— `analysis/` 里既没有它的 sink，
  也没有它的 pattern。于是"能验证"与"能发现"是脱节的：
  一个系统永远不会去验证它从没发现的漏洞。
- **V7**：既没有静态规则，也没有探针模板（"该脱敏没脱敏"不是数据流问题，
  也不是一次请求能证明的问题）。它只有人工复核能发现。

把这两条如实写进 `GROUND_TRUTH.yaml` 而不是删掉，是因为
**召回率这个指标只有在分母诚实的时候才有意义**。
"""

from __future__ import annotations

from flask import Flask, Response, jsonify, request

import db
import settings

app = Flask(__name__)

#: 「当前登录用户」。
#:
#: 这个常量就是 V5 的病根：一个没有任何鉴权的服务，必须自己假定"调用方是谁"。
#: 真实系统里它来自会话/令牌；这里它只能是一个写死的默认值 ——
#: 而写死的默认值意味着**每个匿名请求都自动拥有了 bob 这个账号的身份**。
CURRENT_USER_ID = 2


def _user_to_dict(row: tuple) -> dict:
    """行 → 响应体。**`phone` 原样返回** —— 这就是 V7。"""
    return {
        "id": row[0],
        "username": row[1],
        "nickname": row[2],
        "phone": row[3],  # 明文，未脱敏
        "email": row[4],
        "role": row[5],
    }


# ---------------------------------------------------------------------------
# V5：平行越权（IDOR）
# ---------------------------------------------------------------------------


@app.route("/api/user/<int:user_id>/profile")
def get_profile(user_id: int):
    """读取任意用户的资料 —— V5。

    ## 缺陷：**少了归属校验这一行**

    正确的写法应该是"取到资源之后，比对资源的 owner 与当前身份，不一致就 403"。
    这里没有那一行，于是 `user_id` 由调用方随意指定，谁来问都给。

    `user_id` 是路由的路径形参（Flask 的 `<int:user_id>`），
    在静态分析里它是一个"像对象标识的形参"，而函数体里找不到任何鉴权痕迹 ——
    两个条件同时成立，IDOR 规则就会报出来。
    """
    conn = db.connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "用户不存在"}), 404
    # ⚠️ 缺陷：没有 owner 校验，user_id 是调用方说了算
    return jsonify(_user_to_dict(row))


@app.route("/api/user/profile", methods=["POST"])
def update_profile():
    """更新资料 —— V5 的写入侧，也是 `idor_horizontal` 探针的第一步。

    探针的判定方式是**先写一个自造的标记、再匿名读别人的资源**：
    读到那个标记，就同时证明了「写入接口缺鉴权」与「读取接口缺归属校验」。
    所以这个端点必须真的落库，否则第二步读不到东西。

    这里用参数化查询（不是拼接）是刻意的：**这个端点的缺陷是授权，不是注入**。
    混进一个 SQL 注入会让 ground truth 变浑 —— 到时候"这条 finding 对应
    V5 还是 V5' ？"就说不清了，而 ground truth 的全部价值就在于一一对应。
    """
    nickname = request.form.get("nickname", "")
    # 没有鉴权，只能假定调用方就是 CURRENT_USER_ID
    user_id = request.form.get("user_id", str(CURRENT_USER_ID))

    conn = db.connect()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET nickname = ? WHERE id = ?", (nickname, user_id))
        conn.commit()
        changed = cursor.rowcount
    finally:
        conn.close()

    if not changed:
        return jsonify({"ok": False, "error": "用户不存在"}), 404
    return jsonify({"ok": True, "user_id": user_id, "nickname": nickname})


# ---------------------------------------------------------------------------
# V6：未授权访问
# ---------------------------------------------------------------------------


@app.route("/api/user/list")
def list_users():
    """用户列表 —— V6。

    ## 缺陷：**少了 `@login_required` 这一行**

    函数体本身无懈可击：参数化查询、字段显式挑选、没有注入面。
    问题在函数**外面** —— 没有鉴权装饰器，任何人 GET 一下就拿到全量用户。

    这条同时是攻击链 R4「IDOR → 敏感数据泄露」的一环：
    `unauth_access` 与 `idor` 在 R4 里是「或」的关系
    （`category_mode=ANY`），任一条成立就能推出"全量用户数据可被横读"。

    ## 为什么返回体不能是空 JSON

    未授权访问探针判定的是 `200 + json`，而 `match_status_code` 对 `+json`
    的要求是"**非空**且可解析"：一个返回 200 的空列表说明不了任何事 ——
    它可能是"列表本来就是空的"。固定有 5 个种子用户，这条判据才有意义。
    """
    conn = db.connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY id")
        rows = cursor.fetchall()
    finally:
        conn.close()
    return jsonify([_user_to_dict(row) for row in rows])


# ---------------------------------------------------------------------------
# V8：调试接口未关闭
# ---------------------------------------------------------------------------


@app.route("/debug/config")
def debug_config():
    """调试接口把运行期配置整个倒出来 —— V8。

    线上留一个 `/debug/*` 是真实事故里出现频率极高的一类问题，
    危险在于它把"内网配置"变成了"一个 HTTP GET 就能拿到的东西"。
    """
    return Response(settings.render_debug_dump(), mimetype="text/plain")


# ---------------------------------------------------------------------------


def main() -> None:
    db.seed()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
