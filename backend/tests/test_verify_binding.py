"""探针路由绑定 + 注入上下文（`verify/routes.py` + `verify/context.py`）。

## 这两个模块要修的到底是什么

一条 finding 说的是「**这一行**有漏洞」，而探针模板把路由写死了
（`sqli` 的两条模板都是 `/search`）。于是靶场实测里 15 条 finding 有 10 条
的"动态验证"发生在**别的端点**上，报告里却都印着「已通过动态验证」。

修法分两层，这个文件两层都钉住：

1. **`routes.bind_route`** —— 从污点路径反查出 finding 自己的端点；
2. **`context.infer_sink_context`** —— 反查出来之后才看得见的第二层：
   同一个载荷落在 numeric 与 string 两种拼法里，**一个是真注入、
   一个是合法但恒假的 SQL**。少了第二层，绑定本身会造出新的假 `rejected`。

**这两个 bug 都是端到端跑出来的，不是想出来的** —— 所以每条用例都写明了
它对应靶场里的哪一处真实代码。
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from verify_chain_fakes import FakeFinding, FakeTaintStep

from app.analysis.parser import make_fs_reader, parse_file
from app.verify.context import (
    SqlContext,
    _column_count,
    infer_sink_context,
    payload_fits_context,
)
from app.verify.probe import build_probes
from app.verify.routes import PATH_PAYLOAD_SLOT, bind_route
from app.verify.types import InjectIn, Technique

# ---------------------------------------------------------------------------
# 夹具：把源码写进 tmp_path，再让 reader 读它
# ---------------------------------------------------------------------------


def _app(tmp_path: Path, source: str) -> tuple[Path, object]:
    """写一个单文件应用，返回 `(根目录, reader)`。"""
    (tmp_path / "app.py").write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    return tmp_path, make_fs_reader(tmp_path)


def _finding(*steps: FakeTaintStep, vuln_type: str = "sql_injection") -> FakeFinding:
    return FakeFinding(vuln_type=vuln_type, taint_path=tuple(steps))


def _step(symbol: str, line: int, kind: str = "source", file_path: str = "app.py"):
    return FakeTaintStep(symbol, step_kind=kind, line=line, file_path=file_path)


# ---------------------------------------------------------------------------
# bind_route：端点反查
# ---------------------------------------------------------------------------


def test_反查出_query_参数的端点(tmp_path: Path) -> None:
    """对应靶场 `app.py:88`（`/search` + `q`）。"""
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/search")
        def search():
            q = request.args.get("q", "1")
            cursor.execute("SELECT id FROM products WHERE id = " + q)
        """,
    )
    finding = _finding(_step("request.args.get", 6), _step("cursor.execute", 7, "sink"))

    b = bind_route(reader, finding)

    assert b is not None
    assert b.url_path == "/search"
    assert b.methods == ("GET",)
    assert b.param_name == "q"
    assert b.local_var == "q"
    assert b.inject_in is InjectIn.QUERY
    assert b.route_line == 4


def test_反查出_form_参数的端点并读出局部变量(tmp_path: Path) -> None:
    """对应靶场 `app.py:114`：HTTP 参数叫 `id`、局部变量叫 `order_id`。

    这两个名字**不一样**，而 SQL 拼接链上写的是后者 —— 少了 `local_var`，
    上下文推断会退化成 unknown（第一版就是这么错的）。
    """
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/api/order/query")
        def order_query():
            order_id = request.args.get("id", "1")
            cursor.execute("SELECT id, amount FROM orders WHERE id = " + order_id)
        """,
    )
    finding = _finding(_step("request.args.get", 6), _step("cursor.execute", 7, "sink"))

    b = bind_route(reader, finding)

    assert b is not None
    assert b.param_name == "id"
    assert b.local_var == "order_id"


def test_反查出_post_与_body_参数(tmp_path: Path) -> None:
    """对应靶场 `app.py:301` 的 `@app.route(..., methods=["POST"])` + `request.form`。"""
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/admin/login", methods=["POST"])
        def admin_login():
            username = request.form.get("username", "")
            check_login(username)
        """,
    )
    finding = _finding(_step("request.form.get", 6), _step("check_login", 7, "sink"))

    b = bind_route(reader, finding)

    assert b is not None
    assert b.url_path == "/admin/login"
    assert b.methods == ("POST",)
    assert b.param_name == "username"
    assert b.inject_in is InjectIn.BODY


def test_端点可以跨文件反查(tmp_path: Path) -> None:
    """**这是反查必须锚在 source 步的实证。**

    靶场 `admin_login.py:43` 的 sink 在一个**没有路由**的辅助函数里，
    路由在另一个文件的 `app.py:301`。只锚 sink 所在的文件永远找不到装饰器。
    """
    (tmp_path / "app.py").write_text(
        textwrap.dedent(
            """
            from flask import Flask, request
            from admin_login import check_login
            app = Flask(__name__)

            @app.route("/admin/login", methods=["POST"])
            def admin_login():
                username = request.form.get("username", "")
                check_login(username)
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "admin_login.py").write_text(
        textwrap.dedent(
            """
            def check_login(username):
                cursor.execute("SELECT role FROM users WHERE username = '" + username + "'")
            """
        ).lstrip(),
        encoding="utf-8",
    )
    reader = make_fs_reader(tmp_path)
    # source 在 app.py、sink 在 admin_login.py
    finding = _finding(
        _step("request.form.get", 7, file_path="app.py"),
        _step("cursor.execute", 2, "sink", file_path="admin_login.py"),
    )

    b = bind_route(reader, finding)

    assert b is not None
    assert b.route_file == "app.py"
    assert b.url_path == "/admin/login"


def test_路径参数反查并留出载荷占位(tmp_path: Path) -> None:
    """对应靶场 `app.py:165` 的 `/uploads/<path:name>`。

    占位符必须换成 `{payload}` —— 否则路径注入没有落点，探针发出去的
    是一条**不带载荷的干净请求**，然后"未命中"（静默失效）。
    """
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask
        app = Flask(__name__)

        @app.route("/uploads/<path:name>")
        def serve_upload(name):
            return send_file(os.path.join(UPLOAD_DIR, name))
        """,
    )
    finding = _finding(
        _step("name", 5, "source"),
        _step("send_file", 6, "sink"),
    )

    b = bind_route(reader, finding)

    assert b is not None
    assert b.url_path == f"/uploads/{PATH_PAYLOAD_SLOT}"
    assert b.param_name == "name"
    assert b.inject_in is InjectIn.PATH
    assert b.is_path_injected is True


def test_多段路径只注其中的一个占位(tmp_path: Path) -> None:
    """`/api/user/<int:uid>/file/<name>` 只把被注的那一段换成占位，其余填确定值。"""
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask
        app = Flask(__name__)

        @app.route("/api/user/<int:uid>/file/<name>")
        def get_file(uid, name):
            return open("/data/" + name).read()
        """,
    )
    finding = _finding(_step("name", 5), _step("open", 6, "sink"))

    b = bind_route(reader, finding)

    assert b is not None
    assert b.url_path == f"/api/user/1/file/{PATH_PAYLOAD_SLOT}"
    assert b.param_name == "name"


def test_idor_写入侧不吃绑定_读侧改用反查路由(tmp_path: Path) -> None:
    """IDOR 的探针发**两条打在不同端点上的**请求，两边对绑定的态度相反。

    实测撞出来的：把绑定无差别套上去，`create-marker` 那条的 URL 也被换成了
    finding 的路由，还顺手把 nonce 注进了路径 —— 发出去是
    `POST /api/user/<nonce>/profile`，而那个路由只收 GET，404。
    IDOR 于是**永远测不出来**，失败原因看起来还像"目标没有这个接口"。

    更根本的是：IDOR 的判定**必须**用"另一个合法用户的 id"。
    把 nonce 注进路径只会请求一个不存在的用户，等于把要测的东西测没了。
    所以写入侧整条由模板给死（`binds_route=False`）。

    但**读侧**恰恰相反：它打的正是这条 finding 自己的端点。让它照抄模板里
    写死的 `/api/user/2/profile`，命中就只能算"这一类漏洞在本目标上成立"；
    从反查出的路由生成，命中才算**本条**成立。所以 `aux_resource_id="2"`。
    """
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask
        app = Flask(__name__)

        @app.route("/api/user/<user_id>/profile")
        def profile(user_id):
            return db.get(int(user_id))
        """,
    )
    finding = _finding(_step("user_id", 5), _step("db.get", 6, "sink"), vuln_type="idor")

    # 反查**成功**（这条 finding 确实有端点）
    assert bind_route(reader, finding) is not None

    plan = build_probes(finding, vuln_id=1, src_root=root)
    idor = [p for p in plan.probes if p.technique is Technique.IDOR_HORIZONTAL]
    assert idor, "没生成 IDOR 探针"
    for p in idor:
        # 写入侧：整条来自模板，一个字都不许被绑定改
        assert p.url_path == "/api/user/profile", "create-marker 的 URL 被绑定改掉了"
        assert p.method == "POST"
        assert p.param_name == "nickname", (
            "写入侧参数名被 finding 的污点参数顶掉了 —— 标记值会写进 `user_id`，"
            "`UPDATE ... SET nickname = ?` 于是把昵称置空，第二步读不到 nonce"
        )
        # 读侧：从反查出的路由生成
        assert p.aux_path == "/api/user/2/profile"
        # 命中的是读侧那条 —— 归属按它算，所以这条算逐点
        assert p.bound_to_finding is True


def test_idor_路由里没有载荷占位时读侧退回模板(tmp_path: Path) -> None:
    """占位不在路由里（污点参数在请求体里）时，**不能**拿反查出的路由去替换。

    替换是空操作，会把读侧 URL 变成"这条 finding 自己的端点"（一个写入端点），
    比模板原值还错。这时退回 `aux_path`，并且**不**声称逐点 ——
    没打到本条端点却说"逐点确认"，比漏测更坏。
    """
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/api/user/profile", methods=["POST"])
        def update():
            db.update(request.form.get("nickname"))
        """,
    )
    finding = _finding(_step("nickname", 5), _step("db.update", 6, "sink"), vuln_type="idor")

    plan = build_probes(finding, vuln_id=1, src_root=root)
    idor = [p for p in plan.probes if p.technique is Technique.IDOR_HORIZONTAL]
    assert idor, "没生成 IDOR 探针"
    for p in idor:
        assert p.aux_path == "/api/user/2/profile", "读侧 URL 被替换成了 finding 自己的写入端点"
        assert p.bound_to_finding is False


def test_没有路由装饰器就绑不上(tmp_path: Path) -> None:
    """对应靶场 `config.py:26` 的硬编码密钥 —— **它确实没有端点**。

    返回 None 是**正常结果**，不是失败。调用方必须把它当作
    「本条无法逐点验证」，而不是「用默认路由凑一个」。
    """
    root, reader = _app(
        tmp_path,
        """
        SECRET_KEY = "hardcoded-in-source"

        def helper():
            return SECRET_KEY
        """,
    )
    finding = _finding(_step("SECRET_KEY", 1))

    assert bind_route(reader, finding) is None


def test_读不到源码就绑不上而不是抛异常(tmp_path: Path) -> None:
    """绑定是**增益**，不是前置条件：读不到文件不能让整轮验证崩掉。"""
    reader = make_fs_reader(tmp_path)  # 空目录
    finding = _finding(_step("request.args.get", 6))

    assert bind_route(reader, finding) is None


def test_参数名读不出来时仍然绑定(tmp_path: Path) -> None:
    """对应靶场 `app.py:147`：snippet 只到光秃秃的 `request.files`。

    **通道能确定**（files → body），**参数名不能**。这时绑定照做、
    `param_name` 留 None，由模板的 `default_param` 补上 ——
    补的只是字段名，路由是反查出来的事实。
    """
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/api/upload", methods=["POST"])
        def upload():
            uploaded = request.files.get("file")
            uploaded.save("/tmp/x")
        """,
    )
    # 分析器对这一处只记到属性节点，不是完整调用
    finding = _finding(
        _step("request.files", 6),
        _step("uploaded.save", 7, "sink"),
        vuln_type="file_upload",
    )

    b = bind_route(reader, finding)

    assert b is not None
    assert b.url_path == "/api/upload"
    assert b.param_name == "file"
    assert b.inject_in is InjectIn.BODY


# ---------------------------------------------------------------------------
# infer_sink_context：注入点的语法上下文
# ---------------------------------------------------------------------------


def _ctx(
    tmp_path: Path, source: str, src_line: int, sink_line: int, var: str, name: str = "app.py"
):
    (tmp_path / name).write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    parsed = parse_file(name, (tmp_path / name).read_text(encoding="utf-8"))
    return infer_sink_context(parsed, sink_line, var)


def test_numeric_上下文(tmp_path: Path) -> None:
    """对应靶场 `app.py:88`：`WHERE id = " + q` —— 两列、numeric。"""
    ctx = _ctx(
        tmp_path,
        """
        def search():
            q = request.args.get("q")
            cursor.execute("SELECT id, name FROM products WHERE id = " + q)
        """,
        2,
        3,
        "q",
    )

    assert ctx.kind is SqlContext.NUMERIC
    assert ctx.columns == 2


def test_numeric_但列数不同(tmp_path: Path) -> None:
    """对应靶场 `app.py:114`：三列 —— UNION 载荷（两列）在这里**语法不成立**。"""
    ctx = _ctx(
        tmp_path,
        """
        def order_query():
            order_id = request.args.get("id")
            cursor.execute("SELECT id, product_id, amount FROM orders WHERE id = " + order_id)
        """,
        2,
        3,
        "order_id",
    )

    assert ctx.kind is SqlContext.NUMERIC
    assert ctx.columns == 3


def test_string_上下文(tmp_path: Path) -> None:
    """对应靶场 `admin_login.py:43`：`WHERE username = '" + username + "'`。"""
    ctx = _ctx(
        tmp_path,
        """
        def check_login(username):
            cursor.execute("SELECT role FROM users WHERE username = '" + username + "'")
        """,
        2,
        2,
        "username",
    )

    assert ctx.kind is SqlContext.STRING
    assert ctx.columns == 1


def test_前缀要累计所有字面量而不是只看紧邻的那一个(tmp_path: Path) -> None:
    """**这条钉住一个具体的坑。**

    `password` 紧邻的字面量是 `' AND password = '` —— 两个单引号（偶数），
    只数它会得到 numeric。必须接上前面的 `… username = '` 才是 3 个引号（奇数）
    → string。第一版就是只看紧邻字面量，把 string 读成了 numeric。
    """
    ctx = _ctx(
        tmp_path,
        """
        def check_login(username, password):
            cursor.execute(
                "SELECT role FROM users WHERE username = '"
                + username
                + "' AND password = '"
                + password
                + "'"
            )
        """,
        2,
        6,
        "password",
    )

    assert ctx.kind is SqlContext.STRING


def test_上下文读不出来时是_unknown_而不是猜一个(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path,
        """
        def f(v):
            cursor.execute(build_sql(v))
        """,
        2,
        2,
        "v",
    )

    assert ctx.kind is SqlContext.UNKNOWN


# ---------------------------------------------------------------------------
# payload_fits_context：载荷能不能进语法位置
# ---------------------------------------------------------------------------


def test_union_载荷要求列数相等() -> None:
    from app.verify.context import SinkContext

    union = "1 UNION SELECT '{N}','asa' -- "
    two_numeric = SinkContext(kind=SqlContext.NUMERIC, columns=2)
    three_numeric = SinkContext(kind=SqlContext.NUMERIC, columns=3)
    one_string = SinkContext(kind=SqlContext.STRING, columns=1)

    assert payload_fits_context(Technique.UNION_EXTRACT, union, two_numeric) is True
    # 列数不等 → 数据库报 "different number of result columns"，不是命中
    assert payload_fits_context(Technique.UNION_EXTRACT, union, three_numeric) is False
    # string 上下文里整个载荷被包进引号，成了一条字符串字面量
    assert payload_fits_context(Technique.UNION_EXTRACT, union, one_string) is False


def test_boolean_载荷只认_numeric() -> None:
    from app.verify.context import SinkContext

    boolean = "1 AND 1=1"
    assert (
        payload_fits_context(
            Technique.BOOLEAN_BLIND, boolean, SinkContext(kind=SqlContext.NUMERIC, columns=2)
        )
        is True
    )
    # ⚠️ 这一条是**新假阴性的入口**：`username = '1 AND 1=1'` 是合法 SQL，
    # 响应与基线无差异，布尔差分如实说"无差异" → 真注入被判 rejected。
    assert (
        payload_fits_context(
            Technique.BOOLEAN_BLIND, boolean, SinkContext(kind=SqlContext.STRING, columns=1)
        )
        is False
    )


def test_select_星号的列数是不可知而不是_1() -> None:
    """`SELECT *` 的列数是**不知道**，不是 1 —— 这条钉住一个真实的回归。

    `_column_count` 原本对 `SELECT * FROM t WHERE id = ` 返回 1。
    那时这是**安全的**，但纯属歪打正着：载荷恒为两列，`1 != 2` 于是
    `payload_fits_context` 判"不适配"，未命中不构成证伪。

    载荷改成按 `ctx.columns` 构造之后，1 就**真的会去构造一个一列的载荷**，
    `1 == 1` 判成适配 —— 在一张五列的表上打单列 UNION 必然不命中，
    而这次未命中被当成**证伪**，一条真注入被写成 `rejected`。

    误拒是这个模块最不该犯的错（见文件头）：漏报只是少一条，
    误拒是**在报告里主动写下一句假话**。所以星号必须显式退回"不知道"。
    """
    assert _column_count("SELECT * FROM t WHERE id = ") is None
    assert _column_count("SELECT t.* FROM t WHERE id = ") is None
    # 但 `count(*)` 是**一个**列 —— 星号在函数里，不在选择列表顶层
    assert _column_count("SELECT count(*) FROM t WHERE id = ") == 1


def test_非_sql_技术不受上下文约束() -> None:
    from app.verify.context import SinkContext

    unknown = SinkContext(kind=SqlContext.UNKNOWN)
    # 命令注入的载荷形态是 shell 的事，与 SQL 语法位置无关 ——
    # 这个函数**刻意只对它判断得了的东西表态**
    assert payload_fits_context(Technique.TIME_BLIND, "; sleep 3", unknown) is True
    assert payload_fits_context(Technique.PATH_TRAVERSAL_READ, "../../etc/passwd", unknown) is True


# ---------------------------------------------------------------------------
# build_probes：绑定成功后候选集塌缩
# ---------------------------------------------------------------------------


def test_绑定成功后候选塌缩且标记为逐点(tmp_path: Path) -> None:
    """绑定成功 → 每个模板一条（不再是 30+ 个猜出来的注入点），且 `bound_to_finding=True`。"""
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/search")
        def search():
            q = request.args.get("q", "1")
            cursor.execute("SELECT id, name FROM products WHERE id = " + q)
        """,
    )
    # 污点路径里带上若干个**推导得出的**参数名：未绑定时它们会各自变成一个候选，
    # 绑定之后它们全部作废（路由与参数都已经是从源码里读出来的事实）。
    steps = (
        _step("request.args.get", 6),
        _step("request.args.get('p1')", 6),
        _step("request.args.get('p2')", 6),
        _step("cursor.execute", 7, "sink"),
    )
    finding = _finding(*steps)

    bound = build_probes(finding, vuln_id=1, src_root=root)
    unbound = build_probes(finding, vuln_id=1)  # 不给 src_root = 原行为

    assert len(bound.probes) == 2, "sqli 两条模板，绑定后各一条"
    assert all(p.bound_to_finding for p in bound.probes)
    assert all(p.url_path == "/search" for p in bound.probes)
    assert all(p.param_name == "q" for p in bound.probes)
    assert all(p.payload_fits_context for p in bound.probes)
    # 未绑定时仍是张量积 —— 上游推导出来的注入点照样试（这正是漏洞的来源）
    assert len(unbound.probes) > len(bound.probes)
    assert not any(p.bound_to_finding for p in unbound.probes)


def test_绑定到_string_上下文时载荷被标为不适配(tmp_path: Path) -> None:
    """**这是路由绑定自己会引入的新假阴性，必须被挡住。**

    绑定对了端点、也送对了参数，但 `1 AND 1=1` 落进 `username = '…'`
    会被拼成一条**合法但恒假**的 SQL —— 不挡住的话，`/admin/login` 的
    两条真注入会从 `verified` 变成 `rejected`，比不绑定还糟。
    """
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/admin/login", methods=["POST"])
        def admin_login():
            username = request.form.get("username", "")
            cursor.execute("SELECT role FROM users WHERE username = '" + username + "'")
        """,
    )
    finding = _finding(_step("request.form.get", 6), _step("cursor.execute", 7, "sink"))

    plan = build_probes(finding, vuln_id=1, src_root=root)

    assert plan.probes, "探针照样要发出去 —— 万一命中了，那是真证据"
    assert all(p.bound_to_finding for p in plan.probes)
    assert all(p.payload_fits_context is False for p in plan.probes)


def test_绑定成功时路径探针带上载荷占位(tmp_path: Path) -> None:
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask
        app = Flask(__name__)

        @app.route("/uploads/<path:name>")
        def serve_upload(name):
            return send_file(os.path.join(UPLOAD_DIR, name))
        """,
    )
    finding = _finding(_step("name", 5), _step("send_file", 6, "sink"), vuln_type="path_traversal")

    plan = build_probes(finding, vuln_id=1, src_root=root)

    assert plan.probes
    assert all(p.url_path == f"/uploads/{PATH_PAYLOAD_SLOT}" for p in plan.probes)
    assert all(p.inject_in is InjectIn.PATH for p in plan.probes)


# ---------------------------------------------------------------------------
# 跨模块契约
# ---------------------------------------------------------------------------


def test_路径参数_snippet_与分析器一致() -> None:
    """`routes.PATH_PARAM_SNIPPET` 认的字符串必须与 `analysis/taint.py` 产出的**逐字一致**。

    两边约定同一个中文串是有点脆的 —— 所以这里钉住它。分析器改了措辞、
    这里没跟上，路径参数的绑定会静默失效（snippet 认不出 → 退回默认参数名 →
    打在不读该参数的 URL 上 → 又是一次"没测到被读成不存在"）。
    """
    from app.analysis.taint import __file__ as taint_file

    source = Path(taint_file).read_text(encoding="utf-8")
    assert "路径模板参数" in source, "分析器里已经找不到这个合成 snippet 了"

    from app.verify.routes import PATH_PARAM_SNIPPET

    assert PATH_PARAM_SNIPPET.match("路径模板参数 name")


def test_绑定不引入_analysis_之外的依赖() -> None:
    """`app/verify/` 只依赖 `app.analysis.parser`（纯语法层），
    **不依赖 `app.analysis` 的分析结果**。

    理由：B5 拿到的 finding 已经是分析产物了，再回去调分析器的规则引擎
    等于让验证阶段重跑一遍静态分析 —— 而且会引入"验证与发现用不同版本规则"
    的不一致。这里只用它的 tree-sitter 封装。
    """
    src = (Path(__file__).resolve().parents[1] / "app" / "verify" / "routes.py").read_text(
        encoding="utf-8"
    )
    assert "from app.analysis.parser import" in src
    assert "analyze_project" not in src
    assert "from app.analysis import" not in src


@pytest.mark.parametrize(
    "declared, expected",
    [
        ("def route(): pass", None),
        ("@app.route('/x')", None),  # 没有函数体，不是路由处理函数
    ],
)
def test_非路由装饰器不当路由(tmp_path: Path, declared: str, expected: None) -> None:
    """**封闭集合**：不是路由装饰器的一律不当路由，宁可绑不上也不误绑。"""
    root, reader = _app(tmp_path, f"{declared}\n")
    assert bind_route(reader, _finding(_step("x", 1))) is None


def test_三列目标上_unio_载荷按列数构造(tmp_path: Path) -> None:
    """目标 SELECT 是三列时，UNION 载荷**也必须是三列**。

    `SELECT id, name, price FROM products` 上打两列的 UNION，数据库报
    `SELECTs … do not have the same number of result columns` ——
    命中不了，而响应长得跟"这里没有注入"一样。

    修之前：模板把列数写死成 2，所以这条 finding 在**列数不是 2 的任何目标上**
    都只能落 `unverified`；而且 `payload_fits_context` 会如实判"不适配"，
    意味着连"未命中可证伪"都拿不到，只能停在"没能确认"。

    修之后：列数取自 `ctx.columns`（从这条 finding 自己的 SQL 前缀数出来），
    载荷按目标的形状构造，于是 `payload_fits_context` 是 True，
    未命中**构成证伪**。
    """
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/orders")
        def orders():
            oid = request.args.get("order_id", "1")
            cursor.execute("SELECT order_no, amount, status FROM orders WHERE id = " + oid)
        """,
    )
    finding = _finding(_step("request.args.get", 6), _step("cursor.execute", 7, "sink"))

    plan = build_probes(finding, vuln_id=1, src_root=root)
    union = next(p for p in plan.probes if p.technique is Technique.UNION_EXTRACT)

    assert union.payload.count("'asa'") == 2, (
        f"三列目标应补到三列（nonce + 两个填充），实际载荷 {union.payload!r}"
    )
    assert union.nonce in union.payload, "第一列必须仍是 nonce —— 指纹靠它找证据"
    assert union.payload_fits_context is True, "列数对上之后，未命中就构成证伪了"


def test_sql_列数读不出来时退回模板的两列(tmp_path: Path) -> None:
    """列数读不出来 → 退回模板原形状，且**如实**标为不适配。

    "读不出就不改"是刻意的：宁可少一次证伪，也不要按猜出来的列数发载荷。
    这里钉住的是"退回"这件事本身 —— 退回之后 `payload_fits_context` 应当是
    False（因为读不出列数时 `ctx.columns` 是 None），而不是被悄悄当成适配。
    """
    root, reader = _app(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/raw")
        def raw():
            q = request.args.get("q", "1")
            cursor.execute("SELECT * FROM t WHERE id = " + q)
        """,
    )
    finding = _finding(_step("request.args.get", 6), _step("cursor.execute", 7, "sink"))

    plan = build_probes(finding, vuln_id=1, src_root=root)
    union = next(p for p in plan.probes if p.technique is Technique.UNION_EXTRACT)

    assert union.payload.endswith("'asa' -- "), "退回模板的两列形态"
    assert union.payload_fits_context is False, "读不出列数就不该自称适配"
