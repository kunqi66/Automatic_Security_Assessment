"""B4 污点追踪引擎的端到端测试（设计文档 §8 验收清单）。

**样例代码全部以字符串字面量注入**，不从磁盘读靶场：改一行源码就能改一个断言，
测试文件本身就是「哪些形态会报、哪些不会」的可执行说明书。

**负例与正例同等重要**。静态污点分析这类工具的死穴不是漏报，是误报 ——
一个把参数化查询、`shell=False`、白名单校验都报出来的工具，用户会在
第三份报告之后就不再打开它。所以本文件的结构是：

| 分组 | 在验什么 | 失败意味着 |
|---|---|---|
| 正例 | 每种漏洞类型都能追上，且 `taint_path` 首跳是 source、末跳是 sink | 漏报 |
| 负例 | 参数化查询 / 安全 Loader / 强弱净化 / 白名单守卫 / 鉴权检查 | **误报** |
| 跨函数 | 一层的展开、调用点匹配、未展开的显式标注 | 「跨文件就查不出」 |
| 边界 | 文件数超限、超大文件、语法错误 | 大仓库上崩掉或静默丢结果 |
| 契约 | `analyze(manifest, read_source)` 同步/异步回调 | B3 接不上 |
"""

from __future__ import annotations

import pytest

from app.analysis import analyze, analyze_sources
from app.analysis.types import AnalysisResult, Finding, VulnType
from app.models.enums import DetectionMethod, TaintStepType

# ---------------------------------------------------------------------------
# 断言助手
# ---------------------------------------------------------------------------

PY = "app.py"


def _run(source: str, **kwargs: object) -> AnalysisResult:
    return analyze_sources({PY: source}, **kwargs)  # type: ignore[arg-type]


def _of(result: AnalysisResult, vuln_type: VulnType) -> list[Finding]:
    return [finding for finding in result.findings if finding.vuln_type is vuln_type]


def _only(source: str, vuln_type: VulnType) -> Finding:
    result = _run(source)
    matching = _of(result, vuln_type)
    assert len(matching) == 1, (
        f"期望恰好 1 条 {vuln_type.value}，实际 {len(matching)} 条；"
        f"全部产出：{[(f.vuln_type.value, f.line_start) for f in result.findings]}"
    )
    return matching[0]


def _assert_path_shape(finding: Finding) -> None:
    """污点路径的**结构契约**（设计文档 §3.4 的补丁复验锚点）。

    首跳必须是 source、末跳必须是 sink：补丁复验时靠这两跳的身份
    （行号 + 符号名）判断「同一条路径还在不在」，这里标错会让复验结论整体反向。
    """
    path = finding.taint_path
    assert path, "taint_path 为空"
    assert path[0].step_kind is TaintStepType.SOURCE, f"首跳不是 source：{path[0]}"
    assert path[-1].step_kind is TaintStepType.SINK, f"末跳不是 sink：{path[-1]}"
    assert [step.step_index for step in path] == list(range(len(path))), (
        "step_index 必须从 0 连续编号"
    )
    assert all(step.file_path == PY for step in path)
    assert all(step.line > 0 for step in path)
    assert all(step.snippet for step in path), "每一跳都要带源码片段（前端高亮用）"
    assert finding.file_path == path[-1].file_path
    assert finding.line_start == path[-1].line


# ---------------------------------------------------------------------------
# 正例：每种漏洞类型
# ---------------------------------------------------------------------------


def test_sql_injection_positive() -> None:
    finding = _only(
        """
from flask import request
def order():
    uid = request.args.get("id")
    cur = connect().cursor()
    cur.execute("select * from orders where id = " + uid)
""",
        VulnType.SQL_INJECTION,
    )
    _assert_path_shape(finding)
    assert finding.taint_path[0].symbol == "request.args.get"
    assert finding.taint_path[-1].symbol == "cur.execute"
    assert finding.cwe_id == "CWE-89"
    assert finding.cvss_score == 9.1
    assert finding.detection_method is DetectionMethod.TAINT_INTRA
    assert finding.guard_blocked is False
    assert finding.confidence == pytest.approx(0.9)


def test_chained_call_sink_is_detected() -> None:
    """链式调用 `sqlite3.connect("d").cursor().execute(...)` 的 sink 必须命中。

    接收者本身是另一个调用（`connect("d").cursor()`）时，解析不出「点分名」——
    而这条写法在真实代码里到处都是。只看完整点分名的话，这类 sink 会被整体漏掉，
    且**不报错**（表现为「有些文件一个漏洞都没有」）。
    """
    finding = _only(
        """
from flask import request
def order():
    uid = request.args.get("id")
    sqlite3.connect("d").cursor().execute("select * from orders where id = " + uid)
""",
        VulnType.SQL_INJECTION,
    )
    assert finding.taint_path[-1].symbol.endswith("execute")


def test_with_open_is_detected() -> None:
    """`with open(path) as fh:` 的上下文表达式本身可能就是 sink。

    tree-sitter 的层级是 `with_statement → with_clause → with_item`（三层），
    只遍历一层会让这条最常见的路径穿越写法永远不被求值。
    """
    finding = _only(
        """
from flask import request
def download():
    name = request.args.get("file")
    with open("/srv/data/" + name) as fh:
        return fh.read()
""",
        VulnType.PATH_TRAVERSAL,
    )
    assert finding.line_start == 5


def test_fstring_and_format_sql_are_detected() -> None:
    """f-string 与 `.format()` 是最常见的两种拼接写法，必须是正例。

    它们与 `+` 拼接在 AST 上完全不同（`string` → `interpolation`），
    只按二元运算找拼接的实现会把这两类全漏掉，而它们在现代代码里
    比 `+` 更常见。
    """
    fstring = _only(
        """
from flask import request
def order():
    uid = request.args.get("id")
    cursor.execute(f"select * from orders where id = '{uid}'")
""",
        VulnType.SQL_INJECTION,
    )
    assert fstring.line_start == 5

    formatted = _only(
        """
from flask import request
def order():
    uid = request.args.get("id")
    cursor.execute("select * from orders where id = '{}'".format(uid))
""",
        VulnType.SQL_INJECTION,
    )
    assert formatted.line_start == 5


def test_command_injection_positive() -> None:
    finding = _only(
        """
import os
from flask import request
def ping():
    os.system("ping -c 1 " + request.args.get("host"))
""",
        VulnType.COMMAND_INJECTION,
    )
    _assert_path_shape(finding)
    assert finding.cwe_id == "CWE-78"
    assert finding.cvss_score == 9.8
    # RCE 类置信度 ×1.1（设计文档 §4.5）
    assert finding.confidence == pytest.approx(0.99)


@pytest.mark.parametrize(
    ("label", "call"),
    [
        ("subprocess.run", 'subprocess.run("ls " + request.args.get("p"), shell=True)'),
        ("subprocess.check_output", "subprocess.check_output(cmd, shell=True)"),
        ("subprocess.Popen", "subprocess.Popen(cmd, shell=True)"),
    ],
)
def test_subprocess_shell_true_is_detected(label: str, call: str) -> None:
    """⚠️ 这一条是**补上一个漏掉的测试**，不是补功能。

    `os.system` 不带 `requires_shell` 条件，所以它能报出来；
    `subprocess.*` 五个符号都带 —— 而判定 `shell=True` 的
    `_has_shell_true()` 原先比的是 `value.type == "boolean"`，
    tree-sitter-python 给布尔字面量的节点类型其实是 **`"true"`**，
    于是那个函数**恒为 False**，`subprocess.*` 的命令注入一条都报不出来。

    这个错误能潜伏，是因为原有的反例
    （`subprocess.run([...], shell=False)`）**通过的原因不是它写对了**，
    而是 shell 参数压根没被识别 —— 一个因为错误原因而通过的反例，
    比没有反例更糟：它让人以为这条路径已经被覆盖了。

    所以这里三个 `subprocess.*` 符号各来一条正例。少了任何一条，
    剩下的两条仍然会在符号表变化时静默失效。
    """
    finding = _only(
        f"""
import subprocess
from flask import request
def run():
    cmd = "ls " + request.args.get("p")
    {call}
""",
        VulnType.COMMAND_INJECTION,
    )
    assert finding.sink_kind in {"subprocess.run", "subprocess.check_output", "subprocess.Popen"}
    assert finding.confidence == pytest.approx(0.99)


def test_subprocess_without_shell_is_not_detected() -> None:
    """反例的**正确**写法：不带 `shell` 关键字（默认就是 False）。

    它与上面那条正例成对存在：一个证明 `shell=True` 被识别，
    一个证明"没写 shell"不会被误报。只有反例时，两者都无法区分。
    """
    findings = _of(
        _run(
            """
import subprocess
from flask import request
def run():
    subprocess.run(["ls", request.args.get("p")])
""",
        ),
        VulnType.COMMAND_INJECTION,
    )
    assert findings == []


def test_path_traversal_positive() -> None:
    finding = _only(
        """
from flask import request
def download():
    name = request.args.get("file")
    return open("/srv/data/" + name).read()
""",
        VulnType.PATH_TRAVERSAL,
    )
    _assert_path_shape(finding)
    assert finding.cwe_id == "CWE-22"
    assert finding.cvss_score == 7.5


def test_deserialization_positive() -> None:
    finding = _only(
        """
import pickle
from flask import request
def load():
    return pickle.loads(request.data)
""",
        VulnType.DESERIALIZATION,
    )
    _assert_path_shape(finding)
    assert finding.cwe_id == "CWE-502"
    assert finding.confidence == pytest.approx(0.99)


def test_file_upload_positive() -> None:
    finding = _only(
        """
from flask import request
def upload():
    f = request.files["f"]
    f.save("/srv/uploads/" + f.filename)
""",
        VulnType.FILE_UPLOAD,
    )
    _assert_path_shape(finding)
    assert finding.cwe_id == "CWE-434"


def test_xss_positive() -> None:
    finding = _only(
        """
from markupsafe import Markup
from flask import request
def page():
    return Markup("<b>" + request.args.get("n") + "</b>")
""",
        VulnType.XSS,
    )
    _assert_path_shape(finding)
    assert finding.cwe_id == "CWE-79"


def test_every_finding_carries_derived_fields() -> None:
    """派生字段（标题 / CWE / 向量 / 分数 / 严重度）必须成套出现且互相自洽。

    这些字段与漏洞事实无关，纯由 `vuln_type` 派生 —— 一旦某个调用方绕过
    `finding.py` 自己组装，就会出现「标题说 SQL 注入、CWE 是 79」这种
    只有人眼能发现的错位。
    """
    result = _run(
        """
import os, pickle
from flask import request
def a():
    os.system("x " + request.args.get("c"))
def b():
    return pickle.loads(request.args.get("p"))
"""
    )
    assert result.findings, "样例应当至少产出 2 条 Finding"
    for finding in result.findings:
        assert finding.title
        assert finding.cwe_id and finding.cwe_id.startswith("CWE-")
        assert finding.cvss_vector.startswith("CVSS:3.1/")
        assert 0.0 <= finding.cvss_score <= 10.0
        assert 0.0 <= finding.confidence <= 1.0
        assert finding.rule_id == finding.vuln_type.value
        assert finding.source_kind
        assert finding.sink_kind
        assert finding.code_snippet
        _assert_path_shape(finding)


# ---------------------------------------------------------------------------
# 负例：误报防线（与正例同等重要）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "参数化查询",
            """
from flask import request
def order():
    uid = request.args.get("id")
    cursor.execute("select * from orders where id = ?", (uid,))
""",
        ),
        (
            "命名占位符",
            """
from flask import request
def order():
    uid = request.args.get("id")
    cursor.execute("select * from orders where id = %(uid)s", {"uid": uid})
""",
        ),
        (
            "SQL 文本本身是常量",
            """
def report(cursor):
    cursor.execute("select count(*) from orders")
""",
        ),
        (
            "shell=False 的列表传参",
            """
import subprocess
from flask import request
def run():
    subprocess.run(["ls", request.args.get("p")], shell=False)
""",
        ),
        (
            "SafeLoader",
            """
import yaml
from flask import request
def load():
    return yaml.load(request.data, Loader=yaml.SafeLoader)
""",
        ),
        (
            "safe_load",
            """
import yaml
from flask import request
def load():
    return yaml.safe_load(request.data)
""",
        ),
        (
            "int() 强制转型（SQLi）",
            """
from flask import request
def order():
    uid = int(request.args.get("id"))
    cursor.execute("select * from orders where id = %d" % uid)
""",
        ),
        (
            "路径只由常量拼成",
            """
def read():
    return open("/srv/data/report.csv").read()
""",
        ),
        (
            "ORM 查询接口",
            """
from flask import request
def me():
    return Order.query.filter_by(id=request.args.get("id")).first()
""",
        ),
    ],
)
def test_negative_samples_produce_no_finding(name: str, source: str) -> None:
    result = _run(source)
    assert result.findings == (), (
        f"负例「{name}」被误报："
        f"{[(f.vuln_type.value, f.line_start, f.symbol) for f in result.findings]}"
    )


def test_whitelist_guard_neutralizes_sql_injection() -> None:
    """白名单守卫（`if x not in ALLOWED: return`）是完全中和，不该产出 Finding。

    这条负例同时钉住一个实现陷阱：守卫写进环境后，**终止分支不能参与合并**。
    若在 if 之后把「if 之前的旧状态」也合并进来，`sanitized_types` 求交集
    会把守卫的标记抹掉 —— 表现就是「白名单写了照样报」。
    """
    result = _run(
        """
from flask import request

ALLOWED = {"id", "name", "created_at"}

def report():
    column = request.args.get("col")
    if column not in ALLOWED:
        return "bad request", 400
    cursor.execute("select " + column + " from orders")
"""
    )
    assert result.findings == ()


def test_shlex_quote_neutralizes_command_injection() -> None:
    result = _run(
        """
import os, shlex
from flask import request
def run():
    os.system("grep " + shlex.quote(request.args.get("p")) + " /var/log/app.log")
"""
    )
    assert result.findings == ()


def test_basename_neutralizes_path_traversal_only() -> None:
    """同一个净化函数对**不同漏洞类型的效力不同** —— 这是设计文档 §4.4 的核心。

    `os.path.basename()` 把路径里最后一个 `/` 之前的部分全部丢掉，
    对路径穿越是完全中和；但它对 SQL 注入毫无作用（`basename("1; DROP")`
    原样返回）。按「净化函数 ⇒ 全线安全」实现的引擎会在这里放走一个真漏洞。
    """
    traversal = _run(
        """
import os
from flask import request
def download():
    name = os.path.basename(request.args.get("file"))
    return open("/srv/data/" + name).read()
"""
    )
    assert traversal.findings == (), "basename 足以中和路径穿越"

    sqli = _only(
        """
import os
from flask import request
def order():
    uid = os.path.basename(request.args.get("id"))
    cursor.execute("select * from orders where id = " + uid)
""",
        VulnType.SQL_INJECTION,
    )
    # 仍然报：basename 的中和范围不含 SQLi，所以它**不是** partial（不打折），
    # 而是「与此类型无关的净化」—— 置信度保持原值，不做任何暗示。
    assert sqli.guard_blocked is False
    assert sqli.confidence == pytest.approx(0.9)


def test_weak_sanitizer_reports_with_guard_blocked() -> None:
    """弱净化（`str()` / `.strip()`）：**仍然报**，但降级标注。

    这是「报还是不报」的第三种答案：不能当没看见（载荷照样进去），
    也不能给满置信度（它确实改过值）。落地方式就是
    `guard_blocked=True` + `confidence ×0.6`。
    """
    finding = _only(
        """
import os
from flask import request
def run():
    cmd = str(request.args.get("c")).strip()
    os.system("run " + cmd)
""",
        VulnType.COMMAND_INJECTION,
    )
    assert finding.guard_blocked is True
    # 0.9 × 0.6(partial) × 1.1(rce) = 0.594
    assert finding.confidence == pytest.approx(0.594)
    assert [step.step_kind for step in finding.taint_path].count(TaintStepType.SANITIZE) == 2


# ---------------------------------------------------------------------------
# 输入通道与 source 形态
# ---------------------------------------------------------------------------


def test_multiple_input_channels_are_sources() -> None:
    """Flask 的 header / cookie、通用 env / stdin 都要能作为 source。

    通道集合是设计文档 §3.3 冻结的 —— 每条 Finding 的 `source_kind`
    必须落在这个集合里，否则前端按通道过滤会漏掉一整类。
    """
    result = _run(
        """
import os
from flask import request
def run():
    os.system("deploy " + request.headers.get("X-Target") + request.cookies.get("t"))
    os.system("release " + os.environ.get("TARGET"))
def read_stdin():
    os.system("run " + input())
"""
    )
    # `source_kind` 是**通道**（设计文档 §3.3 冻结的 CHANNELS），不是符号名 ——
    # 符号名在 `taint_path[0].symbol` 里，两处重复存同一串没有意义。
    channels = {finding.source_kind for finding in result.findings}
    assert channels == {"header", "env", "stdin"}
    symbols = {finding.taint_path[0].symbol for finding in result.findings}
    assert symbols == {"request.headers.get", "os.environ.get", "input"}
    assert len(result.findings) == 3


def test_second_order_flow_from_database() -> None:
    """二阶注入：从库里读回来的数据再进 sink（PRD §7.1 ③ 明确要求）。"""
    finding = _only(
        """
from flask import request
def purge():
    cursor = connect().cursor()
    cursor.execute("select name from users where id = ?", (request.args.get("id"),))
    row = cursor.fetchone()
    cursor.execute("delete from logs where user = '" + row[0] + "'")
""",
        VulnType.SQL_INJECTION,
    )
    assert finding.taint_path[0].symbol == "cursor.fetchone"
    assert finding.line_start == 7


# ---------------------------------------------------------------------------
# 跨函数（一层）
# ---------------------------------------------------------------------------


CROSS_FUNCTION = """
import sqlite3
from flask import request

def query_order(uid):
    cur = sqlite3.connect("d").cursor()
    cur.execute("select * from orders where id = " + uid)
    return cur.fetchall()

def view():
    return query_order(request.args.get("id"))
"""


def test_inter_procedural_depth_one() -> None:
    """一层跨函数：路径要完整串起 source → 调用点 → 形参 → sink。"""
    finding = _only(CROSS_FUNCTION, VulnType.SQL_INJECTION)
    _assert_path_shape(finding)
    kinds = [step.step_kind for step in finding.taint_path]
    assert kinds[1] is TaintStepType.PROPAGATE  # 调用点
    assert kinds[2] is TaintStepType.PROPAGATE  # 形参入口
    assert finding.detection_method is DetectionMethod.TAINT_INTER
    # 跨函数再打一次折：0.9 × 0.9
    assert finding.confidence == pytest.approx(0.81)
    assert finding.file_path == PY


def test_inter_procedural_sanitized_at_call_site() -> None:
    """净化发生在**调用点**时同样要生效（不能只看被调用函数体内）。"""
    result = _run(
        CROSS_FUNCTION.replace("query_order(request.args.get", "query_order(int(request.args.get")
    )
    assert result.findings == ()


def test_inter_procedural_sanitized_inside_callee() -> None:
    result = _run(
        """
import sqlite3
from flask import request

def query_order(uid):
    sql = int(uid)
    sqlite3.connect("d").cursor().execute("select " + sql)

def view():
    query_order(request.args.get("id"))
"""
    )
    assert result.findings == ()


def test_inter_procedural_method_call_via_self() -> None:
    """`self.query(...)` 这类方法调用要能跨方法展开（形参名一律叫 `request`
    是 Flask 约定，别名解析见 `_request_aliases`）。"""
    finding = _only(
        """
import sqlite3
from flask import request

class Repo:
    def query(self, uid):
        sqlite3.connect("d").cursor().execute("select * from t where id = " + uid)

    def handle(self, request):
        self.query(request.args.get("id"))
""",
        VulnType.SQL_INJECTION,
    )
    assert finding.detection_method is DetectionMethod.TAINT_INTER
    assert finding.taint_path[1].symbol == "self.query"


def test_utility_function_return_value_flows() -> None:
    """`def build(uid): return "select " + uid` 这类**不落 sink** 的工具函数，
    其返回值必须能把污点带出去。

    摘要生成若把 `returns_tainted` 与「体内有没有 sink 流」绑在一起，
    这个函数就会被判成「返回值干净」，`q = build(uid); execute(q)` 整条链
    静默消失 —— 而「拼 SQL 的工具函数 + 调用点执行」是真实项目里最常见的形状之一。
    """
    finding = _only(
        """
from flask import request

def build_query(uid):
    return "select * from orders where id = " + uid

def view():
    sql = build_query(request.args.get("id"))
    cursor.execute(sql)
""",
        VulnType.SQL_INJECTION,
    )
    assert finding.line_start == 9
    assert finding.taint_path[-1].symbol == "cursor.execute"


def test_function_without_return_does_not_leak_taint() -> None:
    """没有 return 的函数，返回值不可能带污点 —— 不能把实参污点穿过去。

    `q = setup(uid)` 里的 `q` 是 `None`；继续把它当脏值会让紧随其后的
    `execute(q)` 变成纯误报。
    """
    result = _run(
        """
import sqlite3
from flask import request

def setup(uid):
    sqlite3.connect("d").cursor().execute("select " + uid)

def view():
    q = setup(request.args.get("id"))
    sqlite3.connect("d").cursor().execute(q)
"""
    )
    # 只有 setup 内部那一处（经摘要匹配）成立
    assert len(result.findings) == 1
    assert result.findings[0].line_start == 6


def test_deeper_chain_is_marked_unexpanded() -> None:
    """第二层不展开，但**必须显式标注**而不是静默丢弃。

    「未展开」与「没有漏洞」在报告里是两件事：前者要注明
    「调用链更深、静态未展开」，后者才能说「没查到」。
    """
    result = _run(
        """
import sqlite3
from flask import request

def deepest(uid):
    return sqlite3.connect("d").cursor().execute("select " + uid).fetchall()

def middle(uid):
    q = deepest(uid)
    sqlite3.connect("d").cursor().execute(q)

def view():
    middle(request.args.get("id"))
"""
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.unexpanded is True
    assert result.unexpanded_calls == 1
    assert finding.taint_path[-1].symbol == "execute"


# ---------------------------------------------------------------------------
# pattern 类规则（非数据流）
# ---------------------------------------------------------------------------


def test_idor_positive_and_authz_negative() -> None:
    """IDOR 是**平行越权**，数据流水到 sink 不是它的成立条件。

    因此它必须靠「路由参数 + 用它查库 + 没有任何鉴权证据」这套形态规则，
    而不是污点；而**鉴权检查存在时必须不报** —— 这正是这类规则
    最容易变成噪声的地方（每个「用 id 查自己的订单」的正常接口都会被报）。
    """
    result = _run(
        """
from flask import Flask, request

app = Flask(__name__)

@app.get("/orders/<int:oid>")
def get_order(oid):
    row = Order.query.get(oid)
    return {"order": row}

@app.get("/me/<int:uid>")
def get_me(uid):
    if current_user.id != uid:
        return "forbidden", 403
    return {"me": uid}
"""
    )
    idor = _of(result, VulnType.IDOR)
    assert len(idor) == 1, "只该报没有鉴权的那条路由"
    assert idor[0].file_path == PY
    assert idor[0].sink_symbol in {"oid", "query", "get_order"}
    assert idor[0].detection_method is DetectionMethod.PATTERN
    assert idor[0].confidence < 0.9, "形态规则的置信度应当低于数据流规则"


def test_idor_authz_evidence_via_fastapi_dependency_alias() -> None:
    """FastAPI 的权限依赖常常先定义成**类型别名**再到处用：

    ```python
    ProjectViewer = Annotated[User, Depends(require(Permission.PROJECT_VIEW))]
    async def get_project(project_id: int, viewer: ProjectViewer) -> ProjectOut: ...
    ```

    鉴权证据全在模块级赋值里，函数签名上只剩一个名字。只看签名与函数体的话，
    这类接口会被整片判成「没有任何鉴权痕迹」—— 实测自扫本仓库时，
    21 条 IDOR 里有 19 条是这一种，噪声足以让整条规则被人关掉。
    """
    result = _run(
        """
from fastapi import APIRouter, Depends
from typing import Annotated

router = APIRouter()
ProjectViewer = Annotated[User, Depends(require(Permission.PROJECT_VIEW))]

@router.get("/projects/{project_id}")
async def get_project(project_id: int, user: ProjectViewer):
    return await ProjectService(session).get(project_id)

@router.get("/invoices/{invoice_id}")
async def get_invoice(invoice_id: int):
    return await InvoiceService(session).get(invoice_id)
"""
    )
    idor = _of(result, VulnType.IDOR)
    assert [finding.sink_symbol for finding in idor] == ["invoice_id"], (
        "别名注入的权限依赖必须被认出来"
    )


def test_unauth_access_positive_and_four_negatives() -> None:
    """未授权访问（V6）与 IDOR 同源，但**四条负例必须都不报** —— 这才是重点。

    「无鉴权装饰器的路由」在一个真实项目里是**大多数**，所以这条规则的
    精度不取决于正例，取决于负例拦不拦得住：

    * 登录端点**本该**匿名可达 —— 报它是最吵的误报；
    * 公开数据（商品）不算 —— 报它规则会在每个项目上刷屏然后被关掉；
    * 有鉴权痕迹的不报（复用 IDOR 那套「宽进」匹配）；
    * **写操作不报** —— 未授权*修改*是另一个类别，本项目暂无规则覆盖它。
    """
    result = _run(
        """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/user/list")
def list_users():
    cur = db.cursor()
    cur.execute("SELECT id, username, phone, email FROM users ORDER BY id")
    return jsonify(cur.fetchall())

@app.route("/api/login", methods=["POST"])
def login():
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE name = ?", (request.form["u"],))
    return jsonify(cur.fetchall())

@app.route("/api/products")
def list_products():
    cur = db.cursor()
    cur.execute("SELECT id, name, price FROM products")
    return jsonify(cur.fetchall())

@app.route("/api/orders", methods=["POST"])
def update_order():
    cur = db.cursor()
    cur.execute("UPDATE users SET nickname = ? WHERE id = ?", ("x", 1))
    return jsonify({"ok": True})

@login_required
@app.route("/api/accounts")
def list_accounts():
    cur = db.cursor()
    cur.execute("SELECT id, email FROM accounts")
    return jsonify(cur.fetchall())
"""
    )
    unauth = _of(result, VulnType.UNAUTH_ACCESS)
    assert [finding.sink_symbol for finding in unauth] == ["users"], (
        "只该报「无鉴权 + 读账号表 + 只读」的那一条"
    )
    assert unauth[0].detection_method is DetectionMethod.PATTERN
    assert unauth[0].confidence < 0.9, "缺席证明的置信度应当低于数据流规则"


def test_unauth_access_skips_routes_that_also_write() -> None:
    """「先读后写」的路由**不报** —— 不是漏，是影响方向变了。

    `SELECT ... FROM users` 之后紧跟一句 `UPDATE users`，这条端点的真实风险是
    **未授权修改**，而本类别只覆盖只读暴露（CVSS 的 `I:N`）。

    硬报成未授权访问会把 `I:N` 印在一条实际能改数据的 finding 上 ——
    **比不报更坏**：读者会据此认为"最多被读走"，而那是错的。
    未授权修改是另一个类别，本项目暂无规则覆盖它，这里如实排除。

    ⚠️ 这条用例是补出来的：`_has_write_sql` 原本**没有任何用例覆盖** ——
    因为"只写不读"的路由会被 `_account_read` 先挡掉，碰不到这里。
    把这个判断删掉，测试照样全绿（做过变异验证）。真正能碰到它的
    只有"又读又写"这一种形状。
    """
    result = _run(
        """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/user/deactivate", methods=["POST"])
def deactivate():
    cur = db.cursor()
    cur.execute("SELECT id, role FROM users WHERE id = ?", (request.form["id"],))
    if cur.fetchone():
        cur.execute("UPDATE users SET active = 0 WHERE id = ?", (request.form["id"],))
    return jsonify({"ok": True})
"""
    )
    assert _of(result, VulnType.UNAUTH_ACCESS) == [], (
        "又读又写的路由不该被报成只读型的未授权访问"
    )


def test_unauth_access_and_idor_never_double_report() -> None:
    """一条端点只被其中**一条**规则报 —— 判据 4 就是这条分界线。

    带 id 形参 = 「认了人但没校验这个资源是不是他的」→ IDOR。
    不带 id 形参 = 「压根没问来人是谁，整张表端出去」→ 未授权访问。

    两者都报会让同一处代码在报告里出现两次、算两条 finding ——
    分母被撑大，而且复核者会以为是两个问题。
    """
    result = _run(
        """
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/api/user/<int:user_id>/profile")
def get_profile(user_id):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return jsonify(cur.fetchone())

@app.route("/api/user/<int:account_id>/orders")
def get_orders(account_id):
    cur = db.cursor()
    cur.execute("SELECT * FROM orders WHERE uid = ?", (account_id,))
    cur.execute("SELECT count(*) FROM accounts")
    return jsonify(cur.fetchall())
"""
    )
    idor = _of(result, VulnType.IDOR)
    unauth = _of(result, VulnType.UNAUTH_ACCESS)
    assert [f.file_path for f in idor] == [PY, PY], "两条带 id 形参的都归 IDOR"
    assert unauth == [], "带 id 形参（或路由路径形参）的不许再报未授权访问"


def test_unauth_access_ignores_sql_mentioned_in_docstring() -> None:
    """SQL 只在 **docstring** 里出现时不算。

    这条钉的是一个具体的实现决定：`_sql_literals` 只认**调用实参**里的字符串。
    扫全文的话，一段说明文字就能凭空造出一条读操作 —— 而且不报错。
    真实触发过一次：靶场自己那些讲缺陷的注释里满是 `SELECT` 和「写入」。
    """
    result = _run(
        '''
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/api/user/list")
def list_users():
    """返回用户列表。

    正常写法是 `SELECT id, username FROM users ORDER BY id`，
    并且这个端点不该对匿名开放。
    """
    return jsonify(cached_users())

@app.route("/api/accounts")
def list_accounts():
    """同样读账号表，但这次是真的读了。"""
    cur = db.cursor()
    cur.execute("SELECT id, email FROM accounts")
    return jsonify(cur.fetchall())
'''
    )
    # 两条函数的 docstring 形态一样，区别只在**函数体里有没有一条真的读操作** ——
    # 所以这个断言同时钉住了两件事：规则是活的，且它不看 docstring。
    assert [f.file_path for f in _of(result, VulnType.UNAUTH_ACCESS)] == [PY]


def test_hardcoded_secret_positive_and_placeholders_negative() -> None:
    result = _run(
        """
import os

DB_PASSWORD = "Pr0d-Passw0rd-2024"
API_KEY = os.getenv("API_KEY", "sk-live-9f8a7b6c5d4e")
PLACEHOLDER_KEY = "your-key-here"
EMPTY_SECRET = ""
SHORT_SECRET = "abc"
SECRET_SINK_KIND = "pattern:literal_secret"
""",
        # 函数体内的硬编码凭据是已知盲区（见 B4 交付报告的精度边界一节）
    )
    secrets = _of(result, VulnType.HARDCODED_SECRET)
    names = sorted(finding.symbol for finding in secrets)
    assert len(secrets) == 2
    assert any("DB_PASSWORD" in name for name in names)
    assert any("API_KEY" in name for name in names)
    assert all(finding.cwe_id == "CWE-798" for finding in secrets)
    # `SECRET_SINK_KIND` 是**规则常量名**（后缀 `_kind`），不是凭据 ——
    # 这类误报在自扫本仓库时真实出现过（规则扫到了自己的规则名）
    assert all("KIND" not in name for name in names)


def test_function_local_secret_is_a_documented_blind_spot() -> None:
    """函数体内的硬编码凭据**目前不报**（只扫模块级）。

    这是一个刻意选择的边界：模块级赋值是「配置泄漏」这一风险的主战场，
    而函数体内的字符串字面量里混着大量非凭据常量（URL 模板、SQL 文本、
    正则）。把它钉成测试，是为了让「漏了」变成「已知且写下来的漏了」。
    """
    result = _run(
        """
def connect():
    password = "hunter2-super-secret"
    return password
"""
    )
    assert _of(result, VulnType.HARDCODED_SECRET) == []


# ---------------------------------------------------------------------------
# FastAPI 路由参数
# ---------------------------------------------------------------------------


def test_fastapi_route_params_are_sources() -> None:
    """FastAPI 的路由参数由框架按签名注入，符号表里与普通局部变量无异。

    识别条件有两个且缺一不可：默认值是 `Query(...)` 这类标注调用，
    **且**参数名出现在路由路径模板里 —— 只有前者会把每个
    `def helper(limit: int = Query(10))` 都当输入源。
    """
    result = _run(
        """
from fastapi import FastAPI, Query

app = FastAPI()

@app.get("/orders/{oid}")
async def get_order(oid: str, req: Request):
    cursor.execute("select * from orders where id = " + oid)

@app.get("/search")
async def search(q: str = Query(...)):
    cursor.execute("select * from docs where body = '" + q + "'")

async def helper(limit: int = Query(10)):
    cursor.execute("select * from docs limit " + str(limit))
"""
    )
    sqli = _of(result, VulnType.SQL_INJECTION)
    assert len(sqli) == 2, "只该报两条真路由，helper 不是路由"
    assert {finding.taint_path[0].symbol for finding in sqli} == {"oid", "q"}


# ---------------------------------------------------------------------------
# 规模与降级（不崩、并且如实记录）
# ---------------------------------------------------------------------------


def test_max_files_truncates_and_records() -> None:
    sources = {f"mod_{index}.py": "import os\n" for index in range(5)}
    result = analyze_sources(sources, max_files=2)
    assert result.truncated is True
    assert result.files_scanned == 2
    assert len(result.files_skipped) == 3
    assert all(record.level == "L2" for record in result.files_skipped)


def test_truncation_is_still_recorded_when_no_file_is_analyzed() -> None:
    result = analyze_sources({"a.py": "import os\n"}, max_files=0)
    assert result.truncated is True
    assert result.files_scanned == 0
    assert result.findings == ()


def test_oversize_file_is_skipped_but_still_scanned_for_secrets() -> None:
    """超大文件降级成「只做行级凭据匹配」，且**记录下来**。

    静默跳过会让「没扫到」被读成「没有漏洞」；而配置类大文件恰恰是
    硬编码凭据的高发地，全部放弃不划算。
    """
    big = 'API_KEY = "sk-live-9f8a7b6c5d4e"\n' + "# padding\n" * 500
    result = _run(big, max_file_bytes=1000)
    secrets = _of(result, VulnType.HARDCODED_SECRET)
    assert len(secrets) == 1
    assert result.files_scanned == 0
    assert result.files_skipped and result.files_skipped[0].level == "L1"


def test_syntax_error_file_is_analyzed_partially_and_recorded() -> None:
    """语法错误的文件不中断整轮：按可解析部分分析 + 记录 L1。

    容错解析（tree-sitter 而非 `ast`）的意义就在这里 —— 真实仓库里
    总有 `.py` 语法有问题的文件（老代码、模板、Python 2 遗留），
    `ast.parse` 会直接抛异常。
    """
    result = _run(
        """
from flask import request
def broken(
    x = 1
def order():
    cursor.execute("select " + request.args.get("id"))
"""
    )
    assert any(record.level == "L1" for record in result.files_skipped)


def test_empty_input_is_safe() -> None:
    result = analyze_sources({})
    assert result.findings == ()
    assert result.files_scanned == 0
    assert result.truncated is False


# ---------------------------------------------------------------------------
# 契约 4：analyze(manifest, read_source)
# ---------------------------------------------------------------------------

VULN_SOURCE = """
from flask import request
def order():
    cursor.execute("select * from orders where id = " + request.args.get("id"))
"""


async def test_analyze_accepts_dict_manifest_and_sync_callback() -> None:
    result = await analyze(
        {
            "entries": [
                {"rel_path": "app.py", "size_bytes": len(VULN_SOURCE), "language": "Python"}
            ],
            "truncated": False,
        },
        lambda rel_path: VULN_SOURCE,
    )
    assert len(result.findings) == 1
    assert result.files_scanned == 1


async def test_analyze_accepts_object_manifest_and_async_callback() -> None:
    """`app/projects/workspace.py::read_source` 是 `async def`，必须直接可用。"""

    class Entry:
        def __init__(self, rel_path: str, language: str = "Python") -> None:
            self.rel_path = rel_path
            self.size_bytes = len(VULN_SOURCE)
            self.language = language

    class Manifest:
        entries = [Entry("app.py"), Entry("notes.md", language="markdown")]
        truncated = False

    async def read_source(rel_path: str) -> str:
        return VULN_SOURCE

    result = await analyze(Manifest(), read_source)
    assert result.files_scanned == 1, "markdown 不该被当成 Python 分析"
    # 断言**被跳过的那个文件**与「有原因」这件事，不断言措辞 ——
    # 措辞会变（原先按语言显示名写，现在按后缀写，见 test_analysis_language_gate），
    # 而断言措辞会让一次正确的文案改进变成一次假失败。
    skipped = {record.path: record.reason for record in result.files_skipped}
    assert "notes.md" in skipped, f"markdown 没被记录为跳过：{skipped}"
    assert skipped["notes.md"]
    assert len(result.findings) == 1


async def test_analyze_records_read_failure_without_failing() -> None:
    def broken(rel_path: str) -> str:
        raise OSError("磁盘读失败")

    result = await analyze({"entries": [{"rel_path": "app.py"}]}, broken)
    assert result.findings == ()
    assert result.files_scanned == 0
    assert result.files_skipped[0].path == "app.py"


async def test_analyze_never_reads_oversize_entry() -> None:
    """清单已给出体积时**不调用回调** —— 读进内存再丢弃是最浪费的降级方式。"""
    calls: list[str] = []

    def read_source(rel_path: str) -> str:
        calls.append(rel_path)
        return VULN_SOURCE

    result = await analyze(
        {"entries": [{"rel_path": "huge.py", "size_bytes": 10_000_000, "language": "Python"}]},
        read_source,
        max_file_bytes=1000,
    )
    assert calls == []
    assert result.files_skipped[0].level == "L1"


async def test_analyze_manifest_truncated_flag_propagates() -> None:
    result = await analyze(
        {
            "entries": [{"rel_path": "app.py", "language": "Python"}],
            "truncated": True,
        },
        lambda rel_path: VULN_SOURCE,
    )
    assert result.truncated is True, "上游已截断的清单必须把旗标传给报告"
