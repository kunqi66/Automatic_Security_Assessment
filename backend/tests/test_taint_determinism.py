"""确定性契约与分层红线（总纲 L1 / L3）的**可执行证明**。

「拿掉 LLM，B4 的结论一字不变」这句话，如果只写在设计文档里，它就是一个愿望。
本文件把它拆成两件可以被机器验证的事：

1. **确定性**：同一份输入跑两次，`findings` 逐字段完全相等（不是「差不多」）；
   文件的枚举顺序、两次调用之间夹着别的分析，都不改变结论。
   —— 这一条挡的是「隐藏状态 / 时间戳 / 字典序依赖」这类**只在长跑时才暴露**
   的不确定性：单测各自都过，一份报告跑两遍数字对不上，是最难解释的故障。

2. **分层**：`app/analysis/` 不 import `app/llm` / `app/db` / `fastapi` /
   `app/orchestrator`。这不是靠 code review 守住的约定，而是本文件用 AST
   扫描源码**逐个 import 检查**出来的 —— 换句话说，红线一旦被越过，测试先红。

为什么这两件事放在一起：它们是同一条铁律的两面。确定性说明「结论只由规则决定」，
分层说明「LLM 够不着这些规则」。只验前者，一个偷偷 import 了 LLM 的实现在
测试环境（LLM 被 mock 成固定输出）里同样能跑出确定性结果。
"""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import app.analysis
from app.analysis import analyze_sources
from app.analysis.sanitizers import SANITIZERS
from app.analysis.sinks import SINKS
from app.analysis.sources import CHANNELS, SOURCES
from app.analysis.types import VulnType

# ---------------------------------------------------------------------------
# 多文件样例：刻意横跨「函数内 / 跨函数 / pattern」三类判定
# ---------------------------------------------------------------------------

VIEWS = """
from flask import request

def get_order():
    uid = request.args.get("id")
    cur = connect().cursor()
    cur.execute("select * from orders where id = " + uid)

def download():
    name = request.args.get("file")
    return open("/srv/data/" + name).read()

@app.get("/orders/<int:oid>")
def show_order(oid):
    return Order.query.get(oid)
"""

MODELS = """
DB_PASSWORD = "Pr0d-Passw0rd-2024"

def find_user(uid):
    return User.query.filter_by(id=uid).first()
"""

UTIL = """
import sqlite3

def run_sql(sql):
    sqlite3.connect("d").cursor().execute(sql)
"""

PROJECT: dict[str, str] = {
    "app/views.py": VIEWS,
    "app/models.py": MODELS,
    "app/util.py": UTIL,
}


def _fingerprint(result: object) -> tuple[object, ...]:
    """把整个结果压成一个可比较的指纹（**不含 `duration_ms`**，见 AnalysisResult 的说明）。"""
    return (
        result.findings,  # type: ignore[attr-defined]
        result.files_scanned,  # type: ignore[attr-defined]
        result.total_loc,  # type: ignore[attr-defined]
        result.truncated,  # type: ignore[attr-defined]
        result.files_skipped,  # type: ignore[attr-defined]
        result.unexpanded_calls,  # type: ignore[attr-defined]
    )


def test_same_input_twice_is_field_identical() -> None:
    first = analyze_sources(PROJECT)
    second = analyze_sources(PROJECT)
    assert first.findings, "样例必须真的产出 Finding，否则这条断言是空转"
    assert _fingerprint(first) == _fingerprint(second)
    # 逐字段断言一次：元组相等已经覆盖了，这里把「逐字段」写出来，
    # 免得将来有人把 Finding 的 __eq__ 改成只看主键。
    for left, right in zip(first.findings, second.findings, strict=True):
        assert left == right
        assert left.taint_path == right.taint_path


def test_file_enumeration_order_does_not_matter() -> None:
    """字典的插入顺序不该影响结论（内部必须自己排序）。"""
    forward = analyze_sources(dict(PROJECT))
    backward = analyze_sources(dict(reversed(list(PROJECT.items()))))
    assert _fingerprint(forward) == _fingerprint(backward)


def test_no_state_leaks_between_runs() -> None:
    """两个输入交叉跑，结论与各自单独跑时一致 —— 证明没有模块级可变状态。"""
    isolated_a = analyze_sources({"a.py": VIEWS})
    isolated_b = analyze_sources({"b.py": MODELS})

    mixed_a = analyze_sources({"a.py": VIEWS})
    analyze_sources({"b.py": MODELS})
    mixed_a_again = analyze_sources({"a.py": VIEWS})

    assert _fingerprint(isolated_a) == _fingerprint(mixed_a)
    assert _fingerprint(isolated_a) == _fingerprint(mixed_a_again)
    assert _fingerprint(isolated_b) == _fingerprint(analyze_sources({"b.py": MODELS}))


def test_findings_are_deterministically_ordered() -> None:
    """产出顺序必须由**全序排序键**决定，而不是「谁先被遍历到」。

    同一行上可能同时有不同类型的 Finding，所以排序键要一路比到 `rule_id`；
    只按 (文件, 行) 排的话，两行的相对顺序会取决于列表的构造顺序。
    """
    result = analyze_sources(PROJECT)
    keys = [
        (f.file_path, f.line_start, f.line_end, f.rule_id, len(f.taint_path))
        for f in result.findings
    ]
    assert keys == sorted(keys)
    assert len(set(keys)) == len(keys), "排序键必须能区分开每一条 Finding"


def test_duration_ms_is_explicitly_outside_the_contract() -> None:
    """把边界写下来：耗时是实测值，**不参与**确定性承诺。"""
    first = analyze_sources(PROJECT)
    second = analyze_sources(PROJECT)
    assert first.duration_ms >= 0
    assert second.duration_ms >= 0
    assert _fingerprint(first) == _fingerprint(second), "除耗时外的一切都必须相同"


def test_findings_are_frozen() -> None:
    """`Finding` 不可变：下游（含 LLM 文案环节）在类型层面就改不动结论。"""
    finding = analyze_sources(PROJECT).findings[0]
    with pytest.raises(FrozenInstanceError):
        finding.confidence = 0.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# L3 分层红线（扫源码，不靠人工 review）
# ---------------------------------------------------------------------------

FORBIDDEN_PREFIXES = (
    "app.llm",
    "app.db",
    "app.orchestrator",
    "app.sandbox",
    "fastapi",
    "sqlalchemy",
    "openai",
    "anthropic",
    "httpx",
    "requests",
    "aiohttp",
)

ALLOWED_APP_PREFIXES = ("app.analysis", "app.core", "app.models")


def _package_files() -> list[Path]:
    package_dir = Path(app.analysis.__file__).parent
    return sorted(package_dir.glob("*.py"))


def _imported_modules(tree: ast.AST) -> list[tuple[str, int]]:
    modules: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append((node.module, node.lineno))
    return modules


def test_analysis_package_does_not_import_forbidden_layers() -> None:
    """`app/analysis/` 只允许依赖 `app.core` / `app.models.enums`（总纲 L3）。"""
    files = _package_files()
    assert len(files) >= 8, "包文件数量异常，扫描可能没扫到真正的内容"

    violations: list[str] = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for module, lineno in _imported_modules(tree):
            if module.startswith(FORBIDDEN_PREFIXES):
                violations.append(f"{path.name}:{lineno} import {module}")
            elif module.startswith("app.") and not module.startswith(ALLOWED_APP_PREFIXES):
                violations.append(f"{path.name}:{lineno} import {module}")
    assert violations == [], (
        "app/analysis 越层依赖：" + "; ".join(violations) + "（B4 不得依赖 B1/B2/B5/B6）"
    )


def test_analysis_package_has_no_print() -> None:
    """统一用 `logging`：`print` 在 API 进程里既入不了日志也没有级别。"""
    offenders: list[str] = []
    for path in _package_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


# ---------------------------------------------------------------------------
# 规则库完整性（规则是数据，所以可以对数据做全局校验）
# ---------------------------------------------------------------------------


def test_every_source_declares_a_known_channel() -> None:
    for spec in SOURCES:
        assert spec.channel in CHANNELS, (spec.symbol, spec.channel)
        assert spec.kind in {"call", "value"}, (spec.symbol, spec.kind)


def test_every_sink_targets_a_known_vuln_type() -> None:
    """sink 表里写错一个类型名，应当在**导入期/测试期**就炸，而不是落库后才发现。"""
    for spec in SINKS:
        assert isinstance(spec.vuln_type, VulnType), spec.symbol
        assert spec.dangerous_args, f"{spec.symbol} 没有声明危险参数位"
        assert all(index == -1 or index >= 0 for index in spec.dangerous_args)


def test_partial_sanitizers_do_not_claim_to_neutralize() -> None:
    """弱净化（`str()`）不能声称中和任何漏洞类型 —— 那是它升级为强净化的信号。"""
    for spec in SANITIZERS:
        assert spec.strength in {"full", "partial"}, spec.symbol
        if spec.strength == "partial":
            assert spec.neutralizes == (), f"{spec.symbol} 是弱净化，不该有 neutralizes"
        else:
            assert spec.neutralizes, f"{spec.symbol} 是强净化却没声明中和范围"


def test_rule_symbols_are_matched_by_suffix_not_prefix() -> None:
    """sink 匹配必须是**后缀**匹配：`cur.execute` 要能命中 `execute` 规则。

    写成前缀匹配（`startswith`）会让所有「带接收者的调用」全部漏掉，
    而那种漏报在样例工程里可能一个都不出现（全部写成裸 `execute(...)`）。
    """
    from app.analysis.sinks import match_sink

    assert match_sink("cur.execute") is not None
    assert match_sink("db.session.execute") is not None
    assert match_sink("execute") is not None
    # 段边界：不能把 `myexecute` 当成 `execute`
    assert match_sink("myexecute") is None
