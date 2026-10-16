"""补丁四道校验的测试 —— 每道都带**拒绝案例**，第 ④ 道用真分析器跑通。

补丁是本系统里唯一一处「LLM 产出、可能落到用户源码上」的东西，所以这个文件的
重点不是"好补丁能过"，而是**"坏补丁过不去"**：每一道闸门都有一个对应的拒绝
案例，且拒绝原因必须能说清是哪一道、为什么。

第 ④ 道（污点消失）是四道里唯一真正验证"修好了"的一道，因此它有两条：
`test_real_analyzer_*` 用 **B4 的真实污点引擎**（不是替身）跑完整闭环 ——
把补丁打到源码副本上，重跑分析，确认 B4 不再报出那条路径。
"""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path
from typing import Any

import pytest

from app.verify.patch_guard import (
    PATCH_WINDOW_LINES,
    AnalyzerUnavailable,
    PatchGate,
    apply_in_sandbox_copy,
    check_patch,
    check_taint_cleared,
    check_window,
    default_analyzer,
    finding_key,
    parse_unified_diff,
)

# ---------------------------------------------------------------------------
# 样例源码与 finding
# ---------------------------------------------------------------------------

FILE = "app/api/order.py"

#: 一条 B4 能追到的真实 SQL 注入：`request.args.get` → `cur.execute` 字符串拼接
VULNERABLE_SOURCE = textwrap.dedent(
    """\
    from flask import request


    def order():
        uid = request.args.get("id")
        cur = connect().cursor()
        cur.execute("select * from orders where id = " + uid)
    """
)

SINK_LINE = 7
SINK_SYMBOL = "cur.execute"

#: 补丁文本的头部（只有路径，没有 SQL 关键字）
_DIFF_HEAD = f"--- a/{FILE}\n+++ b/{FILE}\n"

#: ⚠️ 下面两段补丁正文写成**纯字符串、不带插值**，是刻意的：一段含
#: `select ...` 的 f-string 会被 ruff 的 S608 判成"SQL 拼接"（有 SQL 关键字
#: 又带插值），而这里插值进来的无非是文件名，跟注入毫无关系。把插值拆到
#: `_DIFF_HEAD` 里，误报自然消失 —— 不需要用 noqa 把一条真的告警规则关掉。
_TRUNCATED_BODY = """\
@@ -4,4 +4,4 @@
 def order():
-    cur.execute("select * from orders where id = " + uid)
+    cur.execute("select * from orders where id = %s", (uid,))
"""

#: 第 ④ 道的拒绝案例：改了名、没改拼接，污点路径**仍在**
_COSMETIC_BODY = """\
@@ -5,3 +5,3 @@
-    uid = request.args.get("id")
+    user_id = request.args.get("id")
     cur = connect().cursor()
-    cur.execute("select * from orders where id = " + uid)
+    cur.execute("select * from orders where id = " + user_id)
"""


class _Finding:
    """`Vulnerability` / `Finding` 的最小视图（第 ④ 道要的身份锚就这三个字段）。"""

    def __init__(
        self,
        *,
        file_path: str = FILE,
        vuln_type: str = "sql_injection",
        line_start: int = SINK_LINE,
        line_end: int = SINK_LINE,
        sink_symbol: str = SINK_SYMBOL,
    ) -> None:
        self.file_path = file_path
        self.vuln_type = vuln_type
        self.line_start = line_start
        self.line_end = line_end
        self.sink_symbol = sink_symbol


def _make_diff(
    lines: list[str],
    *,
    line_no: int,
    old: str,
    new: str,
    file_path: str = FILE,
    context: int = 2,
) -> str:
    """按真实的 unified diff 规则拼一份补丁（行数由上下文推导，不手写块头）。

    测试里手写 `@@ -4,4 +4,4 @@` 极容易错一位，而错一位的后果是"闸门 ① 挂了"，
    表现为一个看起来像产品 bug 的失败。所以块头的行数在这里**算出来**。
    """
    index = line_no - 1  # 0-based
    assert lines[index] == old, f"第 {line_no} 行不是要改的内容：{lines[index]!r}"

    start = max(0, index - context)
    end = min(len(lines), index + context + 1)
    hunk: list[str] = []
    old_count = 0
    new_count = 0
    for position in range(start, end):
        line = lines[position]
        if position == index:
            hunk.append(f"-{old}")
            hunk.append(f"+{new}")
            old_count += 1
            new_count += 1
        else:
            hunk.append(f" {line}")
            old_count += 1
            new_count += 1

    header = f"@@ -{start + 1},{old_count} +{start + 1},{new_count} @@"
    body = "\n".join([f"--- a/{file_path}", f"+++ b/{file_path}", header, *hunk])
    return body + "\n"


def _fixed_source() -> str:
    """修好的版本：参数化查询（B4 的负例里明确不报）。"""
    return VULNERABLE_SOURCE.replace(
        'cur.execute("select * from orders where id = " + uid)',
        'cur.execute("select * from orders where id = %s", (uid,))',
    )


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# ① 合法性
# ---------------------------------------------------------------------------


def test_plain_text_is_not_a_diff() -> None:
    """「把 uid 换成参数化查询」—— 这是建议，不是补丁。"""
    parsed, failure = parse_unified_diff("把 uid 换成参数化查询即可")
    assert parsed is None
    assert failure and "not" not in failure  # 中文原因，能直接给人看
    assert "unified diff" in failure or "缺少" in failure


def test_empty_patch_is_rejected() -> None:
    parsed, failure = parse_unified_diff("   \n\n")
    assert parsed is None
    assert failure == "补丁为空"


def test_truncated_hunk_line_counts_are_rejected() -> None:
    """块头声明 4 行、实际只给 2 行 —— 伪造/截断的补丁必须在这里被抓住。"""
    broken = _DIFF_HEAD + _TRUNCATED_BODY
    parsed, failure = parse_unified_diff(broken)
    assert parsed is None
    assert failure is not None
    assert "行数" in failure and "不符" in failure


def test_multi_file_diff_is_rejected() -> None:
    """一个补丁只能改一个文件：多文件补丁会让 ±20 行窗口失去意义。"""
    two_files = textwrap.dedent(
        f"""\
        --- a/{FILE}
        +++ b/{FILE}
        @@ -7,1 +7,1 @@
        -cur.execute(x)
        +cur.execute(x, y)
        --- a/other.py
        +++ b/other.py
        @@ -1,1 +1,1 @@
        -a
        +b
        """
    )
    parsed, failure = parse_unified_diff(two_files)
    assert parsed is None
    assert failure is not None
    assert "多个" in failure


def test_path_escape_is_rejected() -> None:
    """`../../etc/passwd` 这种路径必须在这里被挡住（第 ② 道只看行号，看不见路径）。"""
    for path in ("../../etc/passwd", "/etc/passwd", "C:/Windows/system32/x.py"):
        text = f"--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,1 @@\n-a\n+b\n"
        parsed, failure = parse_unified_diff(text)
        assert parsed is None, path
        assert failure


def test_device_null_is_rejected() -> None:
    """整文件重写（`--- /dev/null`）不是"修复"：它让人工复核失去焦点。"""
    text = f"--- /dev/null\n+++ b/{FILE}\n@@ -0,0 +1,1 @@\n+new\n"
    parsed, failure = parse_unified_diff(text)
    assert parsed is None
    assert failure


def test_context_only_diff_is_rejected() -> None:
    """没有任何增删的补丁不构成修复。"""
    text = textwrap.dedent(
        f"""\
        --- a/{FILE}
        +++ b/{FILE}
        @@ -1,2 +1,2 @@
         from flask import request
        """
    )
    parsed, failure = parse_unified_diff(text)
    assert parsed is None
    assert failure is not None
    assert "增删" in failure or "行数" in failure


def test_valid_diff_records_touched_lines() -> None:
    parsed, failure = parse_unified_diff(
        _make_diff(
            VULNERABLE_SOURCE.splitlines(),
            line_no=SINK_LINE,
            old='    cur.execute("select * from orders where id = " + uid)',
            new='    cur.execute("select * from orders where id = %s", (uid,))',
        )
    )
    assert failure is None and parsed is not None
    assert parsed.new_path == FILE
    assert SINK_LINE in parsed.touched_lines
    assert parsed.text.startswith("--- a/")


# ---------------------------------------------------------------------------
# ② ±20 行窗口
# ---------------------------------------------------------------------------


def test_far_away_change_is_rejected() -> None:
    """改动落在触发行 200 行之外 → 拒（第 ② 道的存在理由）。"""
    lines = [f"x{i} = {i}" for i in range(1, 301)]
    far = 200
    lines[far - 1] = "target = 0"
    diff = _make_diff(lines, line_no=far, old="target = 0", new="target = 1")

    parsed, failure = parse_unified_diff(diff)
    assert parsed is not None, failure
    ok, reason = check_window(parsed, file_path=FILE, line_start=SINK_LINE, line_end=SINK_LINE)
    assert ok is False
    assert f"±{PATCH_WINDOW_LINES} 行之外" in reason
    assert "第 200 行" in reason


def test_change_just_inside_the_window_is_accepted() -> None:
    """边界：触发行 ±20 行以内是允许的 —— 上限是窗口，不是"越近越好"。"""
    lines = [f"x{i} = {i}" for i in range(1, 121)]
    edge = SINK_LINE + PATCH_WINDOW_LINES
    lines[edge - 1] = "target = 0"
    diff = _make_diff(lines, line_no=edge, old="target = 0", new="target = 1")
    parsed, _ = parse_unified_diff(diff)
    assert parsed is not None
    ok, _reason = check_window(parsed, file_path=FILE, line_start=SINK_LINE, line_end=SINK_LINE)
    assert ok is True


def test_patch_on_another_file_is_rejected() -> None:
    diff = _make_diff(
        VULNERABLE_SOURCE.splitlines(),
        line_no=SINK_LINE,
        old='    cur.execute("select * from orders where id = " + uid)',
        new='    cur.execute("select * from orders where id = %s", (uid,))',
        file_path="app/api/other.py",
    )
    parsed, _ = parse_unified_diff(diff)
    assert parsed is not None
    ok, reason = check_window(parsed, file_path=FILE, line_start=SINK_LINE, line_end=SINK_LINE)
    assert ok is False
    assert "不一致" in reason


def test_missing_line_numbers_reject_instead_of_pass() -> None:
    """没有行号就判不了窗口 —— **判不通过**，而不是放行。"""
    parsed, _ = parse_unified_diff(
        _make_diff(
            VULNERABLE_SOURCE.splitlines(),
            line_no=SINK_LINE,
            old='    cur.execute("select * from orders where id = " + uid)',
            new='    cur.execute("select * from orders where id = %s", (uid,))',
        )
    )
    assert parsed is not None
    ok, reason = check_window(parsed, file_path=FILE, line_start=0, line_end=0)
    assert ok is False
    assert "拒绝而不是放行" in reason


# ---------------------------------------------------------------------------
# ③ 可应用（在临时副本上）
# ---------------------------------------------------------------------------


def test_unappliable_diff_is_rejected() -> None:
    """块头行号对得上、但上下文与真实源码不符 → `git apply --check` 会拒。"""
    diff = _make_diff(
        VULNERABLE_SOURCE.splitlines(),
        line_no=SINK_LINE,
        old='    cur.execute("select * from orders where id = " + uid)',
        new='    cur.execute("select * from orders where id = %s", (uid,))',
    )
    # 改掉**块内**的一行上下文（第 6 行）—— 块外的改动 git apply 根本看不见
    mismatched = VULNERABLE_SOURCE.replace(
        "    cur = connect().cursor()", "    cur = connect_mysql().cursor()"
    )
    applied, reason, patched = apply_in_sandbox_copy(
        parse_unified_diff(diff)[0], file_path=FILE, source=mismatched
    )
    assert applied is False
    assert patched is None
    assert "git apply" in reason


def test_missing_git_rejects_instead_of_passing(monkeypatch: pytest.MonkeyPatch) -> None:
    """环境里没有 git ⇒ **判不通过**。工具缺失不是放行的理由（模块头硬约束 2）。"""
    import subprocess as sp

    def boom(*_a: Any, **_kw: Any) -> Any:
        raise FileNotFoundError("git not found")

    monkeypatch.setattr(sp, "run", boom)
    parsed, _ = parse_unified_diff(
        _make_diff(
            VULNERABLE_SOURCE.splitlines(),
            line_no=SINK_LINE,
            old='    cur.execute("select * from orders where id = " + uid)',
            new='    cur.execute("select * from orders where id = %s", (uid,))',
        )
    )
    assert parsed is not None
    applied, reason, _ = apply_in_sandbox_copy(parsed, file_path=FILE, source=VULNERABLE_SOURCE)
    assert applied is False
    assert "缺少 git" in reason


def test_applied_patch_content_is_the_normalized_diff() -> None:
    """被应用的补丁 = 被校验的那份文本（否则前三道的结论与第 ④ 道无关）。"""
    diff = (
        _make_diff(
            VULNERABLE_SOURCE.splitlines(),
            line_no=SINK_LINE,
            old='    cur.execute("select * from orders where id = " + uid)',
            new='    cur.execute("select * from orders where id = %s", (uid,))',
        )
        .replace("--- a/", "--- ")
        .replace("+++ b/", "+++ ")
    )  # 故意去掉 a/ b/ 前缀，验归一化
    parsed, failure = parse_unified_diff(diff)
    assert parsed is not None, failure
    applied, reason, patched = apply_in_sandbox_copy(
        parsed, file_path=FILE, source=VULNERABLE_SOURCE
    )
    assert applied is True, reason
    assert patched == _fixed_source()


# ---------------------------------------------------------------------------
# ④ 污点消失 —— 用**真实** B4 引擎
# ---------------------------------------------------------------------------


def test_real_analyzer_sees_the_vulnerability() -> None:
    """先证明"分析器确实能看见这条漏洞" —— 否则后面的"消失"没有意义。"""
    analyzer = default_analyzer()
    findings = _run(analyzer(FILE, VULNERABLE_SOURCE))
    keys = {finding_key(f) for f in findings}
    assert (FILE, "sql_injection", SINK_SYMBOL) in keys


def test_real_analyzer_accepts_a_genuine_fix() -> None:
    """**旗舰用例**：合法 + 有效 + 窗口内 + 打上后污点消失 → 四道全过。"""
    diff = _make_diff(
        VULNERABLE_SOURCE.splitlines(),
        line_no=SINK_LINE,
        old='    cur.execute("select * from orders where id = " + uid)',
        new='    cur.execute("select * from orders where id = %s", (uid,))',
    )
    verdict = _run(check_patch(diff, finding=_Finding(), file_path=FILE, source=VULNERABLE_SOURCE))

    assert verdict.valid_diff is True
    assert verdict.window_ok is True
    assert verdict.apply_check_ok is True
    assert verdict.taint_cleared is True
    assert verdict.failure_reason is None
    assert verdict.accepted is True


def test_real_analyzer_rejects_a_cosmetic_patch() -> None:
    """**最重要的一例**：补丁合法、能应用、窗口也对 —— 但污点路径还在。

    这就是第 ④ 道存在的全部理由。前三道校验（格式、窗口、可应用）**全过**，
    只有重跑污点引擎能发现"它什么也没修"。
    """
    diff = _DIFF_HEAD + _COSMETIC_BODY
    verdict = _run(check_patch(diff, finding=_Finding(), file_path=FILE, source=VULNERABLE_SOURCE))

    assert verdict.valid_diff is True
    assert verdict.window_ok is True
    assert verdict.apply_check_ok is True, "这个补丁本身是合法且能应用的"
    assert verdict.taint_cleared is False
    assert verdict.accepted is False
    assert verdict.failure_reason is not None
    assert verdict.failure_reason.startswith("[④ 污点]")
    assert "依然被报出" in verdict.failure_reason


# ---------------------------------------------------------------------------
# ④ 的其余分支：新 finding、分析器缺席（用替身构造）
# ---------------------------------------------------------------------------


def _analyzer_returning(*keys: tuple[str, str, str]) -> Any:
    def _analyze(_file_path: str, _source: str) -> list[Any]:
        return [_Finding(file_path=k[0], vuln_type=k[1], sink_symbol=k[2]) for k in keys]

    return _analyze


def test_new_finding_introduced_by_the_patch_is_rejected() -> None:
    """把 A 漏洞挪成 B 漏洞的补丁必须被拒 —— `after ⊆ before` 这条断言防的就是它。"""
    target = (FILE, "sql_injection", SINK_SYMBOL)
    new_key = (FILE, "command_injection", "os.system")
    calls = {"n": 0}

    def analyzer(_file_path: str, _source: str) -> list[Any]:
        calls["n"] += 1
        keys = [target] if calls["n"] == 1 else [new_key]
        return [_Finding(file_path=k[0], vuln_type=k[1], sink_symbol=k[2]) for k in keys]

    ok, reason = _run(
        check_taint_cleared(
            file_path=FILE,
            original="before",
            patched="after",
            target_key=target,
            analyzer=analyzer,
        )
    )
    assert ok is False
    assert "引入/暴露了新的污点路径" in reason


def test_analyzer_that_never_reported_the_target_is_rejected() -> None:
    """原始源码上就没报出这条 —— 身份锚对不上（finding 过期），拒绝而不是放行。"""
    ok, reason = _run(
        check_taint_cleared(
            file_path=FILE,
            original="before",
            patched="after",
            target_key=(FILE, "sql_injection", SINK_SYMBOL),
            analyzer=_analyzer_returning(),
        )
    )
    assert ok is False
    assert "并未报出" in reason


def test_clean_analyzer_accepts() -> None:
    """打上补丁后找不到该 finding，且没有新增 → 通过。"""
    calls = {"n": 0}

    def analyzer(_file_path: str, _source: str) -> list[Any]:
        calls["n"] += 1
        return [_Finding()] if calls["n"] == 1 else []

    ok, reason = _run(
        check_taint_cleared(
            file_path=FILE,
            original="before",
            patched="after",
            target_key=(FILE, "sql_injection", SINK_SYMBOL),
            analyzer=analyzer,
        )
    )
    assert ok is True, reason


def test_async_analyzer_is_awaited() -> None:
    """分析器可以是协程 —— B4 的 `analyze` 就是协程，取属性会静默拿到空集。"""

    async def analyzer(_file_path: str, _source: str) -> list[Any]:
        return [_Finding()]

    calls: list[str] = []

    async def two_phase(file_path: str, source: str) -> list[Any]:
        calls.append(source)
        return [_Finding()] if source == "before" else []

    ok, reason = _run(
        check_taint_cleared(
            file_path=FILE,
            original="before",
            patched="after",
            target_key=(FILE, "sql_injection", SINK_SYMBOL),
            analyzer=analyzer,
        )
    )
    assert ok is False and "依然被报出" in reason  # 协程真的被 await 了（否则会报"并未报出"）

    ok, reason = _run(
        check_taint_cleared(
            file_path=FILE,
            original="before",
            patched="after",
            target_key=(FILE, "sql_injection", SINK_SYMBOL),
            analyzer=two_phase,
        )
    )
    assert ok is True, reason
    assert calls == ["before", "after"]


def test_unavailable_analyzer_rejects_instead_of_passing() -> None:
    """分析器不可用 ⇒ 第 ④ 道判不通过：它缺席时放行等于把前三道降级成格式检查。"""

    def analyzer(_file_path: str, _source: str) -> list[Any]:
        raise AnalyzerUnavailable("app.analysis 未安装")

    ok, reason = _run(
        check_taint_cleared(
            file_path=FILE,
            original="b",
            patched="a",
            target_key=(FILE, "sql_injection", SINK_SYMBOL),
            analyzer=analyzer,
        )
    )
    assert ok is False
    assert "保守判不通过" in reason


def test_analyzer_exception_rejects_instead_of_passing() -> None:
    def analyzer(_file_path: str, _source: str) -> list[Any]:
        raise RuntimeError("boom")

    ok, reason = _run(
        check_taint_cleared(
            file_path=FILE,
            original="b",
            patched="a",
            target_key=(FILE, "sql_injection", SINK_SYMBOL),
            analyzer=analyzer,
        )
    )
    assert ok is False
    assert "保守判不通过" in reason


def test_gate_returns_verdict_instead_of_raising_when_analyzer_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """默认分析器拿不到时，接口要拿到一个"没通过校验"的结论，而不是 500。"""
    import app.verify.patch_guard as pg

    def no_analyzer() -> Any:
        raise AnalyzerUnavailable("B4 未落地")

    monkeypatch.setattr(pg, "default_analyzer", no_analyzer)
    diff = _make_diff(
        VULNERABLE_SOURCE.splitlines(),
        line_no=SINK_LINE,
        old='    cur.execute("select * from orders where id = " + uid)',
        new='    cur.execute("select * from orders where id = %s", (uid,))',
    )
    verdict = _run(
        PatchGate().check(diff, finding=_Finding(), file_path=FILE, source=VULNERABLE_SOURCE)
    )
    assert verdict.accepted is False
    assert verdict.apply_check_ok is True
    assert verdict.failure_reason is not None
    assert verdict.failure_reason.startswith("[④ 污点]")


# ---------------------------------------------------------------------------
# 红线：工作区只被读过
# ---------------------------------------------------------------------------


def test_workspace_file_is_never_modified(tmp_path: Path) -> None:
    """**绝不自动应用补丁**：跑完四道校验，磁盘上的源码一个字节都没变。"""
    workdir = tmp_path / "src" / "app" / "api"
    workdir.mkdir(parents=True)
    target = workdir / "order.py"
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8", newline="")
    before_bytes = target.read_bytes()
    before_listing = sorted(p.name for p in workdir.iterdir())

    diff = _make_diff(
        VULNERABLE_SOURCE.splitlines(),
        line_no=SINK_LINE,
        old='    cur.execute("select * from orders where id = " + uid)',
        new='    cur.execute("select * from orders where id = %s", (uid,))',
    )
    verdict = _run(
        check_patch(
            diff, finding=_Finding(), file_path=FILE, source=target.read_text(encoding="utf-8")
        )
    )
    assert verdict.accepted is True

    assert target.read_bytes() == before_bytes, "补丁被写到工作区里了"
    assert sorted(p.name for p in workdir.iterdir()) == before_listing, "工作区被塞了临时文件"
    assert not list(tmp_path.rglob("*.diff")), "diff 文件留在了工作区附近"


def test_to_orm_fields_matches_the_patches_table() -> None:
    """`to_orm_fields()` 直接摊进 `Patch(**fields)`：键名必须与表列一一对应。"""
    from app.models.vulnerability import Patch

    fields = _run(
        PatchGate(analyzer=_analyzer_returning()).check(
            _make_diff(
                VULNERABLE_SOURCE.splitlines(),
                line_no=SINK_LINE,
                old='    cur.execute("select * from orders where id = " + uid)',
                new='    cur.execute("select * from orders where id = %s", (uid,))',
            ),
            finding=_Finding(),
            file_path=FILE,
            source=VULNERABLE_SOURCE,
        )
    ).to_orm_fields()
    assert set(fields) == {
        "valid_diff",
        "window_ok",
        "apply_check_ok",
        "taint_cleared",
        "failure_reason",
    }
    for column in fields:
        assert hasattr(Patch, column), f"{column} 不是 patches 表的列"
