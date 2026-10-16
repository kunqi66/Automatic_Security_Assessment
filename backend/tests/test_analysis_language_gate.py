"""`analyze()` 的「能不能分析」闸门 —— B1/B4 两套语言词汇表的边界。

## 这个文件钉的是什么

B1（`projects/types.py`）和 B4（`analysis/`）各自维护一套语言叫法：

| | B1 `LANGUAGE_BY_EXT` | B4 `parser._LANGUAGE_FACTORIES` |
|---|---|---|
| 值 | `"Python"`（显示名） | `"python"`（标识符） |
| 用途 | LOC 统计、前端展示 | 选 tree-sitter 语法 |

长得几乎一样，混用**不报任何错**。原先的闸门拿 manifest 的
`entry.language` 去比 B4 的小写标识符集合：

    实测（2026-10-16，靶场 vulnerable-demo-app —— 本仓库最早的那个靶场，
    现由 `ranges/ecommerce` 取代，原文件保留在 `demo/vulnerable-demo-app/`
    供复核，见 `demo/README.md`）：
    analyze() → files_scanned=0, findings=0
    SkipRecord: 「暂不支持的语言：Python」

**一个 Python 项目被判成「不支持 Python」，一行都没扫，报告输出「0 个漏洞」。**
这是本系统最坏的失败模式：用户读到的是「这个项目很干净」。

## 为什么原有单测是绿的

`test_taint_engine.py` 的契约 4 测试自己造 manifest，写的是
`{"language": "python"}` —— **它用了 B4 的词汇表**，而 B1 实际产出的是
`"Python"`。测试于是验证了一个生产中从不出现的 manifest 形状。

所以下面第一个测试**不自己编 language 值**，而是从 B1 的
`LANGUAGE_BY_EXT` 取真实值 —— 两张表再漂移，这里就会红。
"""

from __future__ import annotations

import pytest

from app.analysis import analyze
from app.projects.types import LANGUAGE_BY_EXT

#: 能触发 SQL 注入的最小样例（与 `test_taint_engine.VULN_SOURCE` 同源）。
VULN_SOURCE = """
from flask import request
def order():
    cursor.execute("select * from orders where id = " + request.args.get("id"))
"""


def _manifest(entries: list[dict[str, object]]) -> dict[str, object]:
    return {"entries": entries, "truncated": False}


def _entry(rel_path: str, *, language: str | None) -> dict[str, object]:
    return {"rel_path": rel_path, "size_bytes": len(VULN_SOURCE), "language": language}


async def _run(manifest: dict[str, object]):
    async def read_source(rel_path: str) -> str:
        return VULN_SOURCE

    return await analyze(manifest, read_source)


async def test_真实_manifest_的显示名下_Python_文件仍被分析() -> None:
    """**这就是那个 bug 的最小复现。**

    用 B1 真实产出的 `"Python"`（不是 B4 的 `"python"`），
    一个含注入的文件必须被扫出结论。
    """
    manifest = _manifest([_entry("app.py", language=LANGUAGE_BY_EXT[".py"])])
    result = await _run(manifest)

    assert result.files_scanned == 1, (
        f"`.py` 文件没被分析；跳过原因={[s.reason for s in result.files_skipped]}"
    )
    assert len(result.findings) == 1
    assert result.files_skipped == ()


@pytest.mark.parametrize("display_name", sorted(set(LANGUAGE_BY_EXT.values())))
async def test_显示名叫什么都不影响_能不能分析(display_name: str) -> None:
    """判据是**扩展名**，不是 manifest 给的语言叫法。

    对 B1 表里每一个显示名都试一遍：只要路径是 `.py`，就必须被分析。
    这样 B1 以后改显示名（比如把 `"C#"` 改成 `"CSharp"`）不会悄悄
    把扫描关掉 —— 而那正是本次 bug 的形状。
    """
    manifest = _manifest([_entry("app.py", language=display_name)])
    result = await _run(manifest)

    assert result.files_scanned == 1, (
        f"language={display_name!r} 把 `.py` 文件挡掉了，"
        f"跳过原因={[s.reason for s in result.files_skipped]}"
    )


@pytest.mark.parametrize("language", [None, "", "python", "Python"])
async def test_language_字段缺失或空也不影响_能否分析(language: str | None) -> None:
    """闸门不该依赖这个字段存在。

    `_manifest_entries` 对缺失 `language` 的条目会兜底成 `"python"`，
    但**兜底值本身不该是判据** —— 有它没它，`.py` 都得被扫。
    """
    result = await _run(_manifest([_entry("app.py", language=language)]))
    assert result.files_scanned == 1


async def test_不支持的扩展名按后缀记录原因() -> None:
    """跳过原因要指向**判据本身**（后缀），不是那个没用的显示名。

    原来写的是「暂不支持的语言：JavaScript」—— 但真正决定的是 `.js`；
    而同为 JavaScript 的 `.mjs` / `.jsx` 会给出同样的提示，
    看日志的人无从知道到底是哪个后缀被拒了。
    """
    manifest = _manifest(
        [
            _entry("app.py", language="Python"),
            _entry("web/app.js", language="JavaScript"),
        ]
    )
    result = await _run(manifest)

    assert result.files_scanned == 1
    reasons = {s.path: s.reason for s in result.files_skipped}
    assert "web/app.js" in reasons
    assert ".js" in reasons["web/app.js"], f"原因里没提后缀：{reasons['web/app.js']!r}"


async def test_无扩展名文件不会当成支持的类型() -> None:
    """`PurePosixPath("Makefile").suffix` 是 `''`，必须落进「不支持」而不是漏过。"""
    result = await _run(_manifest([_entry("Makefile", language="Makefile")]))
    assert result.files_scanned == 0
    assert len(result.files_skipped) == 1


async def test_大小写后缀都认() -> None:
    """`.PY` 少见但合法，判据做了 `lower()`，钉住这个行为。"""
    result = await _run(_manifest([_entry("APP.PY", language="Python")]))
    assert result.files_scanned == 1
