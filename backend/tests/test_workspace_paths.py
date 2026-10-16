"""B1 工作区路径安全测试。

**为什么这个文件值得先写**：`normalize_rel_path` / `safe_join` 是「用户可控字符串 →
文件系统路径」的唯一收口，而路径穿越是**不报错的漏洞** —— 放行了也只是安静地
读出 `/etc/passwd`，没有任何异常、没有日志、功能看起来一切正常。
这一层只能靠测试守住。

攻击样本按绕过手法分类，而不是按「看起来像不像坏路径」罗列。
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from app.core.config import settings
from app.projects.errors import SourcePathEscapeError
from app.projects.workspace import (
    MAX_SPAN_LINES,
    create_layout,
    normalize_rel_path,
    read_source,
    safe_join,
)

# ---------------------------------------------------------------------------
# 归一层：应当拒绝
# ---------------------------------------------------------------------------

REJECTED = {
    "经典上跳": "../../etc/passwd",
    "单层上跳": "../secret.py",
    "裸上跳": "..",
    "夹在中间的上跳": "app/../../../etc/passwd",
    "POSIX 绝对路径": "/etc/passwd",
    "绝对路径带后缀": "/tmp/evil.py",  # noqa: S108 —— 这是攻击载荷字符串，不创建任何文件
    # Windows 风格：只按 "/" 切分会漏掉这里的 ".."，所以实现里先统一了分隔符
    "反斜杠上跳": "..\\..\\windows\\system32",
    "反斜杠夹中间": "app\\..\\..\\secret.py",
    "盘符绝对路径": "C:\\Windows\\System32\\config\\SAM",
    "盘符正斜杠": "C:/Windows/win.ini",
    "UNC 路径": "\\\\server\\share\\evil.py",
    "空串": "",
    "纯空白": "   ",
    "只有点": ".",
    "只有斜杠": "/",
    # NUL 截断：某些系统调用会在 NUL 处截断，造成「检查的路径 ≠ 打开的路径」
    "NUL 截断": "app/ok.py\x00../../etc/passwd",
}


@pytest.mark.parametrize("label,raw", list(REJECTED.items()), ids=list(REJECTED))
def test_normalize_rejects(label: str, raw: str) -> None:
    with pytest.raises(SourcePathEscapeError):
        normalize_rel_path(raw)


# ---------------------------------------------------------------------------
# 归一层：应当接受并归一
# ---------------------------------------------------------------------------

ACCEPTED = {
    "普通相对路径": ("app/api/order.py", "app/api/order.py"),
    "带当前目录": ("./app/main.py", "app/main.py"),
    "重复斜杠": ("app//api///order.py", "app/api/order.py"),
    "反斜杠相对路径": ("app\\api\\order.py", "app/api/order.py"),
    "首尾空白": ("  app/main.py  ", "app/main.py"),
    "文件名含点点": ("app/..hidden.py", "app/..hidden.py"),
    "中间目录名叫点点点": ("a/.../b.py", "a/.../b.py"),
}


@pytest.mark.parametrize("label,case", list(ACCEPTED.items()), ids=list(ACCEPTED))
def test_normalize_accepts(label: str, case: tuple[str, str]) -> None:
    raw, expected = case
    assert normalize_rel_path(raw) == expected


def test_normalize_returns_posix_on_every_platform() -> None:
    """归一结果必须是 POSIX 形式 —— 它要直接落库（总纲 §7.4）。
    在 Windows 上跑出反斜杠会污染 `vulnerabilities.file_path`，
    而且只在 Windows 开发机上错、在 Linux 上对，属于最难查的那类问题。"""
    assert "\\" not in normalize_rel_path("app\\api\\order.py")


# ---------------------------------------------------------------------------
# 落界层：符号链接与越界
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """把工作区根指到临时目录，避免测试碰到真实的 D 盘目录。"""
    monkeypatch.setattr(settings, "workspace_root", tmp_path / "ws")
    return create_layout(project_id=1).src_root


def test_safe_join_accepts_file_inside_root(workspace: Path) -> None:
    (workspace / "pkg").mkdir()
    (workspace / "pkg" / "a.py").write_text("print(1)\n", encoding="utf-8")
    assert safe_join(workspace, "pkg/a.py").name == "a.py"


def test_safe_join_rejects_symlink_pointing_outside(workspace: Path) -> None:
    """归档里放一个指向界外的软链接是最直接的越界读手法。"""
    outside = workspace.parent / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = workspace / "link.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接（Windows 需开发者模式）")

    with pytest.raises(SourcePathEscapeError):
        safe_join(workspace, "link.txt")


def test_safe_join_rejects_symlink_pointing_inside(workspace: Path) -> None:
    """**指向根内的软链接同样拒绝**（实现取设计 §3.1 的更严一侧）。

    理由：软链接是攻击者放进归档的，今天指向根内不代表明天还指向根内，
    而它的替换成本是零。与其做「当前指向是否安全」的判断，不如一律不收。
    """
    (workspace / "real.py").write_text("x = 1\n", encoding="utf-8")
    link = workspace / "alias.py"
    try:
        os.symlink(workspace / "real.py", link)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接（Windows 需开发者模式）")

    with pytest.raises(SourcePathEscapeError):
        safe_join(workspace, "alias.py")


def test_safe_join_rejects_symlinked_directory_component(workspace: Path) -> None:
    """软链接出现在**中间目录**上同样要拦 —— 只看最后一段会漏掉这种。"""
    (workspace / "real_dir").mkdir()
    (workspace / "real_dir" / "a.py").write_text("x = 1\n", encoding="utf-8")
    try:
        os.symlink(workspace / "real_dir", workspace / "link_dir")
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接（Windows 需开发者模式）")

    with pytest.raises(SourcePathEscapeError):
        safe_join(workspace, "link_dir/a.py")


@pytest.mark.skipif(os.name != "nt", reason="junction 是 Windows 特有机制")
def test_safe_join_rejects_windows_junction(workspace: Path) -> None:
    """Windows **目录联接（junction）**：`Path.is_symlink()` 对它返回 `False`。

    这条测试是「为什么要有两道独立检查」的实证。第一道（逐段 `is_symlink()`）
    查不出 junction，能拦住它的只有第二道 `resolve()` 落界 ——
    因为 `resolve()` 会展开 reparse point，而 `is_symlink()` 只认
    `IO_REPARSE_TAG_SYMLINK`、不认 `IO_REPARSE_TAG_MOUNT_POINT`。

    面试里被问「你的路径校验有没有可能被绕过」时，这条是能拿出来的答案；
    同时也说明：**单靠一道检查的路径防护是不可信的**。

    顺带一提，junction 的创建**不需要管理员权限**（软链接才需要），
    所以它是一个比软链接更容易被利用的越界手法。
    """
    outside = workspace.parent / "outside_dir"
    outside.mkdir()
    (outside / "secret.py").write_text("TOP_SECRET = 1\n", encoding="utf-8")

    link = workspace / "junction_dir"
    result = subprocess.run(  # noqa: S603 —— argv 列表，未过 shell
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],  # noqa: S607 —— 系统自带命令
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"无法创建 junction：{result.stderr or result.stdout}")

    # 前提断言：本测试要验证的恰恰是 is_symlink() 查不出 junction。
    # 若某天 Python 改了行为，这个断言会失败并提醒我们更新结论，而不是悄悄失去覆盖。
    assert not link.is_symlink(), "前提不成立：is_symlink() 现在能认出 junction 了"

    with pytest.raises(SourcePathEscapeError):
        safe_join(workspace, "junction_dir/secret.py")


# ---------------------------------------------------------------------------
# read_source：区间语义
# ---------------------------------------------------------------------------


async def test_read_source_clamps_to_actual_range(workspace: Path) -> None:
    """请求 1..9999 而文件只有 3 行时，返回的 start/end 必须是**实际**区间。

    如果这里原样回 1..9999，前端会按错误的区间去对齐高亮，
    表现是「行号全对不上」，而根因在一个看起来完全正常的响应里。
    """
    (workspace / "small.py").write_text("a\nb\nc\n", encoding="utf-8")
    got = await read_source(1, "small.py", 1, 9999)
    assert (got.start, got.end, got.total_lines) == (1, 3, 3)
    assert got.lines == ["a", "b", "c"]


async def test_read_source_caps_span(workspace: Path) -> None:
    """单次返回行数有上限，`?start=1&end=10**9` 不能把整个大文件读进内存。"""
    (workspace / "big.py").write_text("\n".join(f"line{i}" for i in range(5000)), encoding="utf-8")
    got = await read_source(1, "big.py", 1, 10**9)
    assert got.end - got.start + 1 == MAX_SPAN_LINES


async def test_read_source_survives_non_utf8(workspace: Path) -> None:
    """源码里混入非 UTF-8 字节是常事，不该让整个高亮面板报错（§6 第 8 条）。"""
    (workspace / "latin.py").write_bytes(b"# caf\xe9\nx = 1\n")
    got = await read_source(1, "latin.py", 1, 2)
    assert got.total_lines == 2
    assert "x = 1" in got.content


async def test_read_source_rejects_traversal(workspace: Path) -> None:
    (workspace / "ok.py").write_text("x = 1\n", encoding="utf-8")
    secret = workspace.parent / "secret.py"
    secret.write_text("TOP_SECRET = 1\n", encoding="utf-8")

    with pytest.raises(SourcePathEscapeError):
        await read_source(1, "../secret.py", 1, 10)
