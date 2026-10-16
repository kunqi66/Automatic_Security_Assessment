"""修复补丁的四道校验（契约 2 §3 / PRD §7.6 / B5 设计 §4.4）。

## 为什么补丁要在「被应用之前」验四遍

补丁是**本系统唯一一处"由 LLM 产出、又可能落到用户源码上"的东西**。它跟探针不同：
探针错了顶多没打中，补丁错了会改坏用户的代码。所以四道校验的顺序是
**由廉到贵、由外到内**，任何一道不过即刻停手：

| 闸门 | 判据 | 不过的后果 |
|---|---|---|
| ① 合法性 | 手写的 unified diff 解析器：头、块头、行数自洽 | 直接丢弃 |
| ② 窗口 | 改动只落在触发行 ±20 行内，且只动这一个文件 | 直接丢弃 |
| ③ 可应用 | 在**临时目录的副本**上 `git apply --check` 干跑，再真应用一次 | 直接丢弃 |
| ④ 污点消失 | 把补丁打到源码上**重跑污点引擎**：目标路径消失且没引入新 finding | 直接丢弃 |

四道**全过**才算「有补丁」（`Patch.valid_diff/window_ok/apply_check_ok/taint_cleared`
四列全 true）；任何一道不过 → `patch = NULL` + `failure_reason` 写明是哪一道。

## 两条硬约束写死在代码里

1. **绝不自动应用。** 本模块的全部产物是一份校验结论 + 一份补丁文本，
   `patch` 仅作为「建议」落库并展示给用户复制。工作区是只读打开的；
   补丁只在一个 `TemporaryDirectory` 里的副本上被应用过。
2. **工具缺失即拒绝，不是放行。** `git` 不在、`app.analysis` 不可用 ⇒
   对应闸门判不通过。一个"工具不在所以跳过"的闸门等于没有闸门，
   而它会在最需要它的时候（环境不完整）打开。
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import posixpath
import re
import subprocess
import tempfile
from collections.abc import Awaitable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from app.core.logging import get_logger

logger = get_logger(__name__)

#: 补丁允许改动的范围 = 触发行 ±20 行（PRD §7.6 的第 ② 道校验）。
#:
#: 上限的存在理由不是"防手滑"，而是**防止 LLM 把一处修复写成一整文件重写**：
#: 重写会让人工复核失去焦点（"它到底改了哪几行？"），也会让第 ④ 道校验的
#: "污点路径消失"变成"整个文件变了所以原来那条路径自然没了"——那就没在验证修复。
PATCH_WINDOW_LINES = 20

#: `git apply` 的超时。补丁是文本，正常在毫秒级；给 30s 是为了覆盖
#: 磁盘紧张时的极端情况，而不是预期它有用。
_GIT_TIMEOUT_S = 30

_RE_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_RE_FILE_HEADER = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+?)$")


class AnalyzerUnavailable(RuntimeError):
    """污点引擎不可用（B4 未落地 / 导入失败）。**第 ④ 道校验据此判不通过。**"""


class FileAnalyzer(Protocol):
    """重跑污点引擎所需的最小形状。

    契约 4 给的是 `analysis.analyze(manifest, read_source) -> AnalysisResult`，
    那是个"整个工程"级的入口；而第 ④ 道校验只需要**一个文件**的 findings。
    因此这里收窄成单文件函数，再由 `default_analyzer()` 把契约 4 的入口
    适配成一个单文件清单调用 —— **收窄是为了可测**（测试注入一个假分析器，
    就能精确构造"污点仍在""引入了新 finding"两种局面）。

    返回类型允许 `Awaitable`：B4 的 `analyze` 是**协程**（它要 await 读取回调），
    所以第 ④ 道天生是异步的。写成同步函数会在协程上取 `findings` 属性、
    静默拿到空集 —— 于是每一条补丁都以"原始源码上并未报出该漏洞"被拒，
    而报错信息完全指向另一个方向。
    """

    def __call__(self, file_path: str, source: str) -> Sequence[Any] | Awaitable[Sequence[Any]]: ...


async def _call_analyzer(analyzer: FileAnalyzer, file_path: str, source: str) -> Sequence[Any]:
    """调用分析器，**同步/异步都支持**（`isawaitable` 判一次即可）。"""
    result = analyzer(file_path, source)
    if inspect.isawaitable(result):
        return await result
    return result


# ---------------------------------------------------------------------------
# 校验结论
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PatchCheck:
    """四道校验的逐项结论（↔ `patches` 表的四列 + `failure_reason`）。"""

    valid_diff: bool
    window_ok: bool
    apply_check_ok: bool
    taint_cleared: bool
    failure_reason: str | None = None

    @property
    def accepted(self) -> bool:
        """四道全过才算「有补丁」。**这是唯一允许把补丁带给用户的判据。**"""
        return self.valid_diff and self.window_ok and self.apply_check_ok and self.taint_cleared

    def to_orm_fields(self) -> dict[str, Any]:
        """直接摊进 `Patch(**fields)` 的一份映射。"""
        return {
            "valid_diff": self.valid_diff,
            "window_ok": self.window_ok,
            "apply_check_ok": self.apply_check_ok,
            "taint_cleared": self.taint_cleared,
            "failure_reason": self.failure_reason,
        }


@dataclass(frozen=True, slots=True)
class Hunk:
    """一个 diff 块 + 它在**原文件**中触碰到的行号集合。"""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    touched_lines: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class ParsedDiff:
    """手写解析的结果。**它是第 ③ 道校验真正应用的那份文本的唯一来源。**"""

    text: str  # 归一化后的 diff（a/ b/ 前缀补齐）—— 应用的是这一份，不是原始输入
    old_path: str
    new_path: str
    hunks: tuple[Hunk, ...] = field(default_factory=tuple)

    @property
    def touched_lines(self) -> tuple[int, ...]:
        return tuple(sorted({n for h in self.hunks for n in h.touched_lines}))


# ---------------------------------------------------------------------------
# ① 合法性：手写 unified diff 解析器
# ---------------------------------------------------------------------------
#
# 不用 `unidiff` 之类的库：一是环境里没有、而本模块不许装依赖；二是这里需要的
# 不是"通用 diff 解析"，而是"**能被严格判定的一小撮结构**"——需要拒绝的正是
# 那些"看起来像 diff、但块头行数与实际行数对不上"的伪造/截断产物，
# 自己写反而能把这条规则写死。


def parse_unified_diff(text: str) -> tuple[ParsedDiff | None, str | None]:
    """解析 unified diff。返回 `(结果, 失败原因)`，二者必有其一。"""
    if not text or not text.strip():
        return None, "补丁为空"

    lines = text.splitlines()
    old_path: str | None = None
    new_path: str | None = None
    diff_git_path: str | None = None
    hunks: list[Hunk] = []
    header_done = False

    index = 0
    total = len(lines)
    while index < total:
        line = lines[index]

        if line.startswith("diff --git "):
            file_header = _RE_FILE_HEADER.match(line)
            if file_header is None or file_header.group("a") != file_header.group("b"):
                return None, f"不支持的 `diff --git` 头（两侧路径必须一致）：{line!r}"
            diff_git_path = file_header.group("a")
            index += 1
            continue

        # git 的元信息行：不改变补丁语义，跳过（LLM 常顺手带上 index/new file mode）
        if line.startswith(
            ("index ", "new file mode", "deleted file mode", "old mode", "new mode")
        ):
            index += 1
            continue

        if line.startswith("--- "):
            if header_done:
                return None, "一个补丁里出现了多个 `---` 头（multi-file diff 一律拒绝）"
            try:
                old_path = _strip_diff_path(line[4:])
            except ValueError as exc:
                # 路径是外部输入，`../../` 之类的逃逸在这里变成一条拒绝原因。
                # **不能让它以异常穿出去**：解析器的契约是「要么给出结果，
                # 要么给出原因」，抛异常会让调用方（B6 的接口）变成 500，
                # 而 500 的语义是"再试一次可能就好了"，与"这个补丁不能用"完全不同。
                return None, f"`---` 行的路径非法：{exc}"
            if old_path is None:
                return None, f"`---` 行的路径非法：{line[4:]!r}"
            index += 1
            continue

        if line.startswith("+++ "):
            if old_path is None:
                return None, "`+++` 行出现在 `---` 之前"
            try:
                new_path = _strip_diff_path(line[4:])
            except ValueError as exc:
                return None, f"`+++` 行的路径非法：{exc}"
            if new_path is None:
                return None, f"`+++` 行的路径非法：{line[4:]!r}"
            header_done = True
            index += 1
            continue

        if line.startswith("@@"):
            if not header_done:
                return None, "`@@` 块头出现在文件头之前"
            hunk, failure, index = _parse_hunk(lines, index)
            if failure is not None or hunk is None:
                return None, failure
            hunks.append(hunk)
            continue

        # 块外出现非空内容 —— 拼不成一个合法补丁
        if line.strip():
            if old_path is None:
                return None, f"补丁不是 unified diff（缺少 `---`/`+++` 头）：{line.strip()[:60]!r}"
            return None, f"补丁里出现了 diff 结构之外的文本：{line!r}"
        index += 1

    if not header_done or old_path is None or new_path is None:
        return None, "缺少 `---` / `+++` 文件头"
    if not hunks:
        return None, "补丁里没有任何修改块（`@@`）"
    if diff_git_path is not None:
        try:
            same_file = _normalize_rel(diff_git_path) == _normalize_rel(new_path)
        except ValueError as exc:
            return None, f"`diff --git` 头的路径非法：{exc}"
        if not same_file:
            return None, "`diff --git` 头与 `+++` 行的路径不一致"

    touched = sorted({n for h in hunks for n in h.touched_lines})
    if not touched:
        return None, "补丁只有上下文行、没有任何增删，不构成修复"

    normalized = _normalize_headers(text, old_path=old_path, new_path=new_path)
    return (
        ParsedDiff(
            text=normalized,
            old_path=old_path,
            new_path=new_path,
            hunks=tuple(hunks),
        ),
        None,
    )


def _parse_hunk(lines: Sequence[str], start: int) -> tuple[Hunk | None, str | None, int]:
    """解析一个 `@@` 块，**并核对块头声明的行数与实际行数**。

    这条核对是解析器存在的主要价值：`git apply` 也会发现行数不符，但那是第 ③ 道；
    我们要在第 ① 道就用一段可读的中文说清楚"它错在哪"，而不是把 `git` 的英文
    报错原样丢给人。
    """
    match = _RE_HUNK.match(lines[start])
    if match is None:
        return None, f"非法的块头：{lines[start]!r}", start + 1
    old_start = int(match.group(1))
    old_count = int(match.group(2)) if match.group(2) is not None else 1
    new_start = int(match.group(3))
    new_count = int(match.group(4)) if match.group(4) is not None else 1

    old_seen = 0
    new_seen = 0
    old_cursor = old_start
    touched: list[int] = []
    #: 当前这组"改动"（连续的 `-`/`+`）在原文件里的起始行号。
    #:
    #: 为什么需要它：`-\n+` 是**替换**，新增行占据的就是被删掉的那一行在原文件里的
    #: 位置。若按 `old_cursor` 记（删除行已经把它推进了一格），一个恰好落在窗口
    #: 边界上的合法替换会被判成"改到了 ±20 行之外" —— 一次纯属自造的拒绝。
    group_start: int | None = None
    index = start + 1
    while index < len(lines):
        line = lines[index]
        if line.startswith("@@"):
            break
        if line.startswith("diff --git ") or line.startswith("--- "):
            break
        if line.startswith("\\"):  # `\ No newline at end of file`：合法，不计数
            index += 1
            continue
        if line.startswith("+"):
            # 新增行在**原文件**里的位置 = 它插进来的那一点
            touched.append(group_start if group_start is not None else old_cursor)
            new_seen += 1
        elif line.startswith("-"):
            if group_start is None:
                group_start = old_cursor
            touched.append(old_cursor)
            old_cursor += 1
            old_seen += 1
        elif line.startswith(" "):
            group_start = None  # 上下文行结束了上一组改动
            old_cursor += 1
            old_seen += 1
            new_seen += 1
        else:
            break
        index += 1

    if old_seen != old_count or new_seen != new_count:
        return (
            None,
            f"块头声明的行数与实际内容不符（声明 -{old_count}/+{new_count}，"
            f"实际 -{old_seen}/+{new_seen}）—— 补丁被截断或被伪造",
            index,
        )
    return (
        Hunk(
            old_start=old_start,
            old_count=old_count,
            new_start=new_start,
            new_count=new_count,
            touched_lines=tuple(touched),
        ),
        None,
        index,
    )


def _strip_diff_path(raw: str) -> str | None:
    """从 `---` / `+++` 行里取出路径（丢掉制表符后的时间戳，剥掉 a/ b/ 前缀）。

    返回 `None` 表示这个路径**不可接受**：绝对路径、含 `..`、或落到工作区之外。
    补丁路径是外部输入，这里是唯一能拦住"改到别的文件去"的地方 ——
    第 ② 道校验只看得见行号，看不见路径。
    """
    path = raw.split("\t", 1)[0].strip()
    if not path or path == "/dev/null":
        # 新建/删除整文件：我们的补丁一定要改既有文件，整文件增删直接不接受
        return None
    return _normalize_rel(path)


def _normalize_rel(path: str) -> str:
    """剥掉 `a/` `b/` 前缀；非法路径抛 `ValueError`（由调用方转成拒绝原因）。"""
    cleaned = path.replace("\\", "/").strip()
    for prefix in ("a/", "b/"):
        if cleaned.startswith(prefix) and len(cleaned) > len(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise ValueError(f"补丁路径是绝对路径：{path!r}")
    normalized = posixpath.normpath(cleaned)
    if normalized.startswith("..") or normalized in ("", "."):
        raise ValueError(f"补丁路径逃出了工作区：{path!r}")
    return normalized


def _normalize_headers(text: str, *, old_path: str, new_path: str) -> str:
    """把 `---` / `+++` 行统一补成 `a/` `b/` 前缀，供 `git apply -p1` 使用。

    **只改前缀，不改任何内容行** —— 于是"被校验的补丁"与"被应用的补丁"
    是同一份文本，第 ③ 道校验的结论才对第 ② ④ 道有意义。
    """
    out: list[str] = []
    for line in text.splitlines():
        if line.startswith("diff --git "):
            out.append(f"diff --git a/{old_path} b/{new_path}")
        elif line.startswith("--- "):
            out.append(f"--- a/{old_path}")
        elif line.startswith("+++ "):
            out.append(f"+++ b/{new_path}")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# ② 窗口：只允许动触发行 ±20 行，且只动一个文件
# ---------------------------------------------------------------------------


def check_window(
    parsed: ParsedDiff, *, file_path: str, line_start: int, line_end: int
) -> tuple[bool, str]:
    """② 改动是否全部落在 `[line_start-20, line_end+20]`，且目标是这个文件。"""
    try:
        expected = _normalize_rel(file_path) if file_path else ""
    except ValueError as exc:
        return False, f"finding 的文件路径不可用：{exc}"
    if expected and parsed.new_path != expected and parsed.old_path != expected:
        return False, (
            f"补丁的目标文件是 {parsed.new_path!r}，与 finding 的文件 {expected!r} 不一致"
        )
    if line_start <= 0 or line_end <= 0:
        return False, "finding 缺少触发行号，无法判定 ±20 行窗口（拒绝而不是放行）"

    low = max(1, line_start - PATCH_WINDOW_LINES)
    high = line_end + PATCH_WINDOW_LINES
    outside = [n for n in parsed.touched_lines if n < low or n > high]
    if outside:
        return False, (
            f"改到了触发行（{line_start}-{line_end}）±{PATCH_WINDOW_LINES} 行之外："
            f"第 {outside[0]} 行（越界 {len(outside)} 处）。"
            f"允许范围 {low}-{high}"
        )
    return True, ""


# ---------------------------------------------------------------------------
# ③ 可应用：在临时副本上干跑 + 真应用
# ---------------------------------------------------------------------------


def _run_git_apply(diff_file: Path, workdir: Path, *, check: bool) -> tuple[bool, str]:
    """在工作目录里跑 `git apply`。**只用于临时目录，绝不用于工作区。**"""
    argv = ["git", "apply", "-p1", "--whitespace=nowarn"]
    if check:
        argv.append("--check")
    argv.append(str(diff_file))
    try:
        proc = subprocess.run(  # noqa: S603 - argv 全字面量，无 shell，路径由本模块构造
            argv,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            # 显式解码而不是 `text=True` 的默认行为：git 的报错里会带上目标文件名，
            # 在中文 Windows 上那是 GBK 字节。默认按 locale 解码时好时坏，
            # 坏的时候异常发生在 `subprocess` 的读取线程里 —— 表现为评审线程上
            # 冒一条警告，而我们的调用方只看到"没有输出"。这里强制 UTF-8 +
            # 替换非法字节：我们要的是"能不能应用"这个判定，不是那段报错的原文。
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError:
        # 环境里没有 git ⇒ **判不通过**（见模块头第 2 条硬约束）
        return False, "环境缺少 git，无法完成可应用性校验（保守判不通过）"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"git apply 执行失败：{exc}"

    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")
        return False, f"git apply {'--check ' if check else ''}失败：{message[:300]}"
    return True, ""


def apply_in_sandbox_copy(
    parsed: ParsedDiff, *, file_path: str, source: str
) -> tuple[bool, str, str | None]:
    """把补丁应用到**临时目录里的源码副本**上。

    返回 `(是否成功, 失败原因, 打补丁后的源码)`。

    ⚠️ 这里是本模块唯一会执行外部工具的地方，也是"补丁文本被应用"这件事
    在整个系统里唯一的发生地 —— 而且发生在 `TemporaryDirectory()` 里，
    出不出得去由 OS 决定。工作区那一份**从头到尾只被读过**。
    """
    try:
        with tempfile.TemporaryDirectory(prefix="asa-patch-") as tmp:
            workdir = Path(tmp)
            target = workdir / _normalize_rel(file_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8", newline="")

            diff_file = workdir / "asa-patch.diff"
            diff_file.write_text(parsed.text, encoding="utf-8", newline="")

            ok, reason = _run_git_apply(diff_file, workdir, check=True)
            if not ok:
                return False, reason, None

            ok, reason = _run_git_apply(diff_file, workdir, check=False)
            if not ok:
                # --check 过了而真应用没过：极少见（并发/权限），但要报出来
                return False, f"干跑通过但实际应用失败：{reason}", None

            patched = target.read_text(encoding="utf-8")
            return True, "", patched
    except OSError as exc:
        return False, f"临时工作目录不可用：{exc}", None


# ---------------------------------------------------------------------------
# ④ 污点消失：重跑污点引擎
# ---------------------------------------------------------------------------


def finding_key(finding: Any) -> tuple[str, str, str]:
    """finding 的身份锚：`(文件, 漏洞类型, 下沉点符号)`。

    三个字段合起来才够定位"同一个问题"：光看文件会漏掉"同文件里的另一处同类漏洞"，
    光看符号会漏掉"另一个文件里的同名 sink"（`execute` 到处都是）。
    这也正是契约 2 与 B4 自己的 `Finding.sink_symbol` 所指向的那个锚点。
    """
    file_path = str(getattr(finding, "file_path", "") or "")
    vuln_type = getattr(finding, "vuln_type", "")
    vuln_type = getattr(vuln_type, "value", vuln_type)  # StrEnum → str
    symbol = getattr(finding, "symbol", None)
    if not symbol:
        # B4 的 Finding 有 `sink_symbol`；B3 的 FindingRef 没有 —— 两条路都兼容
        symbol = getattr(finding, "sink_symbol", "") or ""
        if not symbol:
            sink_kind = getattr(finding, "sink_kind", "")
            symbol = getattr(sink_kind, "value", sink_kind) or ""
    return (file_path, str(vuln_type), str(symbol))


async def check_taint_cleared(
    *,
    file_path: str,
    original: str,
    patched: str,
    target_key: tuple[str, str, str],
    analyzer: FileAnalyzer,
) -> tuple[bool, str]:
    """④ 在补丁后的源码上重跑污点引擎。

    两个断言，缺一不可：
      * **原来那条路径消失了** —— `target_key` 不再出现在 findings 里；
      * **没有引入新问题** —— 补丁后的 finding 集合 ⊆ 补丁前的集合。
        少了这一条，一个"把 A 的漏洞挪成 B 的漏洞"的补丁会被判通过。

    分析器不可用（`AnalyzerUnavailable`）⇒ **判不通过**：第 ④ 道是四道里唯一
    真正验证"修好了"的一道，它缺席时放行等于把前三道降级成"格式检查"。
    """
    try:
        before = {finding_key(f) for f in await _call_analyzer(analyzer, file_path, original)}
        after = {finding_key(f) for f in await _call_analyzer(analyzer, file_path, patched)}
    except AnalyzerUnavailable as exc:
        return False, f"污点引擎不可用，无法完成第 ④ 道校验（保守判不通过）：{exc}"
    except Exception as exc:  # noqa: BLE001 - 分析器抛任何异常都不能让补丁溜过去
        return False, f"重跑污点引擎时出错（保守判不通过）：{type(exc).__name__}: {exc}"

    if target_key not in before:
        return False, (
            f"污点引擎在**原始源码**上并未报出 {_describe_key(target_key)} —— "
            f"无法确认这次修复修的是什么（可能是 finding 过期或身份锚对不上）"
        )
    if target_key in after:
        return False, f"补丁应用后污点路径**仍在**：{_describe_key(target_key)} 依然被报出"
    introduced = sorted(after - before)
    if introduced:
        return False, (
            f"补丁引入/暴露了新的污点路径（{len(introduced)} 处），例如 "
            f"{_describe_key(introduced[0])}"
        )
    return True, ""


def _describe_key(key: tuple[str, str, str]) -> str:
    return f"{key[0]} 的 {key[1]}（sink={key[2] or '?'}）"


# ---------------------------------------------------------------------------
# 四道闸门的总入口
# ---------------------------------------------------------------------------


class PatchGate:
    """四道校验的门面。**无状态。**"""

    def __init__(self, analyzer: FileAnalyzer | None = None) -> None:
        # 分析器惰性化：默认实现要 import B4，而 B4 未落地时不该在这里就炸
        self._analyzer = analyzer
        self._analyzer_loaded = analyzer is not None

    def _get_analyzer(self) -> FileAnalyzer:
        if not self._analyzer_loaded:
            self._analyzer = default_analyzer()
            self._analyzer_loaded = True
        if self._analyzer is None:  # pragma: no cover - 防御性：默认实现不会返回 None
            raise AnalyzerUnavailable("未注入分析器，且默认分析器不可用")
        return self._analyzer

    async def check(
        self,
        patch_text: str,
        *,
        finding: Any,
        file_path: str,
        source: str,
    ) -> PatchCheck:
        """四道校验顺序执行，**第一道不过就返回**（`PatchCheck` 里其余项保持 false）。

        四道里只有第 ③ 道起子进程（`to_thread`），第 ④ 道本身就是异步的
        （B4 的 `analyze` 是协程）；①② 是纯文本运算，毫秒级，留在当前栈上
        比丢进线程池更省事，也更好读。
        """
        parsed, failure = _safe_parse(patch_text)
        if parsed is None:
            return PatchCheck(
                valid_diff=False,
                window_ok=False,
                apply_check_ok=False,
                taint_cleared=False,
                failure_reason=f"[① 合法性] {failure}",
            )

        window_ok, window_reason = check_window(
            parsed,
            file_path=file_path,
            line_start=int(getattr(finding, "line_start", 0) or 0),
            line_end=int(getattr(finding, "line_end", 0) or 0),
        )
        if not window_ok:
            return PatchCheck(
                valid_diff=True,
                window_ok=False,
                apply_check_ok=False,
                taint_cleared=False,
                failure_reason=f"[② 窗口] {window_reason}",
            )

        applied, apply_reason, patched = await asyncio.to_thread(
            apply_in_sandbox_copy, parsed, file_path=file_path, source=source
        )
        if not applied or patched is None:
            return PatchCheck(
                valid_diff=True,
                window_ok=True,
                apply_check_ok=False,
                taint_cleared=False,
                failure_reason=f"[③ 应用] {apply_reason}",
            )

        try:
            analyzer = self._get_analyzer()
        except AnalyzerUnavailable as exc:
            # 分析器拿不到 = 第 ④ 道做不了 = **判不通过**（模块头硬约束 2）。
            # 这里必须自己接住：让异常穿出去会把「补丁没通过校验」变成
            # 「接口 500」，而 500 的语义是"再试一次可能就好了"。
            return PatchCheck(
                valid_diff=True,
                window_ok=True,
                apply_check_ok=True,
                taint_cleared=False,
                failure_reason=f"[④ 污点] 污点引擎不可用（保守判不通过）：{exc}",
            )

        cleared, taint_reason = await check_taint_cleared(
            file_path=file_path,
            original=source,
            patched=patched,
            target_key=finding_key(finding),
            analyzer=analyzer,
        )
        if not cleared:
            return PatchCheck(
                valid_diff=True,
                window_ok=True,
                apply_check_ok=True,
                taint_cleared=False,
                failure_reason=f"[④ 污点] {taint_reason}",
            )
        return PatchCheck(valid_diff=True, window_ok=True, apply_check_ok=True, taint_cleared=True)


def _safe_parse(text: str) -> tuple[ParsedDiff | None, str | None]:
    """解析补丁。`_normalize_rel` 抛的 `ValueError` 在这里变成一条拒绝原因。"""
    try:
        return parse_unified_diff(text)
    except ValueError as exc:
        return None, str(exc)


async def check_patch(
    patch_text: str,
    *,
    finding: Any,
    file_path: str,
    source: str,
    analyzer: FileAnalyzer | None = None,
) -> PatchCheck:
    """模块级入口：补丁四道校验。

    `source` 是 finding 所在文件的**原始源码文本**（由调用方从工作区只读读出）。
    `analyzer` 只在测试里注入 —— 生产路径用 `default_analyzer()`。
    """
    return await PatchGate(analyzer).check(
        patch_text, finding=finding, file_path=file_path, source=source
    )


# ---------------------------------------------------------------------------
# 默认分析器：把契约 4 的 `analysis.analyze` 适配成单文件调用
# ---------------------------------------------------------------------------


def default_analyzer() -> FileAnalyzer:
    """返回一个基于 `app.analysis.analyze` 的单文件分析器。

    契约 4 的入口是 `analysis.analyze(manifest, read_source) -> AnalysisResult`，
    需要一个**清单**；第 ④ 道只需要一个文件，所以这里现造一个单文件清单
    （`SourceManifest` + 一份 `read_source` 闭包），把补丁后的源码喂进去。
    `sha1` 照实算 —— 分析器可能用它做缓存键，喂个假值会命中错误的缓存。
    """
    try:
        from app.analysis import analyze  # 延迟导入：B4 未落地时不在这里炸
    except ImportError as exc:  # pragma: no cover - 取决于 B4 是否已落地
        raise AnalyzerUnavailable(f"无法导入 app.analysis.analyze：{exc}") from exc

    async def _analyze_file(file_path: str, source: str) -> Sequence[Any]:
        try:
            from app.projects.types import FileEntry, SourceManifest
        except ImportError as exc:  # pragma: no cover
            raise AnalyzerUnavailable(f"无法导入清单类型：{exc}") from exc

        encoded = source.encode("utf-8")
        entry = FileEntry(
            rel_path=file_path,
            ext=os.path.splitext(file_path)[1],
            language=None,
            loc=source.count("\n") + 1,
            size_bytes=len(encoded),
            sha1=hashlib.sha1(encoded).hexdigest(),  # noqa: S324 - 标识用途，不是安全摘要
        )
        manifest = SourceManifest(
            total_files=1,
            total_loc=entry.loc,
            size_bytes=entry.size_bytes,
            entries=[entry],
        )
        # `analyze` 是协程（它要 await 读取回调）—— 必须 await 它，
        # 否则拿到的是协程对象，`findings` 取不到、集合恒为空集，
        # 第 ④ 道就会对**每一条**补丁都报「原始源码上没有报出该漏洞」。
        result = await analyze(manifest, lambda _path: source)
        findings = getattr(result, "findings", None)
        if findings is None:
            raise AnalyzerUnavailable(
                f"analysis.analyze 未返回 findings（拿到 {type(result).__name__}）"
            )
        return list(findings)

    return _analyze_file


#: 供 B3 直接使用的一份共享实例（分析器惰性加载，构造它没有代价）
gate = PatchGate()
