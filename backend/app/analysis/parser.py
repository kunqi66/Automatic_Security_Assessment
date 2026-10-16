"""tree-sitter 封装：语言注册、解析、行号映射、容错降级（设计文档 §2 的 parser）。

**为什么是 tree-sitter 而不是内置 `ast`**（设计文档 §7.2 取舍 2）：内置 `ast`
遇语法错**直接抛**，而真实工程里的 `.py` 常带语法错（半成品、py2 遗留、
被 profile 改坏的文件）。一旦抛，设计文档 §6 场景 1 要求的「该文件跳过、
其余文件继续、文件内可解析片段仍尝试匹配」就无从实现。
tree-sitter **容错解析**：错误节点附近的子树照样成形，我们能继续做匹配。

**为什么不是正则**：污点传播要问的是「这个变量此刻的污点状态」，而它的答案
依赖「哪条赋值先发生、在哪个分支里、是不是在循环回边上」。正则看不出嵌套层级，
`f"{a + b}"`、`x = (y or z)`、跨行续行、字符串里的 `#` 都会让规则错位。
规则一复杂必然在多层嵌套上崩，而「崩」的表现是静默错误而不是报错。
"""

from __future__ import annotations

import fnmatch
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from app.analysis.errors import SourceUnreadable, TaintEngineUnavailable
from app.core.logging import get_logger

logger = get_logger(__name__)

#: 语言名 → tree_sitter 的 language 工厂。**扩展位**：支持新语言只需在这里
#: 加一行 + 在 sources/sinks/sanitizers 三张表里加该语言的规则分组，
#: 不用动传播算法（设计文档 §7.2 取舍 10：本期只实现 Python）。
_LANGUAGE_FACTORIES: dict[str, tuple[str, str]] = {
    "python": ("tree_sitter_python", "language"),
}

#: 默认包含的文件模式。`**/` 前缀由 `_match_include` 显式处理（`PurePosixPath.match`
#: 在 3.12 上不让 `**/*.py` 命中根目录下的 `a.py`，直接用会漏掉 `app.py` 这类入口文件）。
DEFAULT_INCLUDE: tuple[str, ...] = ("**/*.py",)

#: 目录名命中即整棵剪掉。与 B1 `ScanRules.exclude_dirs` 的口径一致 ——
#: 走 `analyze(manifest, ...)` 时用的是 B1 已经过滤好的清单，这份表只服务于
#: `analyze_project(root)` 这个「直接扔一个目录进来」的入口（靶场回归与单测用）。
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "node_modules",
        "bower_components",
        "site-packages",
        "dist",
        "build",
        "target",
        ".idea",
        ".vscode",
    }
)

#: 读取源码时的编码降级阶梯（设计文档 §6 场景 2）。
#: `utf-8-sig` 排在最前：带 BOM 的文件用纯 `utf-8` 读出来首行会带一个
#: `﻿`，那个字符会让第一行的 `import` 解析出一个语法错节点。
#: `latin-1` 兜底：它**永不失败**（任意字节序列都是合法 latin-1），
#: 保证「读不出内容」这件事不会成为跳过文件的理由。
_ENCODING_LADDER: tuple[str, ...] = ("utf-8-sig", "utf-8", "gbk", "latin-1")

#: AST 遍历深度上限（设计文档 §6 场景 5）。超过就停止下钻，用已有结果并记 WARN。
#: 真实源码的嵌套极少超过 20 层，设 500 是「防深到爆栈」而不是「正常路径的闸」。
MAX_AST_DEPTH = 500


@dataclass(frozen=True, slots=True)
class ParsedFile:
    """一个已解析的文件。`lines` 是 1-based 行的列表（`lines[i - 1]` 即第 i 行）。"""

    rel_path: str
    source: str
    lines: tuple[str, ...]
    root: object  # tree_sitter.Node —— 用 object 标注以免在无 tree-sitter 时都无法导入本模块
    has_error: bool
    parse_ms: int

    def line_text(self, line: int) -> str:
        """取第 `line` 行（1-based）的原文。越界返回空串 —— 行号越界通常意味着
        节点位置与文本不一致，返回空串比抛异常更能让分析继续。"""
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""


# ---------------------------------------------------------------------------
# 语言注册与 parser 构建
# ---------------------------------------------------------------------------


def _build_language(language: str):
    """按名字构建 tree_sitter.Language。失败一律转成 `TaintEngineUnavailable`。"""
    entry = _LANGUAGE_FACTORIES.get(language)
    if entry is None:
        raise TaintEngineUnavailable(
            f"污点引擎尚未注册语言：{language}",
            remediation="当前版本仅支持 Python 工程（tree-sitter-python）",
        )
    module_name, attr = entry
    try:
        module = __import__(module_name, fromlist=[attr])
        factory = getattr(module, attr)
        from tree_sitter import Language

        # tree-sitter-python 0.25 起 `language` 是函数（返回 PyCapsule）；
        # 更早的版本是模块级常量。两种形态都接住，避免锁死上游版本形态。
        ptr = factory() if callable(factory) else factory
        return Language(ptr)
    except TaintEngineUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 —— 统一转成 L5：语法分析器不可用
        raise TaintEngineUnavailable(
            f"tree-sitter 语言包不可用（{language}）：{exc}",
            remediation="确认 tree-sitter 与 tree-sitter-python 均已安装且 ABI 匹配",
        ) from exc


def get_parser(language: str = "python"):
    """构建一个解析器。**每次调用新建，不做进程内缓存**：

    Parser 对象持有可变缓冲，跨线程/跨调用复用会引入隐蔽的状态耦合；
    而 B4 的全部收益都建立在「同一个输入必然同一份输出」上。
    构建成本在微秒量级，不值得为它引入共享状态。
    """
    from tree_sitter import Parser

    return Parser(_build_language(language))


# ---------------------------------------------------------------------------
# 文件枚举与读取
# ---------------------------------------------------------------------------


def _match_include(rel_path: str, patterns: Sequence[str]) -> bool:
    """`**/*.py` 这类模式要能命中根目录下的 `app.py`。

    `PurePosixPath.match("**/*.py")` 在 Python 3.12 上对 `a.py` 返回 False
    （`**/` 至少要求一段目录），所以这里额外把 `**/` 前缀剥掉再匹配一次。
    """
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(rel_path, pattern[3:]):
            return True
    return False


def iter_py_files(
    root: Path,
    *,
    include: Sequence[str] | None = None,
    exclude_dirs: frozenset[str] = DEFAULT_EXCLUDE_DIRS,
) -> list[str]:
    """枚举 `root` 下的源码文件，返回**排序后的**相对 POSIX 路径列表。

    排序是确定性地基的一部分：目录遍历顺序由文件系统决定（Windows 与 Linux
    不同、同一台机器上也会随目录项变动），不排序的话 findings 的顺序会漂。
    """
    patterns = tuple(include) if include else DEFAULT_INCLUDE
    found: list[str] = []

    def _walk(directory: Path, prefix: str) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError as exc:  # 权限拒绝 / 目录消失 —— 剪掉这一枝，不影响其它枝
            logger.warning("目录不可读，已跳过：%s（%s）", directory, exc)
            return
        for entry in entries:
            rel = f"{prefix}/{entry.name}" if prefix else entry.name
            if entry.is_dir():
                if entry.name in exclude_dirs or entry.is_symlink():
                    continue
                _walk(entry, rel)
            elif entry.is_file() and _match_include(rel, patterns):
                found.append(rel)

    if not root.is_dir():
        raise SourceUnreadable(
            f"源码根目录不可读：{root}",
            remediation="确认目录存在且进程有读权限",
        )
    _walk(root, "")
    return sorted(found)


def read_text_file(path: Path) -> str:
    """按编码阶梯读文本，全失败才抛 `UnicodeDecodeError`。

    源码里有非 UTF-8 字节是常事（GBK 注释、粘贴进来的全角引号），
    为此让整个文件退出分析不值得（设计文档 §6 场景 2，级别 L1）。
    """
    last_error: Exception | None = None
    for encoding in _ENCODING_LADDER:
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError as exc:
            last_error = exc
        except OSError as exc:  # 文件消失 / 权限 —— 换编码也没用，直接抛
            raise SourceUnreadable(
                f"源码文件不可读：{path}（{exc}）",
                remediation="确认文件存在且进程有读权限",
            ) from exc
    raise UnicodeDecodeError(  # type: ignore[call-arg]  # pragma: no cover - 兜底
        "unknown", b"", 0, 1, f"所有候选编码均失败：{last_error}"
    )


def make_fs_reader(root: Path) -> Callable[[str], str]:
    """构造一个「相对路径 → 源码文本」的读取器，供 `analyze()` 的 `read_source` 回调。

    **这是适配器，不是 `analyze` 的实现方式**：`analyze()` 只认回调，
    永远不自己碰文件系统 —— 这样 B3 既可以喂工作区（含符号链接与越界校验），
    也可以喂内存里的补丁后源码文本（设计文档 §3.4 的补丁复验场景）。
    """

    def _reader(rel_path: str) -> str:
        return read_text_file(root / rel_path)

    return _reader


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------


def parse_file(rel_path: str, source: str, *, language: str = "python") -> ParsedFile:
    """解析单个文件。语法错**不抛**：`has_error=True` 交给上层记 SkipRecord，
    并继续在可解析的片段上做匹配（设计文档 §6 场景 1）。"""
    started = time.monotonic()
    parser = get_parser(language)
    # 统一换行：tree-sitter 的行号来自字节偏移，`\r\n` 会让「行号 → 文本行」
    # 的映射在 Windows 检出上整体偏一行
    normalized = source.replace("\r\n", "\n").replace("\r", "\n")
    tree = parser.parse(normalized.encode("utf-8", errors="replace"))
    lines = tuple(normalized.split("\n"))
    return ParsedFile(
        rel_path=rel_path,
        source=normalized,
        lines=lines,
        root=tree.root_node,
        has_error=bool(tree.root_node.has_error),
        parse_ms=int((time.monotonic() - started) * 1000),
    )


def count_loc(lines: Sequence[str]) -> int:
    """LOC 口径 = **非空行**，与 B1 `scan_source_tree` 一致 ——
    同一份源码在清单页与漏洞页必须给出同一个代码量，否则两个页面会互相打脸。"""
    return sum(1 for line in lines if line.strip())


# ---------------------------------------------------------------------------
# 节点工具
# ---------------------------------------------------------------------------


def node_line(node: object) -> int:
    """1-based 行号。tree-sitter 的 `start_point.row` 是 0-based。"""
    return int(node.start_point[0]) + 1  # type: ignore[attr-defined]


def node_end_line(node: object) -> int:
    return int(node.end_point[0]) + 1  # type: ignore[attr-defined]


def node_column(node: object) -> int:
    """1-based 列号（前端高亮用 1-based，与人读的行列一致）。"""
    return int(node.start_point[1]) + 1  # type: ignore[attr-defined]


def snippet_of(node: object, limit: int = 200) -> str:
    """节点的源码文本（压缩成单行）。多行调用（`cursor.execute(\n  sql)`）
    在时间轴上显示成一段带换行的文本会撑破布局，所以折成单行并截断。"""
    try:
        text = node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 —— 节点文本取不到不是致命问题，降级成空串  # pragma: no cover
        return ""
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


#: 允许作为「点分名前缀」的字面量节点类型。
#:
#: 为什么需要它：`"{}".format(uid)` / `"%s" % ...` 的接收者是一个**字符串字面量**，
#: 不是标识符。若不特判，`dotted_name` 会返回空串 → `format` 传播器匹配不到 →
#: `"...".format(tainted)` 这条 PRD §7.1 ④ 明确要求支持的拼接形态整类漏报。
#: 字面量前缀是**可以安全拼接**的：我们知道它的类型（字符串/数字），
#: 而 `foo().bar`（调用结果）不能 —— 所以那里仍返回空串（见下）。
_LITERAL_BASE_TYPES: frozenset[str] = frozenset({"string", "integer", "float"})


def dotted_name(node: object) -> str:
    """把 `identifier` / `attribute` 链拼成点分名；其它形态一律返回空串。

    **返回空串是刻意的保守**：`foo().bar` / `d[k].m()` 这类「点在调用结果上」
    的名字我们解析不到（不知道 `foo()` 返回什么类型），返回空串意味着
    上游把它当「未知符号」处理 —— 未知符号不会被错配成项目内函数或危险 sink，
    代价是漏报而不是误报。污点工具里这两个方向的错误代价不对称。
    """
    node_type = node.type  # type: ignore[attr-defined]
    if node_type == "identifier":
        return node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
    if node_type == "attribute":
        obj = node.child_by_field_name("object")  # type: ignore[attr-defined]
        attr = node.child_by_field_name("attribute")  # type: ignore[attr-defined]
        if obj is None or attr is None:
            return ""
        base = dotted_name(obj)
        if not base and obj.type in _LITERAL_BASE_TYPES:  # type: ignore[attr-defined]
            base = snippet_of(obj, limit=60)
        if not base:
            return ""
        return f"{base}.{attr.text.decode('utf-8', errors='replace')}"  # type: ignore[attr-defined]
    return ""


def access_path(node: object) -> str | None:
    """把表达式节点转成**访问路径**（access path）：`uid` / `user.name` / `rows[0]`。

    返回 None 表示这个表达式不是「一个可命名的存储位置」（例如 `f()`、
    `a + b`），因此不能作为赋值左值参与 TaintMap 的键。
    """
    node_type = node.type  # type: ignore[attr-defined]
    if node_type == "identifier":
        return node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
    if node_type == "attribute":
        obj = node.child_by_field_name("object")  # type: ignore[attr-defined]
        attr = node.child_by_field_name("attribute")  # type: ignore[attr-defined]
        if obj is None or attr is None:
            return None
        base = access_path(obj)
        if base is None:
            return None
        name = attr.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
        return f"{base}.{name}"
    if node_type == "subscript":
        value = node.child_by_field_name("value")  # type: ignore[attr-defined]
        index = node.child_by_field_name("subscript")  # type: ignore[attr-defined]
        if value is None or index is None:
            return None
        base = access_path(value)
        if base is None:
            return None
        return f"{base}[{snippet_of(index, limit=40)}]"
    return None


def call_function_node(call_node: object) -> object | None:
    """取 `call` 的 `function` 字段（被调对象）。"""
    if call_node.type != "call":  # type: ignore[attr-defined]
        return None
    return call_node.child_by_field_name("function")  # type: ignore[attr-defined]


def call_args(call_node: object) -> tuple[object, ...]:
    """按**源码顺序**取 `call` 的实参节点（不含关键字参数名）。

    ⚠️ 只返回位置实参：`f(x=1)` 里的 `1` 不在其中。跨函数按参数名映射要走
    `call_keyword_args`。把两者混在一个列表里会让「第 2 个实参」这种
    位置语义悄悄错位 —— 而位置语义正是「危险参数位」规则的判据。
    """
    arguments = call_node.child_by_field_name("arguments")  # type: ignore[attr-defined]
    if arguments is None:
        return ()
    result: list[object] = []
    for child in arguments.named_children:  # type: ignore[attr-defined]
        if child.type in ("keyword_argument", "dictionary_splat"):  # type: ignore[attr-defined]
            break
        if child.type == "list_splat":  # type: ignore[attr-defined]
            break
        result.append(child)
    return tuple(result)


def call_keyword_args(call_node: object) -> dict[str, object]:
    """取关键字实参 `{名字: 值节点}`（含 `**kw` 展开的实参名，值为节点）。

    关键字实参**必须按形参名映射**：`query(uid=x)` 与 `query(x)` 在位置规则下
    会落到不同形参上，而两者在源码里长得完全不同 —— 这是跨函数误配的头号来源。
    """
    arguments = call_node.child_by_field_name("arguments")  # type: ignore[attr-defined]
    if arguments is None:
        return {}
    result: dict[str, object] = {}
    for child in arguments.named_children:  # type: ignore[attr-defined]
        if child.type != "keyword_argument":  # type: ignore[attr-defined]
            continue
        name = child.child_by_field_name("name")  # type: ignore[attr-defined]
        value = child.child_by_field_name("value")  # type: ignore[attr-defined]
        if name is not None and value is not None:
            result[name.text.decode("utf-8", errors="replace")] = value  # type: ignore[attr-defined]
    return result


def walk_named(node: object, *, max_depth: int = MAX_AST_DEPTH) -> Iterator[object]:
    """深度优先遍历命名子节点。`max_depth` 是防爆栈的硬闸（设计文档 §6 场景 5），
    到达即停止下钻 —— 用当前结果并记 WARN，而不是抛。"""
    stack: list[tuple[object, int]] = [(node, 0)]
    warned = False
    while stack:
        current, depth = stack.pop()
        yield current
        if depth >= max_depth:
            if not warned:
                logger.warning("AST 嵌套超过 %d 层，已停止下钻（后续节点不再参与分析）", max_depth)
                warned = True
            continue
        for child in reversed(current.named_children):  # type: ignore[attr-defined]
            stack.append((child, depth + 1))


def block_statements(block_node: object | None) -> tuple[object, ...]:
    if block_node is None:
        return ()
    return tuple(block_node.named_children)  # type: ignore[attr-defined]


def is_terminating(block_node: object | None) -> bool:
    """块的最后一条语句是否一定「离开当前控制流」（return / raise / break / abort()）。

    这是白名单守卫判定的一半：`if x not in ALLOWED: return` 之所以等价于净化，
    前提是**非白名单的取值走不出这个 if**。`if x not in ALLOWED: log(x)` 不是守卫。
    """
    statements = block_statements(block_node)
    if not statements:
        return False
    last = statements[-1]
    if last.type in (
        "return_statement",
        "raise_statement",
        "break_statement",
        "continue_statement",
    ):
        return True
    for child in walk_named(last):
        if child.type != "call":
            continue
        name = dotted_name(call_function_node(child) or child)
        if name.rsplit(".", 1)[-1] in _ABORT_NAMES:
            return True
    return False


#: 视为「终止当前请求」的调用名。`abort` / `send_error` 是 Flask，
#: `HTTPException` 由 raise 覆盖，`exit` / `quit` 是进程级终止。
_ABORT_NAMES: frozenset[str] = frozenset(
    {"abort", "send_error", "exit", "quit", "_exit", "redirect"}
)
