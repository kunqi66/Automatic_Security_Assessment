"""`from app.X import Y` 里的 `Y` 必须真的存在。

## 这个文件钉的是什么

实测（2026-10-16）：`orchestrator/engine.py::_default_sandbox_provider` 写的是

    from app.sandbox.service import get_sandbox

而 `app/sandbox/service.py` 只导出 `SandboxService` / `build_docker_client` ——
**`get_sandbox` 从来没被写过**。这个 import 在函数体里，所以：

- 模块导入期不报错（`import app.orchestrator.engine` 完全正常）；
- `ruff` 不报错（它不做跨模块符号解析）；
- **任何「导入全部模块」的冒烟测试也不报错** —— 那个 import 从没被执行到。

症状是 `poc_verify` **永远**降级为 `skipped`，日志里一行 WARNING 说
「沙箱不可用」。而 `poc_verify` 是 B2 里唯一碰 Docker 的阶段，
于是一整条动态验证链路（沙箱服务、Dockerfile、镜像构建、探针）全都白做，
报告还把它解释成「未配置沙箱」—— 一个看起来像**部署没做全**的措辞。

## 为什么用 AST 扫而不是「把模块都 import 一遍」

import 一遍只能执行模块顶层。真正会烂的是**函数体里的惰性 import**
（写它们本来就是为了延迟代价），而惰性 import 恰恰只在对应分支上才执行 ——
即「跑得到就报错，跑不到就静默降级」。AST 扫源码与运行时覆盖率无关，
这条分支有没有被测到都一样会红。
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
from pathlib import Path

import pytest

_APP_ROOT = Path(__file__).resolve().parent.parent / "app"


def _modules() -> list[Path]:
    return sorted(p for p in _APP_ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def _module_name(path: Path) -> str:
    rel = path.relative_to(_APP_ROOT.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported_names(tree: ast.AST) -> list[tuple[str, str, int]]:
    """收集所有 `from <module> import <name>`（含函数体内的）。"""
    out: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:  # 相对 import：模块名不完整，另行处理
            continue
        if not node.module:
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            out.append((node.module, alias.name, node.lineno))
    return out


def _resolve_relative(path: Path, node: ast.ImportFrom) -> str | None:
    """把 `from .foo import bar` 还原成绝对模块名。"""
    parts = list(_module_name(path).split("."))
    if path.name != "__init__.py":
        parts.pop()
    # level=1 表示当前包；level=2 表示上一级
    up = node.level - 1
    if up:
        parts = parts[:-up] if up <= len(parts) else []
    if node.module:
        parts.extend(node.module.split("."))
    return ".".join(parts) if parts else None


def _has(name: str, module: str, attr: str) -> bool:
    """`attr` 要么是 `module` 的属性，要么是它的子模块。"""
    try:
        mod = importlib.import_module(name)
    except Exception:  # noqa: BLE001 —— 导入不了由另一个测试负责，这里不重复报
        return True
    if hasattr(mod, attr):
        return True
    # `from app.analysis import parser` 这类：parser 是子模块，
    # 只有当它已被导入时才是属性 —— 显式查一次 spec，避免误报。
    #
    # 父模块不是包时（`app.sandbox.service` 是模块，没有 `__path__`），
    # `find_spec` 会抛 `ModuleNotFoundError` 而不是返回 None ——
    # 那是「查不了」，不是「找到了」。漏掉这个 except 会让**不存在的名字
    # 把异常抛穿**，看起来像测试自己坏了，而真正的问题是那个名字。
    try:
        return importlib.util.find_spec(f"{name}.{attr}") is not None
    except (ImportError, AttributeError, ValueError):
        return False


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.name)
def test_源码里的_import_名字都存在(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    problems: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        name = node.module if not node.level else _resolve_relative(path, node)
        if not name or not (name == "app" or name.startswith("app.")):
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            if not _has(name, node.module or "", alias.name):
                problems.append(f"第 {node.lineno} 行：{name} 里没有 `{alias.name}`")

    assert not problems, f"{path.relative_to(_APP_ROOT.parent)} 存在无效导入：\n  " + "\n  ".join(
        problems
    )


def test_这个测试真的会抓到不存在的名字() -> None:
    """**给测试本身做个阴性对照。**

    一个永远为绿的守卫比没有守卫更糟：它会让「有测试盯着」变成一句空话。
    这里对一个确定不存在的名字跑一遍判定逻辑，确认它返回 False。
    """
    assert _has("app.sandbox.service", "app.sandbox.service", "get_sandbox") is False
    assert _has("app.sandbox.service", "app.sandbox.service", "SandboxService") is True
