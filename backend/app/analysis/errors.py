"""B4 专用异常（设计文档 §6 第 11、12 条）。

**为什么 B4 只有两个异常**：没有网络、没有沙箱、没有数据库，就没有 L4/L5 的
来源 —— 除了「解析器本身不可用」与「源码根读不出来」这两件事，其它一切都是
「跳过单文件 + 记 SkipRecord」。这是「纯函数、零依赖」的结构性收益：
错误面小到可以用一句话讲完。

两个错误码原先复用 `INTERNAL` / `SOURCE_UNAVAILABLE`（B4 按分层铁律不得改
`app/core/`）；现已在 `app/core/exceptions.py` 登记了
`TAINT_ENGINE_UNAVAILABLE` / `TAINT_ROOT_UNREADABLE`（数字码 5005 / 5006）。
分开的理由：这两个成因的处置方向完全不同 —— 「解析器坏了」要重建环境，
「根目录读不到」要查挂载与权限，而 `INTERNAL` 把两者都糊成「服务端出错了」。
"""

from __future__ import annotations

from app.core.exceptions import (
    CODE_TAINT_ENGINE_UNAVAILABLE,
    CODE_TAINT_ROOT_UNREADABLE,
    AppError,
)


class TaintEngineUnavailable(AppError):
    """tree-sitter 未安装 / ABI 不匹配 —— 总纲 §9.1 的 **L5 致命**。

    刻意抛而不是降级：一个连 AST 都解析不出来的污点引擎，返回空 findings
    的后果是「评估显示零漏洞」，与「没有漏洞」不可区分，比直接失败危险得多。
    B3 捕获后应把 `code_audit` 阶段标 `failed`（总纲 §5.2）。
    """

    code = CODE_TAINT_ENGINE_UNAVAILABLE
    http_status = 500
    error_code = "TAINT_ENGINE_UNAVAILABLE"
    default_remediation = "确认已安装 tree-sitter 与 tree-sitter-python，且二者 ABI 版本匹配"
    default_retryable = False


class SourceUnreadable(AppError):
    """源码工作区根不可读 / 权限拒绝 —— 总纲 §9.1 的 **L5**。

    与「单个文件读不出来」（L1，记 SkipRecord 后继续）是两件事：
    根目录都进不去，说明是环境问题，继续跑只会得到一个空的 TaintReport，
    然后被误读成「这个项目很干净」。
    """

    code = CODE_TAINT_ROOT_UNREADABLE
    http_status = 502
    error_code = "TAINT_ROOT_UNREADABLE"
    default_remediation = "检查源码工作区目录是否存在、进程是否有读权限"
    default_retryable = False
