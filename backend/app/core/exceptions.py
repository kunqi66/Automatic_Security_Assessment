"""异常体系与统一错误载荷。

对应总纲 §9.1（错误分级）与 §9.2（错误信息规范）。

**§9.2 的四要素是刻意的**：每个错误必须能回答「在哪个阶段炸的、怎么修」。
面试演示时最怕「报错了但不知道为什么」，`remediation` 让每次失败自带修复指引。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

# ---------------------------------------------------------------------------
# 错误码表
#
# 说明：本项目初稿未定义错误码表，此处**首次定义并作为唯一来源**。
# 编码规则：4xxx 为客户端可纠正的问题，5xxx 为服务端/依赖的问题。
# ---------------------------------------------------------------------------

CODE_OK = 0
CODE_UNAUTHORIZED = 4001  # 未登录 / token 失效
CODE_FORBIDDEN = 4003  # 已登录但角色不足
CODE_NOT_FOUND = 4004  # 资源不存在
CODE_BAD_REQUEST = 4002  # 参数不合法
CODE_INTERNAL = 5000  # 未预期的服务端异常
CODE_SANDBOX_UNREACHABLE = 5001  # SSH/Docker 不可达（可降级，见 §8.2）
CODE_SOURCE_UNAVAILABLE = 5002  # Git 克隆失败 / 源码包损坏（可降级为改用上传）
CODE_LLM_UNAVAILABLE = 5003  # LLM 不可用（可降级为模板生成）
CODE_DEPENDENCY_DOWN = 5004  # 存储类依赖不可用（MySQL/Redis，不可降级）
CODE_TAINT_ENGINE_UNAVAILABLE = 5005  # tree-sitter 不可用（L5，让 code_audit 阶段 failed）
CODE_TAINT_ROOT_UNREADABLE = 5006  # 源码工作区根不可读（L5，同上传源损坏但成因不同）

#: 后端 ↔ 前端 协议里 error_code 的取值集合（机器可读，区别于给人看的 message）
#:
#: ⚠️ 各模块自有的错误码（如 B1 的 `PROJ_*`）也要登记在这里。
#: 不登记的直接后果：`AppError.error_code` 是 `Literal`，子类给它赋一个表外的值
#: 会在类型检查阶段就被拦下 —— 这是刻意的，避免错误码在代码里散着长出来。
ErrorCode = Literal[
    "UNAUTHORIZED",
    "FORBIDDEN",
    "NOT_FOUND",
    "BAD_REQUEST",
    "INTERNAL",
    "SANDBOX_UNREACHABLE",
    "SOURCE_UNAVAILABLE",
    "LLM_UNAVAILABLE",
    "DEPENDENCY_DOWN",
    # ---- B1 项目管理（B1 模块设计 §6）----
    "PROJ_GIT_NOT_ALLOWED",
    "PROJ_GIT_AUTH_FAILED",
    "PROJ_ARCHIVE_FORMAT",
    "PROJ_ARCHIVE_ESCAPE",
    "PROJ_ARCHIVE_BOMB",
    "PROJ_NO_SOURCE",
    "PROJ_DISK_FULL",
    "PROJ_INGEST_LOCKED",
    "PROJ_DELETE_RUNNING",
    "PROJ_REMOTE_SYNC_FAILED",
    "PROJ_SOURCE_PATH_ESCAPE",
    # ---- B4 污点分析（B4 模块设计 §6）----
    # B4 按分层铁律不得改 `app/core/`，所以它先前复用了 `INTERNAL` /
    # `SOURCE_UNAVAILABLE`。那两个码**分不出**「解析器坏了」与「别的内部错误」，
    # 而两者的处置完全不同：前者要重建环境，后者要看堆栈。
    "TAINT_ENGINE_UNAVAILABLE",
    "TAINT_ROOT_UNREADABLE",
]


class AppError(Exception):
    """所有业务异常的基类。

    `remediation` 与 `retryable` 不是装饰：前者直接进前端错误提示与报告，
    后者决定编排层是否走重试（§8.2 降级矩阵）。
    """

    code: int = CODE_INTERNAL
    http_status: int = 500
    error_code: ErrorCode = "INTERNAL"
    default_remediation: str = ""
    default_retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        stage: str | None = None,
        remediation: str | None = None,
        retryable: bool | None = None,
        detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.stage = stage
        self.remediation = remediation or self.default_remediation
        self.retryable = self.default_retryable if retryable is None else retryable
        self.detail = detail

    def to_payload(self) -> dict[str, Any]:
        """§9.2 规定的四要素（+ stage/detail）载荷。"""
        return {
            "stage": self.stage,
            "error_code": self.error_code,
            "message": self.message,
            "remediation": self.remediation,
            "retryable": self.retryable,
            "occurred_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            **({"detail": self.detail} if self.detail is not None else {}),
        }


# ---------------------------------------------------------------------------
# 4xxx —— 客户端可纠正
# ---------------------------------------------------------------------------


class UnauthorizedError(AppError):
    code = CODE_UNAUTHORIZED
    http_status = 401
    error_code = "UNAUTHORIZED"
    default_remediation = "请重新登录"


class ForbiddenError(AppError):
    code = CODE_FORBIDDEN
    http_status = 403
    error_code = "FORBIDDEN"
    default_remediation = "当前角色无权执行该操作，请联系管理员"


class NotFoundError(AppError):
    code = CODE_NOT_FOUND
    http_status = 404
    error_code = "NOT_FOUND"


class BadRequestError(AppError):
    code = CODE_BAD_REQUEST
    http_status = 400
    error_code = "BAD_REQUEST"


# ---------------------------------------------------------------------------
# 5xxx —— 依赖与服务端
# ---------------------------------------------------------------------------


class DependencyDownError(AppError):
    """存储类依赖不可用。§8.2 的原则是「存储类依赖不可降级」——必须让调用方炸。"""

    code = CODE_DEPENDENCY_DOWN
    http_status = 503
    error_code = "DEPENDENCY_DOWN"
    default_remediation = "检查 MySQL / Redis 连通性与账号权限"


class SandboxUnreachableError(AppError):
    code = CODE_SANDBOX_UNREACHABLE
    http_status = 503
    error_code = "SANDBOX_UNREACHABLE"
    default_remediation = "检查阿里云安全组 SSH 放行与密钥权限"
    default_retryable = True


class SourceUnavailableError(AppError):
    code = CODE_SOURCE_UNAVAILABLE
    http_status = 502
    error_code = "SOURCE_UNAVAILABLE"
    default_remediation = "检查仓库地址与凭证；或改用源码包上传"
    default_retryable = True


class LlmUnavailableError(AppError):
    """LLM 不可用。**注意：正常流程不应当抛出它** —— 按 L4 应降级为模板生成。

    保留此类是给「显式要求 LLM 且允许失败」的调用点（如管理员手动触发连通性测试）用。
    """

    code = CODE_LLM_UNAVAILABLE
    http_status = 503
    error_code = "LLM_UNAVAILABLE"
    default_remediation = "检查 DEEPSEEK_API_KEY 与网络；系统会自动降级为模板生成"
    default_retryable = True


# ---------------------------------------------------------------------------
# 编排层用的阶段级异常（不分级到 HTTP，由 orchestrator 捕获）
# ---------------------------------------------------------------------------


class StageSkippedError(AppError):
    """§9.1 的 L3「可跳过」：沙箱不可达、无匹配规则。

    编排层捕获它后把阶段标为 `skipped`，**后续阶段继续**。
    这不是失败 —— 基础设施问题不该让已完成的静态分析成果作废。
    """

    code = CODE_INTERNAL
    http_status = 200
    error_code = "INTERNAL"
    default_remediation = "该阶段未执行，结果中已标注"


class StageFatalError(AppError):
    """§9.1 的 L5「致命」：评估标 `failed`，但**保留已产出的数据**。"""

    code = CODE_INTERNAL
    http_status = 200
    error_code = "INTERNAL"
