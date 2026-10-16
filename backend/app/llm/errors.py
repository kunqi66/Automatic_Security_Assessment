"""LLM 层内部异常。

**这些异常不应当离开本包** —— 按 L4「可降级不阻断」，`expressions.py` 的四个
使用点会捕获**一切**异常并转成模板产出。它们存在的意义是：把「为什么降级了」
从一句 `except Exception` 里区分出来，写进日志与 `TextResult.reason`，
让「模板生成」这件事可解释，而不是一个沉默的兜底。

`LlmNotConfiguredError` **刻意不是错误**：`DEEPSEEK_API_KEY` 为空是合法的开发态
配置（`core/config.py` 的 `llm_available` 就是为此存在），系统应当安静地走模板。
"""

from __future__ import annotations

from app.core.exceptions import CODE_LLM_UNAVAILABLE, LlmUnavailableError


class LlmError(Exception):
    """本包内部异常基类。**不继承 `AppError`** —— 它不该被 API 层翻译成载荷。"""

    #: 进日志与 `TextResult.reason` 的稳定原因码，便于测试断言与前端提示
    reason_code: str = "llm_error"
    #: 「换个时刻再试可能就好了吗」。
    #:
    #: ⚠️ **光有 `_RETRYABLE_STATUS` 是不够的**：那个集合只决定「这条错误怎么描述」，
    #: 而重试决定发生在 `complete()` 的异常分支里。两者不打通的话，401（key 错）
    #: 和 402（余额耗尽）也会被重试 —— 重试一百次还是同样的错，代价是故障时间翻倍、
    #: 日志里多一行误导性的「将重试」。所以可重试性必须跟着异常对象一起传上去。
    retryable: bool = True

    def __init__(
        self,
        message: str,
        *,
        reason_code: str | None = None,
        retryable: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if reason_code is not None:
            self.reason_code = reason_code
        if retryable is not None:
            self.retryable = retryable


class LlmNotConfiguredError(LlmError):
    """未配置 API Key —— **正常流程**，直接走模板，不打 warning。"""

    reason_code = "no_api_key"
    retryable = False


class LlmRequestError(LlmError):
    """网络层失败：连接被拒、DNS、超时、5xx、429。可重试。"""

    reason_code = "request_failed"


class LlmTimeoutError(LlmRequestError):
    reason_code = "timeout"


class LlmResponseError(LlmError):
    """响应到达了但不是我们认识的样子：非 JSON、缺 `choices`、内容为空。"""

    reason_code = "malformed_response"


class LlmBudgetExceededError(LlmError):
    """本次批量调用已经超出分配的时间预算 —— 剩余项整体走模板。

    存在的理由：报告生成有 ≤30s 的硬指标（PRD §1.2）。若一次评估有 50 条漏洞、
    每条都吃满 15s 超时，串行就是 12 分钟。**表达层必须有预算**，
    预算用尽不影响任何结论（结论根本不来自这里）。
    """

    reason_code = "budget_exceeded"


def as_app_error(exc: LlmError, *, stage: str | None = None) -> LlmUnavailableError:
    """把内部异常翻译成对外的 `LlmUnavailableError`（错误码 `LLM_UNAVAILABLE`）。

    只给「显式要求 LLM 且允许失败」的调用点用（如管理员手动触发连通性测试）。
    正常流水线**不该**用它 —— 正常流水线走降级。
    """
    return LlmUnavailableError(exc.message, stage=stage, detail={"reason": exc.reason_code})


__all__ = [
    "CODE_LLM_UNAVAILABLE",
    "LlmBudgetExceededError",
    "LlmError",
    "LlmNotConfiguredError",
    "LlmRequestError",
    "LlmResponseError",
    "LlmTimeoutError",
    "as_app_error",
]
