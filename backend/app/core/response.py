"""统一异常处理与错误载荷（PRD §9.1 / 总纲 §9.2）。

**成功响应不套信封**，直接返回资源 JSON。失败响应长这样：

```json
{
  "detail": "给人看的一句话",
  "error": { "stage": ..., "error_code": ..., "message": ..., "remediation": ...,
             "retryable": ..., "occurred_at": ... }
}
```

`detail` 冗余是因为前端 `errorMessage()` 读的就是它（FastAPI 原生形状）；
`error` 里是总纲 §9.2 要求的四要素，供 UI 展示修复指引。一个给人看，一个给程序看。
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import AppError, BadRequestError
from app.core.logging import get_logger

logger = get_logger(__name__)


def _body(exc: AppError) -> dict[str, Any]:
    payload = exc.to_payload()
    return {"detail": exc.message, "error": payload}


async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    """业务异常。5xx 记 error 级，4xx 记 info —— 用户输错密码不该刷 ERROR 日志。"""
    if exc.http_status >= 500:
        logger.error("[%s] %s | remediation=%s", exc.error_code, exc.message, exc.remediation)
    else:
        logger.info("[%s] %s", exc.error_code, exc.message)
    return JSONResponse(status_code=exc.http_status, content=_body(exc))


async def validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """Pydantic 入参校验失败 → 转成统一的 4002。

    把 pydantic 的 `loc` 拼成 `body.name` 这样的字段路径，
    否则前端只能显示一句「输入不合法」，定位不到是哪个字段。
    """
    first = exc.errors()[0] if exc.errors() else {}
    loc = ".".join(str(p) for p in first.get("loc", ()))
    msg = first.get("msg", "参数校验失败")
    err = BadRequestError(
        f"参数校验失败：{loc} —— {msg}" if loc else f"参数校验失败：{msg}",
        remediation="请检查请求参数的类型与取值范围",
        detail=exc.errors()[:5],
    )
    return JSONResponse(status_code=err.http_status, content=_body(err))


async def http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Starlette/FastAPI 自带的 HTTPException（如 404 路由不存在）。

    也要转成统一形状 —— 否则前端会遇到两种错误结构，`errorMessage()` 只认其中一种。
    """
    err = AppError(str(exc.detail))
    err.http_status = exc.status_code
    err.code = 4000 + exc.status_code if exc.status_code < 500 else 5000
    err.error_code = "NOT_FOUND" if exc.status_code == 404 else "BAD_REQUEST"
    return JSONResponse(status_code=exc.status_code, content=_body(err))


async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    """兜底。

    ⚠️ **不把异常原文回给客户端** —— 堆栈里可能带数据库连接串、文件绝对路径。
    原文只进服务端日志，客户端拿到一个可检索的 request_id 与一句通用提示。
    """
    logger.exception("未处理异常：%s", exc)
    err = AppError(
        "服务内部错误，请查看服务端日志",
        remediation="携带本次请求时间检索后端日志；若可复现请提交 issue",
    )
    return JSONResponse(status_code=500, content=_body(err))


def install_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_error_handler)
