"""FastAPI 入口。

启动顺序是有讲究的：**先初始化日志，再自检依赖**。
反过来的话，数据库连不上时那行错误会因为日志还没配好而丢掉格式，
只剩一句裸 print 级别的输出 —— 而那正是最需要看清上下文的一刻。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.core.response import install_exception_handlers
from app.db.redis import close_redis
from app.db.session import dispose_engine, verify_connection
from app.llm.client import close_default_client

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await verify_connection()  # 存储类依赖不可降级：连不上就起不来（总纲 §8.2）
    logger.info(
        "%s v%s 已就绪 | debug=%s | LLM=%s",
        settings.app_name,
        __version__,
        settings.debug,
        "可用" if settings.llm_available else "未配置（将降级为模板生成）",
    )
    yield
    # 逐个关，且各自 try —— 一个关不掉不该让其余的连接池泄漏到进程退出。
    # 这里刻意**不**启动队列消费：API 与 worker 是两个进程
    # （理由见 `app/worker.py` 的模块文档）。
    for label, closer in (
        ("LLM 客户端", close_default_client),
        ("Redis", close_redis),
        ("MySQL", dispose_engine),
    ):
        try:
            await closer()
        except Exception as exc:  # noqa: BLE001 —— 关闭阶段的失败只能记，不能抛
            logger.warning("关闭 %s 时出错：%s", label, exc)
    logger.info("已停止")


def create_app() -> FastAPI:
    setup_logging()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="可控多智能体自动化安全评估系统 —— 大语言模型只做表达，不参与任何判定。",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
        openapi_url=f"{settings.api_prefix}/openapi.json",
    )

    # 前端 dev server 与后端不同源，必须放行；生产由 Nginx 同源代理，这份配置不生效
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    install_exception_handlers(app)
    app.include_router(api_router, prefix=settings.api_prefix)
    return app


app = create_app()
