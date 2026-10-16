"""日志配置。全项目用 `logging`，**禁止 print**。

Windows 控制台默认 GBK，直接打中文会乱码；这里顺带把 stdout 切成 UTF-8。
注意：验证脚本不要靠肉眼读中文输出，要断言布尔值。
"""

from __future__ import annotations

import logging
import sys

from app.core.config import settings

_CONFIGURED = False

#: 这些库在 INFO 级别下噪音很大，且它们的正常输出对本系统没有信息量
_NOISY_LOGGERS = ("aiomysql", "docker", "httpx", "httpcore", "urllib3", "asyncio")

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-28s | %(message)s"
_DATEFMT = "%H:%M:%S"


def setup_logging() -> None:
    """进程级日志初始化。幂等 —— 重复调用不会叠加 handler。"""
    global _CONFIGURED
    if _CONFIGURED:
        return

    # Windows 下 stdout 默认是 GBK，中文日志会变成乱码
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, OSError):
        # 非 TTY（如被重定向到文件）时可能不支持，忽略即可
        pass

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if settings.debug else logging.INFO)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
