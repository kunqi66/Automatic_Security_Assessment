"""HTML → PDF（Playwright Chromium，B6 设计 §4.2 / §7.4）。

## 三条刻意的设计

1. **惰性**：`report_gen` 阶段只产 HTML + Markdown，PDF 在**首次有人要**的时候
   才生成。理由是 PDF 是三者里最慢的一步（起一次 Chromium），而它在流水线里
   并不是必需产物 —— 把它放进关键路径，等于让「报告生成 ≤30s」这个硬指标
   去赌一台 2 vCPU 机器上 Chromium 的启动速度。

2. **单例复用**：Chromium 进程常驻，靠一把 `asyncio.Lock` 串行化。
   2 vCPU / 7.3G 的机器上并发起两个 Chromium 就是往 OOM 走，
   而报告下载本来就是低频操作，串行化的代价是零。

3. **失败即降级（L3）**：Chromium 没装 / 打印超时都**不阻断**，
   页面结构照常落盘，PDF 位置留空并在报告首页标注「pdf」。

   ⚠️ 这与「报告写不进去」是两种性质：`REPORT_WRITE_FAILED` 是 L5 不可降级，
   因为产物交付不了就是交付不了；而 PDF 是**冗余格式**，缺了它另外两份照样可用。

## 为什么不用 weasyprint / reportlab

`weasyprint` 依赖 GTK/Pango 一整套本地库，在 Windows 上装起来是一场持久战
（且面试现场大概率装不上）；`reportlab` 要从零手写排版，等于把 HTML 模板重做一遍。
Chromium 已经把「HTML + 内联 CSS + 内联 SVG」渲染得很好了 —— 报告正好是这三样。
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.core.logging import get_logger
from app.report.errors import PdfRenderTimeoutError, PdfUnavailableError

logger = get_logger(__name__)

#: PDF 打印的超时（毫秒）。20s 是设计 §4.2 定的值。
#:
#: ⚠️ **这个超时不能交给 `page.pdf()`**：Playwright 的 `Page.pdf()` 是少数
#: 不收 `timeout` 参数的方法之一（它没有"等待"语义，只做一次打印），
#: 传进去会直接抛 `TypeError: Page.pdf() got an unexpected keyword argument 'timeout'`。
#: 而这个 `TypeError` 被下面的 `except Exception` 照单全收，于是表现为
#: 「渲染超时或失败」—— **一句和真实原因无关的报错**，还白重试一次。
#:
#: 所以超时由 `asyncio.wait_for` 在**外层**兜：它约束的是整个打印动作的
#: 墙钟时间，与 Playwright 的参数表无关。上面这个坑是装了 Chromium 之后
#: 才暴露的 —— 在那之前 `Chromium 启动失败` 把后面所有问题都挡住了。
PDF_TIMEOUT_MS = 20_000

#: PDF 的 A4 版面。边距取 12mm：报告里全是表格，边距再大一点就会频繁断行。
_PDF_MARGIN = {"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"}

_playwright: Any = None
_browser: Any = None
_lock = asyncio.Lock()


async def _get_browser() -> Any:
    """拿到（必要时启动）共享的 Chromium 实例。

    `import playwright` 放在函数内部：没装 Playwright 时，`app.report` 的
    其它功能（HTML / Markdown）不该因为这个 import 就整体不可用。
    把可选依赖的失败点压到它真正被用到的那一刻。
    """
    global _playwright, _browser
    if _browser is not None and _browser.is_connected():
        return _browser

    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover - 取决于本地是否装了 playwright
        raise PdfUnavailableError(
            "未安装 Playwright，PDF 导出不可用（HTML / Markdown 不受影响）",
            detail={"reason": str(exc)},
        ) from exc

    try:
        if _playwright is None:
            _playwright = await async_playwright().start()
        _browser = await _playwright.chromium.launch(
            args=[
                # 容器 / 受限环境里没有 /dev/shm，不给这个参数 Chromium 会在
                # 渲染大页面时随机崩掉 —— 而崩溃点与报告内容无关，极难排查
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ]
        )
    except Exception as exc:  # noqa: BLE001 - 启动失败的一切原因都归为「不可用」
        # 最常见的是 `playwright install chromium` 没跑过。这里刻意不区分
        # 「未安装浏览器」与「启动失败」：对调用方而言应对方式一样（降级），
        # 而原始异常文本已经带在 detail 里了。
        raise PdfUnavailableError(
            "Chromium 启动失败，PDF 导出不可用（HTML / Markdown 不受影响）",
            detail={"reason": str(exc)},
        ) from exc
    logger.info("Chromium 已启动，PDF 导出可用")
    return _browser


async def render_pdf(html: str) -> bytes:
    """HTML 字符串 → PDF 字节。

    超时后**关掉 page 重试一次**再放弃：Chromium 偶发卡在首次启动的字体加载上，
    第二次通常就过了；而无条件重试三次以上只会在 2 vCPU 机器上把等待时间翻倍。
    """
    async with _lock:
        browser = await _get_browser()
        last_error: Exception | None = None
        for attempt in range(2):
            page = None
            try:
                page = await browser.new_page()
                await page.set_content(html, wait_until="load")
                # 超时兜在外层：`page.pdf()` 不收 `timeout`（见 `PDF_TIMEOUT_MS` 的注释），
                # 而 `wait_for` 约束的是整个打印动作的墙钟时间，不依赖 Playwright 的参数表。
                # 超时会取消 `page.pdf()` 这个协程，由下面的 `finally` 关掉 page。
                data = await asyncio.wait_for(
                    page.pdf(
                        format="A4",
                        print_background=True,
                        margin=_PDF_MARGIN,
                    ),
                    timeout=PDF_TIMEOUT_MS / 1000,
                )
                return bytes(data)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                logger.info("PDF 打印第 %d 次失败：%s", attempt + 1, exc)
            finally:
                if page is not None:
                    # page 必须显式关掉：它持有一份渲染上下文，
                    # 泄漏几个之后 Chromium 的常驻内存就会把 7.3G 吃光
                    await page.close()

        raise PdfRenderTimeoutError(
            "PDF 渲染超时或失败，本次导出降级为不提供 PDF",
            detail={"reason": str(last_error)},
        ) from last_error


async def aclose() -> None:
    """进程退出时释放 Chromium。**幂等**，重复调用无副作用。"""
    global _playwright, _browser
    browser, playwright = _browser, _playwright
    _browser = _playwright = None
    for resource, closer in ((browser, "close"), (playwright, "stop")):
        if resource is None:
            continue
        try:
            await getattr(resource, closer)()
        except Exception as exc:  # noqa: BLE001 - 关闭失败不该影响进程退出
            logger.info("释放 Chromium 资源时出错（忽略）：%s", exc)


__all__ = ["PDF_TIMEOUT_MS", "aclose", "render_pdf"]
