"""`render_pdf` 本身的行为（B6 设计 §4.2）。

## 为什么这个文件是后补的

原先 `render_pdf` **一条测试都没有**：`test_report_export.py` 里那几组用例
都在 exporter 那一层把 `render_pdf` 整个 monkeypatch 掉了（那是对的 ——
它们要测的是"降级后落盘状态对不对"，不该真起 Chromium）。

代价是**从来没跑过真的 `render_pdf`**，于是下面这个 bug 活了下来：

    page.pdf(format=..., print_background=..., margin=..., timeout=PDF_TIMEOUT_MS)

Playwright 的 `Page.pdf()` **不收 `timeout`**，直接抛
`TypeError: Page.pdf() got an unexpected keyword argument 'timeout'`。
而 `render_pdf` 的 `except Exception` 把它和"渲染超时"归成一类，
于是日志里写的是「PDF 渲染超时或失败」—— **一句与真实原因无关的报错**，
重试一次后照样降级，`assert 有 PDF` 之类的用例永远轮不到。

它直到 `playwright install chromium` 跑完才暴露：在那之前
`Chromium 启动失败` 挡在前面，这个 TypeError 根本走不到。

**教训不是"要装 Chromium"**，是：`except Exception` 配一句笼统的报错，
会让一个必现的编码错误看起来像一个偶发的环境问题。
"""

from __future__ import annotations

import asyncio

import pytest

from app.report import pdf as pdf_mod
from app.report.errors import PdfRenderTimeoutError

# ---------------------------------------------------------------------------
# 伪造的 browser / page：只实现 `render_pdf` 真正调用到的那几个方法
# ---------------------------------------------------------------------------


class _FakePage:
    def __init__(self, *, pdf_kwargs_out: dict, hang: bool = False) -> None:
        self._out = pdf_kwargs_out
        self._hang = hang
        self.closed = False
        self.content: str | None = None

    async def set_content(self, html: str, wait_until: str | None = None) -> None:
        self.content = html

    async def pdf(self, **kwargs: object) -> bytes:
        # 把收到的关键字记下来 —— 这是本文件第一条断言要用的证据
        self._out.clear()
        self._out.update(kwargs)

        # **真实 API 的形状**：不接受 `timeout`。这里刻意复刻它，
        # 好让"误传 timeout"在测试里就是一个 TypeError，与线上一致。
        if "timeout" in kwargs:
            raise TypeError("Page.pdf() got an unexpected keyword argument 'timeout'")

        if self._hang:
            await asyncio.sleep(3600)
        return b"%PDF-1.4 fake"

    async def close(self) -> None:
        self.closed = True


class _FakeBrowser:
    def __init__(self, *, pdf_kwargs_out: dict, hang: bool = False) -> None:
        self._out = pdf_kwargs_out
        self._hang = hang
        self.pages: list[_FakePage] = []

    async def new_page(self) -> _FakePage:
        page = _FakePage(pdf_kwargs_out=self._out, hang=self._hang)
        self.pages.append(page)
        return page


@pytest.fixture
def fake_browser(monkeypatch: pytest.MonkeyPatch) -> tuple[_FakeBrowser, dict]:
    """把 `_get_browser` 换掉，返回 `(browser, pdf_kwargs)`。"""
    out: dict = {}
    browser = _FakeBrowser(pdf_kwargs_out=out)
    monkeypatch.setattr(pdf_mod, "_get_browser", lambda: _ready(browser))
    return browser, out


async def _ready(browser: _FakeBrowser) -> _FakeBrowser:
    return browser


# ---------------------------------------------------------------------------
# 1. 传给 `page.pdf()` 的参数必须是它真收得下的
# ---------------------------------------------------------------------------


async def test_render_pdf_不把_timeout_传给_page_pdf(
    fake_browser: tuple[_FakeBrowser, dict],
) -> None:
    """回归用例：`Page.pdf()` 不收 `timeout`，超时必须由外层兜。

    这条断言看着很细（只是"某个 kwarg 别出现"），但它挡的是一个
    **必现的崩溃被伪装成偶发超时**的 bug，而且伪装得很成功 ——
    日志、错误码、降级路径全都"正常"，只有 PDF 永远出不来。
    """
    browser, pdf_kwargs = fake_browser

    data = await pdf_mod.render_pdf("<html><body>报告</body></html>")

    assert data == b"%PDF-1.4 fake"
    assert "timeout" not in pdf_kwargs, (
        f"`Page.pdf()` 不接受 timeout（会抛 TypeError），实际传了：{sorted(pdf_kwargs)}"
    )
    # 版面参数该在的还在 —— 别为了躲 timeout 把它俩一起删了
    assert pdf_kwargs.get("format") == "A4"
    assert pdf_kwargs.get("print_background") is True
    assert "margin" in pdf_kwargs


async def test_render_pdf_打印用的_page_一定会被关掉(
    fake_browser: tuple[_FakeBrowser, dict],
) -> None:
    """page 持有渲染上下文，泄漏几个就能把 7.3G 吃光（见 `pdf.py` 的注释）。"""
    browser, _ = fake_browser

    await pdf_mod.render_pdf("<html></html>")

    assert browser.pages and all(p.closed for p in browser.pages)


# ---------------------------------------------------------------------------
# 2. 真的卡住时：超时兜得住，且重试一次就放弃
# ---------------------------------------------------------------------------


async def test_render_pdf_卡住时由外层超时兜住并重试一次(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`asyncio.wait_for` 是超时的唯一执行者 —— 把预算调到毫秒级验证它真的生效。

    同时断言**重试恰好一次**：`render_pdf` 的契约是"关掉 page 再来一遍就放弃"，
    多试几次只会在 2 vCPU 上把等待时间翻倍。
    """
    monkeypatch.setattr(pdf_mod, "PDF_TIMEOUT_MS", 50)
    browser = _FakeBrowser(pdf_kwargs_out={}, hang=True)
    monkeypatch.setattr(pdf_mod, "_get_browser", lambda: _ready(browser))

    with pytest.raises(PdfRenderTimeoutError):
        await pdf_mod.render_pdf("<html></html>")

    assert len(browser.pages) == 2, "应当重试一次（共 2 次尝试）后放弃"
    assert all(p.closed for p in browser.pages), "每次尝试的 page 都要关掉"


async def test_render_pdf_第一次成功就不重试(
    fake_browser: tuple[_FakeBrowser, dict],
) -> None:
    browser, _ = fake_browser

    await pdf_mod.render_pdf("<html></html>")

    assert len(browser.pages) == 1
