"""LLM 层的假客户端 —— 测试**绝不真调 DeepSeek**。

## 为什么用一个十行的假客户端，而不是打桩 httpx

`app/llm/expressions.py` 依赖的全部能力就是 `TextCompleter` 的两个成员
（`model_name` / `complete`）。把假客户端做到这个协议的粒度，
「超时 / 500 / 畸形 JSON / 实体白名单不过」四种失败就能各自写成一行，
而且**断言的是降级行为**，不是 HTTP 细节。

## 为什么这里没有 API key

本文件里**没有任何 key**，连假 key 都没有。假客户端根本不走 HTTP，
也就不存在「拿假 key 真发请求」的可能 —— 这是刻意的：
一旦测试里出现 `sk-xxxx` 这样的字面量，它就迟早会被复制到别处。
"""

from __future__ import annotations

from app.llm.errors import LlmNotConfiguredError, LlmRequestError, LlmResponseError
from app.llm.types import ChatMessage


class FakeCompleter:
    """正常返回固定文本的假客户端。用来演「LLM 可用」那一半。"""

    #: 非 str 的类属性会被 `TextCompleter` 协议当作 property，但这里足够用
    def __init__(self, reply: str = "模型生成的文案。", *, model: str = "deepseek-chat") -> None:
        self._reply = reply
        self._model = model
        self.calls: list[list[ChatMessage]] = []

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def is_configured(self) -> bool:
        return True

    async def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> str:
        self.calls.append(list(messages))
        return self._reply


class NoKeyCompleter:
    """**未配 key** 的假客户端。

    模拟 `DeepSeekClient` 在 `DEEPSEEK_API_KEY` 为空时的行为：
    `is_configured=False`，且 `complete()` 立刻抛 `LlmNotConfiguredError`
    —— 不打网络、不重试、不打 warning。
    """

    model_name = "deepseek-chat"

    def __init__(self) -> None:
        self.calls = 0

    @property
    def is_configured(self) -> bool:
        return False

    async def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> str:
        self.calls += 1
        raise LlmNotConfiguredError("未配置 DEEPSEEK_API_KEY")


class FailingCompleter:
    """**配了 key 但调不通**：超时 / 500 / 畸形响应都用它演。

    与 `NoKeyCompleter` 分开是刻意的 —— 这两条路径在真实系统里
    触发原因、日志级别、`reason` 全都不同，合并成一个会漏测其中一条。
    """

    def __init__(self, exc: Exception | None = None) -> None:
        self._exc = exc or LlmRequestError("LLM 返回可重试状态码 500", reason_code="request_failed")
        self.calls = 0

    @property
    def model_name(self) -> str:
        return "deepseek-chat"

    @property
    def is_configured(self) -> bool:
        return True

    async def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> str:
        self.calls += 1
        raise self._exc


class MalformedCompleter(FailingCompleter):
    """响应到了但不是 chat 补全结构（网关错误页当 200 返回是真实存在的）。"""

    def __init__(self) -> None:
        super().__init__(LlmResponseError("LLM 响应不是预期的 chat 补全结构"))


class HallucinatingCompleter:
    """**返回了文案，但文案里编造了输入中不存在的实体。**

    这是实体白名单（`guard.py`）存在的唯一理由：模型很乐意在描述里
    顺手写一个「第 233 行」或一个 `CVE-2021-44228`，而那条路径根本不长那样。
    这类输出**必须被整段拒收换模板**，不能「改一改接着用」。
    """

    def __init__(
        self, reply: str = "该漏洞位于 app/evil.py 第 9999 行，对应 CVE-2021-44228。"
    ) -> None:
        self._reply = reply

    @property
    def model_name(self) -> str:
        return "deepseek-chat"

    @property
    def is_configured(self) -> bool:
        return True

    async def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> str:
        return self._reply


__all__ = [
    "FakeCompleter",
    "FailingCompleter",
    "HallucinatingCompleter",
    "MalformedCompleter",
    "NoKeyCompleter",
]
