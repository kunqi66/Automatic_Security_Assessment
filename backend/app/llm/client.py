"""DeepSeek 客户端（OpenAI 兼容 HTTP 接口）。

## 三个刻意的选择

**1. 用 httpx 而不是 `openai` 官方 SDK。**
本系统用的是「OpenAI 兼容接口」——它就是一个 `POST {base_url}/chat/completions`，
请求体是 JSON、响应体是 JSON。为这一件事引一个官方 SDK，换来的是多一个重依赖、
多一层自己的重试/超时语义、以及「SDK 的异常类型」与「我们的降级判据」之间
多一道翻译。**HTTP 就是接口本身**（`httpx` 本就是项目已有依赖，见 pyproject）。

**2. API Key 只从 `settings` 读，只出现在 Authorization 头里。**
不入库（`models/llm.py` 的表里没有 key 列）、不经任何接口返回、不进日志 ——
日志里一律走 `mask_key()`。这样设计是因为：一张会进数据库备份的表、一份会被
贴进 issue 的日志，都不该有长期密钥。

**3. 超时与重试是显式参数，不是默认值。**
`llm_timeout_seconds=15`、`llm_max_retries=1`（PRD §7.6.1 固化参数）。
一次 LLM 调用最多占用 `15s × 2`，且报告层还会套一层总预算（`BudgetGuard`）——
不能让一次模型抽风把整条评估流水线拖死。
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.llm.errors import (
    LlmNotConfiguredError,
    LlmRequestError,
    LlmResponseError,
    LlmTimeoutError,
)
from app.llm.types import ChatMessage, TextCompleter

logger = get_logger(__name__)

#: 重试判定：只有「换个时刻再试可能就好了」的情况才重试。
#: 401/403（key 错、额度耗尽）重试一百次还是错，重试只会把故障时间翻倍。
_RETRYABLE_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504})

#: 退避基数（秒）。刻意很短：本函数处在报告生成的 ≤30s 预算里，
#: 长退避等于用「等」把预算吃光，还不如早点降级成模板把报告交出去。
_BACKOFF_SECONDS = 0.5

#: 默认输出上限。四个用点的产出都是「一段中文文案」，不需要长文；
#: 上限同时是成本闸与延迟闸。
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.2


def mask_key(key: str | None) -> str:
    """日志里**永不出现完整 key**。只留前 4 位用于「是不是这把 key」的粗略判断。

    `mask_key("")` 返回 `(未配置)` 而不是空串：日志里一片空白会让人以为
    「打了但值是空」，而这里是「压根没配」——两件事的排查方向完全不同。
    """
    if not key:
        return "(未配置)"
    if len(key) <= 4:
        return "***"
    return f"{key[:4]}***"


class DeepSeekClient(TextCompleter):
    """OpenAI 兼容的 chat 补全客户端。**实例可复用，持有连接池。**"""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: int | None = None,
        max_retries: int | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        # 全部从 settings 取默认值，**不在代码里写死任何 key 或地址**（PRD §8.3）
        self._api_key = (settings.deepseek_api_key if api_key is None else api_key).strip()
        self._base_url = (base_url or settings.llm_base_url).rstrip("/")
        self._model = model or settings.llm_model
        self._timeout = float(
            settings.llm_timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        self._max_retries = settings.llm_max_retries if max_retries is None else max_retries

        # 传入 http_client 是为了测试：注入一个挂 MockTransport 的客户端即可
        # 演完全部失败路径，不必起服务、不必打桩 asyncio。
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(connect=5.0, read=self._timeout, write=10.0, pool=5.0),
            headers={"Content-Type": "application/json"},
            # 连接池小是刻意的：报告层的并发上限本来就只有 4（见 expressions.py），
            # 池子开大只会让压测时看不出真实的排队行为
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )

    # ------------------------------------------------------------------

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    @property
    def is_closed(self) -> bool:
        return self._http.is_closed

    def describe(self) -> str:
        """可安全写进日志的自述。**注意这里不含 key 本身，只有掩码。**"""
        return (
            f"DeepSeekClient(model={self._model}, base_url={self._base_url}, "
            f"key={mask_key(self._api_key)})"
        )

    # ------------------------------------------------------------------

    async def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = DEFAULT_TEMPERATURE,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """发一次对话补全请求，返回纯文本内容。

        失败一律抛 `LlmError` 子类，**由调用方（`expressions.py`）决定降级** ——
        客户端自己不吞异常，否则「为什么这次是模板」就无从查起。
        """
        if not self.is_configured:
            # ⚠️ 这里是 `LlmNotConfiguredError` 而**不是** warning 日志：
            # 未配 key 是合法的开发态配置（config.llm_available 就是为此存在），
            # 系统应当安静地走模板，而不是每次调用都刷一行「密钥缺失」。
            raise LlmNotConfiguredError(
                "未配置 DEEPSEEK_API_KEY，本次请求直接走确定性模板",
                reason_code="no_api_key",
            )

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [m.model_dump() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }

        last_exc: Exception | None = None
        # max_retries=1 → 最多 2 次尝试（首次 + 1 次重试），与 llm_configs.max_retries 同义
        for attempt in range(self._max_retries + 1):
            try:
                return await self._once(payload)
            except (LlmTimeoutError, LlmRequestError, LlmResponseError) as exc:
                # 三个分支的**处理完全一样**，合并成一个 except 是为了让下面这句
                # 「不可重试就立刻放弃」只写一处 —— 复制三遍的话，迟早有一遍漏改
                # 而漏改的那一遍会安静地多打一次无用的请求。
                #
                # 畸形响应（`LlmResponseError`）也重试一次：网关偶发吐空是真实存在的，
                # 总纲 §8.5 的 L3 说的就是「校验失败重试不超过 1 次」。
                last_exc = exc
                if not getattr(exc, "retryable", True):
                    # 401 / 402 / 403 这类：重试一百次还是同样的错。
                    # 重试只会把故障时间翻倍，并在日志里留下一行误导性的「将重试」。
                    break
                self._log_retry(attempt, exc)

            if attempt < self._max_retries:
                await asyncio.sleep(_BACKOFF_SECONDS * (attempt + 1))

        assert last_exc is not None  # 循环至少跑一次，且只有异常路径能走到这里
        raise last_exc

    async def _once(self, payload: dict[str, Any]) -> str:
        """单次尝试。**只负责把 HTTP 世界翻译成本包自己的异常。**"""
        started = time.monotonic()
        try:
            response = await self._http.post(
                "/chat/completions",
                json=payload,
                # key 只在这里出现，且不进任何日志
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        except httpx.TimeoutException as exc:
            raise LlmTimeoutError(f"LLM 请求超时（{self._timeout:.0f}s）") from exc
        except httpx.HTTPError as exc:  # 连接被拒 / DNS / 代理
            raise LlmRequestError(f"LLM 请求失败：{exc.__class__.__name__}") from exc

        elapsed_ms = int((time.monotonic() - started) * 1000)

        if response.status_code in _RETRYABLE_STATUS:
            raise LlmRequestError(f"LLM 返回可重试状态码 {response.status_code}（{elapsed_ms}ms）")
        if response.status_code >= 400:
            # 4xx 里除上面几个外都是「重试没用」的（401 key 错、402 余额、403 权限）。
            # 错误体里可能回显请求，但**绝不回显** Authorization 头，所以截断后是安全的。
            raise LlmRequestError(
                f"LLM 返回 {response.status_code}：{response.text[:200]}",
                # `>= 500` 的（如 501 / 505）仍算「换个时刻可能就好」；
                # 4xx 一律不可重试，`complete()` 据此直接放弃。
                retryable=response.status_code >= 500,
            )

        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            # 这一类降级在真实环境里比超时更常见：网关把错误页当 200 返回、
            # 免费额度用尽后返回一个 `{"error": ...}` 的 200 体
            raise LlmResponseError("LLM 响应不是预期的 chat 补全结构") from exc

        if not isinstance(content, str) or not content.strip():
            raise LlmResponseError("LLM 返回了空内容")

        logger.debug(
            "LLM 调用完成：model=%s elapsed=%dms chars=%d",
            self._model,
            elapsed_ms,
            len(content),
        )
        return content

    def _log_retry(self, attempt: int, exc: Exception) -> None:
        reason = getattr(exc, "reason_code", exc.__class__.__name__)
        if attempt < self._max_retries:
            logger.warning(
                "LLM 调用失败（%s），将重试 %d/%d", reason, attempt + 1, self._max_retries
            )
        else:
            # 到这里的最终结论是「这次走模板」，调用方会记 INFO 级别的降级日志；
            # 这里用 warning 是因为「配了 key 但调不通」确实是需要人看一眼的信号
            logger.warning("LLM 调用失败（%s），重试已用尽，本次降级为模板", reason)

    async def aclose(self) -> None:
        """只关自己建的连接池。注入进来的客户端由注入方负责（测试里要复用）。"""
        if self._owns_client and not self._http.is_closed:
            await self._http.aclose()


# ---------------------------------------------------------------------------
# 进程级单例
# ---------------------------------------------------------------------------

_default_client: DeepSeekClient | None = None


def get_default_client() -> DeepSeekClient:
    """进程内复用同一个连接池。FastAPI 的生命周期钩子与编排层都从这里取。

    不做 `asyncio.Lock`：这个函数是同步的，且在同一个事件循环里被调用；
    最坏情况是并发首调建了两个客户端，其中一个随即成为垃圾 —— 代价是一次
    多余的握手，而为此引入锁会把「同步获取」变成「同步等待事件循环」，不值得。
    """
    global _default_client
    if _default_client is None or _default_client.is_closed:
        _default_client = DeepSeekClient()
        logger.info("初始化 LLM 客户端：%s", _default_client.describe())
    return _default_client


async def close_default_client() -> None:
    """应用关闭时调用（`app/main.py` 的生命周期钩子）。"""
    global _default_client
    if _default_client is not None:
        await _default_client.aclose()
        _default_client = None


async def configure_default_client(
    *,
    base_url: str | None = None,
    model: str | None = None,
    timeout_seconds: int | None = None,
    max_retries: int | None = None,
) -> None:
    """用**数据库里那份** `llm_configs` 重建进程级客户端。

    ## 为什么需要这个函数

    `get_default_client()` 只从 `settings` 取值，而管理员改的是数据库表
    （需求 2.5.2）。两者之间原本没有任何通路 —— 症状是**管理员改了模型参数、
    界面显示已保存、而实际调用一如既往用旧参数**，且不报任何错。

    由**组合根（L1 的启动钩子 / L2 的评估入口）**调用，而不是让 `app/llm`
    自己去查库：`app/llm` 不认识数据库，也不该认识。

    ## 为什么重建而不是改字段

    客户端持有 httpx 连接池，而 `base_url` 是**建池时**绑定的。
    只改 `self._model` 之类的字段会让池子仍指向旧地址 —— 那是那种
    「改了地址还在往老地方发请求」的 bug。整个重建最省心，代价是一次握手。
    """
    global _default_client
    await close_default_client()
    _default_client = DeepSeekClient(
        base_url=base_url,
        model=model,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )
    logger.info("按数据库配置重建 LLM 客户端：%s", _default_client.describe())


__all__ = [
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_TEMPERATURE",
    "DeepSeekClient",
    "close_default_client",
    "configure_default_client",
    "get_default_client",
    "mask_key",
]
