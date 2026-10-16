"""DeepSeek 客户端测试：**全程用 `httpx.MockTransport`，一次真实请求都不发。**

## 为什么坚持用 MockTransport 而不是打桩 `DeepSeekClient.complete`

打桩 `complete()` 只能验「上层拿到异常后怎么降级」，验不到**异常本身是怎么
翻译出来的** —— 而 500 与 401 的区别、超时的识别、畸形响应的判定，
恰恰都在 `_once()` 里。换个 HTTP 层实现（比如将来真换 SDK）时，
只打桩上层的测试会全绿，而系统已经不认识 500 了。

`MockTransport` 正好卡在这个位置：它替换的是**传输层**，
`httpx.TimeoutException` 是真的被 `httpx` 抛出来的，`response.json()` 是真的解析过。

## Key 不出现在任何断言之外的地方

本文件仍然**没有任何 key 字面量**。为了验「key 不进日志」，构造一个明显的
哨兵字符串即可 —— 它在测试结束后就没了，不会被复制到别处。
"""

from __future__ import annotations

import httpx
import pytest

from app.core.config import settings
from app.llm.client import DeepSeekClient, mask_key
from app.llm.errors import (
    LlmNotConfiguredError,
    LlmRequestError,
    LlmResponseError,
    LlmTimeoutError,
)
from app.llm.expressions import describe_finding
from app.llm.types import TEMPLATE_MODEL, ChatMessage
from tests.test_llm_fallback import FINDING

#: 只在本文件内存活的一次性哨兵。不是真 key，也不会被发往任何地方。
SENTINEL_KEY = "sentinel-not-a-real-key-0123456789"

MESSAGES = [ChatMessage(role="user", content="写一段漏洞描述")]


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """退避置零。

    重试逻辑本身要测，但没必要真的等 0.5s —— 等待是测试环境里最纯粹的浪费，
    而它会让「跑一遍全套测试」这件事慢慢变得没人愿意做。
    """
    monkeypatch.setattr("app.llm.client._BACKOFF_SECONDS", 0.0)


def make_client(
    handler: object, *, api_key: str | None = SENTINEL_KEY, **kwargs: object
) -> DeepSeekClient:
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]
    return DeepSeekClient(
        api_key=api_key,
        http_client=httpx.AsyncClient(transport=transport, base_url="https://example.invalid"),
        **kwargs,  # type: ignore[arg-type]
    )


def ok_handler(content: str = "模型返回的文案。"):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    return handler


def status_handler(status: int):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(status, json={"error": "boom"})

    return handler, calls


# ---------------------------------------------------------------------------
# 一、Key 的处理：只从 settings 来，只进 Authorization 头，只以掩码进日志
# ---------------------------------------------------------------------------


def test_mask_key_永不泄露完整值() -> None:
    # 只留前 4 位：够用来判断「是不是这把 key」，不够用来复原
    assert mask_key(SENTINEL_KEY) == "sent***"
    assert SENTINEL_KEY not in mask_key(SENTINEL_KEY)
    # 短 key 一律全遮 —— 前 4 位就占了大半，遮了等于没遮
    assert mask_key("abc") == "***"
    # 空值写「未配置」而不是空串：日志里一片空白会被读成「打了但值是空」
    assert mask_key("") == "(未配置)"
    assert mask_key(None) == "(未配置)"


def test_describe_只输出掩码() -> None:
    client = make_client(ok_handler())
    described = client.describe()
    assert SENTINEL_KEY not in described
    assert "sent***" in described


async def test_key_不进日志(caplog: pytest.LogCaptureFixture) -> None:
    """「Key 不写进日志」必须在代码里成立，而不是靠 code review 记住。

    这里抓的是**真实调用路径**上的日志：成功一次、失败一次（500），
    两次的日志里都不许出现完整 key。
    """
    caplog.set_level("DEBUG")
    client = make_client(ok_handler(), max_retries=0)
    await client.complete(MESSAGES)

    handler, _ = status_handler(500)
    failing = make_client(handler, max_retries=0)
    with pytest.raises(LlmRequestError):
        await failing.complete(MESSAGES)

    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert SENTINEL_KEY not in joined
    assert "sent-s***" not in joined  # 连掩码也不主动打，除非显式 describe()


async def test_key_只出现在_authorization_头() -> None:
    """**唯一**允许出现 key 的位置就是请求头。

    请求体现在也断言一遍：一处疏忽（比如把 key 塞进 body 方便排查）
    就会让密钥进到服务商的日志与代理的日志里。
    """
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization", "")
        seen["body"] = request.content.decode("utf-8")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = make_client(handler, max_retries=0)
    await client.complete(MESSAGES)

    assert seen["auth"] == f"Bearer {SENTINEL_KEY}"
    assert SENTINEL_KEY not in seen["body"]


# ---------------------------------------------------------------------------
# 二、未配 key：不发请求、不重试、安静降级
# ---------------------------------------------------------------------------


async def test_未配_key_时不发请求() -> None:
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, json={})

    client = make_client(handler, api_key="")
    assert client.is_configured is False

    with pytest.raises(LlmNotConfiguredError) as exc:
        await client.complete(MESSAGES)

    assert exc.value.reason_code == "no_api_key"
    assert called["n"] == 0, "未配 key 时不许打网络 —— 那是把配置问题当成网络问题"
    assert client.describe().endswith("key=(未配置))")


# ---------------------------------------------------------------------------
# 三、失败路径：可重试的会重试，不可重试的立刻放弃
# ---------------------------------------------------------------------------


async def test_超时被翻译成_LlmTimeoutError() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom", request=request)

    client = make_client(handler, max_retries=0)
    with pytest.raises(LlmTimeoutError) as exc:
        await client.complete(MESSAGES)
    assert exc.value.reason_code == "timeout"


async def test_5xx_会重试到上限() -> None:
    handler, calls = status_handler(500)
    client = make_client(handler, max_retries=1)

    with pytest.raises(LlmRequestError):
        await client.complete(MESSAGES)

    # max_retries=1 → 首次 + 1 次重试
    assert calls["n"] == 2


async def test_401_不重试() -> None:
    """key 错 / 权限不足 / 余额耗尽：**重试是没有意义的**。

    这条断言存在的理由：`_RETRYABLE_STATUS` 只决定「错误怎么描述」，
    而重试决定发生在 `complete()` 的异常分支里。两者不打通的话，
    401 也会被重试 —— 代价是故障时间翻倍，以及日志里一行误导性的「将重试」。
    """
    handler, calls = status_handler(401)
    client = make_client(handler, max_retries=3)

    with pytest.raises(LlmRequestError) as exc:
        await client.complete(MESSAGES)

    assert exc.value.retryable is False
    assert calls["n"] == 1, "401 只该尝试一次"


async def test_畸形响应被识别并重试一次() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        # 网关把错误页当 200 返回：结构对不上，但 HTTP 层是「成功」的
        return httpx.Response(200, json={"error": {"message": "quota exceeded"}})

    client = make_client(handler, max_retries=1)
    with pytest.raises(LlmResponseError) as exc:
        await client.complete(MESSAGES)

    assert exc.value.reason_code == "malformed_response"
    assert calls["n"] == 2


async def test_空内容也算畸形响应() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "   "}}]})

    client = make_client(handler, max_retries=0)
    with pytest.raises(LlmResponseError):
        await client.complete(MESSAGES)


async def test_正常响应返回纯文本() -> None:
    client = make_client(ok_handler("该接口将外部输入直接拼接进 SQL 语句。"), max_retries=0)
    text = await client.complete(MESSAGES)
    assert text == "该接口将外部输入直接拼接进 SQL 语句。"
    assert client.model_name == settings.llm_model


# ---------------------------------------------------------------------------
# 四、端到端：HTTP 层的失败 → 表达层降级（不只测「没配 key」那一条路）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "handler"),
    [
        ("500", lambda: status_handler(500)[0]),
        (
            "timeout",
            lambda: lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("t", request=request)),
        ),
        ("malformed", lambda: lambda request: httpx.Response(200, json={"nope": 1})),
    ],
)
async def test_真实_http_失败也会降级而不是抛异常(name: str, handler: object) -> None:
    """用真 httpx + MockTransport 走完整条「失败 → 降级」链路。

    这条用例与 `test_llm_fallback.py` 里的假客户端用例**不重复**：
    那一组验的是「拿到异常之后的行为」，这一组验的是「异常真的会被产生出来」。
    """
    client = make_client(handler, max_retries=0)  # type: ignore[arg-type]
    result = await describe_finding(FINDING, client=client)

    assert result.degraded is True, f"{name} 情况下没有降级"
    assert result.llm_model == TEMPLATE_MODEL
    assert result.text.strip()
    assert "app/api/order.py:40-48" in result.text, "降级后信息量不该缩水"
