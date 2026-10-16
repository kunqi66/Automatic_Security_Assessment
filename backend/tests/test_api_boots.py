"""**把真的 FastAPI 应用起起来，走真的 HTTP 层。**

## 这个文件补的是哪一块

在这之前，27 条路由**从来没有被任何测试执行过一次**。所有测试都在
「服务层 / 引擎层」下面打转 —— 那是模块自己的单元测试，它们直接调
`ReportService`、直接调 `analyze()`，绕过了 FastAPI 这一整层。

于是下面这些出错方式**一个测试都拦不住**：

- `app.include_router` 的 prefix 拼错（路由挂到了 `/assessments` 而不是
  `/api/v1/assessments`）；
- 某个 `Depends(...)` 注入了一个不存在的依赖；
- Pydantic 的请求体模型与路由签名对不上，**只有真正收到请求时才校验**；
- 异常处理器没挂上，业务异常变成 500 而不是约定的 `{code, message, data}`。

它们的共同点是「**应用能 import，但一收请求就炸**」—— 而 import 成功
是最容易让人误以为「能跑」的信号。

## 为什么要覆盖 lifespan

`lifespan` 里那句 `await verify_connection()` 是**故意的**（总纲 §8.2：
存储类依赖不可降级），所以起真应用必须先有 MySQL。这里把它换掉，
**但只是换掉「连得上吗」这一个探针** —— `create_app()` 组装出来的
中间件、路由、异常处理器全都是真的。
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("DEBUG", "true")

from collections.abc import AsyncIterator  # noqa: E402

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.base import Base  # noqa: E402


@pytest.fixture
async def api() -> AsyncIterator[httpx.AsyncClient]:
    """真应用 + 内存库，通过 ASGI 直连（不开端口）。"""
    from app.db import session as session_mod
    from app.main import app

    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def _session() -> AsyncIterator[AsyncSession]:
        async with factory() as sess:
            try:
                yield sess
            except Exception:
                await sess.rollback()
                raise

    # ① 把「有请求进来时拿哪个会话」换掉 —— 这是 FastAPI 官方的
    #    dependency_overrides 机制，不是 monkeypatch 内部实现。
    app.dependency_overrides[session_mod.get_session] = _session

    # ② lifespan 的启动自检会去连真 MySQL；这里只把它换成 no-op。
    #    注意**不换 create_app**，中间件/路由/异常处理器全是真的。
    import app.main as main_mod

    async def _no_db_check() -> None:
        return None

    original = main_mod.verify_connection
    main_mod.verify_connection = _no_db_check  # type: ignore[assignment]

    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    finally:
        main_mod.verify_connection = original  # type: ignore[assignment]
        app.dependency_overrides.clear()
        await test_engine.dispose()


# ---------------------------------------------------------------------------
# 一、应用真的能起来并响应
# ---------------------------------------------------------------------------


async def test_应用能启动并响应请求(api: httpx.AsyncClient) -> None:
    """lifespan 跑完、路由可达。这一条挂了，其余全是空谈。"""
    resp = await api.get("/api/v1/health")
    assert resp.status_code == 200, resp.text


async def test_健康检查的形状符合契约(api: httpx.AsyncClient) -> None:
    """`/health` 是我们唯一敢说不查库的探针，它的字段被部署脚本读。

    `database` 这一项在真实环境里由 `SELECT 1` 决定；这里注入的是内存库，
    所以只断言**字段在**、且 `status` 是 ok —— 具体取值留给集成环境。
    """
    body = (await api.get("/api/v1/health")).json()
    assert body["status"] == "ok"
    assert "database" in body
    assert "llm_available" in body


async def test_openapi_能生成且路径数对得上(api: httpx.AsyncClient) -> None:
    """路由挂载的**结构性**断言。

    数量写死在这里是刻意的：加路由时这条会红，逼人确认「是我想加的」，
    而不是某次重构把 prefix 写错、路由集体挪走却没人发现。
    """
    spec = (await api.get("/api/v1/openapi.json")).json()
    assert len(spec["paths"]) == 27, sorted(spec["paths"])


# ---------------------------------------------------------------------------
# 二、鉴权真的生效 —— 每条受保护路由都要拦下匿名请求
# ---------------------------------------------------------------------------

#: 前端会调的受保护读接口。**故意挑不写库的 GET**，
#: 这样「403 而不是 500」这个断言不会被「没造数」干扰。
_PROTECTED_GETS = [
    "/api/v1/auth/me",
    "/api/v1/projects",
    "/api/v1/assessments",
    "/api/v1/dashboard/stats",
    "/api/v1/reports",
    "/api/v1/admin/audit-logs",
    "/api/v1/admin/llm/config",
    "/api/v1/admin/sandbox/configs",
]


@pytest.mark.parametrize("path", _PROTECTED_GETS)
async def test_受保护路由对匿名请求返回_401(api: httpx.AsyncClient, path: str) -> None:
    """**这是本项目最重要的单条断言。**

    CLAUDE.md 安全红线第 1 条：身份只能从 JWT 来，且每个写接口要独立校验权限。
    这里的失败模式不是「报错」，而是**悄悄放行** —— 一个漏挂
    `Depends(require_user)` 的路由会正常返回 200 和一堆数据，
    而所有单元测试照绿，因为没人从 HTTP 这一层敲过它。

    所以逐条列出来点名，而不是抽查一条：漏的那一条往往不在抽查样本里。
    """
    resp = await api.get(path)
    assert resp.status_code == 401, (
        f"{path} 对匿名请求返回了 {resp.status_code} 而不是 401 —— "
        f"这条路由可能漏挂了鉴权依赖，会无声地泄露数据。body={resp.text[:200]}"
    )


async def test_错误响应的形状是_9_2_的四要素信封(api: httpx.AsyncClient) -> None:
    """错误信封是**本项目自己的** §9.2 契约，不是 FastAPI 默认的 `{"detail": ...}`。

    四要素：`stage` / `error_code` / `message` / `remediation`（+ `retryable` /
    `occurred_at`）。前端的错误提示只写一套解析，靠的就是这个形状稳定。

    ⚠️ 顶层还有 FastAPI 自带的 `detail`。**两个键都要有**：`detail` 是
    HTTPException 的固有字段（去掉它会绕过 FastAPI 自己的约定），
    `error` 才是我们给前端用的。改动这里之前先确认前端读的是哪个。
    """
    body = (await api.get("/api/v1/auth/me")).json()

    assert "error" in body, f"错误响应没有 §9.2 的 error 信封：{body}"
    err = body["error"]
    for key in ("error_code", "message", "remediation", "retryable", "occurred_at"):
        assert key in err, f"error 信封缺 `{key}`：{err}"
    assert err["error_code"] == "UNAUTHORIZED"


async def test_登录接口对空请求体返回_400_而不是_500(api: httpx.AsyncClient) -> None:
    """Pydantic 的请求体校验真的接上了，且**被归一化进了 §9.2 信封**。

    ⚠️ 这里**不是** FastAPI 默认的 422：`install_exception_handlers` 把
    `RequestValidationError` 收拢成了 400 + `BAD_REQUEST`，为的是
    「所有失败都长同一个形状」。断言 422 会红，而那不代表代码错了 ——
    这一条就是钉住这个刻意的选择。

    真正要防的是 500（读空 body 的属性），那才说明校验被跳过了。
    """
    resp = await api.post("/api/v1/auth/login", json={})
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["error_code"] == "BAD_REQUEST"
    # 逐字段的错误要透出来，否则前端只能提示「参数错误」而说不清是哪个
    assert "username" in resp.text


async def test_登录接口对错误口令返回_401_而不是_500(api: httpx.AsyncClient) -> None:
    """库里没有这个用户 —— 要回 401，不能把 `None` 当对象用。"""
    resp = await api.post(
        "/api/v1/auth/login", json={"username": "nobody", "password": "wrong-password"}
    )
    assert resp.status_code == 401, resp.text


# ---------------------------------------------------------------------------
# 三、404 与路径参数
# ---------------------------------------------------------------------------


async def test_不存在的路径返回_404(api: httpx.AsyncClient) -> None:
    assert (await api.get("/api/v1/definitely-not-a-route")).status_code == 404


async def test_路径参数类型不符返回_422(api: httpx.AsyncClient) -> None:
    """`/assessments/{id}` 的 id 是 int；传字符串要在进入业务前就被挡下。

    先过鉴权关才有意义 —— 所以这里断言「422 或 401，但**绝不是 500**」。
    """
    resp = await api.get("/api/v1/assessments/not-a-number")
    assert resp.status_code in (401, 422), resp.text
