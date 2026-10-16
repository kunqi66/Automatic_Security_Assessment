"""「新建评估」这条入口的三个前提 —— 谁能建、权限怎么告诉前端、能不能连点两次。

三件事放一个文件，是因为它们共同决定这条入口的行为：
前端依据 `permissions` 决定按钮显不显示，后端依据在途状态决定放不放行。
**任何一处单独看都自洽，错都在交界处。**

`api` fixture 与 `test_api_boots.py` 的那份**刻意不同**：那份不种任何数据
（它测的是应用能不能起来、路由全不全），这份要种两个不同角色的用户和一个
已就绪的项目，否则鉴权与守卫都无从谈起。共用一份会逼着边测边改。
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("DEBUG", "true")

from collections.abc import AsyncIterator  # noqa: E402

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.api.deps import ROLE_PERMISSIONS, Permission, permissions_for  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.models.enums import AssessmentStatus, ProjectStatus, UserRole  # noqa: E402
from app.models.project import Project  # noqa: E402
from app.models.user import User  # noqa: E402

#: 两个账号共用同一个口令，只差角色。测试专用，不是任何真实凭据。
PW = "correct-horse-battery-staple"

#: 已就绪的项目：`storage_path` 非空，否则启动评估会被「还没有源码」挡掉，
#: 于是守卫那条用例根本走不到它要测的分支，变成假绿。
READY_PROJECT = "已就绪的项目"


@pytest.fixture
async def db_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """内存库 + 种好的数据。SQLite 走 `StaticPool`，所有会话共享同一条连接。"""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        sess.add_all(
            [
                User(
                    username="eng",
                    password_hash=hash_password(PW),
                    role=UserRole.SECURITY_ENGINEER,
                ),
                User(username="adm", password_hash=hash_password(PW), role=UserRole.ADMIN),
                Project(
                    name=READY_PROJECT,
                    source_type="upload",
                    storage_path="1",
                    status=ProjectStatus.CREATED,
                ),
            ]
        )
        await sess.commit()

    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
async def api(
    db_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[httpx.AsyncClient]:
    """真应用 + 上面那个内存库，走 ASGI 直连（不开端口）。"""
    from app.db import session as session_mod
    from app.main import app

    async def _session() -> AsyncIterator[AsyncSession]:
        async with db_factory() as sess:
            try:
                yield sess
            except Exception:
                await sess.rollback()
                raise

    app.dependency_overrides[session_mod.get_session] = _session

    # lifespan 的启动自检会去连真 MySQL（`test_api_boots.py` 里有同样的处理）
    import app.main as main_mod

    original = main_mod.verify_connection
    main_mod.verify_connection = _noop  # type: ignore[assignment]

    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    finally:
        main_mod.verify_connection = original  # type: ignore[assignment]
        app.dependency_overrides.clear()


async def _noop() -> None:
    return None


async def _auth(api: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await api.post("/api/v1/auth/login", json={"username": username, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _project_id(api: httpx.AsyncClient, headers: dict[str, str]) -> int:
    r = await api.get("/api/v1/projects", headers=headers)
    assert r.status_code == 200, r.text
    return next(p["id"] for p in r.json()["items"] if p["name"] == READY_PROJECT)


# ---------------------------------------------------------------------------
# 一、权限映射：这是「前端按钮显不显示」的唯一依据
# ---------------------------------------------------------------------------


def test_安全工程师有创建评估的权限() -> None:
    assert Permission.ASSESSMENT_CREATE in permissions_for(UserRole.SECURITY_ENGINEER)


def test_管理员没有创建评估的权限() -> None:
    """需求 2.5.2 的三条职责：管理员管沙箱/LLM/审计，**不建评估任务**。

    这条用例的存在理由：管理员是最容易「以为自己是超级用户」的角色，
    而前端正是靠这个集合决定「新建评估」按钮显不显示。
    哪天有人顺手给 ADMIN 加上 `assessment:create`，这里必须红 ——
    否则按钮会静默出现，而按钮背后是一份没人审视过的权限扩张。
    """
    assert Permission.ASSESSMENT_CREATE not in permissions_for(UserRole.ADMIN)


def test_三个角色都能读() -> None:
    """只读权限三角色共有（`_READ_ONLY`）。建评估可以不给，看评估必须给。"""
    for role in UserRole:
        assert Permission.ASSESSMENT_VIEW in permissions_for(role)


def test_未知角色拿到空集而不是抛异常() -> None:
    """库里冒出一个没见过的 role 时，后果应该是「什么都干不了」，
    而不是「所有接口 500」—— 后者会把一个数据问题放大成一次故障。"""
    assert permissions_for("auditor") == frozenset()  # type: ignore[arg-type]


def test_权限集合非空且不含重复语义() -> None:
    """每个角色至少有一项权限；`ROLE_PERMISSIONS` 的键覆盖全部角色。

    漏一个角色的后果是**静默的**：`permissions_for` 返回空集，
    该角色登录后所有写接口 403，而没有任何地方会报错。
    """
    assert set(ROLE_PERMISSIONS) == set(UserRole)
    for role, perms in ROLE_PERMISSIONS.items():
        assert perms, f"{role} 一项权限都没有"


# ---------------------------------------------------------------------------
# 二、权限要随身份返回 —— 前端不该自己抄一份 role→权限 的映射
# ---------------------------------------------------------------------------


async def test_登录与_me_返回同一份权限(api: httpx.AsyncClient) -> None:
    """两个接口必须一致。

    不一致的症状是「刚登录时按钮在、刷新一下没了」——
    一个只能用重启来解释的现象。
    """
    login = await api.post("/api/v1/auth/login", json={"username": "eng", "password": PW})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    from_login = login.json()["user"]["permissions"]

    me = await api.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    assert me.json()["permissions"] == from_login


async def test_权限以字符串码返回且前端据此区分角色(api: httpx.AsyncClient) -> None:
    eng = await api.get("/api/v1/auth/me", headers=await _auth(api, "eng"))
    adm = await api.get("/api/v1/auth/me", headers=await _auth(api, "adm"))

    eng_perms = eng.json()["permissions"]
    adm_perms = adm.json()["permissions"]

    # 形状：字符串码，不是枚举对象、也不是 {name, value} 这种包一层的结构
    assert all(isinstance(p, str) and ":" in p for p in eng_perms), eng_perms
    assert eng_perms == sorted(eng_perms), "顺序不稳定会让响应体无谓地跨进程不同"

    assert "assessment:create" in eng_perms
    assert "assessment:create" not in adm_perms
    # 反过来：管理员该有的，工程师没有
    assert "sandbox:manage" in adm_perms
    assert "sandbox:manage" not in eng_perms


async def test_响应里不含口令哈希(api: httpx.AsyncClient) -> None:
    """`UserOut` 的存在理由就是这个。加了 `permissions` 之后仍然成立。"""
    body = (await api.get("/api/v1/auth/me", headers=await _auth(api, "eng"))).text
    assert "password" not in body.lower()
    assert "$argon2" not in body


# ---------------------------------------------------------------------------
# 三、在途守卫：一个项目同时只能有一个未结束的评估
# ---------------------------------------------------------------------------


async def test_管理员建项目被拒_工程师放行(api: httpx.AsyncClient) -> None:
    """这条同时验证「权限在后端真的拦住了」，而不只是前端不显示按钮。

    安全红线 7：每个写接口独立校验，不得依赖前端隐藏按钮。
    """
    body = {"name": "管理员试建", "source_type": "upload"}
    denied = await api.post("/api/v1/projects", json=body, headers=await _auth(api, "adm"))
    assert denied.status_code == 403, denied.text

    allowed = await api.post("/api/v1/projects", json=body, headers=await _auth(api, "eng"))
    assert allowed.status_code == 201, allowed.text


async def test_连点两次新建评估_第二次被拒(
    api: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**本文件的核心用例。**

    原先的守卫只判 `status == RUNNING`，但刚建出来的行是 `created`，
    要等 worker 从 Redis 流里取走才转 `running`。所以在这个窗口里连点两次，
    两次都拿到 201（实测过），两个评估都被入队、被 worker 顺序跑完 ——
    白跑一遍并留下两条重复记录，且**不报任何错**。

    把守卫改回 `== RUNNING`，这条必须红。
    """
    monkeypatch.setattr(
        "app.orchestrator.queue.TaskQueue.enqueue",
        _noop_enqueue,
    )
    headers = await _auth(api, "eng")
    pid = await _project_id(api, headers)

    first = await api.post(f"/api/v1/projects/{pid}/assessments", headers=headers)
    assert first.status_code == 201, first.text
    assert first.json()["status"] == AssessmentStatus.CREATED.value, (
        "前提变了：行不再是 created 起步，这条用例测的窗口就不存在了"
    )

    second = await api.post(f"/api/v1/projects/{pid}/assessments", headers=headers)
    assert second.status_code == 400, (
        f"第二次应当被拒，实际 {second.status_code} —— 在途窗口漏了：{second.text}"
    )


async def test_评估到终态后可以再次发起(
    api: httpx.AsyncClient,
    db_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """守卫不能把关得太死：跑完（终态）就该允许重跑。

    只测「被拒」是不够的 —— 把守卫写成「该项目有任何评估就拒」
    一样能让上一条通过，而那样重跑就永远做不到了。
    """
    monkeypatch.setattr("app.orchestrator.queue.TaskQueue.enqueue", _noop_enqueue)
    headers = await _auth(api, "eng")
    pid = await _project_id(api, headers)

    first = await api.post(f"/api/v1/projects/{pid}/assessments", headers=headers)
    assert first.status_code == 201, first.text

    # 直接把它推到终态。走 /stop 需要 Redis 置标志位，这里要测的是守卫对
    # 终态的判定，不是取消链路（那条另有 `test_orchestrator_core.py` 覆盖）。
    async with db_factory() as sess:
        from app.models.assessment import Assessment

        row = await sess.get(Assessment, first.json()["id"])
        assert row is not None
        row.status = AssessmentStatus.COMPLETED
        await sess.commit()

    again = await api.post(f"/api/v1/projects/{pid}/assessments", headers=headers)
    assert again.status_code == 201, f"终态之后应当允许重新发起：{again.text}"


async def test_没有源码的项目不能启动评估(api: httpx.AsyncClient) -> None:
    """`storage_path` 为空时给出可操作的错误，而不是等到 recon 阶段才炸。"""
    headers = await _auth(api, "eng")
    created = await api.post(
        "/api/v1/projects",
        json={"name": "没传源码的项目", "source_type": "upload"},
        headers=headers,
    )
    assert created.status_code == 201, created.text

    started = await api.post(
        f"/api/v1/projects/{created.json()['id']}/assessments", headers=headers
    )
    assert started.status_code == 400, started.text
    body = started.json()
    assert "源码" in str(body)


async def _noop_enqueue(self: object, assessment_id: int) -> str:
    """把入队换成空操作 —— **本文件测的是守卫，不是队列**。

    真入队要连 Redis，而 Redis 不可用时接口会抛 `DependencyDownError`
    并把评估置为 `failed`。`failed` 是终态，于是第二次请求本来就会被放行，
    那条用例会**假绿** —— 看起来在测守卫，其实什么都没测。

    参数保留原名以便与真实签名对照；`self` 用不到但不能省。
    """
    del self, assessment_id
    return "0-0"
