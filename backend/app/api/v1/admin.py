"""管理员配置（L1 接口层）：LLM 参数、沙箱配置。

**两处写入都留痕**（`llm_config.update` / `sandbox_config.update`）—— 需求 2.5.2
把它们和「人工复核」「采纳补丁」并列为会改变系统行为的操作。

**API Key 不在本模块的任何输入输出里**：它只从 `.env` 读（`app/models/llm.py`
的模块文档写了理由）。所以 `LlmConfigOut` 没有、也不该有 key 字段 ——
一个能改 key 的接口，等于把长期密钥请进数据库和备份。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select, update

from app.api.deps import DBSession, Permission, require
from app.core.config import settings
from app.core.exceptions import BadRequestError
from app.core.logging import get_logger
from app.db import audit
from app.llm import client as llm_client
from app.models.enums import NetworkPolicy
from app.models.llm import LlmConfig
from app.models.sandbox import SandboxConfig
from app.models.user import User
from app.schemas.admin import (
    LlmConfigOut,
    LlmConfigUpdate,
    SandboxConfigOut,
    SandboxConfigUpdate,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["管理"])

LlmAdmin = Annotated[User, Depends(require(Permission.LLM_MANAGE))]
SandboxAdmin = Annotated[User, Depends(require(Permission.SANDBOX_MANAGE))]


# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------


@router.get("/llm/config", response_model=LlmConfigOut, summary="读取 LLM 参数")
async def get_llm_config(session: DBSession, _: LlmAdmin) -> LlmConfigOut:
    return _llm_out(await _default_llm(session))


@router.put("/llm/config", response_model=LlmConfigOut, summary="更新 LLM 参数")
async def update_llm_config(
    payload: LlmConfigUpdate, session: DBSession, user: LlmAdmin, request: Request
) -> LlmConfigOut:
    config = await _default_llm(session)
    changed = payload.model_dump(exclude_none=True)
    if not changed:
        raise BadRequestError("没有需要更新的字段")

    before = {key: getattr(config, key) for key in changed}
    for key, value in changed.items():
        setattr(config, key, value)

    audit.record(
        session,
        user=user,
        action="llm_config.update",
        target_type="llm_config",
        target_id=config.id,
        detail={"before": _jsonable(before), "after": _jsonable(changed)},
        request=request,
    )
    await session.commit()
    await session.refresh(config)

    # **提交之后再重建客户端**：先重建的话，事务若回滚，进程里就留下了一个
    # 按「没生效的配置」建的客户端，而数据库里还是旧值 —— 两者不一致且无人察觉。
    #
    # 只影响**本进程**。worker 进程在每次评估开始时会自己按库里的配置重建
    # （见 `OrchestrationEngine.start`），所以不需要重启 worker。
    await llm_client.configure_default_client(
        base_url=config.base_url,
        model=config.model,
        timeout_seconds=config.timeout_seconds,
        max_retries=config.max_retries,
    )

    logger.info("用户 %s 更新了 LLM 参数：%s", user.username, sorted(changed))
    return _llm_out(config)


async def _default_llm(session: DBSession) -> LlmConfig:
    """取那条生效的配置；一行都没有时按 settings 补一行。

    自举而不是报 404：全新部署时管理员打开这一页应该看到**当前实际生效的默认值**，
    而不是一片空白 —— 空白会让人以为要自己从零填，而实际上 `.env` 里已经有了。
    """
    config = await session.scalar(
        select(LlmConfig).where(LlmConfig.is_default.is_(True)).order_by(LlmConfig.id.asc())
    )
    if config is not None:
        return config

    config = LlmConfig(
        provider="deepseek",
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        timeout_seconds=settings.llm_timeout_seconds,
        max_retries=settings.llm_max_retries,
        is_default=True,
    )
    session.add(config)
    await session.commit()
    await session.refresh(config)
    return config


def _llm_out(config: LlmConfig) -> LlmConfigOut:
    return LlmConfigOut(
        provider=config.provider,
        base_url=config.base_url,
        model=config.model,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        timeout_seconds=config.timeout_seconds,
        max_retries=config.max_retries,
        is_default=config.is_default,
        # 「配了 key 吗」和「参数是什么」是两个问题。前者决定系统走 LLM 还是走模板，
        # 管理员需要一眼看到 —— 参数填得再漂亮，没 key 也全是模板产出。
        available=settings.llm_available,
        updated_at=config.updated_at or config.created_at,
    )


# ---------------------------------------------------------------------------
# 沙箱
# ---------------------------------------------------------------------------


@router.get("/sandbox/configs", response_model=list[SandboxConfigOut], summary="读取沙箱配置")
async def list_sandbox_configs(session: DBSession, _: SandboxAdmin) -> list[SandboxConfigOut]:
    rows = (
        (await session.execute(select(SandboxConfig).order_by(SandboxConfig.id.asc())))
        .scalars()
        .all()
    )
    return [SandboxConfigOut.model_validate(row) for row in rows]


@router.put("/sandbox/configs", response_model=list[SandboxConfigOut], summary="更新沙箱配置")
async def update_sandbox_configs(
    payload: list[SandboxConfigUpdate],
    session: DBSession,
    user: SandboxAdmin,
    request: Request,
) -> list[SandboxConfigOut]:
    if not payload:
        raise BadRequestError("没有需要更新的配置")

    for item in payload:
        config = await session.get(SandboxConfig, item.id)
        if config is None:
            raise BadRequestError(f"沙箱配置 {item.id} 不存在")

        changed = item.model_dump(exclude_none=True, exclude={"id"})
        if not changed:
            continue

        # 🔴 **网络的硬闸门放在这里，而不是靠管理员自觉**。
        # `bridge` 会让容器拿到出网能力，而「无出网」是这套系统敢在真实
        # 靶场上跑探针的前提（总纲 §8.4）。放它过去，等于给一个自动化
        # 攻击工具开了条通往内网的路。
        # 校验在**写入前**，所以被拒的配置不会留下半截状态。
        _guard_network(item.id, changed)

        before = {key: getattr(config, key) for key in changed}
        for key, value in changed.items():
            setattr(config, key, value)

        # 🔴 **`is_default` 是单选语义，在这里强制。** 引擎按它挑「那一行」
        # （`engine._resolve_sandbox_config` 取 `is_default` 为真、按 id 排序的第一条）。
        # 若允许两行同时为默认，引擎用哪一行就取决于 id —— 一个**不报错的静默歧义**，
        # 正好是原理 8 要防的那类问题。设了一行就把其余的清掉。
        cleared: list[int] = []
        if changed.get("is_default") is True:
            cleared = list(
                (
                    await session.execute(
                        select(SandboxConfig.id).where(
                            SandboxConfig.id != config.id, SandboxConfig.is_default.is_(True)
                        )
                    )
                )
                .scalars()
                .all()
            )
            if cleared:
                await session.execute(
                    update(SandboxConfig)
                    .where(SandboxConfig.id.in_(cleared))
                    .values(is_default=False)
                )

        audit.record(
            session,
            user=user,
            action="sandbox_config.update",
            target_type="sandbox_config",
            target_id=config.id,
            detail={
                "before": _jsonable(before),
                "after": _jsonable(changed),
                # 连带改动也要留痕：审计里只记 `target_id` 那一行的话，
                # 「谁把另一条配置的默认取消了」就查不出来了。
                "cleared_default_on": cleared,
            },
            request=request,
        )

    await session.commit()

    rows = (
        (await session.execute(select(SandboxConfig).order_by(SandboxConfig.id.asc())))
        .scalars()
        .all()
    )
    logger.info("用户 %s 更新了 %d 条沙箱配置", user.username, len(payload))
    return [SandboxConfigOut.model_validate(row) for row in rows]


def _guard_network(config_id: int, changed: dict[str, object]) -> None:
    policy = changed.get("network_policy")
    if policy is not None and policy != NetworkPolicy.INTERNAL and policy != NetworkPolicy.NONE:
        raise BadRequestError(
            f"沙箱配置 {config_id} 不允许使用 {policy} 网络",
            remediation=(
                "容器必须无出网访问。探针跑在 internal 网络上，"
                "出网会让自动化攻击流量泄漏到被测网络之外"
            ),
        )


def _jsonable(data: dict[str, object]) -> dict[str, object]:
    """枚举值落成字面量，便于人读审计详情。"""
    return {k: (v.value if hasattr(v, "value") else v) for k, v in data.items()}
