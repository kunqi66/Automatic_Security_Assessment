"""管理端 DTO：沙箱配置与 LLM 推理参数。"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import NetworkPolicy
from app.models.llm import LlmConfig
from app.schemas.common import ORMModel

# ---------------------------------------------------------------------------
# 沙箱配置
# ---------------------------------------------------------------------------


class SandboxConfigOut(ORMModel):
    id: int
    name: str
    base_image: str
    network_policy: NetworkPolicy
    cpu_limit: float
    memory_limit_mb: int
    timeout_seconds: int
    #: 界面上要**看得见**，但不给改（因此不在 `SandboxConfigUpdate` 里）。
    #: 调度并发由 worker 固定为 1（总纲 §8.1：2 vCPU 下并发只会让所有任务都
    #: 变慢并撞 OOM），引擎侧没有对应的执行参数 —— 做成可编辑就是一个假控件。
    max_concurrency: int
    is_default: bool


class SandboxConfigUpdate(BaseModel):
    """`PUT /admin/sandbox/configs` —— 按 body 里的 `id` 定位单条。

    之所以是这个形状：`sandbox_configs` 是**多行集合**（带 `is_default`），
    但更新动作一次只针对一行。把 id 放 body 而不是路径，是为了让
    「集合资源的整体提交」这个语义保持成立。
    """

    id: int
    name: str | None = Field(default=None, min_length=1, max_length=64)
    base_image: str | None = Field(default=None, max_length=255)
    network_policy: NetworkPolicy | None = None
    cpu_limit: float | None = Field(default=None, gt=0, le=16)
    memory_limit_mb: int | None = Field(default=None, ge=128, le=32768)
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    is_default: bool | None = None


# ---------------------------------------------------------------------------
# LLM 推理参数
# ---------------------------------------------------------------------------


class LlmConfigOut(BaseModel):
    """⚠️ **永远不含 `api_key`** —— 密钥只在后端 `.env`，不入库、不经接口回传。"""

    provider: str
    base_url: str
    model: str
    temperature: float
    max_tokens: int
    timeout_seconds: int
    max_retries: int
    is_default: bool
    #: 由后端探测（当前实现 = 是否配了 key）。false 时全站走模板降级，**结论不受影响**。
    available: bool
    updated_at: datetime

    @classmethod
    def from_model(cls, cfg: LlmConfig, *, available: bool) -> LlmConfigOut:
        return cls(
            provider=cfg.provider,
            base_url=cfg.base_url,
            model=cfg.model,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            timeout_seconds=cfg.timeout_seconds,
            max_retries=cfg.max_retries,
            is_default=cfg.is_default,
            available=available,
            updated_at=cfg.updated_at,
        )


class LlmConfigUpdate(BaseModel):
    """只改推理参数。**没有 api_key 字段** —— 想换密钥请改 `.env` 并重启。"""

    provider: str | None = Field(default=None, max_length=32)
    base_url: str | None = Field(default=None, max_length=255)
    model: str | None = Field(default=None, max_length=64)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1, le=32768)
    timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    max_retries: int | None = Field(default=None, ge=0, le=3)
