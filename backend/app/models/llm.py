"""LLM 推理参数表（需求 2.5.2 管理员配置）。

⚠️ **API Key 不入库**：只从 `.env` 的 `DEEPSEEK_API_KEY` 读取，由部署者自行填写。
这样设计是为了避免密钥随数据库备份 / 导出而泄露 —— 一张会进备份的表里不该有长期密钥。
"""

from __future__ import annotations

from sqlalchemy import Boolean, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class LlmConfig(Base, TimestampMixin):
    __tablename__ = "llm_configs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="deepseek")
    base_url: Mapped[str] = mapped_column(String(255), nullable=False)
    model: Mapped[str] = mapped_column(String(64), nullable=False)

    #: 低温度只是为了让**措辞**稳定；模型不参与判定，所以它调不出任何结论差异
    temperature: Mapped[float] = mapped_column(Float, nullable=False, default=0.2)
    max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=2048)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    #: 校验失败重试不超过 1 次（总纲 §8.5 L3）
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
