"""跨模块共用的 DTO 片段。

**分层铁律**：跨层传数据一律用这里的 Pydantic 模型，**不传裸 dict**（总纲 §3.4）。
裸 dict 的代价是字段拼错要到运行期才发现，而且 API 层与引擎层对同一个键的理解可能不同。
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    """可从 ORM 实例直接构造的响应模型基类。"""

    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):  # noqa: UP046 —— 刻意不用 PEP 695 的 `class Page[T]`：
    # Pydantic 对 PEP 695 泛型的支持要 2.9+，而 `Generic[T]` 在 2.x 全系都能建模型。
    # 分页信封是全项目每个列表接口都要过的路径，不值得为省一行语法去赌版本。
    """分页信封。**全项目唯一的分页形状**（PRD §9.1）。

    注意本系统**不使用** `{code, message, data}` 信封 —— 成功直接返回资源 JSON。
    理由见 PRD §9.1：信封会让「哪一层负责剥壳」变成每个调用点各自判断的事。
    """

    items: list[T]
    total: int
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)

    @classmethod
    def of(cls, items: list[T], total: int, page: int, page_size: int) -> Page[T]:
        return cls(items=items, total=total, page=page, page_size=page_size)

    @classmethod
    def empty(cls, page: int = 1, page_size: int = 20) -> Page[T]:
        return cls(items=[], total=0, page=page, page_size=page_size)
