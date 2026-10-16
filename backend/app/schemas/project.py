"""项目相关 DTO（B1）。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from app.models.enums import ProjectStatus
from app.schemas.common import ORMModel


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    source_type: Literal["git", "upload"]

    #: Git 必填；upload 时为 null（源码随后走 POST /projects/{id}/upload 补传）
    source_url: str | None = Field(default=None, max_length=512)
    source_branch: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _check_source(self) -> ProjectCreate:
        if self.source_type == "git" and not self.source_url:
            raise ValueError("source_type=git 时必须提供 source_url")
        return self


class ProjectOut(ORMModel):
    id: int
    name: str
    description: str | None
    source_type: str
    source_url: str | None
    source_branch: str | None
    #: 相对 workspace 根的 POSIX 路径（总纲 §7.4）。**绝不返回绝对路径。**
    storage_path: str | None
    tech_stack: dict[str, Any] | None
    total_loc: int | None
    status: ProjectStatus
    error_message: str | None
    created_at: datetime


class SourceSnippet(BaseModel):
    """`GET /projects/{id}/source` 的响应。

    入参与出参的 `path` 都**必须是相对 workspace 根的 POSIX 路径** ——
    这样配合路径穿越校验（拒绝 `..`、绝对路径、符号链接）即可安全解析。
    """

    path: str
    start: int
    end: int
    content: str
