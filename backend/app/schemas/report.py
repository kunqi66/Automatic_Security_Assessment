"""报告 DTO（B6）。"""

from __future__ import annotations

from datetime import datetime

from app.models.enums import ReportFormat, ReportStatus
from app.models.report import Report
from app.schemas.common import ORMModel


class ReportOut(ORMModel):
    id: int
    assessment_id: int
    #: 派生字段：报告中心要显示所属项目名，但 reports 表没有这一列（要经 assessment 绕一层）
    project_name: str
    title: str
    format: ReportFormat
    status: ReportStatus
    #: 相对 workspace 根的 POSIX 路径；`status != ready` 时为 null
    content_path: str | None
    size_bytes: int | None
    generated_at: datetime

    @classmethod
    def from_model(cls, report: Report, project_name: str) -> ReportOut:
        """字段名与 ORM 逐一同名，所以走 `model_validate` 而不是手写映射 ——
        哪天列改名了，这里会在测试里炸出来，而不是安静地返回 null。"""
        out = cls.model_validate(report)
        out.project_name = project_name
        return out
