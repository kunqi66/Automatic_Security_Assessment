"""概览大盘聚合 DTO（F1）。"""

from __future__ import annotations

from pydantic import BaseModel, model_validator

from app.models.enums import SecurityGrade, Severity, VulnStatus
from app.schemas.assessment import AssessmentOut


def _fill_all_keys(counts: dict[str, int], enum_cls: type) -> dict[str, int]:
    """补齐缺失的枚举键为 0。

    前端把这三个字段声明成 `Record<Severity, number>` 这类**全键**类型，
    缺键在 TS 里不会报错，但渲染出来就是 `undefined` —— 一个只在「某等级恰好没有漏洞」
    时才出现的显示 bug。在序列化前补齐，比在前端到处写 `?? 0` 干净。
    """
    return {member.value: counts.get(member.value, 0) for member in enum_cls}


class DashboardStatsOut(BaseModel):
    project_count: int
    assessment_count: int
    running_count: int
    vuln_total: int
    vuln_by_severity: dict[str, int]
    grade_distribution: dict[str, int]
    vuln_by_status: dict[str, int]
    recent_assessments: list[AssessmentOut]

    @model_validator(mode="after")
    def _complete_distributions(self) -> DashboardStatsOut:
        self.vuln_by_severity = _fill_all_keys(self.vuln_by_severity, Severity)
        self.grade_distribution = _fill_all_keys(self.grade_distribution, SecurityGrade)
        self.vuln_by_status = _fill_all_keys(self.vuln_by_status, VulnStatus)
        return self
