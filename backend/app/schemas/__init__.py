"""Pydantic DTO。

**分层铁律**：跨层传数据一律用这里的模型，不传裸 dict。
API 层负责「入参校验 → 转 DTO → 交给引擎」，引擎层只认这些类型。
"""

from app.schemas.admin import (
    LlmConfigOut,
    LlmConfigUpdate,
    SandboxConfigOut,
    SandboxConfigUpdate,
)
from app.schemas.assessment import AssessmentCreate, AssessmentOut, ResourceSampleOut, StageStateOut
from app.schemas.audit import AuditLogOut
from app.schemas.auth import LoginRequest, LoginResponse, UserOut
from app.schemas.chain import AttackChainNodeOut
from app.schemas.common import ORMModel, Page
from app.schemas.dashboard import DashboardStatsOut
from app.schemas.project import ProjectCreate, ProjectOut, SourceSnippet
from app.schemas.report import ReportOut
from app.schemas.vulnerability import (
    PatchSuggestionOut,
    PatchValidationOut,
    TaintStepOut,
    VulnerabilityOut,
    VulnStatusUpdate,
)

__all__ = [
    "AssessmentCreate",
    "AssessmentOut",
    "AttackChainNodeOut",
    "AuditLogOut",
    "DashboardStatsOut",
    "LlmConfigOut",
    "LlmConfigUpdate",
    "LoginRequest",
    "LoginResponse",
    "ORMModel",
    "Page",
    "PatchSuggestionOut",
    "PatchValidationOut",
    "ProjectCreate",
    "ProjectOut",
    "ReportOut",
    "ResourceSampleOut",
    "SandboxConfigOut",
    "SandboxConfigUpdate",
    "SourceSnippet",
    "StageStateOut",
    "TaintStepOut",
    "UserOut",
    "VulnStatusUpdate",
    "VulnerabilityOut",
]
