"""ORM 模型。

**这里必须把每一张表都 import 进来**：Alembic autogenerate 靠 `Base.metadata`
比对库表差异，而 `Base.metadata` 只包含**被 import 过**的模型类。
漏一个模型的症状是「迁移里凭空出现 DROP TABLE xxx」—— 因为 autogenerate 认为
那张表该被删掉。新增模型时务必同步加到这里。
"""

from app.db.base import Base
from app.models.assessment import Assessment, AssessmentStage
from app.models.chain import AttackChain, AttackChainNode
from app.models.llm import LlmConfig
from app.models.observability import AuditLog, ResourceMetric
from app.models.project import Project
from app.models.report import Report
from app.models.sandbox import SandboxConfig
from app.models.user import User
from app.models.vulnerability import Patch, PocAttempt, TaintPath, Vulnerability

__all__ = [
    "Assessment",
    "AssessmentStage",
    "AttackChain",
    "AttackChainNode",
    "AuditLog",
    "Base",
    "LlmConfig",
    "Patch",
    "PocAttempt",
    "Project",
    "Report",
    "ResourceMetric",
    "SandboxConfig",
    "TaintPath",
    "User",
    "Vulnerability",
]
