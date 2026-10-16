"""状态与类型枚举（PRD §6 / 总纲 §5 的唯一落点）。

**两个刻意的选择：**

1. **不用 MySQL 原生 ENUM**（`native_enum=False`）。原生 ENUM 每加一个取值都要
   `ALTER TABLE`，而本系统的取值集是会长大的（规则库演进 → `vuln_type` 变多）。
   落成 `VARCHAR(32)`：可读、可加值、不锁死数据库方言。

   ⚠️ **注意这里没有 CHECK 约束**，别以为数据库在兜底。SQLAlchemy 1.4 起
   `create_constraint` 默认为 `False`（且 MySQL 的 CHECK 要 8.0.16+ 才真正生效），
   所以库里就是个裸 `VARCHAR(32)`。非法值唯一的拦截点是 ORM 读回时的枚举查表 ——
   它会直接抛 `LookupError`，响得够大声，但不是「写不进去」，是「读不出来」。
   要真正的写侧约束，得显式 `create_constraint=True` 并确认 MySQL 版本。

2. **必须传 `values_callable`**。SQLAlchemy 的 `Enum` 默认持久化的是枚举**成员名**
   （`SECURITY_ENGINEER`）而不是**值**（`security_engineer`）。不显式指定，
   数据库里存的就全是大写成员名，与 PRD §6 写的值集对不上 ——
   而且这个错误只在真正写入数据时才暴露，类型检查阶段完全看不出来。
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import sqlalchemy as sa


class UserRole(StrEnum):
    """三角色（需求 2.5.2）。"""

    SECURITY_ENGINEER = "security_engineer"
    DEVELOPER = "developer"
    ADMIN = "admin"


class ProjectStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class AssessmentStatus(StrEnum):
    """评估状态机（总纲 §5.1）。

    注意是 `created` 而不是 `queued`：行在「启动评估」时就创建为 `created`，
    真正被 worker 取走执行才转 `running`。
    """

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


#: **在途**状态：行已经建出来、但还没跑到终态。
#:
#: `CREATED` 必须算进来，这是本常量存在的唯一理由 ——
#: 行在「启动评估」时就建为 `created`，要等 worker 从 Redis 流里取走才转 `running`。
#: 只判 `RUNNING` 会漏掉中间那个窗口，症状是：
#:
#: - 连点两次「开始评估」→ 两个评估都入队，被 worker **顺序**跑完，
#:   白跑一遍并留下两条重复记录（`api/v1/assessments.py` 的并发守卫就这么漏的）；
#: - 在窗口内删项目 → 守卫放行，项目与工作区都没了，
#:   随后 worker 取走那条任务，评估凭空消失或带着缺失的工作区往下跑
#:   （`projects/repository.py` 的 `has_running_assessment`）。
#:
#: 两处都是**不报错的静默失败**，所以宁可在这里定义一次，
#: 也不要三处各写一个 `== RUNNING`（`stop` 接口早就判了两个状态，正是这种不一致）。
IN_FLIGHT_STATUSES: frozenset[AssessmentStatus] = frozenset(
    {AssessmentStatus.CREATED, AssessmentStatus.RUNNING}
)


class StageName(StrEnum):
    """五阶段流水线（总纲 §5.2）。顺序即依赖顺序，见 orchestrator/engine.py。"""

    RECON = "recon"
    CODE_AUDIT = "code_audit"
    POC_VERIFY = "poc_verify"
    EXPLOIT_CHAIN = "exploit_chain"
    REPORT_GEN = "report_gen"


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    #: 降级态，不是失败 —— 沙箱不可达 / 无匹配规则时使用（总纲 §9.1 L3）
    SKIPPED = "skipped"


class Severity(StrEnum):
    """单漏洞严重度。**与项目综合等级不是同一套术语**（见 SecurityGrade）。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecurityGrade(StrEnum):
    """项目综合等级（需求 2.5.8：极高危 / 高危 / 中危 / 安全）。

    ⚠️ 与 `Severity` 是**两套不同的四级术语**，不可混用：本枚举描述「整个项目有多危险」，
    `Severity` 描述「某一个漏洞有多危险」。
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    SAFE = "safe"


class VulnStatus(StrEnum):
    """漏洞四态（需求 2.5.4 / 总纲 §5.3）。

    产出阶段的约束是硬的：`unverified` 只由静态阶段产出，
    其余三态**只由动态验证阶段产出** —— B4 是纯分析引擎，不写任何 status。
    """

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    POTENTIAL = "potential"
    REJECTED = "rejected"


class DetectionMethod(StrEnum):
    """让报告能区分「函数内已确认」与「跨函数推断」（总纲 §7.3）。"""

    TAINT_INTRA = "taint_intra"
    TAINT_INTER = "taint_inter"
    PATTERN = "pattern"


class TaintStepType(StrEnum):
    """污点传播轨迹的一步（总纲 §7.3）。

    `sanitize` 步骤要落库，前端才能渲染「净化点」标记 —— 这是 F3 的加分项。
    """

    SOURCE = "source"
    PROPAGATE = "propagate"
    SANITIZE = "sanitize"
    SINK = "sink"


class ChainNodeType(StrEnum):
    """攻击链节点类型。

    比「vuln / asset / goal」更细，是因为需求 2.5.9 的演示链
    （SQL 注入 → 管理员凭证 → 上传 WebShell → 宿主机 RCE）需要区分
    「凭证」与「Shell」与「宿主」，F4 也据此着色。
    """

    ENTRY = "entry"
    VULN = "vuln"
    CREDENTIAL = "credential"
    SHELL = "shell"
    HOST = "host"
    IMPACT = "impact"


class VerificationStatus(StrEnum):
    """攻击链每一环的验证状态（总纲 §12.2 Q24 定案 = 方案 A）。

    `inferred` 是**推演结论而非实测结果**，报告必须声明该环未实际执行。
    这个区分是无害化原则的直接产物：扫描器可以推断「这里能打穿」，但不该自己打穿。
    """

    VERIFIED = "verified"
    INFERRED = "inferred"


class PatchStatus(StrEnum):
    """补丁的**人工**处置状态。与 `PatchSource`（产出源）正交。"""

    SUGGESTED = "suggested"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class PatchSource(StrEnum):
    """补丁的产出源。

    `validate_failed` 表示四道校验未通过、已降级为人工参考 ——
    前端与报告要据此显式标注，不能让用户以为它是可用的修复。
    """

    LLM = "llm"
    TEMPLATE = "template"
    VALIDATE_FAILED = "validate_failed"


class ReportFormat(StrEnum):
    HTML = "html"
    MD = "md"
    PDF = "pdf"


class ReportStatus(StrEnum):
    """HTML/MD 同步产出，PDF 惰性生成 —— 必须有中间态。"""

    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


class NetworkPolicy(StrEnum):
    """沙箱网络策略。默认 `internal`：仅回环与任务内网，**禁出站**。

    这不是可调的性能选项，而是安全模型的基石 —— 有出站能力就意味着
    验证代码可能把源码/口令/内网探测结果发往外部地址。
    """

    NONE = "none"
    INTERNAL = "internal"
    BRIDGE = "bridge"


def sa_enum(enum_cls: type[StrEnum], **kwargs: Any) -> sa.Enum:
    """构造「落库存值、不用原生 ENUM」的 SQLAlchemy 枚举列类型。"""
    return sa.Enum(
        enum_cls,
        native_enum=False,
        length=32,
        # 关键：不传这个，落库的是成员名（SECURITY_ENGINEER）而不是值（security_engineer）
        values_callable=lambda e: [m.value for m in e],
        **kwargs,
    )
