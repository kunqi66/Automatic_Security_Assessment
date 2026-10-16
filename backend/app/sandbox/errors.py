"""B2 专用异常。

**只有一个族**：`SandboxUnavailableError` 及其两个精确子类。理由是 B3 需要一个
**单点判断**：「沙箱这次能不能用」。三种名字（不可达 / 镜像没有 / 磁盘满）在编排层的
处置完全相同 —— `poc_verify` 标 `skipped`，全部 Finding 退 `potential`，**评估继续**
（总纲 §8.2：计算类依赖可降级，存储类不可降级）。分成三个互不相干的异常只会让
B3 写三遍 `except`，然后漏掉第四个。

**为什么子类而不是一个类**：三者对**人**的修复指引完全不同（`remediation` 直接进
前端提示与报告）。不可达 → 查安全组/SSH；镜像缺失 → 去 build；磁盘满 → 维护窗口 prune。
错误码只有 `SANDBOX_UNREACHABLE` 一个（`core/exceptions.py` 的 `ErrorCode` 是封闭
Literal，扩展它属于改 B2 之外的模块），语义上「沙箱无法为你服务」是它们的共同点。
"""

from __future__ import annotations

from app.core.exceptions import SandboxUnreachableError


class SandboxUnavailableError(SandboxUnreachableError):
    """沙箱不可用 —— **B3 的降级判据就是这个类**。

    继承 `core.exceptions.SandboxUnreachableError`，因此天然带上：
    `error_code="SANDBOX_UNREACHABLE"`、`http_status=503`、`retryable=True`
    与总纲 §9.2 的四要素。

    注意语义：它表达的是「这次用不了沙箱」，**不是**「探针没打通」。后者（容器正常
    跑完、命令非零退出）由 `ExecResult` 表达。混为一谈的后果是：Docker 连不上时
    B5 会把每条漏洞都记成一次「验证失败」，而正确的结论是「这一阶段根本没验」。
    """

    default_remediation = (
        "检查 ECS 安全组 SSH 放行、DOCKER_HOST 配置与 ssh 连通性；"
        "该阶段已标记为跳过，静态分析结果不受影响"
    )


class SandboxImageMissingError(SandboxUnavailableError):
    """基础镜像不存在（B2 模块设计 §6 E5，L3 可跳过）。

    **刻意不可重试**：镜像不会因为再试一次就出现。重试只会把一次明确的配置错误
    拖成三倍等待。
    """

    default_retryable = False
    default_remediation = (
        "在能访问沙箱宿主的机器上执行 "
        "docker build -f app/sandbox/base/Dockerfile -t asa/sandbox-base:latest . 后重跑；"
        "运行期不 pip（容器无出网），依赖必须预置进镜像"
    )


class SandboxDiskFullError(SandboxUnavailableError):
    """沙箱宿主磁盘满（B2 模块设计 §6 E6，L3 可跳过）。

    19G 的 ECS 上这是真实会发生的：镜像层 + 容器写层都能吃穿它。

    **不自动 `docker system prune`**：同一台机器上还有 Milvus(19530)、MySQL、
    Redis 与未知 :8000。全量 prune 会连别人的镜像一起删掉，而「顺手清理」这种
    副作用没有任何事务能回滚。清理只在维护窗口人工执行（设计 T13 / §4.2）。
    """

    default_retryable = False
    default_remediation = (
        "沙箱宿主磁盘已满。请在维护窗口人工清理（docker image prune / 清理旧评估的 "
        "/srv/asa/tasks 目录）；系统刻意不自动 prune，以免误删同机其他服务的镜像"
    )
