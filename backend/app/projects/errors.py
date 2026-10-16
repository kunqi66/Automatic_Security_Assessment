"""B1 专用异常（错误码 `PROJ_*`，见 B1 模块设计 §6）。

**为什么单开一个文件而不是塞进 `core/exceptions.py`**：
`core/exceptions.py` 放的是跨模块共用的错误族（认证、依赖不可用等），
`PROJ_*` 是 B1 的内部词汇。混在一起会让核心异常表随着模块增加而无限膨胀，
最后没人敢删任何一条。
"""

from __future__ import annotations

from app.core.exceptions import (
    CODE_BAD_REQUEST,
    CODE_SOURCE_UNAVAILABLE,
    AppError,
)


class ProjectError(AppError):
    """B1 异常基类，默认按「客户端可纠正」处理。"""

    code = CODE_BAD_REQUEST
    http_status = 400
    error_code = "BAD_REQUEST"


# ---------------------------------------------------------------------------
# 接入与解包
# ---------------------------------------------------------------------------


class GitNotAllowedError(ProjectError):
    """Git 地址不在白名单（PRD §12 风险 8 的三条限制之一）。"""

    error_code = "PROJ_GIT_NOT_ALLOWED"
    http_status = 400
    default_remediation = "公网演示模式下只允许扫描内置靶场仓库；如需扫描其它仓库请改用源码包上传"


class GitAuthFailedError(ProjectError):
    """Git 认证失败。**刻意标不可重试** —— 口令错重试一百次还是错。"""

    error_code = "PROJ_GIT_AUTH_FAILED"
    http_status = 400
    default_remediation = "检查仓库凭证（credential_ref 指向的凭据）是否有效；或改用源码包上传"
    default_retryable = False


class ArchiveFormatError(ProjectError):
    error_code = "PROJ_ARCHIVE_FORMAT"
    http_status = 400
    default_remediation = "仅支持 .zip / .tar / .tar.gz / .tgz 格式的源码包"


class ArchiveEscapeError(ProjectError):
    """归档路径穿越 / 符号链接逃逸。**安全拒绝，不是「格式不对」。**"""

    error_code = "PROJ_ARCHIVE_ESCAPE"
    http_status = 400
    default_remediation = "源码包内含越界路径（../ 或指向包外的符号链接），已拒绝解包；请重新打包"


class ArchiveBombError(ProjectError):
    """压缩炸弹：解压后体积或条目数超阈值。"""

    error_code = "PROJ_ARCHIVE_BOMB"
    http_status = 400
    default_remediation = "源码包解压后体积超出限制，请排除构建产物与依赖目录后重新打包"


class NoAnalyzableSourceError(ProjectError):
    """工作区 0 个可解析源文件。

    `http_status` 用 400 而非 500：这是**输入**的问题，不是系统的问题。
    """

    error_code = "PROJ_NO_SOURCE"
    http_status = 400
    default_remediation = (
        "未发现 .py 源文件。当前版本的污点引擎基于 tree-sitter-python，仅支持 Python 工程"
    )


class DiskFullError(AppError):
    """控制面磁盘不足。不可降级 —— 落盘失败无法假装成功。"""

    code = CODE_SOURCE_UNAVAILABLE
    http_status = 507
    error_code = "PROJ_DISK_FULL"
    default_remediation = "清理 D 盘工作区目录（WORKSPACE_ROOT）后重试"


# ---------------------------------------------------------------------------
# 并发与生命周期
# ---------------------------------------------------------------------------


class IngestLockedError(ProjectError):
    """同一项目并发 ingest。"""

    code = 4090
    error_code = "PROJ_INGEST_LOCKED"
    http_status = 409
    default_remediation = "该项目正在导入源码，请稍后重试"
    default_retryable = True


class DeleteRunningError(ProjectError):
    """删除时存在运行中的评估。"""

    code = 4091
    error_code = "PROJ_DELETE_RUNNING"
    http_status = 409
    default_remediation = "该项目下仍有运行中的评估，请先终止评估再删除项目"


class RemoteSyncFailedError(AppError):
    """同步源码到 ECS 失败。

    可重试（L4）。重试耗尽后不阻断建档 —— 由 `ensure_ready()` 在评估启动前拦截，
    这样「建档成功但暂时不能评估」是一个可表达的状态，而不是让用户重头再来。
    """

    code = CODE_SOURCE_UNAVAILABLE
    http_status = 502
    error_code = "PROJ_REMOTE_SYNC_FAILED"
    default_remediation = "检查 ECS 连通性（SSH 密钥 / 安全组）与远端磁盘剩余空间"
    default_retryable = True


# ---------------------------------------------------------------------------
# 源码读取
# ---------------------------------------------------------------------------


class SourcePathEscapeError(ProjectError):
    """`GET /projects/{id}/source` 传入穿越路径。

    **这个异常应当永远不被触发**——它一旦出现就说明有人在主动探测。
    因此除了 400 之外，调用点还要写安全告警日志（B1 设计 §6 第 15 条）。
    """

    error_code = "PROJ_SOURCE_PATH_ESCAPE"
    http_status = 400
    default_remediation = "源码路径必须是以工作区根为基准的相对路径，且不得包含 .. 或指向软链接"
