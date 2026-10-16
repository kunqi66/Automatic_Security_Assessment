"""B6 专用异常（B6 模块设计 §6，`stage` 恒为 `report_gen`）。

错误码取值来自 B6 设计 §6：`REPORT_SNAPSHOT_FAILED` / `REPORT_WRITE_FAILED` /
`PDF_CHROMIUM_MISSING` / `PDF_RENDER_TIMEOUT` / `REPORT_GRADE_WRITEBACK_FAILED`。

## ⚠️ 一个集成缺口（需要上游补一行）

`core/exceptions.py` 的 `ErrorCode` 是一个**封闭的 `Literal`**，目前只登记了
`INTERNAL` / `DEPENDENCY_DOWN` / B1 的 `PROJ_*`。上面这几个 `REPORT_*` / `PDF_*`
**尚未登记**，所以这里的赋值在静态类型检查下会被判为越界（运行期无影响）。

不登记它们是刻意的选择吗？不是 —— 而是 `core/exceptions.py` 不在本模块的改动边界内
（并行开发时改共享文件会与其它模块的改动冲突）。**这份清单已写进交付报告，
需要上游在 `ErrorCode` 里补 4 个取值**。在那之前，这些错误码会以原样字符串出现在
错误载荷里（前端能正常显示，只是类型系统少了一道保护）。
"""

from __future__ import annotations

from app.core.exceptions import CODE_DEPENDENCY_DOWN, CODE_INTERNAL, AppError

#: 阶段名恒定 —— 本模块的所有错误都发生在 `report_gen`
STAGE = "report_gen"


class ReportError(AppError):
    """B6 异常基类。"""

    code = CODE_INTERNAL
    http_status = 500
    error_code = "INTERNAL"  # type: ignore[assignment]  # 见模块文档的 ErrorCode 缺口

    def __init__(self, message: str, **kwargs: object) -> None:
        kwargs.setdefault("stage", STAGE)
        super().__init__(message, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 不可降级（L5）：存储类依赖与产物交付
# ---------------------------------------------------------------------------


class ReportSnapshotError(ReportError):
    """快照查询失败 / 关键数据缺失（`projects` / `assessments` 取不到）。

    **不可降级**：没有快照就没有报告，硬造一份「部分数据」的报告等于交付一份
    看起来完整、实际错漏的结论 —— 那比不出报告糟得多（总纲 §8.2 存储类不可降级）。
    """

    code = CODE_DEPENDENCY_DOWN
    http_status = 503
    error_code = "REPORT_SNAPSHOT_FAILED"  # type: ignore[assignment]
    default_remediation = "检查 MySQL 连通性；确认该 assessment_id 存在且其项目未被删除"
    default_retryable = True


class ReportWriteError(ReportError):
    """报告落盘失败（磁盘满 / 权限）。**不可降级** —— 产物交付不了就是交付不了。"""

    error_code = "REPORT_WRITE_FAILED"  # type: ignore[assignment]
    default_remediation = "检查 REPORT_ROOT 所在磁盘剩余空间与目录写权限"
    default_retryable = True


class GradeWritebackError(ReportError):
    """回写 `assessments.security_score` / `security_grade` 失败。

    与 `reports` 写入同处一个事务（B6 设计 §5.2），因此这里抛出的后果是
    **整体回滚**，不留「报告已生成但评分未落库」的半成品。
    """

    error_code = "REPORT_GRADE_WRITEBACK_FAILED"  # type: ignore[assignment]
    default_remediation = "确认 assessments 表可写；该错误会随事务一并回滚，可整体重试"
    default_retryable = True


# ---------------------------------------------------------------------------
# 可降级（L3）：只丢 PDF
# ---------------------------------------------------------------------------


class PdfUnavailableError(ReportError):
    """Playwright 未安装 Chromium。

    **这不是失败，是降级**：HTML + Markdown 照常交付，`degraded += ["pdf"]`。
    PDF 之所以是可选依赖，是因为它被刻意移出了 `report_gen` 的关键路径
    （B6 设计 §7.4 PDF 惰性生成）。
    """

    http_status = 503
    error_code = "PDF_CHROMIUM_MISSING"  # type: ignore[assignment]
    default_remediation = (
        "运行 `playwright install chromium` 安装浏览器；"
        "开发机需设 PLAYWRIGHT_BROWSERS_PATH 指向非 C 盘目录（C 盘空间紧张）"
    )
    default_retryable = False


class PdfRenderTimeoutError(ReportError):
    """`page.pdf()` 超过 20s。超时后关 page 重试 1 次，仍失败则按 L3 跳过 PDF。"""

    http_status = 503
    error_code = "PDF_RENDER_TIMEOUT"  # type: ignore[assignment]
    default_remediation = "确认机器没有同时跑多个 Chromium 实例；可减少报告中的图表数量后重试"
    default_retryable = True


__all__ = [
    "STAGE",
    "GradeWritebackError",
    "PdfRenderTimeoutError",
    "PdfUnavailableError",
    "ReportError",
    "ReportSnapshotError",
    "ReportWriteError",
]
