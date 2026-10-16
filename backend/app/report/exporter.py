"""产物落盘与 `reports` 行写入（B6 设计 §4.2 exporter）。

## 三种格式的**不可降级程度**是递增的

| 格式 | 依赖 | 失败后果 |
|---|---|---|
| Markdown | 纯文本写文件（L5） | 报 `REPORT_WRITE_FAILED` |
| HTML | 同上（L5） | 同上 |
| PDF | Chromium（L3） | **降级**：不提供 PDF，另两份照常 |

把这张表放在模块头上，是因为它决定了每个函数里 `try` 的范围 ——
PDF 那一段包着 `try`，HTML/Markdown 那一段**不包**。给所有导出都加一层
「失败就跳过」的 try，等于把「报告丢了」也降级成「少个格式」，
而那时用户只会看到一个空白的报告中心，不会知道磁盘满了。

## 原子写

先写 `.tmp` 再 `replace`。报告文件是**可能被并发读取**的（用户在生成过程中
点了预览），直接覆盖会读到半截文件 —— 截断的 HTML 在浏览器里能渲染，
只是少了后半章，这种错误没有任何提示。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.enums import ReportFormat, ReportStatus
from app.report import paths, repository
from app.report.errors import PdfRenderTimeoutError, PdfUnavailableError, ReportWriteError
from app.report.types import ExportResult, ReportDraft

logger = get_logger(__name__)


async def persist(
    session: AsyncSession,
    draft: ReportDraft,
    *,
    formats: tuple[ReportFormat, ...] = (ReportFormat.HTML, ReportFormat.MD),
) -> list[ExportResult]:
    """把 HTML / Markdown 落盘 + 写 `reports` 行 + 回写评分（**不 commit**）。

    三件事在同一段代码里、同一个事务里 —— 调用方一次 commit 让它们一起生效。
    这是 B6 设计 §5.2「报告与评分同事务」的直接实现。
    """
    paths.ensure_dir(draft.assessment_id)
    title = f"{draft.data.meta.project_name} 安全评估报告"
    results: list[ExportResult] = []

    for fmt in formats:
        content = draft.html if fmt == ReportFormat.HTML else draft.markdown
        result = await _write_one(draft.assessment_id, fmt, content, title)
        results.append(result)
        await repository.upsert_report(
            session,
            assessment_id=draft.assessment_id,
            fmt=fmt,
            title=title,
            content_path=result.content_path,
            size_bytes=result.size_bytes,
            summary=draft.summary.model_dump(mode="json"),
            status=ReportStatus.READY,
        )

    await repository.writeback_score(session, draft.assessment_id, draft.data.score)
    logger.info(
        "报告已落盘：assessment=#%s 格式 %s",
        draft.assessment_id,
        [r.format.value for r in results],
    )
    return results


async def export_pdf(
    session: AsyncSession, assessment_id: int, html: str, *, title: str = ""
) -> ExportResult:
    """惰性生成 PDF。**唯一会降级的导出**（L3）。

    Chromium 缺失 / 打印超时时返回 `ExportResult(degraded=True)` 并把
    `reports` 行标成 `failed`，**不抛异常** —— 用户点了「下载 PDF」，
    该看到的是「本次没生成成功，原因如下，你可以先下 HTML」，
    而不是一个 500。
    """
    from app.report import pdf as pdf_mod

    try:
        data = await pdf_mod.render_pdf(html)
    except (PdfUnavailableError, PdfRenderTimeoutError) as exc:
        await repository.mark_failed(
            session, assessment_id=assessment_id, fmt=ReportFormat.PDF, title=title
        )
        logger.info("PDF 导出降级：%s", exc.message)
        return ExportResult(
            assessment_id=assessment_id,
            format=ReportFormat.PDF,
            content_path=None,
            degraded=True,
            message=exc.message,
        )

    result = await _write_one(assessment_id, ReportFormat.PDF, data, title, binary=True)
    await repository.upsert_report(
        session,
        assessment_id=assessment_id,
        fmt=ReportFormat.PDF,
        title=title,
        content_path=result.content_path,
        size_bytes=result.size_bytes,
        status=ReportStatus.READY,
    )
    return result


async def read_content(
    session: AsyncSession, assessment_id: int, fmt: ReportFormat | str
) -> bytes | None:
    """按 `reports` 行读回产物内容（下载接口用）。

    路径经 `paths.resolve()` 归一化并校验未越出报告根目录（见 `paths.py` 的
    「路径逃逸」一段）—— **数据库里的字符串不是可信输入**。
    """
    row = await repository.get_report(session, assessment_id, fmt)
    if row is None or not row.content_path:
        return None
    stage_dir = Path(paths.resolve(row.content_path))
    if not await asyncio.to_thread(stage_dir.exists):
        return None
    return await asyncio.to_thread(stage_dir.read_bytes)


# ---------------------------------------------------------------------------
# 内部
# ---------------------------------------------------------------------------


async def _write_one(
    assessment_id: int,
    fmt: ReportFormat,
    content: str | bytes,
    title: str,
    *,
    binary: bool = False,
) -> ExportResult:
    target = paths.absolute_path(assessment_id, fmt)
    payload = content if isinstance(content, bytes) else content.encode("utf-8")
    await _write_atomic(target, payload)
    return ExportResult(
        assessment_id=assessment_id,
        format=fmt,
        content_path=paths.relative_path(assessment_id, fmt),
        size_bytes=len(payload),
        degraded=False,
    )


async def _write_atomic(target: Path, payload: bytes) -> None:
    """`.tmp` + `replace`。

    `Path.replace` 在同分区上是原子的（POSIX `rename` / Windows `MoveFileEx`）。
    报告目录与临时文件同目录，因此不会跨分区 —— 跨分区的 `replace` 会退化成
    「复制 + 删除」，那就不再是原子的了。
    """
    tmp = target.with_suffix(target.suffix + ".tmp")

    def _do() -> None:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(payload)
            tmp.replace(target)
        except OSError as exc:
            raise ReportWriteError(
                f"报告写入失败：{target}",
                detail={"path": str(target), "reason": str(exc)},
            ) from exc

    await asyncio.to_thread(_do)
