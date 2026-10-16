"""`ReportService` —— B6 的应用服务门面（B6 设计 §3.1 的三个接口）。

```
generate(assessment_id)          → 装配 + 渲染 + 落盘 + 写库（一个事务）
preview(assessment_id)           → 只装配，不落盘（给「报告预览」用）
export(assessment_id, format)    → 单格式导出 / 读取（PDF 在这里惰性生成）
```

## 与契约 4 的关系

契约 4 规定的是 `report.build_report(assessment_id, session) -> ReportDraft`，
它对应下面的 `build_report`（装配 + 渲染，**不落盘**）。`ReportService.generate`
是在它之上加了持久化的一层。

分成两层而不是合成一个，是因为**事务边界属于调用方**（总纲 §9.3）：
`report_gen` 阶段要把「写报告」与「回写评分」放进同一个事务，
而 API 层的「重新生成报告」只需要一次独立提交。
两种用法对事务的要求不同，硬合成一个就只能照顾其中一种。

## ⚠️ 本模块不 import FastAPI

分层法要求 `app/report/` 与 `app/llm/` 都是纯粹的业务层。
`ReportService` 直接吃一个 `AsyncSession`，由 API 层在依赖注入里构造它 ——
反过来（服务里 import `Request`）会让这个包再也无法在 worker 里用。
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.llm.types import TextCompleter
from app.models.enums import ReportFormat
from app.report import assembler, exporter, paths, repository
from app.report.errors import ReportWriteError
from app.report.types import ExportResult, ReportData, ReportDraft

logger = get_logger(__name__)


class ReportService:
    """报告生成与导出的门面。**无状态**，每次请求构造一个即可（只持 session）。"""

    def __init__(self, session: AsyncSession, *, client: TextCompleter | None = None) -> None:
        self._session = session
        # 注入点保留在构造器上：测试传假客户端，生产传 None 走默认客户端
        self._client = client

    # ------------------------------------------------------------------
    # 契约 4 的入口（装配 + 渲染，不落盘）
    # ------------------------------------------------------------------

    async def build(self, assessment_id: int) -> ReportDraft:
        return await assembler.build_report(assessment_id, self._session, client=self._client)

    # ------------------------------------------------------------------
    # generate：装配 → 渲染 → 落盘 → 写库
    # ------------------------------------------------------------------

    async def generate(self, assessment_id: int, *, commit: bool = True) -> ReportDraft:
        """生成并持久化 HTML + Markdown。

        `commit=False` 给编排层用（`report_gen` 阶段要和阶段行一起提交）；
        默认 `True` 给「手动重新生成报告」这类独立操作。

        **PDF 不在这里生成**（见 `pdf.py` 的三条设计）。
        """
        draft = await self.build(assessment_id)
        await exporter.persist(self._session, draft)
        if commit:
            await self._session.commit()
        return draft

    # ------------------------------------------------------------------
    # preview：只装配，不落盘
    # ------------------------------------------------------------------

    async def preview(
        self, assessment_id: int, fmt: ReportFormat | str = ReportFormat.HTML
    ) -> tuple[ReportData, str]:
        """返回 `(ReportData, 该格式的正文)`，`fmt` 取 `html` / `md`。

        给前端 iframe（`html`）与 Markdown 视图（`md`）用（B6 设计 §3.1 preview，
        端点 `GET /assessments/{id}/report?format=html|md`）—— 预览**不写任何文件**：
        预览会被频繁点击，每次都落盘会让报告目录长出成堆没人看的中间产物，
        而它们与最终产物的唯一区别就是时间戳。

        `fmt` 是必须的：F5 的预览面板有「文档视图 / Markdown 视图」两档，
        只回 HTML 就逼着上层自己再渲染一次 Markdown —— 那等于把
        「一套数据三格式」这个不变量复制到第二处，迟早会有一份漏改。

        返回元组而不是单个字符串：TOC（F5 §8 T2）要的是 `ReportData` 里的结构，
        另开一个只回正文的接口会让同一次预览装配两遍。
        """
        draft = await self.build(assessment_id)
        value = str(getattr(fmt, "value", fmt))
        if value == ReportFormat.MD.value:
            return draft.data, draft.markdown
        return draft.data, draft.html

    # ------------------------------------------------------------------
    # export：单格式
    # ------------------------------------------------------------------

    async def export(
        self, assessment_id: int, fmt: ReportFormat | str, *, commit: bool = True
    ) -> ExportResult:
        """导出单个格式。

        * HTML / MD 已在 `generate` 时落盘 → 直接读回 `reports` 行；
          行不存在时（例如从未生成过）**就地补生成一次**，而不是回 404 ——
          「报告还没生成」与「报告生成失败」对用户是两件事，前者不该报错。
        * PDF → 惰性生成（首次下载时）。生成失败返回 `degraded=True`，不抛。
        """
        value = str(getattr(fmt, "value", fmt))

        if value == ReportFormat.PDF.value:
            result = await self._export_pdf(assessment_id)
            if commit:
                await self._session.commit()
            return result

        row = await repository.get_report(self._session, assessment_id, value)
        if row is None or not row.content_path:
            draft = await self.generate(assessment_id, commit=commit)
            size = len(draft.html if value == ReportFormat.HTML.value else draft.markdown)
            return ExportResult(
                assessment_id=assessment_id,
                format=ReportFormat(value),
                content_path=paths.relative_path(assessment_id, value),
                size_bytes=size,
                degraded=False,
                message="该格式此前未生成，本次已补生成",
            )

        return ExportResult(
            assessment_id=assessment_id,
            format=ReportFormat(value),
            content_path=row.content_path,
            size_bytes=row.size_bytes,
            degraded=False,
        )

    async def read(self, assessment_id: int, fmt: ReportFormat | str) -> bytes | None:
        """按格式读回产物字节（下载接口用）。不存在时返回 None。"""
        return await exporter.read_content(self._session, assessment_id, fmt)

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    async def _export_pdf(self, assessment_id: int) -> ExportResult:
        row = await repository.get_report(self._session, assessment_id, ReportFormat.PDF)
        if row is not None and row.content_path:
            return ExportResult(
                assessment_id=assessment_id,
                format=ReportFormat.PDF,
                content_path=row.content_path,
                size_bytes=row.size_bytes,
            )

        # PDF 从 HTML 打。HTML 文件缺失时先补生成，再由 `export_pdf` 打 ——
        # 「先确保 HTML 存在」是 PDF 的前置条件，不是可选项。
        try:
            html = (
                await exporter.read_content(self._session, assessment_id, ReportFormat.HTML) or b""
            ).decode("utf-8")
        except ReportWriteError:
            html = ""
        if not html:
            draft = await self.generate(assessment_id, commit=False)
            html = draft.html

        title = f"评估 #{assessment_id} 报告"
        return await exporter.export_pdf(self._session, assessment_id, html, title=title)


__all__ = ["ReportService", "assembler", "exporter"]
