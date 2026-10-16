"""落盘与 `reports` 行：三类失败被区别对待（B6 设计 §4.2 / §5.2 / §6）。

## 这一组守的是一条容易写反的分界线

| 失败 | 后果 | 为什么不能一视同仁 |
|---|---|---|
| HTML/MD 写不进去 | 抛 `REPORT_WRITE_FAILED` | 报告是交付物；磁盘满却降级成空白报告中心，没人知道 |
| 评分回写失败 | 抛 + 整体回滚 | 报告生成了但等级是空的，比不出报告更让人困惑 |
| PDF 打不出来 | **不抛**，`degraded=True` | Chromium 缺失是环境问题，不该拖垮已经生成好的 HTML/MD |

把三条都包进 `try: ... except: pass` 是最省事的写法，也是这一组测试存在的理由。
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.assessment import Assessment
from app.models.enums import ReportFormat, ReportStatus
from app.models.report import Report
from app.report import exporter, paths, repository, service
from app.report.errors import PdfUnavailableError, ReportWriteError
from tests.llm_fakes import NoKeyCompleter
from tests.test_report_assembler import memory_session, seed


@pytest.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """与装配测试同一个内存库 —— 只是这里还叠了「报告根目录进 tmp」。"""
    async with memory_session() as sess:
        yield sess


@pytest.fixture(autouse=True)
def _isolated_report_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """把报告根目录挪进临时目录。

    **必须隔离**：默认值指向 `D:/myself_complete_code/.asa/reports`，
    测试往那儿写会污染开发机的真实报告目录，而且下一次跑就变成
    「文件已存在」—— 一个只在第二次运行时出现的失败。
    """
    root = tmp_path / "reports"
    monkeypatch.setattr(settings, "report_root", root)
    return root


async def make_draft(session: AsyncSession):
    assessment_id = await seed(session)
    from app.report.assembler import build_report

    return await build_report(assessment_id, session, client=NoKeyCompleter())


# ---------------------------------------------------------------------------
# 一、落盘：写文件 + 写行 + 回写评分，同一段代码里
# ---------------------------------------------------------------------------


async def test_落盘写出两份文件与两行(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    draft = await make_draft(db_session)
    results = await exporter.persist(db_session, draft)
    await db_session.commit()

    assert [r.format for r in results] == [ReportFormat.HTML, ReportFormat.MD]
    assert [r.content_path for r in results] == [
        "1/report.html",
        "1/report.md",
    ]

    root = _isolated_report_root
    assert (root / "1" / "report.html").is_file()
    assert (root / "1" / "report.md").is_file()
    # 原子写的临时文件不许留在盘上
    assert not list(root.rglob("*.tmp"))

    html = (root / "1" / "report.html").read_text(encoding="utf-8")
    assert html == draft.html, "落盘内容与内存中的不完全一致"
    assert draft.html.encode("utf-8").__len__() == results[0].size_bytes

    rows = await repository.list_reports(db_session, 1)
    assert [r.format for r in rows] == ["html", "md"]
    assert all(r.status == ReportStatus.READY for r in rows)
    assert rows[0].summary["total"] == 2, "摘要没写进去 —— 报告列表页会没有数据"


async def test_落盘同时回写评分且不自己提交(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    """「不 commit」是契约，不是风格。

    事务边界属于调用方（总纲 §9.3）：`report_gen` 阶段要把写报告与回写评分
    放进同一个事务。这里在 commit 之前断言两件事**都还没生效** ——
    一旦有人在 `repository` 里补了一个 `commit()`，这条会红。
    """
    draft = await make_draft(db_session)
    await exporter.persist(db_session, draft)

    # 同一事务内可见
    assessment = await db_session.get(Assessment, draft.assessment_id)
    assert assessment is not None
    assert assessment.security_score == pytest.approx(draft.data.score.score)
    assert assessment.security_grade == draft.data.score.grade

    # 回滚之后必须什么都不剩（文件是例外，见下）
    await db_session.rollback()
    count = (await db_session.execute(select(func.count()).select_from(Report))).scalar_one()
    assert count == 0
    assessment = await db_session.get(Assessment, draft.assessment_id)
    assert assessment is not None
    assert assessment.security_score is None

    # ⚠️ 已知且刻意的例外：**文件不受事务保护**。回滚后磁盘上的 HTML/MD 还在，
    # 且它与数据库行指向同一路径。这是「文件系统没有事务」的必然结果，
    # 不试图用两阶段提交去修 —— 代价远大于收益。真正的防线是
    # `reports` 行是唯一的真相来源：没有行就没有下载入口，
    # 残留文件是垃圾，不是错误数据。


async def test_同一评估同一格式只留一行(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    """`uk_report_assessment_format` 的语义在代码里也要成立。

    PDF 是惰性生成的，用户点两次「下载」就会走两次 `upsert_report`；
    没有这张唯一约束，第二次会变成两行 —— 一行指向不存在的旧文件。
    """
    draft = await make_draft(db_session)
    await exporter.persist(db_session, draft)
    await db_session.commit()

    await exporter.persist(db_session, draft)
    await db_session.commit()

    count = (await db_session.execute(select(func.count()).select_from(Report))).scalar_one()
    assert count == 2, "html / md 各一行，重复落盘不该新增"


# ---------------------------------------------------------------------------
# 二、PDF：唯一会降级的导出
# ---------------------------------------------------------------------------


async def test_PDF_不可用时降级而不是抛异常(
    db_session: AsyncSession, _isolated_report_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Chromium 没装是**环境问题**，不该让「下载 PDF」变成 500。

    用户该看到的是「本次没生成成功，原因如下，你可以先下 HTML」。
    """
    from app.report import pdf as pdf_mod

    async def boom(html: str) -> bytes:
        raise PdfUnavailableError("未安装 Playwright Chromium")

    monkeypatch.setattr(pdf_mod, "render_pdf", boom)

    result = await exporter.export_pdf(db_session, 1, "<html></html>", title="测试报告")
    await db_session.commit()

    assert result.degraded is True
    assert result.content_path is None
    assert "Chromium" in (result.message or "")

    # 行**留在表里**并标成 failed：删掉行会让报告中心显示「没有这份报告」，
    # 与「报告生成失败过」是两件事
    row = await repository.get_report(db_session, 1, ReportFormat.PDF)
    assert row is not None
    assert row.status == ReportStatus.FAILED
    assert row.content_path is None


async def test_PDF_成功时落盘并写行(
    db_session: AsyncSession, _isolated_report_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.report import pdf as pdf_mod

    async def fake(html: str) -> bytes:
        return b"%PDF-1.4 fake"

    monkeypatch.setattr(pdf_mod, "render_pdf", fake)

    result = await exporter.export_pdf(db_session, 1, "<html></html>", title="测试报告")
    await db_session.commit()

    assert result.degraded is False
    assert (_isolated_report_root / "1" / "report.pdf").read_bytes() == b"%PDF-1.4 fake"
    row = await repository.get_report(db_session, 1, ReportFormat.PDF)
    assert row is not None and row.status == ReportStatus.READY


async def test_PDF_输入的是已落盘的_HTML(
    db_session: AsyncSession, _isolated_report_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PDF 从 HTML 打，且必须是**同一份** HTML。"""
    seen: dict[str, str] = {}

    from app.report import pdf as pdf_mod

    async def fake(html: str) -> bytes:
        seen["html"] = html
        return b"%PDF"

    monkeypatch.setattr(pdf_mod, "render_pdf", fake)

    draft = await make_draft(db_session)
    await exporter.persist(db_session, draft)
    await db_session.commit()

    svc = service.ReportService(db_session, client=NoKeyCompleter())
    await svc.export(1, ReportFormat.PDF)

    assert seen["html"] == draft.html


# ---------------------------------------------------------------------------
# 三、路径逃逸：数据库里的字符串不是可信输入
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "evil",
    [
        "../secrets.html",
        "../../etc/passwd",
        "1/../../outside.html",
        "..\\..\\outside.html",
    ],
)
async def test_越出报告根目录的相对路径被拒绝(
    db_session: AsyncSession, _isolated_report_root: Path, evil: str
) -> None:
    """`content_path` 是**从数据库读回来的**。

    少了这一步校验，一个被手工改过（或由旧版本写入逻辑产生）的
    `../../../etc/passwd` 就能让「下载报告」接口变成任意文件读取 ——
    而它的表现只是「下载下来一个奇怪的文件」，不会有任何告警。
    """
    with pytest.raises(ReportWriteError) as exc:
        paths.resolve(evil)

    assert "越出报告根目录" in exc.value.message
    assert exc.value.retryable is False


async def test_逃逸路径在下载时被拦下(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    """校验必须发生在**下载路径上**，而不只是存在于 `paths.py` 里。"""
    outside = _isolated_report_root.parent / "outside.html"
    outside.write_text("绝密", encoding="utf-8")

    await repository.upsert_report(
        db_session,
        assessment_id=1,
        fmt=ReportFormat.HTML,
        title="x",
        content_path="../outside.html",
        size_bytes=4,
    )
    await db_session.commit()

    with pytest.raises(ReportWriteError):
        await exporter.read_content(db_session, 1, ReportFormat.HTML)


async def test_行不存在时读回_None_而不是报错(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    """「还没生成」与「生成失败」是两件事 —— 前者不该是错误。"""
    assert await exporter.read_content(db_session, 1, ReportFormat.HTML) is None
    assert await exporter.read_content(db_session, 999, ReportFormat.PDF) is None


async def test_文件被手工删掉时读回_None(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    """行在、文件不在（有人清过盘）—— 下载接口要能受得住。"""
    draft = await make_draft(db_session)
    await exporter.persist(db_session, draft)
    await db_session.commit()
    (_isolated_report_root / "1" / "report.html").unlink()

    assert await exporter.read_content(db_session, 1, ReportFormat.HTML) is None


# ---------------------------------------------------------------------------
# 四、门面：generate / preview / export
# ---------------------------------------------------------------------------


async def test_preview_不写任何文件(db_session: AsyncSession, _isolated_report_root: Path) -> None:
    """预览会被频繁点击。每次都落盘会让报告目录长出成堆没人看的中间产物，
    而它们与最终产物的唯一区别就是时间戳 —— 那种目录没人敢清理。"""
    await seed(db_session)
    svc = service.ReportService(db_session, client=NoKeyCompleter())
    data, html = await svc.preview(1)

    assert data.meta.assessment_id == 1
    assert "1. 项目概况与执行信息" in html
    # 测试里的同步文件 IO：文件小、次数少，为它套一层 to_thread 只会让断言更难读
    assert not _isolated_report_root.exists() or not list(  # noqa: ASYNC240
        _isolated_report_root.rglob("*")  # noqa: ASYNC240
    )


async def test_preview_支持_md_格式_与_html_同源(db_session: AsyncSession) -> None:
    """F5 的预览面板有「文档视图 / Markdown 视图」两档，两个都要能直接拿。

    断言两件事：① `fmt="md"` 回的是 Markdown 正文而不是 HTML；
    ② 两者来自**同一次装配** —— 漏洞条数这类数字必须一致，否则同一屏里
    切个视图就变数，报告的可信度就没了。
    """
    await seed(db_session)
    svc = service.ReportService(db_session, client=NoKeyCompleter())
    data_md, md = await svc.preview(1, "md")
    data_html, html = await svc.preview(1)

    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert not md.lstrip().startswith("<!DOCTYPE html>")
    assert "1. 项目概况与执行信息" in md
    assert len(data_md.vulnerabilities) == len(data_html.vulnerabilities)


async def test_从未生成过时_export_就地补生成(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    """「报告还没生成」与「报告生成失败」对用户是两件事。

    下载接口在这两种情况下都回 404 是最省事的写法，也是最没用的 ——
    用户点下载，得到的是「报告不存在」，而他明明刚看过预览。
    """
    await seed(db_session)
    svc = service.ReportService(db_session, client=NoKeyCompleter())
    result = await svc.export(1, ReportFormat.MD)

    assert result.degraded is False
    assert result.content_path == "1/report.md"
    assert "未生成，本次已补生成" in (result.message or "")
    assert (_isolated_report_root / "1" / "report.md").is_file()


async def test_已生成过时_export_直接读行(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    await seed(db_session)
    svc = service.ReportService(db_session, client=NoKeyCompleter())
    await svc.generate(1)
    result = await svc.export(1, ReportFormat.HTML)

    assert (result.message or "") == ""
    assert result.content_path == "1/report.html"
    assert result.size_bytes and result.size_bytes > 0


async def test_generate_后能按格式读回内容(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    await seed(db_session)
    svc = service.ReportService(db_session, client=NoKeyCompleter())
    draft = await svc.generate(1)

    html = await svc.read(1, ReportFormat.HTML)
    markdown = await svc.read(1, ReportFormat.MD)

    assert html is not None and html.decode("utf-8") == draft.html
    assert markdown is not None and markdown.decode("utf-8") == draft.markdown


async def test_generate_幂等_重复生成得到同一份内容(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    await seed(db_session)
    svc = service.ReportService(db_session, client=NoKeyCompleter())
    await svc.generate(1)
    first = await svc.read(1, ReportFormat.HTML)
    await svc.generate(1)
    second = await svc.read(1, ReportFormat.HTML)

    # 正文里只有「生成时间」会变。抹掉它之后必须**逐字相同** ——
    # 「差不多一样」不是可复现，它只说明这次没撞上随机性
    assert first is not None and second is not None
    stamp = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
    first_text = stamp.sub("<TIME>", first.decode("utf-8"))
    second_text = stamp.sub("<TIME>", second.decode("utf-8"))
    assert first_text == second_text


async def test_落盘后报告目录结构符合约定(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    draft = await make_draft(db_session)
    await exporter.persist(db_session, draft)
    await db_session.commit()

    files = sorted(
        p.relative_to(_isolated_report_root).as_posix()
        for p in _isolated_report_root.rglob("*")  # noqa: ASYNC240 —— 见上
        if p.is_file()
    )
    assert files == ["1/report.html", "1/report.md"]


# ---------------------------------------------------------------------------
# `commit=False` —— 编排层（`report_gen` Agent）走的就是这条路
# ---------------------------------------------------------------------------


async def test_generate_commit_false_不提交但同一事务内可见(
    db_session: AsyncSession, _isolated_report_root: Path
) -> None:
    """**这一条钉的是 T4：阶段边界才是唯一的原子提交点。**

    `report_gen` Agent 调的就是 `generate(assessment_id, commit=False)`，
    好让「落盘 + `reports` 行 + 评分两列 + 阶段行」在引擎那一层一次提交。
    如果这个参数被静默忽略（比如实现里顺手写了个 `await session.commit()`），
    **没有任何现有测试会红** —— 报告的落盘会脱离阶段事务，
    崩溃后留下「文件在、阶段行不在」的中间态，而报告已经在磁盘上了。

    断言分两半，缺一不可：
    ① 同一 session 内数据**可见**（说明真的写进去了，不是跳过了写库）；
    ② 换一个 session 从库里查**查不到**（说明没提交）。

    只测②会因为「压根没写」而假绿 —— 那是个更糟的实现。
    """
    from app.db.session import AsyncSessionLocal  # noqa: F401  —— 见下方说明

    await seed(db_session)
    svc = service.ReportService(db_session, client=NoKeyCompleter())

    draft = await svc.generate(1, commit=False)

    # ① 同事务内可见
    row = await db_session.scalar(
        select(Report).where(Report.assessment_id == 1, Report.format == ReportFormat.HTML)
    )
    assert row is not None, "未提交也要在**本事务内**读得到"
    assert row.status is ReportStatus.READY

    # ② 未提交 —— 用同一个连接开一个「新事务」看不到它。
    #
    # 这里**不能**另开一个 AsyncSessionLocal：内存 SQLite 每个连接是**独立**的
    # 数据库，第二个会话连的是另一个空库，必然查不到 —— 那样②会在
    # 「根本没写」时也通过，等于没测。
    # 正确做法是 `rollback()` 后重查：回滚会丢掉未提交的写，
    # 若之前 commit 过，rollback 不会撤销它，于是这一查仍能查到。
    ...
    await db_session.rollback()

    after = await db_session.scalar(
        select(Report).where(Report.assessment_id == 1, Report.format == ReportFormat.HTML)
    )
    assert after is None, (
        "`generate(commit=False)` 提交了 —— 阶段边界的事务边界被破坏（T4）。"
        "报告文件此时已在磁盘上，而库里没有对应的行。"
    )

    # 落盘是**不随事务回滚**的（文件系统没有事务），所以这里反过来确认：
    # 文件确实写了。这正是「必须由引擎统一提交」的代价所在 ——
    # 一旦在提交前崩溃，磁盘上会留一份没有库记录的孤儿报告。
    assert (_isolated_report_root / "1" / "report.html").is_file()
    assert draft.html
