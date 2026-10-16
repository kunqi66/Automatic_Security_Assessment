"""B1 唯一对外门面 `ProjectService`（B1 模块设计 §3.1）。

调用方只有两个：L1 接口层 `api/v1/projects.py`，以及 B3 编排引擎在启动评估前
取工作区句柄。**任何子模块都不互相反向调用**，全部经这里编排。
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import BadRequestError, NotFoundError
from app.core.logging import get_logger
from app.db.redis import redis_lock
from app.models.enums import ProjectStatus
from app.models.project import Project
from app.projects import fetcher, workspace
from app.projects import sync as sync_mod
from app.projects.errors import (
    ArchiveBombError,
    DeleteRunningError,
    IngestLockedError,
    RemoteSyncFailedError,
)
from app.projects.repository import ProjectRepository
from app.projects.sync import remote_src_dir, sync_to_data_plane
from app.projects.types import (
    ArchiveUpload,
    GitSource,
    ScanRules,
    SourceManifest,
    SourceSlice,
    WorkspaceHandle,
)

logger = get_logger(__name__)


class ProjectService:
    def __init__(self, session: AsyncSession, *, rules: ScanRules | None = None) -> None:
        self.session = session
        self.repo = ProjectRepository(session)
        self.rules = rules or ScanRules()

    # ------------------------------------------------------------------
    # 建档
    # ------------------------------------------------------------------

    async def create_from_git(
        self, req: GitSource, *, name: str, description: str | None, created_by: int | None
    ) -> Project:
        fetcher.check_git_allowlist(req.url)  # 白名单在**克隆之前**校验

        project = await self.repo.create(
            name=name,
            description=description,
            source_type="git",
            source_url=req.url,
            source_branch=req.branch,
            # 只存引用，不存明文口令（PRD §6）
            credential_ref=req.credential_ref,
            status=ProjectStatus.CREATED,
            created_by=created_by,
        )
        paths = workspace.create_layout(project.id)

        async with redis_lock(f"asa:proj:{project.id}:ingest_lock") as acquired:
            if not acquired:
                raise IngestLockedError("该项目正在进行源码导入")

            try:
                await asyncio.to_thread(
                    fetcher.clone_git, req.url, paths.src_root, branch=req.branch
                )
                manifest = await asyncio.to_thread(
                    fetcher.scan_source_tree, paths.src_root, self.rules
                )
                workspace.write_manifest(project.id, manifest)
                await self._after_ingest(project, paths.src_root, manifest)
            except Exception as exc:
                await self._mark_failed(project, exc)
                raise

        return project

    async def ingest_archive(self, project: Project, upload: ArchiveUpload) -> Project:
        """解包并落盘 —— `POST /projects/{id}/upload` 的**补传**路径。

        建档（`POST /projects`，`source_type=upload`）只写一条占位记录；
        源码到这里才真正落盘。两步分开是 PRD §9 定死的接口形状。
        """
        paths = workspace.workspace_paths(project.id)
        paths.tmp_root.mkdir(parents=True, exist_ok=True)

        # `Path(...).name` 只保留末段：上传上来的 `filename` 是**客户端完全可控**的，
        # 拿它直接拼路径就等于把 `../../` 交给了对方
        staging = paths.tmp_root / Path(upload.filename).name
        workspace.ensure_free_space(upload.size_bytes + 64 * 1024 * 1024, probe=staging)

        async with redis_lock(f"asa:proj:{project.id}:ingest_lock") as acquired:
            if not acquired:
                raise IngestLockedError("该项目正在进行源码导入")
            try:
                # 落盘是**阻塞 IO**，不能直接在事件循环里跑 —— 一个 500MB 的包
                # 会把整个进程卡住几十秒，期间所有请求（含 SSE 心跳）全部停摆
                await asyncio.to_thread(_spool_to_disk, upload, staging)
                # 补传是**替换**语义：先清空 src/，否则新旧源码会混在一起，
                # 而混合后的目录树既不等于旧版本也不等于新版本
                if paths.src_root.exists():
                    shutil.rmtree(paths.src_root, ignore_errors=True)
                paths.src_root.mkdir(parents=True, exist_ok=True)

                await asyncio.to_thread(
                    fetcher.SafeExtractor(self.rules).extract, staging, paths.src_root
                )
                manifest = await asyncio.to_thread(
                    fetcher.scan_source_tree, paths.src_root, self.rules
                )
                workspace.write_manifest(project.id, manifest)
                await self._after_ingest(project, paths.src_root, manifest)
            except Exception as exc:
                await self._mark_failed(project, exc)
                raise
            finally:
                workspace.clear_tmp(project.id)  # 归档临时区，无论成败都清

        return project

    # ------------------------------------------------------------------
    # 查询与删除
    # ------------------------------------------------------------------

    async def get(self, project_id: int) -> Project:
        project = await self.repo.get(project_id)
        if project is None:
            raise NotFoundError("项目不存在", remediation="请确认项目编号，或返回列表页重新选择")
        return project

    async def list_page(
        self,
        *,
        keyword: str | None = None,
        status: ProjectStatus | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Project], int]:
        return await self.repo.list_page(
            keyword=keyword, status=status, page=page, page_size=page_size
        )

    async def delete(self, project_id: int) -> None:
        project = await self.get(project_id)

        if await self.repo.has_running_assessment(project_id):
            raise DeleteRunningError("该项目下仍有运行中的评估，无法删除")

        await self.repo.delete(project)
        await self.session.commit()  # 先落库成功，再删磁盘 —— 反过来的话删库失败就没得恢复了

        await asyncio.to_thread(workspace.remove_workspace, project_id)

    # ------------------------------------------------------------------
    # 供 F3 与 B3 使用
    # ------------------------------------------------------------------

    async def read_source(self, project_id: int, path: str, start: int, end: int) -> SourceSlice:
        await self.get(project_id)  # 先确认项目存在，否则会把「项目不存在」报成「源码文件不存在」
        return await workspace.read_source(project_id, path, start, end)

    def workspace_of(self, project_id: int) -> WorkspaceHandle:
        """**纯读**，不产生任何 I/O 副作用（B1 模块设计 §3.1）。"""
        paths = workspace.workspace_paths(project_id)
        return WorkspaceHandle(
            project_id=project_id,
            local_root=paths.root,
            src_root=paths.src_root,
            mount_host_path=remote_src_dir(project_id),
            relative_path_base="src",
        )

    async def ensure_ready(self, project_id: int) -> WorkspaceHandle:
        """评估启动前的前置检查（B3 调用）。

        与 `workspace_of()` 的区别：这个方法**会做 I/O**，且是唯一的补同步入口。
        远端副本因 ECS 重启 / LRU 清理而不在时，这里重新推一次；
        推不上去就抛出去，由 B3 拦截评估 —— 让「建档成功但暂时不能评估」
        成为一个可表达的状态，而不是让用户重头再来一遍。
        """
        project = await self.get(project_id)
        handle = self.workspace_of(project_id)

        if not handle.src_root.is_dir():
            raise BadRequestError(
                "项目源码尚未就绪",
                remediation="请先完成源码导入（Git 克隆或上传源码包）",
            )

        if not await sync_mod.remote_dir_exists(handle.mount_host_path):
            logger.info("远端副本缺失，重新同步：project=%d", project_id)
            await sync_to_data_plane(project_id, handle.src_root)
            project.status = ProjectStatus.CREATED

        return handle

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    async def _after_ingest(
        self, project: Project, src_root: Path, manifest: SourceManifest
    ) -> None:
        project.storage_path = str(project.id)
        project.total_loc = manifest.total_loc
        project.status = ProjectStatus.CREATED
        project.error_message = None
        await self.session.commit()

        # 同步失败**不让建档失败**（设计 §6 第 11 条，级别 L4）：
        # 源码已经在控制面落好了，这是有价值的结果；远端副本缺失由 ensure_ready 兜。
        try:
            await sync_to_data_plane(project.id, src_root)
        except RemoteSyncFailedError as exc:
            logger.warning(
                "项目 %d 已建档，但远端源码同步失败（将在评估启动前重试）：%s",
                project.id,
                exc.message,
            )

    async def _mark_failed(self, project: Project, exc: Exception) -> None:
        """建档失败时把**错误四要素**写进 `projects.error_message`（设计 §6 末段）。

        这样 `status=failed` 的项目在列表页就能看到失败原因与修复方向，
        而不是只有一个红点，让人去翻服务端日志。
        """
        from app.core.exceptions import AppError

        project.status = ProjectStatus.FAILED
        if isinstance(exc, AppError):
            project.error_message = f"[{exc.error_code}] {exc.message}" + (
                f"　修复建议：{exc.remediation}" if exc.remediation else ""
            )
        else:
            project.error_message = f"建档失败：{exc}"

        await self.session.commit()
        await asyncio.to_thread(workspace.remove_workspace, project.id)


def _spool_to_disk(upload: ArchiveUpload, staging: Path) -> None:
    """把上传流落成一个临时归档文件（在 worker 线程里执行）。

    分块读而不是 `shutil.copyfileobj(upload.stream, out)`：分块的大小由我们定，
    可以顺带做**实际字节数**的二次校验 —— `UploadFile.size` 来自 Content-Length，
    而那个头是可以撒谎的（声明 1MB、实发 10GB），只信它等于没设上限。
    """
    written = 0
    limit = settings.archive_max_total_bytes
    with staging.open("wb") as out:
        while chunk := upload.stream.read(1 << 20):
            written += len(chunk)
            if written > limit:
                raise ArchiveBombError(
                    f"上传体积超过上限 {limit // 1024**2} MB",
                    remediation="请排除构建产物与依赖目录后重新打包",
                )
            out.write(chunk)
