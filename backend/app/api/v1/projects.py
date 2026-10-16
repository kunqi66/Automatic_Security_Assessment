"""B1 接口层（L1）。

**只做三件事**：注入权限、校验入参、转发给 `ProjectService`。
这里不写业务逻辑，也不直接碰文件系统 —— 路径穿越校验在 `projects/workspace.py` 里。
放在这一层的后果是：安全边界要靠「每个写路由的人都记得调一下」来维持，
而下一个加路由的人不会知道这件事。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile, status

from app.api.deps import DBSession, Permission, require
from app.core.config import settings
from app.core.exceptions import BadRequestError
from app.db.audit import record
from app.models.enums import ProjectStatus
from app.models.user import User
from app.projects.errors import SourcePathEscapeError
from app.projects.service import ProjectService
from app.projects.types import ArchiveUpload, GitSource
from app.projects.workspace import normalize_rel_path
from app.schemas.common import Page
from app.schemas.project import ProjectCreate, ProjectOut, SourceSnippet

router = APIRouter(prefix="/projects", tags=["项目管理"])

#: 建档 / 补传 / 删除共用 `assessment:create`。
#:
#: 需求 2.5.2 只写了安全工程师「创建评估任务」，没有单列建档与删除项目的权限。
#: 建档是创建评估任务的前置步骤，删除是对同一资源的反向操作，因此归到同一权限点。
#: **这是需求的一处空缺，按最小授权原则归并，而不是发明一个需求里没有对应职责的
#: 新权限点** —— 后者会让权限表出现无人负责的条目。
ProjectViewer = Annotated[User, Depends(require(Permission.PROJECT_VIEW))]
ProjectManager = Annotated[User, Depends(require(Permission.ASSESSMENT_CREATE))]


@router.get("", response_model=Page[ProjectOut], summary="项目列表")
async def list_projects(
    session: DBSession,
    _viewer: ProjectViewer,
    keyword: Annotated[str | None, Query(max_length=128)] = None,
    project_status: Annotated[ProjectStatus | None, Query(alias="status")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Page[ProjectOut]:
    rows, total = await ProjectService(session).list_page(
        keyword=keyword, status=project_status, page=page, page_size=page_size
    )
    return Page[ProjectOut](
        items=[ProjectOut.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "",
    response_model=ProjectOut,
    status_code=status.HTTP_201_CREATED,
    summary="建档（Git 或上传入口）",
)
async def create_project(
    payload: ProjectCreate,
    session: DBSession,
    user: ProjectManager,
    request: Request,
) -> ProjectOut:
    """`POST /projects` = **建档**；`POST /projects/{id}/upload` = **补传**。

    这两个动作的分界是 PRD §9 定死的：
    - `source_type=git` → 这里同步完成克隆与扫描，返回时项目已可用；
    - `source_type=upload` → 这里**只写一条占位记录**，源码随后补传。
      拆两步是因为 HTTP 请求里同时传 JSON 元数据和一个大文件包很别扭，
      而且上传中断时不该丢掉已经填好的项目信息。
    """
    service = ProjectService(session)

    if payload.source_type == "git":
        # ProjectCreate 的校验器已保证 git 分支必有 source_url；
        # 这里断言是为了让类型收窄，不是二次校验
        assert payload.source_url is not None
        project = await service.create_from_git(
            GitSource(url=payload.source_url, branch=payload.source_branch),
            name=payload.name,
            description=payload.description,
            created_by=user.id,
        )
    else:
        project = await service.repo.create(
            name=payload.name,
            description=payload.description,
            source_type="upload",
            status=ProjectStatus.CREATED,
            created_by=user.id,
        )

    record(
        session,
        user=user,
        action="project.create",
        target_type="project",
        target_id=project.id,
        detail={"source_type": payload.source_type, "name": payload.name},
        request=request,
    )
    await session.commit()
    return ProjectOut.model_validate(project)


@router.get("/{project_id}", response_model=ProjectOut, summary="项目详情")
async def get_project(project_id: int, session: DBSession, _viewer: ProjectViewer) -> ProjectOut:
    return ProjectOut.model_validate(await ProjectService(session).get(project_id))


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, summary="删除项目")
async def delete_project(
    project_id: int,
    session: DBSession,
    user: ProjectManager,
    request: Request,
) -> None:
    """删除项目及其全部关联数据（评估、漏洞、报告）。

    `service.delete()` 内部会先查有没有 `running` 的评估，避免删掉一个
    正在被写入的工作区。审计记录写在**删除之后**——因为要记下被删对象的名称，
    而那个名称随行一起没了。
    """
    service = ProjectService(session)
    project = await service.get(project_id)
    name = project.name

    await service.delete(project_id)

    record(
        session,
        user=user,
        action="project.delete",
        target_type="project",
        target_id=project_id,
        detail={"name": name},
        request=request,
    )
    await session.commit()


@router.post("/{project_id}/upload", response_model=ProjectOut, summary="补传源码包")
async def upload_archive(
    project_id: int,
    session: DBSession,
    user: ProjectManager,
    request: Request,
    file: Annotated[UploadFile, File(description="源码包（.zip / .tar / .tar.gz）")],
) -> ProjectOut:
    """**补传**源码包。

    `file` 走 multipart，字段名必须是 `file`（前端 `FormData` 已经这么拼了）。
    ⚠️ 归档格式**按魔数判定，不看扩展名** —— 扩展名是客户端随手可改的，
    而按扩展名选解包器会在格式不符时报出一个与真实原因无关的错误。
    """
    declared = file.size or 0
    if declared > settings.archive_max_total_bytes:
        raise BadRequestError(
            f"上传文件过大（{declared / 1024**2:.1f} MB），"
            f"超出上限 {settings.archive_max_total_bytes // 1024**2} MB",
            remediation="请排除构建产物与依赖目录后重新打包",
        )

    service = ProjectService(session)
    project = await service.get(project_id)
    await service.ingest_archive(
        project,
        # 注意 `declared` 只用于**提前拒绝**，真正的上限在 ProjectService
        # 边读边数的字节数上 —— Content-Length 是客户端可撒谎的
        ArchiveUpload(
            filename=file.filename or "upload.zip", size_bytes=declared, stream=file.file
        ),
    )

    record(
        session,
        user=user,
        action="project.upload",
        target_type="project",
        target_id=project_id,
        detail={"filename": file.filename, "size_bytes": declared},
        request=request,
    )
    await session.commit()
    return ProjectOut.model_validate(project)


@router.get("/{project_id}/source", response_model=SourceSnippet, summary="读取源码片段")
async def read_source(
    project_id: int,
    session: DBSession,
    _viewer: ProjectViewer,
    path: Annotated[str, Query(description="工作区根相对 POSIX 路径")],
    start: Annotated[int, Query(ge=1)] = 1,
    end: Annotated[int, Query(ge=1)] = 50,
) -> SourceSnippet:
    """服务 F3 漏洞视窗的源码高亮。

    `path` 是**用户可控输入**。这里先做一次 `normalize_rel_path`，
    让格式非法（含 `..`、绝对路径、NUL）的请求在这一层就拿到 400，
    而不是落到 `read_source` 里变成一个笼统的「文件不存在」。

    ⚠️ **这只是提前失败，不是安全边界**。真正的边界是 `workspace.safe_join()`
    的两道独立检查（逐段查符号链接 + realpath 落界）—— 规范化过的路径
    仍然可能指向一个指向根外的符号链接。
    """
    try:
        safe_path = normalize_rel_path(path)
    except SourcePathEscapeError as exc:
        raise BadRequestError(f"非法的源码路径：{exc.message}", detail=exc.detail) from exc

    if end < start:
        raise BadRequestError("end 不能小于 start")

    slice_ = await ProjectService(session).read_source(project_id, safe_path, start, end)
    return SourceSnippet(
        path=slice_.rel_path,
        start=slice_.start,
        end=slice_.end,
        content=slice_.content,
    )
