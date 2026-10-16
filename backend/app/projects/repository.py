"""B1-6 项目仓储：`projects` 表读写。

**不在这里 commit**。提交点是阶段边界（总纲 §9.3），由 service 决定 ——
仓储层自己 commit 会让「建档失败时清理工作区」和「落库」变成两个不可回滚的独立动作，
一旦第二步失败，就留下一个 status=failed 但工作区已删的项目。
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.assessment import Assessment
from app.models.enums import AssessmentStatus, ProjectStatus
from app.models.project import Project


class ProjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, project_id: int) -> Project | None:
        return await self.session.get(Project, project_id)

    async def create(self, **fields: object) -> Project:
        project = Project(**fields)
        self.session.add(project)
        # flush 而不是 commit：拿到自增 id 以便建工作区目录，
        # 但事务仍开着，后续步骤失败可以整体回滚
        await self.session.flush()
        return project

    async def list_page(
        self,
        *,
        keyword: str | None = None,
        status: ProjectStatus | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Project], int]:
        """分页查询。

        返回 `(rows, total)`：`total` 必须是**过滤后**的总数而不是当前页长度，
        否则前端分页器只会显示一页。
        """
        conditions = []
        if keyword:
            # 参数化 LIKE：`%` 由驱动绑定，不拼进 SQL（安全红线 8）
            conditions.append(Project.name.ilike(f"%{keyword}%"))
        if status is not None:
            conditions.append(Project.status == status)

        count_stmt = select(func.count()).select_from(Project)
        rows_stmt = select(Project).order_by(Project.id.desc())
        for cond in conditions:
            count_stmt = count_stmt.where(cond)
            rows_stmt = rows_stmt.where(cond)

        total = (await self.session.execute(count_stmt)).scalar_one()
        rows = (
            (await self.session.execute(rows_stmt.offset((page - 1) * page_size).limit(page_size)))
            .scalars()
            .all()
        )
        return list(rows), total

    async def has_running_assessment(self, project_id: int) -> bool:
        """删除前检查（B1 设计 §6 第 13 条）。

        只查 `running`：`created` 状态的评估还没开始跑，删掉它不会留下
        一个「正写到一半」的工作区。
        """
        stmt = (
            select(func.count())
            .select_from(Assessment)
            .where(
                Assessment.project_id == project_id,
                Assessment.status == AssessmentStatus.RUNNING,
            )
        )
        return (await self.session.execute(stmt)).scalar_one() > 0

    async def delete(self, project: Project) -> None:
        # ORM 关系上已配 cascade="all, delete-orphan"，删项目会连带删评估与漏洞
        await self.session.delete(project)
