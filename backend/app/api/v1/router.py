"""v1 路由聚合。

**新增模块时在这里挂一行**。挂漏的症状是这一组接口全部 404，
而路由文件本身看起来完全正常 —— 排查时容易盯着 handler 看半天。

验证方式用 `app.openapi()["paths"]`，**不要数 `app.routes`**：
Starlette 1.7 起 `include_router` 不再把子路由摊平进去，而是包成
`_IncludedRouter`，数出来的结果会漏报，看起来像是没挂上。
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    admin,
    assessments,
    audit,
    auth,
    chains,
    dashboard,
    health,
    projects,
    reports,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(projects.router)

# `assessments` 的 router **没有 prefix**：它同时承载 `/assessments/*`
# 与 `/projects/{id}/assessments`（PRD §8 把「创建评估」挂在项目下）。
# 给它加前缀就得把创建接口拆到 projects.py 里去，那样「评估的生命周期」
# 就散在两个文件里了。
api_router.include_router(assessments.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(chains.router)
api_router.include_router(reports.router)
api_router.include_router(dashboard.router)
api_router.include_router(admin.router)
api_router.include_router(audit.router)
