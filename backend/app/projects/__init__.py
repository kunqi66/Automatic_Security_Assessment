"""B1 项目管理模块（L3 领域引擎层）。

职责：Git 克隆 / 压缩包解包 / 目录只读挂载准备 / 元数据解析 / 源码落盘。
对外唯一门面是 `service.ProjectService`。

**边界**：本模块不 import `agents/`、`sandbox/`、`analysis/`（总纲 §3.4 禁止反向依赖）；
技术栈识别不在这里，属 ReconAgent，B1 只建 `projects.tech_stack` 列不填值。

**刻意不做 re-export**：`from app.projects import ProjectService` 这种写法看着方便，
但它让包导入与子模块导入顺序绑定，容易出现「导入 `app.projects.types` 却触发了
整个 service 及其数据库依赖」的环形导入。调用方请写 `from app.projects.service import ...`。
"""
