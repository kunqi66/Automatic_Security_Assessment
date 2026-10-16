"""`recon` 阶段：技术栈识别（B1 设计 §1.2 的划界、B3 设计 §4.1）。

## 这个 Agent 为什么不需要 LLM

技术栈识别是**从依赖清单里读出框架名**。这是一件有唯一正确答案的事：
`requirements.txt` 里有 `fastapi==0.115` 就是 FastAPI 项目，没有第二种读法。

让 LLM 来「判断这是什么项目」会引入一个无法验证的结论 ——
而 `projects.tech_stack` 是**下游一切决策的输入**：它决定了 B4 加载哪套
source/sink 规则、沙箱用哪个基础镜像、报告里写什么。一个猜错的框架名
不会报错，只会让整轮分析的规则集悄悄错配。

**确定性识别的代价是覆盖率**：遇到没见过的依赖清单就识别不出来。
应对方式是**如实输出空值**（`framework` 留空），而不是猜 ——
报告里「框架：未识别」是个诚实的结论，「框架：Spring」猜错了则不是。

## 与 B1 的分工

结构的活 B1 已经干完了（`scan_source_tree` 产出 `by_language` /
`entry_candidates` / `dependency_manifest_paths`，见 `projects/fetcher.py`）。
本模块**只读依赖清单的内容**，不重新遍历目录树 —— 再遍历一遍不仅慢，
还会得出与 `manifest.json` 不一致的结果（比如忽略了同样的忽略规则）。

## 一条贯穿全模块的匹配纪律

依赖名的匹配一律是**带边界的**（`_matches`），不是 `in`。
理由是真实踩过的坑：`"uv" in "uvicorn"` 为真，于是每个 FastAPI 项目的
包管理器都被识别成 `uv`；`"pg" in "psycopg2"` 同样为真。
这类错误的症状是**报告里出现一个看似合理、实则错误的字段**，
没有任何异常、没有任何日志，只有懂行的人看一眼才知道不对。
"""

from __future__ import annotations

import json
import re
import tomllib
from typing import Any

from app.agents.base import BaseAgent, FaultTolerance
from app.core.exceptions import StageFatalError
from app.core.logging import get_logger
from app.models.enums import StageName
from app.orchestrator.context import AssessmentContext
from app.orchestrator.events import LogLevel
from app.projects.workspace import read_manifest_async

logger = get_logger(__name__)

#: 单份依赖清单的读取上限。清单是文本，正常都在几十 KB；
#: 超过这个数说明它不是清单（比如一个被误命名的 lock 文件），读了也没用。
_MAX_MANIFEST_BYTES = 512 * 1024

#: 一次 recon 最多读几份清单。README 里贴的示例清单、vendor 目录里的副本
#: 都可能被 B1 收进来；读前几份就够了，多读只是多花时间。
_MAX_MANIFESTS = 12

#: 内容里出现的标记，与「依赖名」共用一套集合传递。
#: 前缀 `#` 保证它不可能与真实包名冲突（PyPI / npm 都不允许 `#`）。
_MARKER_PREFIX = "#"


# ---------------------------------------------------------------------------
# 识别规则
# ---------------------------------------------------------------------------

#: 依赖清单文件名（小写）→ 生态。
#:
#: 这张表的键必须是 `projects/types.py` 的 `DEPENDENCY_MANIFEST_NAMES` 的
#: **子集** —— B1 只把那张表里的文件收进 `dependency_manifest_paths`，
#: 这里多写的键永远不会被命中，只会让人以为系统支持它。
_ECOSYSTEM_BY_FILENAME: dict[str, str] = {
    "requirements.txt": "python",
    "requirements-dev.txt": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "setup.cfg": "python",
    "pipfile": "python",
    "package.json": "node",
    "go.mod": "go",
    "pom.xml": "java",
    "build.gradle": "java",
    "gemfile": "ruby",
    "composer.json": "php",
}

#: 锁文件 → 包管理器。**比依赖名可靠得多**：`uv.lock` 的存在就是「这个项目用 uv」
#: 的直接证据，而依赖名只能推断。有锁文件时优先用它。
_LOCKFILE_MANAGERS: dict[str, str] = {
    "poetry.lock": "Poetry",
    "package-lock.json": "npm",
    "yarn.lock": "Yarn",
}

#: 依赖名 → (生态, 框架显示名)。**全小写，带边界匹配**。
#:
#: 顺序有意义：命中多个时取**先命中的**。排列按「这个包有多能代表这个技术栈」
#: 降序 —— 一个项目同时有 `flask` 和 `fastapi`（迁移中的代码库）时，
#: 报 FastAPI 比报 Flask 更有用，因为新代码是它。
_FRAMEWORKS: tuple[tuple[str, str, str], ...] = (
    # Python
    ("fastapi", "python", "FastAPI"),
    ("django", "python", "Django"),
    ("flask", "python", "Flask"),
    ("tornado", "python", "Tornado"),
    ("aiohttp", "python", "aiohttp"),
    ("sanic", "python", "Sanic"),
    # Node
    ("@nestjs/core", "node", "NestJS"),
    ("next", "node", "Next.js"),
    ("koa", "node", "Koa"),
    ("express", "node", "Express"),
    ("fastify", "node", "Fastify"),
    # Java
    ("spring-boot", "java", "Spring Boot"),
    ("springframework", "java", "Spring"),
    ("quarkus", "java", "Quarkus"),
    ("micronaut", "java", "Micronaut"),
    ("struts", "java", "Struts"),
    # Go
    ("gin-gonic/gin", "go", "Gin"),
    ("labstack/echo", "go", "Echo"),
    ("gofiber/fiber", "go", "Fiber"),
    # PHP / Ruby
    ("laravel/framework", "php", "Laravel"),
    # 写成 `symfony` 而不是 `symfony/`：边界规则已经负责那个斜杠，
    # 而带斜杠的 needle 会让 `_matches` 去找 `symfony/-`（永远不存在）
    ("symfony", "php", "Symfony"),
    ("rails", "ruby", "Ruby on Rails"),
    ("sinatra", "ruby", "Sinatra"),
)

#: 依赖名 → 数据存储显示名。报告里单列一项，
#: 因为它直接影响「这轮评估要起哪些服务」。
_DATASTORES: tuple[tuple[str, str], ...] = (
    ("pymysql", "MySQL"),
    ("mysqlclient", "MySQL"),
    ("mysql-connector", "MySQL"),
    ("aiomysql", "MySQL"),
    ("asyncmy", "MySQL"),
    ("psycopg", "PostgreSQL"),
    ("asyncpg", "PostgreSQL"),
    ("pymongo", "MongoDB"),
    ("motor", "MongoDB"),
    ("mongoose", "MongoDB"),
    ("sqlalchemy", "SQLAlchemy"),
    ("redis", "Redis"),
)


class ReconAgent(BaseAgent[AssessmentContext, dict[str, Any]]):
    """识别技术栈并写回 `projects.tech_stack`。

    **致命档**：没有技术栈就没有审计规则集，后续四个阶段没有可用输入。
    让它在失败后「跳过继续」，只会得到一份「扫描了 0 个文件、0 个漏洞」的报告 ——
    而用户会把它读成「这个项目是安全的」。
    """

    name = "技术栈识别"
    stage = StageName.RECON
    fault_tolerance = FaultTolerance.FATAL

    async def run(self, ctx: AssessmentContext, inp: AssessmentContext) -> dict[str, Any]:
        """`inp` 与 `ctx` 是同一个对象（`gather_input` 的默认实现）。

        保留两个参数是因为基类签名如此，而「本阶段的输入就是整个上下文」
        正是 `gather_input` 默认实现所表达的意思 —— 不为了少一个参数去覆盖它。
        """
        await self.emit(LogLevel.INFO, "开始识别项目技术栈")

        manifest = await read_manifest_async(ctx.project_id)
        if manifest is None:
            # `manifest.json` 不存在 = 源码还没导入或导入未完成。
            # 抛出而不是产出空技术栈：空技术栈会让后续阶段「跑得很正常」，
            # 最后交出一份「0 个漏洞」的报告。
            raise StageFatalError(
                "找不到源码清单，项目源码可能尚未导入完成",
                detail={"project_id": ctx.project_id},
                remediation="请重新上传源码包或重新拉取 Git 仓库",
            )

        await self.emit(
            LogLevel.INFO,
            f"扫描到 {manifest.total_files} 个文件、{manifest.total_loc} 行代码",
        )
        if manifest.truncated:
            # 必须显式说出来。用户会把「没扫到」读成「没有漏洞」，
            # 而这里正是那个会发生「没扫到」的地方。
            await self.emit(
                LogLevel.WARN,
                "源码规模超过扫描上限，本次只分析了部分文件；报告将标注此限制",
            )

        tech_stack = await self._detect(ctx, manifest)
        await self._persist(ctx, tech_stack)

        if tech_stack["framework"]:
            await self.emit(
                LogLevel.INFO,
                f"识别结果：{tech_stack['language']} / {tech_stack['framework']}",
            )
        else:
            # 识别不出框架是**正常结果**，不是错误 —— 但要让人知道
            # 后续用的是通用规则集，而不是某个框架的专用规则。
            await self.emit(
                LogLevel.WARN,
                f"未能识别出具体框架（语言：{tech_stack['language']}），后续将使用通用规则集",
            )

        return tech_stack

    def apply_output(self, ctx: AssessmentContext, out: dict[str, Any]) -> None:
        ctx.tech_stack = out

    # ------------------------------------------------------------------

    async def _detect(self, ctx: AssessmentContext, manifest: Any) -> dict[str, Any]:
        from app.projects.workspace import read_whole_source

        dependencies: set[str] = set()
        ecosystems: set[str] = set()
        present_names: set[str] = set()
        read_count = 0

        for rel in manifest.dependency_manifest_paths:
            filename = rel.rsplit("/", 1)[-1].lower()
            present_names.add(filename)
            ecosystem = _ECOSYSTEM_BY_FILENAME.get(filename)
            if ecosystem is None:
                # 锁文件 / Dockerfile 只看「在不在」，不读内容
                continue
            if read_count >= _MAX_MANIFESTS:
                continue
            try:
                text = await read_whole_source(ctx.project_id, rel)
            except Exception as exc:  # noqa: BLE001
                # 单份清单读不到不影响整体识别：多生态项目里少读一份
                # 只是少一个参考。为它中断整轮 recon 是过度反应 ——
                # 该项目的语言与框架会由其余清单（或空值）给出。
                logger.info("读取依赖清单 %s 失败：%s", rel, exc)
                continue
            if len(text.encode("utf-8")) > _MAX_MANIFEST_BYTES:
                logger.info("依赖清单 %s 过大，跳过", rel)
                continue

            read_count += 1
            ecosystems.add(ecosystem)
            dependencies |= _parse_dependencies(filename, text)

        return {
            "language": _dominant_language(manifest),
            "framework": _framework(dependencies) or "",
            "datastore": _datastores(dependencies),
            "package_manager": _package_manager(present_names, dependencies, ecosystems),
            "containerized": (
                "是" if {"dockerfile", "docker-compose.yml"} & present_names else "否"
            ),
            "entry_points": ", ".join(manifest.entry_candidates[:5]),
            "total_files": str(manifest.total_files),
            "total_loc": str(manifest.total_loc),
        }

    async def _persist(self, ctx: AssessmentContext, tech_stack: dict[str, Any]) -> None:
        """写回 `projects.tech_stack`。

        **不 commit** —— T4 定的是「阶段边界是唯一原子提交点」，提交由引擎做。
        这里只 `flush()`，让同一阶段内后续读到的是一致的值。

        找不到项目行时只记日志：`ctx.project_id` 来自引擎解析出的评估行，
        理论上必然存在；真丢了说明数据被外部删了，那是 `code_audit` 阶段
        会因为读不到源码而炸出来的问题，不该由这里抛一个更难懂的错误。
        """
        from sqlalchemy import update

        from app.models.project import Project

        result = await self.deps.session.execute(
            update(Project).where(Project.id == ctx.project_id).values(tech_stack=tech_stack)
        )
        if result.rowcount == 0:
            logger.warning(
                "评估 %s 的项目 %s 不存在，技术栈未落库", ctx.assessment_id, ctx.project_id
            )
            return
        await self.deps.session.flush()
        logger.info(
            "评估 %s 技术栈已写入项目 %s：%s",
            ctx.assessment_id,
            ctx.project_id,
            tech_stack,
        )


# ---------------------------------------------------------------------------
# 依赖清单解析
# ---------------------------------------------------------------------------


def _parse_dependencies(filename: str, text: str) -> set[str]:
    """按清单文件名分派解析器。返回**全小写**的依赖名集合（可能含 `#` 标记）。"""
    try:
        if filename == "pyproject.toml":
            return _parse_pyproject(text)
        if filename in {"package.json", "composer.json"}:
            return _parse_json(text)
        if filename in {"requirements.txt", "requirements-dev.txt"}:
            return _parse_requirements(text)
        if filename == "go.mod":
            return _parse_gomod(text)
        if filename in {"pom.xml", "build.gradle"}:
            return _parse_jvm(text)
        if filename == "gemfile":
            return _parse_gemfile(text)
        if filename in {"pipfile", "setup.py", "setup.cfg"}:
            return _parse_loose(text)
    except Exception as exc:  # noqa: BLE001
        # 解析失败**不是错误**：清单文件格式千奇百怪（模板化的 pom、
        # 带条件判断的 setup.py）。读不出依赖就当作「这个生态没识别到」，
        # 而不是让整个 recon 失败。
        logger.info("解析 %s 失败，按空依赖处理：%s", filename, exc)
    return set()


def _parse_pyproject(text: str) -> set[str]:
    data = tomllib.loads(text)
    names: set[str] = set()

    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        names.add(_dep_name(spec))
    for group in (project.get("optional-dependencies") or {}).values():
        for spec in group or []:
            names.add(_dep_name(spec))

    # PEP 735 的 dependency-groups（uv 主推的写法）
    for group in (data.get("dependency-groups") or {}).values():
        for spec in group or []:
            if isinstance(spec, str):
                names.add(_dep_name(spec))

    tool = data.get("tool") or {}
    poetry = tool.get("poetry") or {}
    if poetry:
        # `[tool.poetry]` 这一节的存在本身就是判据，不需要它声明了什么依赖 ——
        # 别的工具不会写这个节。
        names.add(f"{_MARKER_PREFIX}poetry")
        names |= {str(k).lower() for k in (poetry.get("dependencies") or {})}
        names |= {str(k).lower() for k in (poetry.get("dev-dependencies") or {})}
    if tool.get("uv"):
        names.add(f"{_MARKER_PREFIX}uv")
    if data.get("dependency-groups") and not poetry:
        # `[dependency-groups]` 是 uv 引入的写法，Poetry 项目不会有它。
        # 两者同时存在时以 Poetry 为准（那说明是从 Poetry 迁移过来的）。
        names.add(f"{_MARKER_PREFIX}uv")

    return {n for n in names if n}


def _parse_json(text: str) -> set[str]:
    data = json.loads(text)
    names = {str(k).lower() for k in (data.get("dependencies") or {})}
    names |= {str(k).lower() for k in (data.get("devDependencies") or {})}
    # composer.json 用 require / require-dev
    names |= {str(k).lower() for k in (data.get("require") or {})}
    names |= {str(k).lower() for k in (data.get("require-dev") or {})}
    return names


def _parse_requirements(text: str) -> set[str]:
    names: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        # `-r other.txt` / `--index-url ...` / `-e .` 都不是依赖名
        if not line or line.startswith("-"):
            continue
        names.add(_dep_name(line))
    return {n for n in names if n}


def _parse_gomod(text: str) -> set[str]:
    names: set[str] = set()
    for raw in text.splitlines():
        line = re.sub(r"^require\s+", "", raw.strip())
        if not line or line.startswith("//") or line in {"(", ")"}:
            continue
        # 块内是 `<module> <version>`，块外是 `require <module> <version>` ——
        # 去掉 `require` 前缀后两种形态一致。
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith(("github.com/", "gitlab.com/", "gopkg.in/")):
            names.add(parts[0].lower())
    return names


def _parse_jvm(text: str) -> set[str]:
    """Maven / Gradle。

    不解析 XML 树：`pom.xml` 里同一个 `artifactId` 会出现在
    `dependency` / `plugin` / `parent` 三处，语义完全不同，
    而这里只想知道「有没有 spring-boot」。多抓一个 plugin 名的代价
    只是多一个候选，会被 `_framework` 忽略。
    """
    names = {m.lower() for m in re.findall(r"<artifactId>\s*([^<\s]+)", text)}
    names |= {m.lower() for m in re.findall(r"['\"]([\w.\-]+:[\w.\-]+):", text)}
    return names


def _parse_gemfile(text: str) -> set[str]:
    return {
        match.group(1).lower()
        for raw in text.splitlines()
        if (match := re.match(r"\s*gem\s+['\"]([^'\"]+)['\"]", raw))
    }


def _parse_loose(text: str) -> set[str]:
    """Pipfile / setup.py / setup.cfg —— 只做宽松的标识符提取。

    `setup.py` 允许任意 Python 代码（它本身就是一个程序），静态解析做不到完整。
    抓每行开头的带引号标识符够用：抓漏的后果只是少一个候选，
    而抓错的后果也只是一个不影响判定的多余名字。
    """
    return {
        match.group(1).lower()
        for raw in text.splitlines()
        if (match := re.match(r"""\s*["']([A-Za-z][\w.\-]*)["']""", raw))
    }


def _dep_name(spec: str) -> str:
    """`uvicorn[standard]>=0.32 ; python_version>='3.11'` → `uvicorn`。"""
    return re.split(r"[\[<>=!~;,\s]", spec.strip(), maxsplit=1)[0].strip().lower()


# ---------------------------------------------------------------------------
# 匹配
# ---------------------------------------------------------------------------

#: 不遵守「分隔符命名」约定的真实包名 → 它们实际代表的框架。
#:
#: 这张表是**例外清单**，不是匹配规则的替代品。每加一条都要问：
#: 这个名字是不是真的没有分隔符？`django-rest-framework` 有，
#: `djangorestframework` 也有（PyPI 上两个名字都存在，后者是正式发行名）。
_ALIASES: dict[str, frozenset[str]] = {
    "django": frozenset({"djangorestframework"}),
    "next": frozenset({"nextjs"}),
}


def _matches(deps: set[str], needle: str) -> bool:
    """**带边界**的子串判断，不是 `in`。

    `uvicorn` 与 `uv` 的关系是「碰巧前两个字符相同」，不是「同类工具」；
    `psycopg2` 与 `pg` 同理。依赖生态里的分隔符是 `-` / `.` / `/` / `:`，
    只有以这些为边界（或完全相等）才算命中：

    - `django` ↦ `django-cors-headers` ✅
    - `flask`  ↦ `flask-sqlalchemy` ✅
    - `spring-boot` ↦ `spring-boot-starter-web` ✅
    - `uv`     ↦ `uvicorn` ❌（这正是要挡掉的那个）
    - `pg`     ↦ `psycopg2` ❌

    有少数真实包名**不遵守**这个约定（见 `_ALIASES`），它们靠一张显式表补上，
    而不是放宽上面的规则 —— 放宽规则会把 `uvicorn` 那个洞重新打开。
    """
    if _ALIASES.get(needle, frozenset()) & deps:
        return True
    for dep in deps:
        if dep == needle or dep.startswith(f"{needle}-") or dep.startswith(f"{needle}."):
            return True
        if dep.startswith(f"{needle}/") or dep.startswith(f"{needle}:"):
            return True
    return False


def _framework(deps: set[str]) -> str | None:
    """`_FRAMEWORKS` 里**先命中**的那条。

    顺序即优先级，所以不排序、不取「最长匹配」—— 那会让 `flask` 与 `fastapi`
    同时存在时的结果取决于字符串长度，而正确的判据是「哪个更能代表项目的现状」。
    """
    for needle, _ecosystem, label in _FRAMEWORKS:
        if _matches(deps, needle):
            return label
    return None


def _datastores(deps: set[str]) -> str:
    """去重但**保序**：`mysql-connector` 与 `pymysql` 都命中时只输出一次 MySQL。

    用 dict 当有序集合，而不是 `sorted(set(...))` —— 后者的顺序是字典序，
    会让「MySQL, SQLAlchemy」变成「MySQL, SQLAlchemy」以外的排列，
    与 `_DATASTORES` 里「越靠前越具体」的编排意图脱节。
    """
    labels: dict[str, None] = {}
    for needle, label in _DATASTORES:
        if _matches(deps, needle):
            labels.setdefault(label, None)
    return ", ".join(labels)


def _dominant_language(manifest: Any) -> str:
    """取 LOC 占比最高的语言。

    `by_language` 已经是 `most_common()` 排好序的（B1 的 `scan_source_tree`），
    所以取第一个即可。没有语言信息时回 `unknown` —— **不猜**。
    """
    for language in manifest.by_language:
        return str(language)
    return "unknown"


def _package_manager(present_names: set[str], deps: set[str], ecosystems: set[str]) -> str:
    """按「证据强度」降序判定。

    1. **锁文件** —— 最强的证据，它就是这个工具自己写出来的；
    2. **清单内容里的标记**（`[tool.poetry]` / `[dependency-groups]`）；
    3. **按生态兜底** —— 明确标注为「未能识别出具体工具」而不是编一个。

    第 3 档刻意回空串而不是 `pip`：一个只有 `requirements.txt` 的项目
    用 `pip` / `pipenv` / `uv` 装都有可能，猜一个等于在报告里写一个
    没有依据的字段。空值的含义是「不知道」，而「不知道」是真的。
    """
    for lockfile, manager in _LOCKFILE_MANAGERS.items():
        if lockfile in present_names:
            return manager
    if f"{_MARKER_PREFIX}poetry" in deps:
        return "Poetry"
    if f"{_MARKER_PREFIX}uv" in deps:
        return "uv"
    if "pipfile" in present_names:
        return "Pipenv"
    if "go.mod" in present_names:
        return "Go Modules"
    if "pom.xml" in present_names:
        return "Maven"
    if "build.gradle" in present_names:
        return "Gradle"
    if "composer.json" in present_names:
        return "Composer"
    if "gemfile" in present_names:
        return "Bundler"
    return ""


__all__ = ["ReconAgent"]
