"""技术栈识别（`app/agents/recon.py`）的单元测试。

**只测纯函数**：清单解析与匹配规则。`ReconAgent.run` 需要数据库与工作区，
它靠集成测试覆盖 —— 在这里搭一套假的 session + 假的工作区，
断言的就变成「我按这个顺序调了这些函数」，而不是「识别得对不对」。

这个模块值得测的原因是：**它错了不会报错**。一个识别成 `uv` 的包管理器、
一个识别成 `PostgreSQL` 的 MySQL 项目，都会安静地进报告。
"""

from __future__ import annotations

import pytest

from app.agents.recon import (
    _datastores,
    _dep_name,
    _dominant_language,
    _framework,
    _matches,
    _package_manager,
    _parse_dependencies,
)

# ---------------------------------------------------------------------------
# 边界匹配
# ---------------------------------------------------------------------------


def test_matches_is_not_substring() -> None:
    """`in` 会把 `uvicorn` 判成 `uv`、`psycopg2` 判成 `pg`。

    这是本模块最容易写错、也最难发现的一处：两个字段都会被填上一个
    **看起来完全合理**的错值（每个 FastAPI 项目都装 uvicorn），
    没有任何异常、没有任何日志。
    """
    assert not _matches({"uvicorn"}, "uv")
    assert not _matches({"psycopg2"}, "pg")


def test_matches_accepts_ecosystem_separators() -> None:
    assert _matches({"django-cors-headers"}, "django")
    assert _matches({"djangorestframework"}, "django")
    assert _matches({"flask-sqlalchemy"}, "flask")
    assert _matches({"@nestjs/core"}, "@nestjs/core")
    assert _matches({"symfony/framework-bundle"}, "symfony")
    assert _matches({"spring-boot-starter-web"}, "spring-boot")


def test_matches_accepts_exact() -> None:
    assert _matches({"fastapi"}, "fastapi")
    assert not _matches({"fastapi"}, "flask")


def test_matches_handles_aliases_without_separators() -> None:
    """`nextjs` / `djangorestframework` 是真实发行名，但没按约定加分隔符。

    它们靠 `_ALIASES` 这张**显式例外表**补上，而不是放宽边界规则 ——
    放宽规则会把 `uvicorn` / `uv` 那个洞重新打开。
    """
    assert _matches({"nextjs"}, "next")
    assert _matches({"djangorestframework"}, "django")


def test_matches_does_not_treat_next_as_prefix_of_anything() -> None:
    """`next` 是三个字母的常见词，必须挡住 `next-auth` 之外的一切。

    `next-auth` 是本项目的合法依赖，该命中；但一个叫 `nextcloud` 的
    包不该被判成 Next.js —— 它不是。
    """
    assert _matches({"next-auth"}, "next")
    assert not _matches({"nextcloud"}, "next")


# ---------------------------------------------------------------------------
# 依赖名归一
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("uvicorn[standard]>=0.32", "uvicorn"),
        ("Django==5.0", "django"),
        ("requests ; python_version>='3.11'", "requests"),
        ("sqlalchemy[asyncio]~=2.0", "sqlalchemy"),
        ("  FastAPI  ", "fastapi"),
    ],
)
def test_dep_name_strips_extras_and_constraints(spec: str, expected: str) -> None:
    assert _dep_name(spec) == expected


# ---------------------------------------------------------------------------
# 清单解析
# ---------------------------------------------------------------------------


def test_parse_requirements_skips_directives() -> None:
    text = """
    # 注释行
    -r other.txt
    --index-url https://example.com/simple
    -e .
    fastapi==0.115.0
    uvicorn[standard]>=0.32   # 行内注释
    """
    assert _parse_dependencies("requirements.txt", text) == {"fastapi", "uvicorn"}


def test_parse_pyproject_pep621() -> None:
    text = """
    [project]
    name = "demo"
    dependencies = ["fastapi>=0.115", "pymysql"]

    [project.optional-dependencies]
    dev = ["pytest"]
    """
    assert _parse_dependencies("pyproject.toml", text) == {
        "fastapi",
        "pymysql",
        "pytest",
    }


def test_parse_pyproject_poetry_marks_manager() -> None:
    """`[tool.poetry]` 这一节的存在本身就是判据 —— 别的工具不写它。"""
    text = """
    [tool.poetry]
    name = "demo"

    [tool.poetry.dependencies]
    python = "^3.12"
    flask = "^3.0"
    """
    deps = _parse_dependencies("pyproject.toml", text)

    assert "flask" in deps
    assert _package_manager(set(), deps, {"python"}) == "Poetry"


def test_parse_pyproject_dependency_groups_implies_uv() -> None:
    text = """
    [project]
    name = "demo"
    dependencies = ["fastapi"]

    [dependency-groups]
    dev = ["pytest"]
    """
    deps = _parse_dependencies("pyproject.toml", text)

    assert _package_manager(set(), deps, {"python"}) == "uv"


def test_parse_package_json() -> None:
    text = '{"dependencies": {"express": "^4"}, "devDependencies": {"jest": "^29"}}'
    assert _parse_dependencies("package.json", text) == {"express", "jest"}


def test_parse_composer_json() -> None:
    text = '{"require": {"laravel/framework": "^11"}, "require-dev": {"phpunit/phpunit": "^11"}}'
    assert _parse_dependencies("composer.json", text) == {
        "laravel/framework",
        "phpunit/phpunit",
    }


def test_parse_gomod_block_and_inline() -> None:
    """`go.mod` 的 require 有「块」和「单行」两种写法，都要认。"""
    text = """
    module example.com/demo

    go 1.22

    require github.com/gin-gonic/gin v1.10.0

    require (
        github.com/go-sql-driver/mysql v1.8.1
        // 间接依赖的注释
    )
    """
    assert _parse_dependencies("go.mod", text) == {
        "github.com/gin-gonic/gin",
        "github.com/go-sql-driver/mysql",
    }


def test_parse_pom_xml() -> None:
    text = """
    <project>
      <dependencies>
        <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
      </dependencies>
    </project>
    """
    assert _framework(_parse_dependencies("pom.xml", text)) == "Spring Boot"


def test_malformed_manifest_yields_empty_not_raise() -> None:
    """格式坏的清单**不能**让整个 recon 失败。

    真实世界的 `pom.xml` 是模板化的、`setup.py` 里可能有任意逻辑。
    读不出来就当「这个生态没识别到」，而不是把整轮评估判死。
    """
    assert _parse_dependencies("pyproject.toml", "这不是 TOML {{{") == set()
    assert _parse_dependencies("package.json", "{\n  broken") == set()


# ---------------------------------------------------------------------------
# 匹配优先级
# ---------------------------------------------------------------------------


def test_framework_prefers_more_representative_one() -> None:
    """迁移中的代码库同时有 flask 与 fastapi 时，报 FastAPI。

    判据是「哪个更能代表项目的现状」，所以 `_FRAMEWORKS` 的顺序就是答案，
    不能改成「最长匹配」—— 那会让结果取决于字符串长度。
    """
    assert _framework({"flask", "fastapi"}) == "FastAPI"
    assert _framework({"flask"}) == "Flask"


def test_framework_returns_none_when_unrecognized() -> None:
    """识别不出是**正常结果**，回 None 由调用方如实写空串，不猜一个。"""
    assert _framework({"numpy", "pandas"}) is None


def test_datastores_dedupes_preserving_declaration_order() -> None:
    """两个 MySQL 驱动只输出一次 MySQL，且顺序按 `_DATASTORES` 的定义。"""
    result = _datastores({"pymysql", "mysql-connector", "sqlalchemy", "redis"})

    assert result == "MySQL, SQLAlchemy, Redis"
    assert result.count("MySQL") == 1


# ---------------------------------------------------------------------------
# 包管理器
# ---------------------------------------------------------------------------


def test_lockfile_beats_everything() -> None:
    """锁文件是最强证据 —— 它是那个工具自己写出来的。"""
    assert _package_manager({"poetry.lock"}, {"#uv"}, {"python"}) == "Poetry"
    assert _package_manager({"yarn.lock"}, set(), {"node"}) == "Yarn"
    assert _package_manager({"package-lock.json"}, set(), {"node"}) == "npm"


def test_package_manager_empty_when_only_requirements_txt() -> None:
    """只有 `requirements.txt` 时回**空串**，不回 `pip`。

    pip / pipenv / uv 都能装它，猜一个等于在报告里写一个没有依据的字段。
    「不知道」是真的，就写不知道。
    """
    assert _package_manager({"requirements.txt"}, {"fastapi"}, {"python"}) == ""


def test_package_manager_by_manifest_ecosystem() -> None:
    assert _package_manager({"go.mod"}, set(), {"go"}) == "Go Modules"
    assert _package_manager({"pom.xml"}, set(), {"java"}) == "Maven"


# ---------------------------------------------------------------------------
# 语言
# ---------------------------------------------------------------------------


class _StubManifest:
    def __init__(self, by_language: dict[str, int]) -> None:
        self.by_language = by_language


def test_dominant_language_takes_first_entry() -> None:
    """`by_language` 已按 LOC 降序（B1 的 `most_common()`），取第一个即可。"""
    assert _dominant_language(_StubManifest({"Python": 900, "JavaScript": 100})) == "Python"


def test_dominant_language_unknown_when_empty() -> None:
    assert _dominant_language(_StubManifest({})) == "unknown"
