"""B1 内部值对象（B1 模块设计 §3.3）。

**放这里而不是 `app/schemas/`**：`app/schemas/` 是跨层共享的**协议** DTO
（L1 出入参），这里是 B1 的**内部词汇**。混在一起会让 API 契约看起来比实际大得多，
也会让人误以为改个内部结构就要动前端。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# 语言与文件分类
# ---------------------------------------------------------------------------

#: 扩展名 → 语言。用于 LOC 的分语言统计。
#:
#: ⚠️ 这张表**只影响统计口径，不影响可分析性**。一个 .js 文件会被计入 LOC，
#: 但不会产出任何漏洞 —— 见 `ANALYZABLE_EXTS` 的注释。
LANGUAGE_BY_EXT: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".rs": "Rust",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".sql": "SQL",
    ".sh": "Shell",
    ".ps1": "PowerShell",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".xml": "XML",
    ".toml": "TOML",
    ".ini": "INI",
    ".md": "Markdown",
}

#: **可被污点引擎解析**的扩展名。
#:
#: 当前只有 `.py` —— B4 基于 `tree-sitter-python`。这个集合决定
#: 「工作区是否含可解析源文件」（B1 设计 §6 第 9 条，0 个则建档失败）。
#: 它与 `LANGUAGE_BY_EXT` 是**两个不同的问题**：前者问「能不能分析」，
#: 后者问「有多少代码」。别把它们合并成一个集合。
ANALYZABLE_EXTS: frozenset[str] = frozenset({".py"})

#: 依赖清单文件名（只索引**路径**，内容解析属 ReconAgent，B1 设计 §7 第 7 条）
DEPENDENCY_MANIFEST_NAMES: frozenset[str] = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "poetry.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pom.xml",
        "build.gradle",
        "go.mod",
        "composer.json",
        "Gemfile",
        "Dockerfile",
        "docker-compose.yml",
    }
)

#: 候选入口点文件名（同样只定位路径，不解析内容）
ENTRY_CANDIDATE_NAMES: frozenset[str] = frozenset(
    {"main.py", "app.py", "wsgi.py", "asgi.py", "manage.py", "run.py", "server.py", "__main__.py"}
)


# ---------------------------------------------------------------------------
# 扫描规则
# ---------------------------------------------------------------------------


class ScanRules(BaseModel):
    """源码扫描规则与上限。

    **阈值集中在这一个对象里**，而不是散落在遍历代码中 —— 这样
    「大仓库阈值是多少」有一个能指得出来的答案（B1 设计 §8 待定项 7）。
    """

    #: 目录名命中即整棵剪掉。`.venv` / `node_modules` 这类既不含业务逻辑，
    #: 又会把 LOC 与文件数吹大几个数量级。
    exclude_dirs: frozenset[str] = frozenset(
        {
            ".git",
            ".hg",
            ".svn",
            ".venv",
            "venv",
            "env",
            "__pycache__",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".tox",
            "node_modules",
            "bower_components",
            "site-packages",
            "dist",
            "build",
            "target",
            ".next",
            ".nuxt",
            ".idea",
            ".vscode",
            ".gradle",
            "vendor",
            "coverage",
            "htmlcov",
        }
    )
    #: 单文件超过这个大小直接跳过 —— 巨型生成文件（打包产物、压缩过的 JS）
    #: 会让 tree-sitter 解析耗时非线性上升，而它们几乎不可能藏业务漏洞。
    max_file_bytes: int = 2 * 1024 * 1024
    #: 扫描的文件总数上限。超了就截断并标 `truncated`（B1 设计 §6 第 14 条）。
    max_files: int = 20_000
    #: 扫描的总时长上限（秒）。2 vCPU 上跑大仓库时必须有个闸。
    max_scan_seconds: float = 60.0


class FileEntry(BaseModel):
    """单个源文件的结构元数据。

    `rel_path` **必须是工作区根相对 POSIX 路径**（总纲 §7.4）——
    落库、跨模块传递、报告渲染全靠它对齐。
    """

    rel_path: str
    ext: str
    language: str | None
    loc: int
    size_bytes: int
    sha1: str


class SourceManifest(BaseModel):
    """扫描产物，落 `meta/manifest.json`。

    `truncated=True` 是有意义的信息：报告必须注明「本次只扫描了前 N 个文件」，
    否则用户会把「没扫到」误读成「没有漏洞」。
    """

    total_files: int
    total_loc: int
    size_bytes: int
    by_language: dict[str, int] = Field(default_factory=dict)
    entries: list[FileEntry] = Field(default_factory=list)
    entry_candidates: list[str] = Field(default_factory=list)
    dependency_manifest_paths: list[str] = Field(default_factory=list)
    #: 因大小 / 数量 / 时长上限被跳过的文件数
    skipped_files: int = 0
    truncated: bool = False


class SourceSlice(BaseModel):
    """`read_source()` 的返回（B1 模块设计 §3.3）。

    `start` / `end` 是**实际返回的**行号区间，不一定等于调用方请求的区间 ——
    请求了 1..9999 而文件只有 40 行时，这里回 1..40。前端的高亮必须按返回的
    区间来，否则行号会整体错位。
    """

    rel_path: str
    start: int
    end: int
    total_lines: int
    lines: list[str] = Field(default_factory=list)

    @property
    def content(self) -> str:
        return "\n".join(self.lines)


class WorkspaceHandle(BaseModel):
    """交给 B3 编排引擎的工作区句柄（B1 模块设计 §3.1）。

    `mount_host_path` 是 **ECS 宿主侧**路径，不是控制面路径 ——
    B2 要用它做 `ro` bind mount，挂载语义由**远端 Docker** 解析。
    """

    project_id: int
    #: 控制面权威副本根（Windows 绝对路径）
    local_root: Path
    #: 控制面源码根 = local_root / "src"
    src_root: Path
    #: ECS 宿主侧路径，交给 B2 做只读挂载
    mount_host_path: str
    #: 入库 `file_path` 的基准 = 源码工作区根（总纲 §7.4）
    relative_path_base: str


# ---------------------------------------------------------------------------
# 接入源
# ---------------------------------------------------------------------------


class GitSource(BaseModel):
    url: str = Field(min_length=1, max_length=512)
    branch: str | None = Field(default=None, max_length=128)
    #: **引用**而非明文口令。明文凭证不入库（PRD §6、B1 设计 §7 第 10 条）。
    credential_ref: str | None = Field(default=None, max_length=128)


@dataclass(slots=True)
class ArchiveUpload:
    """上传的源码包。

    用 dataclass 而不是 Pydantic：`stream` 是个文件对象，Pydantic 校验不了它，
    硬塞进去只会得到一堆 `arbitrary_types_allowed` 的噪声。
    """

    filename: str
    size_bytes: int
    stream: BinaryIO
