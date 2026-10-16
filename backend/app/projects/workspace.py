"""B1-4 工作区管理 —— **B1 唯一的安全关口**。

这个文件的实现密度明显高于 B1 其它文件，因为它是「用户可控字符串 → 文件系统路径」
的唯一收口。所有涉及路径的入口（源码片段读取、解包落盘、清单写入）都必须经过
`normalize_rel_path()` + `safe_join()` 这两道，不允许任何地方自己拼路径。

承接总纲 §7.4：**所有落库路径一律为「源码工作区根相对 POSIX 路径」**
（如 `app/api/order.py`）。三端绝对根由配置解析，绝对路径不入库、不跨模块传递：

| 端 | 绝对根 | 分隔符 |
|---|---|---|
| 控制面（Windows） | `WORKSPACE_ROOT/{id}/src/` | 反斜杠 |
| 数据面（ECS 宿主） | `/srv/asa/tasks/{id}/src/` | POSIX |
| 沙箱容器内 | `/workspace`（挂载点） | POSIX |
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import BadRequestError, NotFoundError
from app.core.logging import get_logger
from app.projects.errors import DiskFullError, SourcePathEscapeError
from app.projects.types import SourceManifest, SourceSlice

logger = get_logger(__name__)

#: Windows 盘符前缀，如 `C:`。归一化后仍以这个开头的就是绝对路径。
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")

#: 源码片段单次返回的最大行数。
#:
#: 前端要的是「漏洞行 ±20 行」用于高亮（B1 设计 §7 第 11 条），400 行已远超所需。
#: 设这个上限是为了让 `?start=1&end=999999999` 这种请求无法把整个大文件读进内存。
MAX_SPAN_LINES = 400

#: 建档前要求的最小可用空间。低于它直接拒绝，而不是写到一半发现盘满了。
MIN_FREE_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class WorkspacePaths:
    """一个项目在控制面的工作区布局。全部为**绝对路径**（不进数据库）。"""

    project_id: int
    root: Path
    src_root: Path
    meta_root: Path
    tmp_root: Path

    @property
    def manifest_path(self) -> Path:
        return self.meta_root / "manifest.json"


def workspace_paths(project_id: int) -> WorkspacePaths:
    root = settings.workspace_root / str(project_id)
    return WorkspacePaths(
        project_id=project_id,
        root=root,
        src_root=root / "src",
        meta_root=root / "meta",
        tmp_root=root / "tmp",
    )


def create_layout(project_id: int) -> WorkspacePaths:
    """建出 `src/` `meta/` `tmp/` 三层。`tmp/` 是上传归档的临时区，建档结束即清。"""
    paths = workspace_paths(project_id)
    for d in (paths.src_root, paths.meta_root, paths.tmp_root):
        d.mkdir(parents=True, exist_ok=True)
    return paths


def remove_workspace(project_id: int) -> None:
    """删除工作区。`ignore_errors=True` —— 删不掉不该让删除项目这个操作失败。"""
    root = workspace_paths(project_id).root
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
        logger.info("已清理控制面工作区 %s", root)


def clear_tmp(project_id: int) -> None:
    tmp = workspace_paths(project_id).tmp_root
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# 路径归一与落界 —— 安全核心
# ---------------------------------------------------------------------------


def normalize_rel_path(raw: str) -> str:
    """把外部传入的路径归一为「工作区根相对 POSIX 路径」，不合法直接拒绝。

    拒绝清单里的每一条都对应一个具体的绕过手法，不是洁癖：

    - **空串 / 纯空白**：`src_root / ""` 就是 `src_root` 本身，会把目录当文件处理。
    - **NUL 字节**：`"a\\x00.py"` 在部分系统调用里被当作 `"a"` 截断，
      于是「检查的是这个路径、打开的是另一个路径」。
    - **POSIX 绝对路径** `/etc/passwd`：`Path(root) / "/etc/passwd"` 的结果是
      `/etc/passwd` —— 左侧被整个丢弃。这是最容易踩的一个。
    - **Windows 盘符** `C:\\Windows`、**UNC** `\\\\server\\share`：同上，且绕过 `/` 检查。
    - **任何 `..` 段**：包含夹在中间的 `a/../../b`，不只看开头。
    - **反斜杠**：Windows 上 `a\\..\\b` 是两段，只按 `/` 切分会漏掉这个 `..`。
      所以先统一分隔符，再切分。

    返回值为 POSIX 形式（`/` 分隔），这是入库与跨模块传递的唯一合法形态。
    """
    if raw is None:
        raise SourcePathEscapeError("源码路径不能为空")

    candidate = raw.strip()
    if not candidate:
        raise SourcePathEscapeError("源码路径不能为空")

    if "\x00" in candidate:
        raise SourcePathEscapeError("源码路径含非法字符", detail={"raw": repr(raw)})

    # 先统一分隔符：不这么做，Windows 风格的反斜杠能把下面的 `..` 检查绕过去
    unified = candidate.replace("\\", "/")

    if unified.startswith("/"):
        raise SourcePathEscapeError("不接受绝对路径", detail={"raw": raw})
    if unified.startswith("//"):
        raise SourcePathEscapeError("不接受 UNC 路径", detail={"raw": raw})
    if _WINDOWS_DRIVE.match(unified):
        raise SourcePathEscapeError("不接受带盘符的路径", detail={"raw": raw})

    # `.` 段直接丢弃（`./a/b` 与 `a/b` 等价），空段来自重复斜杠
    parts = [p for p in unified.split("/") if p not in ("", ".")]
    if not parts:
        raise SourcePathEscapeError("源码路径不能为空")

    if any(p == ".." for p in parts):
        raise SourcePathEscapeError("源码路径不得包含 .. 段", detail={"raw": raw})

    return "/".join(parts)


def safe_join(root: Path, rel: str) -> Path:
    """把**已归一化**的相对路径安全地拼到根下。已是第二道防线。

    两道**独立**的检查，任何一道不过都拒绝：

    1. **逐段查符号链接**：路径上任何一段是软链接就拒绝。
       即便软链接指向根内也拒绝 —— 归档里的软链接是攻击者放的，
       今天指向根内，明天可能被换成指向根外，不如一律不收。
    2. **realpath 落界**：`resolve()` 会展开所有软链接，解析结果必须仍在根内。
       这一道防的是第 1 道没想到的情况（挂载点、Windows junction 等）。

    设计 §3.1 与 §4.3 对「指向根内的软链接」描述略有出入，这里取**更严**的一侧。
    """
    root_resolved = root.resolve()

    target = root_resolved
    for part in rel.split("/"):
        target = target / part
        if target.is_symlink():
            raise SourcePathEscapeError(
                "源码路径指向符号链接，已拒绝",
                detail={"rel_path": rel, "symlink_at": str(target)},
            )

    if not target.resolve().is_relative_to(root_resolved):
        raise SourcePathEscapeError("源码路径越出工作区根目录", detail={"rel_path": rel})

    return target


# ---------------------------------------------------------------------------
# 磁盘空间
# ---------------------------------------------------------------------------


def _nearest_existing(path: Path) -> Path:
    """往上找第一个存在的祖先。给 `disk_usage` 用 —— 它对不存在的路径会抛异常。"""
    current = path
    while not current.exists():
        parent = current.parent
        if parent == current:
            break
        current = parent
    return current


def ensure_free_space(required_bytes: int, *, probe: Path | None = None) -> None:
    """落盘前预检。宁可拒绝建档，也不要写到一半撑爆 D 盘 ——
    半截工作区比没有工作区更难清理（B1 设计 §6 第 10 条）。"""
    target = _nearest_existing(probe or settings.workspace_root)
    free = shutil.disk_usage(target).free
    if free - required_bytes < MIN_FREE_BYTES:
        raise DiskFullError(
            f"磁盘可用空间不足：剩余 {free / 1024**2:.0f} MB，"
            f"本次还需 {required_bytes / 1024**2:.0f} MB，"
            f"并需保留 {MIN_FREE_BYTES / 1024**2:.0f} MB 余量"
        )


# ---------------------------------------------------------------------------
# 清单读写
# ---------------------------------------------------------------------------


def write_manifest(project_id: int, manifest: SourceManifest) -> Path:
    paths = workspace_paths(project_id)
    paths.meta_root.mkdir(parents=True, exist_ok=True)
    payload = manifest.model_dump_json(indent=2)
    # 先写临时文件再原子替换：中途崩了不会留下一个半截的 manifest.json，
    # 而半截的 JSON 会在下次「重评估免重扫」时炸在 json.loads 上，很难定位
    tmp = paths.manifest_path.with_suffix(".json.tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(paths.manifest_path)
    return paths.manifest_path


def read_manifest(project_id: int) -> SourceManifest | None:
    """读清单。**任何解析失败都返回 None**（当作没有清单，重扫一遍）——
    缓存读不出来不该让整个流程失败。"""
    path = workspace_paths(project_id).manifest_path
    if not path.is_file():
        return None
    try:
        return SourceManifest.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        logger.warning("manifest.json 解析失败，将重新扫描：%s（%s）", path, exc)
        return None


async def read_manifest_async(project_id: int) -> SourceManifest | None:
    """`read_manifest` 的异步包装。

    **它属于本模块**，而不是每个 Agent 各包一遍：路径解析（`workspace_paths`）
    本来就归这里，谁把绝对路径拼出来就该由谁负责怎么读。放在 Agent 里包一层
    会让「清单文件在哪」这件事泄漏到 L2 —— 而那正是契约 5 要挡住的东西。

    走 `to_thread` 而不是直接调用：`read_manifest` 是同步阻塞 IO，
    调用点全在事件循环里。「它通常只有几毫秒」正是这类代码变成偶发卡顿的原因。
    """
    return await asyncio.to_thread(read_manifest, project_id)


# ---------------------------------------------------------------------------
# 源码片段读取（服务 F3 源码高亮）
# ---------------------------------------------------------------------------


def _read_lines(path: Path) -> list[str]:
    """读文本行。编码失败不抛异常 —— 源码里有非 UTF-8 字节是常事，
    为此让整个高亮面板报错不值得（B1 设计 §6 第 8 条，级别 L1 可忽略）。"""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="replace")
    return text.splitlines()


async def read_source(project_id: int, rel_path: str, start: int, end: int) -> SourceSlice:
    """按行区间读取工作区内的源码（B1 设计 §4.3）。

    `start` / `end` 为 1-based 闭区间。返回值里的 `start`/`end` 是**实际区间**，
    调用方必须按它对齐高亮，不能假定还是请求时的值。
    """
    paths = workspace_paths(project_id)
    if not paths.src_root.is_dir():
        raise NotFoundError(
            "该项目尚未导入源码",
            remediation="请先完成源码导入（Git 克隆或上传源码包）",
        )

    rel = normalize_rel_path(rel_path)
    target = safe_join(paths.src_root, rel)

    if not target.is_file():
        raise NotFoundError(f"源码文件不存在：{rel}", remediation="请确认路径是否拼写正确")

    size = target.stat().st_size
    if size > settings.max_source_file_bytes:
        raise BadRequestError(
            f"文件过大（{size / 1024**2:.1f} MB），超出单文件读取上限",
            remediation="该文件超出源码高亮的读取上限，请在本地查看",
        )

    if end < start:
        raise BadRequestError("结束行号不能小于起始行号", remediation="请检查 start / end 参数")

    if end - start + 1 > MAX_SPAN_LINES:
        end = start + MAX_SPAN_LINES - 1

    # 读文件是阻塞 IO，扔线程池 —— 别在事件循环里等磁盘
    lines = await asyncio.to_thread(_read_lines, target)
    total = len(lines)

    lo = max(1, start)
    hi = min(end, total)
    if lo > total:
        # 请求区间整个落在文件末尾之外：返回空内容而不是报错，
        # 因为「漏洞行号比文件长」通常意味着源码版本与扫描时不一致，值得看而不是值得炸
        logger.info("源码读取区间超出文件长度：%s 请求 %s..%s，实际 %s 行", rel, start, end, total)
        return SourceSlice(rel_path=rel, start=total, end=total, total_lines=total, lines=[])

    return SourceSlice(
        rel_path=rel,
        start=lo,
        end=hi,
        total_lines=total,
        lines=lines[lo - 1 : hi],
    )


async def read_whole_source(project_id: int, rel_path: str) -> str:
    """读**整份**源码文件。

    与 `read_source` 分开而不是给它加一个 `end=None` 的开关，有两个理由：

    1. **上限不同**。`read_source` 服务于「前端高亮一段」，所以有
       `MAX_SPAN_LINES` 的截断；而这里服务于「`git apply` 干跑 + 重跑污点分析」，
       源码被截断会得到一个**打不上的补丁**，而且失败信息会指向
       「补丁格式不对」—— 一个完全错误的方向。
    2. **返回值不同**。这里只要文本，不要行号区间。塞一个 `SourceSlice`
       回去会让人以为调用方在乎 `start`/`end`。

    仍然受 `max_source_file_bytes` 约束，并且**抛错而不是截断** ——
    超限时正确的结论是「这个文件不参与补丁校验」，不是「拿半份去校验」。
    """
    paths = workspace_paths(project_id)
    if not paths.src_root.is_dir():
        raise NotFoundError(
            "该项目尚未导入源码",
            remediation="请先完成源码导入（Git 克隆或上传源码包）",
        )

    rel = normalize_rel_path(rel_path)
    target = safe_join(paths.src_root, rel)

    if not target.is_file():
        raise NotFoundError(f"源码文件不存在：{rel}", remediation="请确认路径是否拼写正确")

    size = target.stat().st_size
    if size > settings.max_source_file_bytes:
        raise BadRequestError(
            f"文件过大（{size / 1024**2:.1f} MB），超出上限，无法进行补丁校验",
            remediation="请在本地对该文件应用补丁",
        )

    return await asyncio.to_thread(target.read_text, encoding="utf-8", errors="replace")


def sha1_of(path: Path, *, chunk: int = 1 << 20) -> str:
    """分块算摘要 —— 一次 read() 整文件在大文件上会直接把内存顶上去。"""
    digest = hashlib.sha1()  # noqa: S324 —— 用途是变更检测，不是完整性/抗碰撞
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            digest.update(block)
    return digest.hexdigest()
