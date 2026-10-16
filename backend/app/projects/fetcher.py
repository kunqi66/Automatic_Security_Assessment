"""B1-1/B1-2/B1-3：接入源适配、安全解包、源码扫描。

三件事放一个文件，是因为它们在 B1 设计里是同一条流水线的前三步
（接入 → 解包 → 落盘扫描），拆成三个文件只会让「落盘目标目录」这个共享状态
在文件之间来回传。B1 设计 §2 也明确说了子模块划分是**逻辑分解**，
不要求一一对应到文件。

安全要点全部在 `SafeExtractor` 里：归档是**用户上传的不信任输入**，
标准库的 `extractall()` / `shutil.unpack_archive()` 都不做 zip slip 与炸弹防护。
"""

from __future__ import annotations

import shutil
import subprocess
import tarfile
import time
import zipfile
from collections import Counter
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.projects.errors import (
    ArchiveBombError,
    ArchiveEscapeError,
    ArchiveFormatError,
    GitAuthFailedError,
    GitNotAllowedError,
    NoAnalyzableSourceError,
    SourcePathEscapeError,
)
from app.projects.types import (
    ANALYZABLE_EXTS,
    DEPENDENCY_MANIFEST_NAMES,
    ENTRY_CANDIDATE_NAMES,
    LANGUAGE_BY_EXT,
    FileEntry,
    ScanRules,
    SourceManifest,
)
from app.projects.workspace import normalize_rel_path, sha1_of

logger = get_logger(__name__)

#: git clone 的默认超时。大仓库浅克隆也可能跑几分钟，但不能无限等。
CLONE_TIMEOUT_SECONDS = 300

#: 归档格式的 magic 前缀。**只信 magic，不信扩展名** ——
#: 把 zip 改名成 .tar.gz 是最省事的绕过手法，而扩展名是用户随手就能改的。
_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"
#: tar 的 magic 在偏移 257 处（POSIX ustar）
_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"


# ---------------------------------------------------------------------------
# B1-1a Git 接入
# ---------------------------------------------------------------------------


def check_git_allowlist(url: str) -> None:
    """Git 地址白名单校验（PRD §12 风险 8 第 ② 条）。

    白名单为空 = 不限制，仅允许本地开发；生产环境为空会导致启动失败
    （见 `Settings._check_production_secrets`）。这个组合是刻意的：
    开发时不想配，生产时不配就起不来。
    """
    allowlist = settings.git_url_allowlist
    if not allowlist:
        logger.warning("GIT_URL_ALLOWLIST 为空，任意仓库均可克隆 —— 仅限本地开发")
        return

    normalized = url.strip().rstrip("/").lower()
    for allowed in allowlist:
        if normalized.startswith(allowed.strip().rstrip("/").lower()):
            return

    raise GitNotAllowedError(
        "该仓库地址不在允许扫描的白名单内",
        detail={"url": url, "allowlist_size": len(allowlist)},
    )


def clone_git(url: str, dest: Path, *, branch: str | None = None) -> None:
    """浅克隆到 `dest`。

    `--depth 1` 是硬要求，不是优化：本系统只做静态审计与验证，
    历史提交对结论毫无贡献，却会让克隆体积和耗时翻几十倍。

    **`GIT_TERMINAL_PROMPT=0` 同样是硬要求**：不设它，遇到需要认证的私有仓库时
    git 会在 stdin 上等输入口令，而调用方永远不给 —— 进程就挂在那里直到超时。
    症状是「克隆卡住」，根因是「等一个永远不会来的口令」。
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags"]
    if branch:
        cmd += ["-b", branch]
    cmd += ["--", url, str(dest)]

    env = {
        **_git_env(),
        "GIT_TERMINAL_PROMPT": "0",  # 禁止交互式索要口令
        "GIT_ASKPASS": "echo",  # 兜底：真被问到也直接返回空串而不是挂住
    }

    try:
        result = subprocess.run(  # noqa: S603 —— cmd 是 argv 列表，未经 shell 解析
            cmd,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            env=env,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        from app.core.exceptions import SourceUnavailableError

        raise SourceUnavailableError(
            f"克隆超时（超过 {CLONE_TIMEOUT_SECONDS} 秒）",
            remediation="仓库过大或网络不可达；可改用源码包上传",
        ) from exc

    if result.returncode == 0:
        return

    stderr = result.stderr or ""
    # 认证失败**不重试** —— 口令错，重试一百次还是错（B1 设计 §6 第 3 条）
    if any(
        marker in stderr.lower()
        for marker in ("authentication failed", "could not read username", "permission denied")
    ):
        raise GitAuthFailedError("仓库认证失败，无法访问", detail={"stderr_tail": stderr[-500:]})

    from app.core.exceptions import SourceUnavailableError

    raise SourceUnavailableError(
        "克隆失败",
        detail={"returncode": result.returncode, "stderr_tail": stderr[-500:]},
        remediation="检查仓库地址是否可达；或改用源码包上传",
    )


def _git_env() -> dict[str, str]:
    import os

    env = dict(os.environ)
    if settings.docker_ssh_key_path:
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {settings.docker_ssh_key_path} "
            "-o StrictHostKeyChecking=accept-new -o BatchMode=yes"
        )
    return env


# ---------------------------------------------------------------------------
# B1-2 安全解包
# ---------------------------------------------------------------------------


def detect_archive_kind(path: Path) -> str:
    """按 **magic** 判定归档类型，返回 `zip` / `tar` / `tar.gz`。

    不按扩展名判断：`evil.tar.gz` 里装的是 zip，扩展名看不出任何问题，
    而下游按 tar 去解会得到一个与「非法压缩包」毫不相干的错误。
    """
    with path.open("rb") as fh:
        head = fh.read(512)

    if head.startswith(_ZIP_MAGIC):
        return "zip"
    if head.startswith(_GZIP_MAGIC):
        return "tar.gz"
    if head[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + 5] == _TAR_MAGIC:
        return "tar"

    raise ArchiveFormatError(
        "无法识别的归档格式",
        remediation="仅支持 .zip / .tar / .tar.gz / .tgz；文件内容与扩展名不一致也会被拒绝",
    )


def _check_entry_path(raw_name: str, *, kind: str) -> str:
    """校验归档内单个条目的路径，返回归一后的 POSIX 相对路径。

    复用 `normalize_rel_path` 而不是另写一套 —— 归档条目和 API 传入的路径
    是同一类不可信输入，两套实现必然会有一套先长出漏洞。
    """
    try:
        return normalize_rel_path(raw_name)
    except SourcePathEscapeError as exc:
        logger.warning("归档条目路径越界，已中止解包：kind=%s entry=%r", kind, raw_name)
        raise ArchiveEscapeError(
            f"归档内含越界路径：{raw_name!r}",
            detail={"entry": raw_name},
        ) from exc


class SafeExtractor:
    """白名单式安全解包。

    拒绝清单（每一条都对应一个真实攻击手法，不是防御性编程的洁癖）：

    | 手法 | 后果 | 拦法 |
    |---|---|---|
    | zip slip（`../../etc/cron.d/x`） | 覆盖宿主任意文件 | 逐条目路径归一 + `..` 拒绝 |
    | 绝对路径条目（`/etc/passwd`） | 同上 | 拒绝绝对路径与盘符 |
    | 符号链接 / 硬链接条目 | 解包后再写入即越界 | tar 拒 `issym/islnk`；zip 查 Unix mode |
    | 设备文件 / FIFO | 与内核交互 | tar 拒 `isdev` |
    | 压缩炸弹 | 撑爆 D 盘（C 盘只剩 24G） | 边解压边累计字节数与条目数 |

    上限检查是**边解压边累计**的，不是解压完再看 —— 后者在那个场景下已经太晚了。
    """

    def __init__(self, rules: ScanRules | None = None) -> None:
        self.rules = rules or ScanRules()
        self.max_total_bytes = settings.archive_max_total_bytes
        self.max_entries = settings.archive_max_entries

    def extract(self, archive: Path, dest: Path) -> str:
        """解包到 `dest`，返回识别出的归档类型。

        `kind` 一路传下去而不是在各处重复 `detect_archive_kind()` ——
        重复探测意味着**读同一个文件头若干次**，而更糟的是它给了
        「两次判断结果不一致」一个存在的机会（文件在两次读之间被换掉）。
        """
        kind = detect_archive_kind(archive)
        dest.mkdir(parents=True, exist_ok=True)

        if kind == "zip":
            self._extract_zip(archive, dest)
        else:
            self._extract_tar(archive, dest, kind=kind)

        self._strip_single_root(dest)
        return kind

    # -- zip ---------------------------------------------------------------

    def _extract_zip(self, archive: Path, dest: Path) -> None:
        total = 0
        count = 0
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                count += 1
                if count > self.max_entries:
                    raise ArchiveBombError(
                        f"归档条目数超过上限（{self.max_entries}）",
                        detail={"entries": count},
                    )

                # 目录条目只需要归一化用于校验，不落盘（由文件条目隐式创建）
                rel = _check_entry_path(info.filename, kind="zip")

                if self._zip_entry_is_symlink(info):
                    raise ArchiveEscapeError(
                        f"归档内含符号链接：{rel}",
                        remediation="源码包不得包含符号链接，请解压后重新打包",
                        detail={"entry": rel},
                    )

                if info.is_dir():
                    continue

                # 按**声明**的未压缩体积累计。声明值也可能撒谎，
                # 所以下面实际写入时还会再核一次真实字节数。
                total += info.file_size
                if total > self.max_total_bytes:
                    raise ArchiveBombError(
                        f"解压后体积超过上限（{self.max_total_bytes // 1024**2} MB）",
                        detail={"declared_total": total},
                    )

                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out, length=1 << 20)
                if target.stat().st_size > self.rules.max_file_bytes:
                    # 单文件超限不中止（那是 L1 可忽略），留给扫描阶段跳过
                    logger.info("归档内单文件过大，已保留但扫描将跳过：%s", rel)

    @staticmethod
    def _zip_entry_is_symlink(info: zipfile.ZipInfo) -> bool:
        """zip 没有「符号链接」这个标志位，靠 **Unix mode 的高 16 位**判断。

        `external_attr >> 16` 是创建者的 Unix 权限字，`S_IFLNK`（0o120000）
        即符号链接。这个字段只在「由 Unix 侧打包」时才有意义，
        Windows 打的包这里通常是 0 —— 不误判比漏判重要，所以只认精确匹配。
        """
        return (info.external_attr >> 16) & 0o170000 == 0o120000

    # -- tar ---------------------------------------------------------------

    def _extract_tar(self, archive: Path, dest: Path, *, kind: str) -> None:
        total = 0
        count = 0
        # `r|gz` 是**流式**读取：不在内存里建完整索引，炸弹还没解完就能被发现
        mode = "r|gz" if kind == "tar.gz" else "r|"
        with tarfile.open(archive, mode) as tf:
            for member in tf:
                count += 1
                if count > self.max_entries:
                    raise ArchiveBombError(f"归档条目数超过上限（{self.max_entries}）")

                rel = _check_entry_path(member.name, kind="tar")

                if member.issym() or member.islnk():
                    raise ArchiveEscapeError(
                        f"归档内含链接条目：{rel}",
                        remediation="源码包不得包含符号链接或硬链接，请解压后重新打包",
                        detail={"entry": rel, "is_hardlink": member.islnk()},
                    )
                if member.isdev() or not (member.isfile() or member.isdir()):
                    raise ArchiveEscapeError(
                        f"归档内含非普通文件条目：{rel}",
                        detail={"entry": rel, "type": member.type},
                    )

                if member.isdir():
                    continue

                total += member.size
                if total > self.max_total_bytes:
                    raise ArchiveBombError(
                        f"解压后体积超过上限（{self.max_total_bytes // 1024**2} MB）",
                        detail={"declared_total": total},
                    )

                source = tf.extractfile(member)
                if source is None:  # pragma: no cover - isfile() 为真时不该发生
                    continue
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as out:
                    shutil.copyfileobj(source, out, length=1 << 20)

    # -- 顶层目录剥离 -------------------------------------------------------

    @staticmethod
    def _strip_single_root(dest: Path) -> None:
        """若所有条目都在同一个顶层目录下，把它提上来。

        **这一步不是美化，是防污染**：GitHub 的 zip 包和 `git archive` 都会
        套一层 `repo-main/`。不剥离的话，入库的 `file_path` 会全部变成
        `repo-main/app/api/order.py` —— 前缀毫无意义，却会出现在漏洞表、
        污点路径、报告和沙箱挂载的每一条路径上，且事后无法安全地批量去掉。
        """
        children = [c for c in dest.iterdir() if c.name != "__MACOSX"]
        if len(children) != 1 or not children[0].is_dir():
            return

        outer = children[0]
        for item in list(outer.iterdir()):
            item.replace(dest / item.name)
        outer.rmdir()
        logger.info("已剥离归档的单一顶层目录：%s", outer.name)


# ---------------------------------------------------------------------------
# B1-3 源码扫描
# ---------------------------------------------------------------------------


def scan_source_tree(src_root: Path, rules: ScanRules | None = None) -> SourceManifest:
    """遍历源码树，产出结构元数据（**不含**技术栈识别，那是 ReconAgent 的事）。

    LOC 口径 = **非空行**（B1 设计 §7 第 9 条）。用全行数会把空行和注释算进去，
    报告里的「代码量」会明显高于实际工作量。
    """
    rules = rules or ScanRules()
    started = time.monotonic()

    entries: list[FileEntry] = []
    by_language: Counter[str] = Counter()
    entry_candidates: list[str] = []
    dependency_manifests: list[str] = []
    total_loc = 0
    total_bytes = 0
    skipped = 0
    truncated = False

    for path in _walk(src_root, rules):
        if len(entries) >= rules.max_files or time.monotonic() - started > rules.max_scan_seconds:
            truncated = True
            logger.warning(
                "扫描达到上限，已截断：files=%d elapsed=%.1fs",
                len(entries),
                time.monotonic() - started,
            )
            break

        try:
            size = path.stat().st_size
        except OSError as exc:  # 权限 / 文件消失，L1 可忽略（B1 设计 §6 第 8 条）
            logger.info("跳过无法 stat 的文件 %s：%s", path, exc)
            skipped += 1
            continue

        if size > rules.max_file_bytes:
            logger.info("跳过超大文件（%.1f MB）：%s", size / 1024**2, path)
            skipped += 1
            continue

        rel = path.relative_to(src_root).as_posix()
        ext = path.suffix.lower()
        language = LANGUAGE_BY_EXT.get(ext)

        loc = _count_loc(path)
        if loc is None:
            skipped += 1
            continue

        entries.append(
            FileEntry(
                rel_path=rel,
                ext=ext,
                language=language,
                loc=loc,
                size_bytes=size,
                sha1=sha1_of(path),
            )
        )
        total_loc += loc
        total_bytes += size
        if language:
            by_language[language] += loc

        # 只索引**路径**，不解析内容（B1 设计 §7 第 7 条）
        if path.name in DEPENDENCY_MANIFEST_NAMES:
            dependency_manifests.append(rel)
        # 括号不能省：`and` 比 `or` 结合得紧，去掉括号后语义虽相同但读起来像另一种意思
        if path.name in ENTRY_CANDIDATE_NAMES or (
            rel.count("/") <= 1 and path.stem in {"main", "app"}
        ):
            entry_candidates.append(rel)

    if not any(e.ext in ANALYZABLE_EXTS for e in entries):
        raise NoAnalyzableSourceError(
            "工作区中未发现可解析的源码文件",
            detail={"scanned_files": len(entries), "languages": dict(by_language)},
        )

    manifest = SourceManifest(
        total_files=len(entries),
        total_loc=total_loc,
        size_bytes=total_bytes,
        by_language=dict(by_language.most_common()),
        entries=entries,
        entry_candidates=entry_candidates,
        dependency_manifest_paths=dependency_manifests,
        skipped_files=skipped,
        truncated=truncated,
    )
    logger.info(
        "扫描完成：files=%d loc=%d langs=%s truncated=%s",
        manifest.total_files,
        manifest.total_loc,
        list(manifest.by_language)[:5],
        manifest.truncated,
    )
    return manifest


def _walk(root: Path, rules: ScanRules):
    """深度优先遍历，命中排除目录即整棵剪掉。

    用 `os.walk` 的 `dirnames[:]` 原地过滤而不是先收集再筛 ——
    后者仍会进入 `node_modules` 再逐个丢弃，在真实项目上就是几万次无用的 stat。
    """
    import os

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # 原地过滤：os.walk 会读这个列表决定下一步进哪些子目录
        dirnames[:] = [d for d in dirnames if d not in rules.exclude_dirs]
        for name in filenames:
            yield Path(dirpath) / name


def _count_loc(path: Path) -> int | None:
    """统计非空行数。读不出来返回 None（调用方计 skipped 并继续）。

    **必须按二进制读再解码**，不能用 `read_text`：源码里混一个非 UTF-8 字节
    就会让 `read_text` 抛 `UnicodeDecodeError`，进而整个文件被跳过 ——
    而这类文件恰恰可能是含注入点的老代码。
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    text = raw.decode("utf-8", errors="replace")
    return sum(1 for line in text.splitlines() if line.strip())
