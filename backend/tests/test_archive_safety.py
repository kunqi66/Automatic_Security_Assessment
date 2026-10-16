"""B1 安全解包测试。

归档是**用户上传**的不信任输入，而标准库的 `extractall()` / `unpack_archive()`
都不做 zip slip 与压缩炸弹防护 —— 也就是说这层防护一旦写漏，
表现是「功能完全正常，只是宿主机被写了文件」，不会有任何报错。

每个攻击样本都对应 B1 设计 §7 权衡表第 6 行里列出的具体手法。
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.core.config import settings
from app.projects.errors import (
    ArchiveBombError,
    ArchiveEscapeError,
    ArchiveFormatError,
    NoAnalyzableSourceError,
)
from app.projects.fetcher import SafeExtractor, detect_archive_kind, scan_source_tree
from app.projects.types import ScanRules

# ---------------------------------------------------------------------------
# 构造器
# ---------------------------------------------------------------------------


def make_zip(path: Path, entries: dict[str, bytes], *, symlink: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            # 高 16 位是 Unix 权限字，0o120000 = S_IFLNK。这是 zip 里
            # 表达「符号链接」的唯一方式，也是判定它的唯一依据。
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "/etc/passwd")
    return path


def make_tar(
    path: Path, entries: dict[str, bytes], *, link: tuple[str, bytes] | None = None
) -> Path:
    mode = "w:gz" if path.suffix == ".gz" else "w"
    with tarfile.open(path, mode) as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if link:
            name, target, link_type = link
            info = tarfile.TarInfo(name)
            info.type = link_type
            info.linkname = target
            tf.addfile(info)
    return path


# ---------------------------------------------------------------------------
# 应当拒绝
# ---------------------------------------------------------------------------


def test_rejects_zip_slip(tmp_path: Path) -> None:
    """zip slip：条目名上跳，写到解压目标之外。"""
    archive = make_zip(tmp_path / "a.zip", {"../../evil.py": b"pwned"})
    dest = tmp_path / "out"

    with pytest.raises(ArchiveEscapeError):
        SafeExtractor().extract(archive, dest)
    assert not (tmp_path / "evil.py").exists()


def test_rejects_absolute_path_entry(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "a.zip", {"/etc/cron.d/evil": b"pwned"})
    with pytest.raises(ArchiveEscapeError):
        SafeExtractor().extract(archive, tmp_path / "out")


def test_rejects_windows_style_traversal_in_zip(tmp_path: Path) -> None:
    """`..\\..\\evil.py`：只按 `/` 切分的实现会漏掉这个。"""
    archive = make_zip(tmp_path / "a.zip", {"..\\..\\evil.py": b"pwned"})
    with pytest.raises(ArchiveEscapeError):
        SafeExtractor().extract(archive, tmp_path / "out")


def test_rejects_zip_symlink_entry(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "a.zip", {"ok.py": b"x = 1\n"}, symlink="link.py")
    with pytest.raises(ArchiveEscapeError):
        SafeExtractor().extract(archive, tmp_path / "out")


def test_rejects_tar_symlink_entry(tmp_path: Path) -> None:
    """tar 的软链接：解包后再往里写就是越界写。"""
    archive = make_tar(
        tmp_path / "a.tar", {"ok.py": b"x = 1\n"}, link=("link.py", "/etc/passwd", tarfile.SYMTYPE)
    )
    with pytest.raises(ArchiveEscapeError):
        SafeExtractor().extract(archive, tmp_path / "out")


def test_rejects_tar_hardlink_entry(tmp_path: Path) -> None:
    """硬链接同样拒绝 —— 它能指向包外的已存在文件。"""
    archive = make_tar(
        tmp_path / "a.tar", {"ok.py": b"x = 1\n"}, link=("h.py", "/etc/passwd", tarfile.LNKTYPE)
    )
    with pytest.raises(ArchiveEscapeError):
        SafeExtractor().extract(archive, tmp_path / "out")


def test_rejects_tar_device_entry(tmp_path: Path) -> None:
    """设备文件：解包出来就是一个能与内核交互的节点。"""
    archive = make_tar(tmp_path / "a.tar", {"ok.py": b"x = 1\n"}, link=("dev", "", tarfile.CHRTYPE))
    with pytest.raises(ArchiveEscapeError):
        SafeExtractor().extract(archive, tmp_path / "out")


def test_rejects_bomb_by_total_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """压缩炸弹（按体积）。阈值调小以便快速触发，无需真造一个 500MB 的包。"""
    monkeypatch.setattr(settings, "archive_max_total_bytes", 1024)
    archive = make_zip(tmp_path / "a.zip", {"big.py": b"A" * 5000})

    with pytest.raises(ArchiveBombError):
        SafeExtractor().extract(archive, tmp_path / "out")


def test_rejects_bomb_by_entry_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """压缩炸弹（按条目数）。

    体积上限拦不住「十万个 1 字节文件」—— 总体积可能只有 100KB，
    但每个文件都要占一个 inode 与一个簇。两个上限缺一不可。
    """
    monkeypatch.setattr(settings, "archive_max_entries", 5)
    archive = make_zip(tmp_path / "a.zip", {f"f{i}.py": b"x" for i in range(20)})

    with pytest.raises(ArchiveBombError):
        SafeExtractor().extract(archive, tmp_path / "out")


def test_rejects_unknown_format(tmp_path: Path) -> None:
    junk = tmp_path / "a.zip"
    junk.write_bytes(b"not an archive at all")
    with pytest.raises(ArchiveFormatError):
        SafeExtractor().extract(junk, tmp_path / "out")


# ---------------------------------------------------------------------------
# 应当接受
# ---------------------------------------------------------------------------


def test_extracts_normal_zip(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "a.zip", {"app/main.py": b"x = 1\n", "README.md": b"hi\n"})
    dest = tmp_path / "out"

    assert SafeExtractor().extract(archive, dest) == "zip"
    assert (dest / "app" / "main.py").read_text(encoding="utf-8") == "x = 1\n"


def test_detects_format_by_magic_not_extension(tmp_path: Path) -> None:
    """**zip 改名成 .tar.gz**：扩展名是用户随手就能改的，只有 magic 可信。

    按扩展名判断的实现会拿 tarfile 去解一个 zip，报出的错与「格式不对」
    毫无关系，排查方向一开始就是歪的。
    """
    disguised = make_zip(tmp_path / "actually_tar.tar.gz", {"app/main.py": b"x = 1\n"})
    assert detect_archive_kind(disguised) == "zip"
    # 而且它应当被正常解出来，而不是因为扩展名被拒
    assert SafeExtractor().extract(disguised, tmp_path / "out") == "zip"


def test_strips_single_top_level_directory(tmp_path: Path) -> None:
    """GitHub 的 zip 包会套一层 `repo-main/`，必须剥掉。

    不剥的后果：入库 `file_path` 全变成 `repo-main/app/api/order.py`，
    这个前缀会渗进漏洞表、污点路径、沙箱挂载与报告，事后无法安全批量去除。
    """
    archive = make_zip(
        tmp_path / "a.zip",
        {"repo-main/app/main.py": b"x = 1\n", "repo-main/README.md": b"hi\n"},
    )
    dest = tmp_path / "out"
    SafeExtractor().extract(archive, dest)

    assert (dest / "app" / "main.py").is_file()
    assert not (dest / "repo-main").exists()


def test_keeps_tree_when_no_single_root(tmp_path: Path) -> None:
    """多个顶层目录时**不能**剥 —— 剥了就是丢文件。"""
    archive = make_zip(tmp_path / "a.zip", {"a/x.py": b"x = 1\n", "b/y.py": b"y = 2\n"})
    dest = tmp_path / "out"
    SafeExtractor().extract(archive, dest)

    assert (dest / "a" / "x.py").is_file()
    assert (dest / "b" / "y.py").is_file()


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------


def test_scan_counts_non_empty_lines_only(tmp_path: Path) -> None:
    """LOC 口径 = 非空行（设计 §7 第 9 条）。空行算进去会让报告里的
    「代码量」明显高于实际工作量。"""
    (tmp_path / "m.py").write_text("a = 1\n\n\n   \nb = 2\n", encoding="utf-8")
    manifest = scan_source_tree(tmp_path)

    assert manifest.total_loc == 2
    assert manifest.by_language == {"Python": 2}


def test_scan_excludes_vendor_dirs(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "big.js").write_text("var a;\n" * 100, encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("y = 1\n", encoding="utf-8")

    manifest = scan_source_tree(tmp_path)
    paths = {e.rel_path for e in manifest.entries}

    assert paths == {"app/main.py"}


def test_scan_rejects_workspace_without_python(tmp_path: Path) -> None:
    """0 个可解析源文件 → 建档失败（设计 §6 第 9 条）。

    这里刻意放一个 .js：它有 LOC、会计入 by_language，但**不构成可分析性** ——
    「有多少代码」与「能不能分析」是两个不同的问题。
    """
    (tmp_path / "app.js").write_text("var a = 1;\n", encoding="utf-8")

    with pytest.raises(NoAnalyzableSourceError):
        scan_source_tree(tmp_path)


def test_scan_indexes_manifest_paths_without_parsing(tmp_path: Path) -> None:
    """依赖清单只索引**路径**，内容解析归 ReconAgent（设计 §7 第 7 条）。"""
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    manifest = scan_source_tree(tmp_path)
    assert manifest.dependency_manifest_paths == ["requirements.txt"]
    assert "main.py" in manifest.entry_candidates


def test_scan_skips_oversized_file_but_continues(tmp_path: Path) -> None:
    """超大文件跳过而不是中止（L1 可忽略）—— 一个生成文件不该毁掉整轮扫描。"""
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "huge.py").write_bytes(b"#" * (3 * 1024 * 1024))

    manifest = scan_source_tree(tmp_path, ScanRules(max_file_bytes=1024 * 1024))

    assert {e.rel_path for e in manifest.entries} == {"main.py"}
    assert manifest.skipped_files == 1


# ---------------------------------------------------------------------------
# 上传落盘（Content-Length 不可信）
# ---------------------------------------------------------------------------


def test_spool_rejects_when_content_length_lies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`UploadFile.size` 来自 Content-Length，**是客户端可以撒谎的**。

    这里声明的 `size_bytes=10` 与实发的 4KB 不一致。如果上限只靠那个声明值来判断，
    一个声称 10 字节的请求就能塞进任意大的文件 —— 所以真正的上限必须在
    **边读边数**的字节数上，而 `_spool_to_disk` 就是那道闸。

    直接测这个私有函数是有意的：它是安全闸，不是内部实现细节。
    走 `ProjectService.ingest_archive` 需要真 MySQL + Redis + 工作区，
    而那三样在这个测试里都不是被验证的对象。
    """
    from app.projects.service import _spool_to_disk
    from app.projects.types import ArchiveUpload

    monkeypatch.setattr(settings, "archive_max_total_bytes", 1024)
    upload = ArchiveUpload(filename="a.zip", size_bytes=10, stream=io.BytesIO(b"A" * 4096))

    with pytest.raises(ArchiveBombError):
        _spool_to_disk(upload, tmp_path / "staging.zip")
