"""报告产物的路径规则（总纲 §7.4 / B6 设计 §5.2）。

## 一条规则：入库的路径一律是「相对 + POSIX」

```
{report_root}/{assessment_id}/report.html
{report_root}/{assessment_id}/report.md
{report_root}/{assessment_id}/report.pdf
```

入库的是 `reports/{assessment_id}/report.html` 这种相对路径，**绝不入绝对路径**。
绝对路径一旦入库，报告换台机器（开发机 → ECS）就读不了，
而失败形态是「下载 404」而不是「路径非法」—— 排查方向会被带偏。

## ⚠️ 与设计文档 §5.2 的一处偏离（写进交付报告）

设计 §5.2 写的字面路径是 `{REPORT_ROOT}/reports/{assessment_id}/report.*`。
但 `core/config.py` 里的 `report_root` 默认值是 `.../.asa/reports`，
即**它本身就已经是报告根目录** —— 照字面拼会得到 `.../reports/reports/{id}`。
这里以 config 为准（配置项是运行期 SSOT），目录层级少一层。

## ⚠️ 路径逃逸

`content_path` 是从数据库读回来的，而数据库里的字符串**不是**可信输入
（可能被手工改过、可能来自旧版本的写入逻辑）。`resolve()` 因此对拼接结果做
`is_relative_to` 校验 —— 少了这一步，一个 `../../../etc/passwd` 就能让
「下载报告」接口变成任意文件读取。
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import settings
from app.models.enums import ReportFormat
from app.report.errors import ReportWriteError

#: 扩展名映射。`md` 用 `.md` 而不是 `.markdown` —— 与 `ReportFormat.MD` 的值一致。
_EXTENSION: dict[str, str] = {
    ReportFormat.HTML.value: "html",
    ReportFormat.MD.value: "md",
    ReportFormat.PDF.value: "pdf",
}


def report_root() -> Path:
    """报告根目录（绝对路径，仅运行期内存有，不入库）。"""
    return Path(settings.report_root)


def relative_dir(assessment_id: int) -> str:
    """`{assessment_id}` —— 相对 `report_root` 的目录，POSIX 分隔符。"""
    return str(int(assessment_id))


def relative_path(assessment_id: int, fmt: ReportFormat | str) -> str:
    """`{assessment_id}/report.{ext}` —— 入库用的相对路径。"""
    return f"{relative_dir(assessment_id)}/report.{_extension(fmt)}"


def absolute_dir(assessment_id: int) -> Path:
    return report_root() / relative_dir(assessment_id)


def absolute_path(assessment_id: int, fmt: ReportFormat | str) -> Path:
    return report_root() / relative_path(assessment_id, fmt)


def ensure_dir(assessment_id: int) -> Path:
    """建目录。磁盘满 / 无权限在这里就会暴露成 `ReportWriteError`（不可降级）。"""
    target = absolute_dir(assessment_id)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportWriteError(
            f"报告目录创建失败：{target}",
            detail={"path": str(target), "reason": str(exc)},
        ) from exc
    return target


def resolve(relative: str) -> Path:
    """相对路径 → 绝对路径，**带逃逸校验**。

    只接受 `report_root` 之下的路径。用 `Path.resolve()` 先归一化再比较，
    是因为 `a/../../b` 这种字符串在拼接前看不出问题 —— 归一化之后才现形。
    """
    root = report_root().resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        raise ReportWriteError(
            f"报告路径越出报告根目录，已拒绝：{relative}",
            detail={"relative": relative, "root": str(root)},
            retryable=False,
        )
    return candidate


def _extension(fmt: ReportFormat | str) -> str:
    value = str(getattr(fmt, "value", fmt))
    ext = _EXTENSION.get(value)
    if ext is None:
        # 新增 `ReportFormat` 取值却不加扩展名，会得到一个叫 `report.` 的文件 ——
        # 响亮地失败比安静地写出一个没有后缀的文件好
        raise ReportWriteError(f"未知的报告格式：{value}", retryable=False)
    return ext


__all__ = [
    "absolute_dir",
    "absolute_path",
    "ensure_dir",
    "relative_dir",
    "relative_path",
    "report_root",
    "resolve",
]
