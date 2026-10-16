"""内联 SVG 图表（B6 设计 §7.3 方案 A）。

**纯 Python 拼字符串，零外部依赖、零网络、零 JS。** 选它而不是 ECharts 截图的理由
（设计 §7.3）：报告必须**离线可成**（PRD §1.2 一键启动，不该依赖 CDN）；
SVG 是唯一能同时服务 HTML 与 PDF 的表达（矢量、打印清晰）；
Markdown 天然降级为表格。

只有三种图：CVSS 分布柱状图、漏洞类型占比环形图、评分环形图。手写量可控。

## ⚠️ 注入防护：返回 `Markup` 就必须自己负责转义

这些函数返回 `markupsafe.Markup`，意味着 **Jinja2 不会再对它们做 HTML 转义**
（`.html.j2` 开了 `autoescape=True`，但 `Markup` 被视为「已经安全」而原样输出）。
这正是我们要的 —— SVG 标签必须真的变成标签。

代价是：**凡是插进 SVG 的文本，必须在本文件里 `escape()` 一遍**。
图表的标签来自 `vuln_type`（规则库）与项目名，它们都不是用户可写的常数字面量，
但「不是常数字面量」不等于可信 —— 规则库会被扩充，项目名来自上传。这条规则没有例外。

## 关于 `# noqa: S704`

`S704`（unsafe use of Markup）是**有意留下的**：本模块的每一个插值点都经过 `_text()`
（内部走 `escape()`），而 `_text()` 是本文件唯一的文本入口 —— 这正是上面那段
「必须自己负责转义」的落地方式。把 S704 关进 per-file-ignores 也行，但写在调用点
上更好：它让「这里绕过了一次转义，原因是……」就停在那一行，谁改谁看见。
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from markupsafe import Markup, escape

from app.report.types import TypeSlice

#: 确定性调色板。**不随机取色** —— 同一个漏洞类型两次生成必须同色，
#: 否则报告的可复现性在肉眼层面就破产了。
PALETTE: tuple[str, ...] = (
    "#c0392b",
    "#e67e22",
    "#f1c40f",
    "#27ae60",
    "#2980b9",
    "#8e44ad",
    "#16a085",
    "#7f8c8d",
)

#: 严重度 → 颜色。与严重度的语义绑死（红/橙/黄/绿），不参与轮转。
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#27ae60",
}
_FONT = "font-family='-apple-system,BlinkMacSystemFont,Segoe UI,Microsoft YaHei,sans-serif'"


def _num(value: float) -> str:
    """统一数字格式。

    SVG 坐标动辄 `123.45678901`，既撑大文件又让「两次生成逐字节一致」变得脆弱
    （浮点末位在不同平台上有细微差异）。统一保留两位。
    """
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _text(value: object) -> str:
    """插进 SVG 的**任何**文本都从这里过 —— 这是本文件的注入防护闸。"""
    return str(escape(str(value)))


# ---------------------------------------------------------------------------
# 柱状图：CVSS / 严重度分布
# ---------------------------------------------------------------------------


def severity_bar_chart(
    counts: dict[str, int],
    *,
    order: Sequence[str] = ("critical", "high", "medium", "low"),
    labels: dict[str, str] | None = None,
    width: int = 560,
    height: int = 220,
) -> Markup:
    """各严重度的漏洞数量柱状图。

    空数据时返回**空字符串而不是空图**：空的坐标轴看起来像「图挂了」，
    而调用方（模板）在无漏洞时会走「未发现漏洞」空态，根本不该画图
    （B6 设计 §4.4 第 2 章降级形态）。
    """
    label_map = labels or {}
    series = [(key, int(counts.get(key, 0))) for key in order]
    peak = max((c for _, c in series), default=0)
    if peak <= 0:
        return Markup("")

    pad_l, pad_r, pad_t, pad_b = 44, 16, 16, 40
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    slot = plot_w / len(series)
    bar_w = slot * 0.52

    parts: list[str] = [
        f"<svg viewBox='0 0 {width} {height}' width='100%' role='img' "
        f"aria-label='漏洞严重度分布柱状图' {_FONT}>"
    ]

    # Y 轴：4 条网格线 + 刻度值。刻度用「向上取整到 5 的倍数」，
    # 免得出现 3.333 这种刻度值
    step = max(1, math.ceil(peak / 4))
    top = step * 4
    for i in range(5):
        value = step * i
        y = pad_t + plot_h - plot_h * (value / top)
        parts.append(
            f"<line x1='{pad_l}' y1='{_num(y)}' x2='{pad_l + plot_w}' y2='{_num(y)}' "
            "stroke='#e5e7eb' stroke-width='1'/>"
        )
        parts.append(
            f"<text x='{pad_l - 8}' y='{_num(y + 4)}' text-anchor='end' "
            f"font-size='11' fill='#6b7280'>{value}</text>"
        )

    for index, (key, count) in enumerate(series):
        ratio = count / top if top else 0.0
        bar_h = plot_h * ratio
        x = pad_l + slot * index + (slot - bar_w) / 2
        y = pad_t + plot_h - bar_h
        color = SEVERITY_COLORS.get(key, PALETTE[index % len(PALETTE)])
        label = label_map.get(key, key)
        if count > 0:
            parts.append(
                f"<rect x='{_num(x)}' y='{_num(y)}' width='{_num(bar_w)}' "
                f"height='{_num(bar_h)}' rx='3' fill='{color}'/>"
            )
        # 计数标在柱顶（0 也标，明确区分「没有」与「没画」）
        parts.append(
            f"<text x='{_num(x + bar_w / 2)}' y='{_num(y - 6)}' text-anchor='middle' "
            f"font-size='12' font-weight='600' fill='#374151'>{count}</text>"
        )
        parts.append(
            f"<text x='{_num(x + bar_w / 2)}' y='{height - pad_b + 20}' "
            f"text-anchor='middle' font-size='12' fill='#4b5563'>{_text(label)}</text>"
        )

    parts.append(
        f"<line x1='{pad_l}' y1='{pad_t + plot_h}' x2='{pad_l + plot_w}' "
        f"y2='{pad_t + plot_h}' stroke='#9ca3af' stroke-width='1'/>"
    )
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 —— 见模块文档：插值点全部经过 _text()


# ---------------------------------------------------------------------------
# 环形图：漏洞类型占比 / 评分
# ---------------------------------------------------------------------------


def type_donut(slices: Sequence[TypeSlice], *, size: int = 260, thickness: int = 30) -> Markup:
    """漏洞类型占比环形图 + 图例。

    **用 `stroke-dasharray` 而不是 `<path>` 画弧**：贝塞尔/弧线命令要算
    大弧标志与扫描方向，浮点边界上会偶发画出反向的一段；`dasharray` 只有一个
    除法，且各段长度之和恒等于周长，不会出现「图少了一块」的视觉 bug。
    """
    if not slices:
        return Markup("")

    center = size / 2
    radius = center - thickness / 2 - 2
    circumference = 2 * math.pi * radius
    total = sum(s.count for s in slices) or 1

    parts: list[str] = [
        f"<svg viewBox='0 0 {size} {size}' width='{size}' height='{size}' role='img' "
        f"aria-label='漏洞类型占比环形图' {_FONT}>",
        f"<g transform='rotate(-90 {_num(center)} {_num(center)})'>",
    ]

    offset = 0.0
    for index, item in enumerate(slices):
        arc = circumference * (item.count / total)
        color = PALETTE[index % len(PALETTE)]
        parts.append(
            f"<circle cx='{_num(center)}' cy='{_num(center)}' r='{_num(radius)}' fill='none' "
            f"stroke='{color}' stroke-width='{thickness}' "
            f"stroke-dasharray='{_num(arc)} {_num(circumference - arc)}' "
            f"stroke-dashoffset='{_num(-offset)}'/>"
        )
        offset += arc
    parts.append("</g>")
    parts.append(
        f"<text x='{_num(center)}' y='{_num(center - 2)}' text-anchor='middle' "
        f"font-size='22' font-weight='700' fill='#111827'>{total}</text>"
    )
    parts.append(
        f"<text x='{_num(center)}' y='{_num(center + 18)}' text-anchor='middle' "
        "font-size='11' fill='#6b7280'>条漏洞</text>"
    )
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 —— 见模块文档：插值点全部经过 _text()


def type_legend(slices: Sequence[TypeSlice]) -> Markup:
    """环形图的图例。**与环形图分开放**，因为 Markdown 只保留图例（表格形式）。"""
    if not slices:
        return Markup("")
    rows = []
    for index, item in enumerate(slices):
        color = PALETTE[index % len(PALETTE)]
        rows.append(
            "<li class='legend-item'>"
            f"<span class='legend-swatch' style='background:{color}'></span>"
            f"<span class='legend-label'>{_text(item.label)}</span>"
            f"<span class='legend-value'>{item.count}（{item.ratio * 100:.1f}%）</span>"
            "</li>"
        )
    return Markup(f"<ul class='legend'>{''.join(rows)}</ul>")  # noqa: S704 —— 同上


def score_ring(score: float, *, label: str, size: int = 180, thickness: int = 18) -> Markup:
    """项目安全评分环形图。`score` 越高越安全（0–100）。"""
    center = size / 2
    radius = center - thickness / 2 - 2
    circumference = 2 * math.pi * radius
    bounded = max(0.0, min(100.0, float(score)))
    arc = circumference * (bounded / 100.0)
    color = (
        "#c0392b"
        if bounded < 40
        else "#e67e22"
        if bounded < 70
        else "#f1c40f"
        if bounded < 90
        else "#27ae60"
    )

    return Markup(  # noqa: S704 —— 见模块文档：插值点全部经过 _text()
        f"<svg viewBox='0 0 {size} {size}' width='{size}' height='{size}' role='img' "
        f"aria-label='项目安全评分 {_num(bounded)} 分，项目综合等级{_text(label)}' {_FONT}>"
        f"<g transform='rotate(-90 {_num(center)} {_num(center)})'>"
        f"<circle cx='{_num(center)}' cy='{_num(center)}' r='{_num(radius)}' fill='none' "
        f"stroke='#e5e7eb' stroke-width='{thickness}'/>"
        f"<circle cx='{_num(center)}' cy='{_num(center)}' r='{_num(radius)}' fill='none' "
        f"stroke='{color}' stroke-width='{thickness}' "
        f"stroke-dasharray='{_num(arc)} {_num(circumference - arc)}'/>"
        "</g>"
        f"<text x='{_num(center)}' y='{_num(center + 4)}' text-anchor='middle' "
        f"font-size='30' font-weight='700' fill='#111827'>{_num(bounded)}</text>"
        f"<text x='{_num(center)}' y='{_num(center + 26)}' text-anchor='middle' "
        f"font-size='12' fill='#6b7280'>{_text(label)}</text>"
        "</svg>"
    )


__all__ = [
    "PALETTE",
    "SEVERITY_COLORS",
    "score_ring",
    "severity_bar_chart",
    "type_donut",
    "type_legend",
]
