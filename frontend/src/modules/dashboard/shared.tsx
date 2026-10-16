/**
 * 概览大盘的图表公共件：语义色表、图例、文字与坐标轴 token。
 *
 * 三条硬约束 —— 写在最前面，因为它们决定了下面每一个取值：
 *
 * 1. **前端不做任何推算。**
 *    本系统的核心设计原则是「LLM 只产出自然语言文案，一切判定与数字由确定性代码产出」。
 *    因此本模块里的每一个数字都**原样**来自后端 `DashboardSummary`：
 *    不求和、不算占比、不排序、不排名。颜色与图例只负责一件事 ——
 *    把后端已经算好的值翻译成人看得懂的样子。若哪天这里出现了 `reduce` / `sort` / `/total`，
 *    那就是把判定权从前端捡了回来，属于设计错误。
 *
 * 2. **颜色是冗余编码，不是唯一编码。**
 *    每个图表都必须同时给出文字（图例 / 坐标轴 / 说明），让色盲用户、黑白打印、
 *    截图转灰都能读出来 —— 与 `components/tags.tsx` 的「颜色 + 文字 + 图标」同一条无障碍规则。
 *
 * 3. **配色经过校验，不是凭感觉挑的。**
 *    以 OKLab ΔE 逐项验证：明度带 / 色度下限 / 相邻对 CVD 分离度（protan · deutan · tritan）/
 *    正常视觉分离度。结论记录在每张色表旁，残余风险也一并写明。
 */
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  QuestionCircleOutlined,
  StopOutlined,
} from '@ant-design/icons'
import type { ReactNode } from 'react'

import type { SecurityGrade, Severity, VulnStatus } from '@/api/types'

// ---------------------------------------------------------------------------
// 文字与坐标轴 token
// ---------------------------------------------------------------------------

/**
 * 图表里的文字一律用中性墨色，**不用系列色**。
 * 颜色由色块承担「这是哪一类」，文字只承担可读性 —— 彩色文字在浅色底上对比度不达标，
 * 灰度打印时更会糊成一片。
 */
export const INK = {
  primary: 'rgba(0, 0, 0, 0.88)',
  secondary: 'rgba(0, 0, 0, 0.65)',
  muted: 'rgba(0, 0, 0, 0.45)',
} as const

/** 网格与轴线保持退让：数据是主角，坐标系是背景 */
export const AXIS_LINE_STYLE = { lineStyle: { color: 'rgba(0, 0, 0, 0.15)' } } as const
export const SPLIT_LINE_STYLE = { lineStyle: { color: 'rgba(0, 0, 0, 0.06)' } } as const

/** 三个图共用同一套留白，避免并排时基线对不齐 */
export const CHART_GRID = {
  left: 8,
  right: 24,
  top: 24,
  bottom: 8,
  containLabel: true,
} as const

// ---------------------------------------------------------------------------
// 顺序表
// ---------------------------------------------------------------------------

/**
 * 以下三个顺序**不是随手排的**，它们同时是：
 * - 图表的渲染顺序；
 * - 配色校验时取「相邻对」的顺序。
 * 改动顺序必须重新跑一遍调色板校验，否则相邻色块可能突然变成难以分辨的一对。
 */

/** 环形图渲染顺序：严重 → 高危 → 中危 → 安全（安全只与严重、中危相邻，见 GRADE_COLOR 注释） */
export const GRADE_ORDER: SecurityGrade[] = ['critical', 'high', 'medium', 'safe']

/** 严重度由高到低的自然次序 —— 有序量用条形图，顺序本身就是信息 */
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low']

/** 四态按「证据强度」降序：已验证 → 潜在 → 待验证 → 已排除（与 tags.tsx 的排列一致） */
export const VULN_STATUS_ORDER: VulnStatus[] = ['verified', 'potential', 'unverified', 'rejected']

// ---------------------------------------------------------------------------
// 项目综合等级（security_grade）
// ---------------------------------------------------------------------------

/**
 * ⚠️ 与下面的 SEVERITY_COLOR 是**两套独立概念**：这里描述「整个项目」的结论，
 * 那里描述「单条漏洞」的严重度。两处只是恰好复用同一批语义色族，不是同一份数据。
 *
 * 校验结论（浅色面、环形相邻对 critical→high→medium→safe）：
 * 明度带 ✓ / 色度下限 ✓ / 正常视觉最小 ΔE 18.9 ✓ / 相邻对 CVD ✓。
 * 残余风险：「安全」的绿与「高危」的橙在红绿色盲下几乎不可分（protan ΔE≈2.4），
 * 因此这里依赖两件事兜底 —— ① 环形顺序固定，绿与橙永远不相邻；
 * ② 每一片都带文字图例（名称 + 数量），身份从不单独由颜色承担。
 */
export const GRADE_COLOR: Record<SecurityGrade, string> = {
  critical: '#a8071a',
  high: '#e8590c',
  medium: '#d4b106',
  safe: '#237804',
}

export const GRADE_LABEL: Record<SecurityGrade, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  safe: '安全',
}

// ---------------------------------------------------------------------------
// 漏洞严重度（severity）
// ---------------------------------------------------------------------------

/**
 * 校验结论（浅色面、连续次序 critical→high→medium→low）：全部通过，
 * 含全组合（非相邻对）CVD 分离度 —— 因此条形图里任意两根柱子都区分得开。
 */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#a8071a',
  high: '#e8590c',
  medium: '#d4b106',
  low: '#0958d9',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

// ---------------------------------------------------------------------------
// 漏洞四态（需求 2.5.4）
// ---------------------------------------------------------------------------

export interface VulnStatusMeta {
  label: string
  color: string
  icon: ReactNode
  /** 一句话说明这个状态到底意味着什么 —— 页面上必须与数字一起出现 */
  meaning: string
}

/**
 * 四态的含义（与后端判定口径一一对应，前端不重新解释）：
 * - 已验证 沙箱内无害探针实际命中，证据充分；
 * - 潜在   静态命中但未通过动态验证（含被 HarmlessGuard 拦下的），有风险但证据不足；
 * - 待验证 静态审计已标记，尚未进入动态验证环节；
 * - 已排除 经人工复核判定为误报，不计入风险统计。
 *
 * 「已排除」刻意用中性灰：它是「被排除出风险口径」的状态，本就不该在色相上与其他三态争抢注意力。
 * 校验脚本对它的色度下限报 FAIL，这是**有意为之**——那条下限针对的是需要靠色相区分的分类调色板；
 * 而这里每个状态都同时带图标与文字说明，语义不依赖色相。
 * 残余风险：灰与绿在 tritan 下 ΔE≈6.6，落在「仅在有二次编码时可用」的区间 —— 图标与文字即是二次编码。
 */
export const VULN_STATUS_META: Record<VulnStatus, VulnStatusMeta> = {
  verified: {
    label: '已验证',
    color: '#237804',
    icon: <CheckCircleOutlined />,
    meaning: '沙箱内无害探针实际命中，证据充分',
  },
  potential: {
    label: '潜在',
    color: '#d4b106',
    icon: <QuestionCircleOutlined />,
    meaning: '静态命中但未通过动态验证（含被 HarmlessGuard 拦下），有风险但证据不足',
  },
  unverified: {
    label: '待验证',
    color: '#0958d9',
    icon: <ClockCircleOutlined />,
    meaning: '静态审计已标记，尚未进入动态验证环节',
  },
  rejected: {
    label: '已排除',
    color: '#8c8c8c',
    icon: <StopOutlined />,
    meaning: '经人工复核判定为误报，不计入风险统计',
  },
}

// ---------------------------------------------------------------------------
// 图例
// ---------------------------------------------------------------------------

export interface LegendItem {
  /** 色块颜色 —— 身份由它 + 旁边的文字共同承担 */
  color: string
  label: string
  /** 后端返回的原始计数，前端只负责显示 */
  value: number
}

/**
 * 自绘图例（环形图与条形图共用）。
 *
 * 为什么不用 ECharts 自带的 `legend`：条形图是单系列、按数据点着色，
 * 而 ECharts 的 legend 只能按「系列名」取色 —— 单系列下它根本表达不出
 * 「每个颜色代表哪一类」。既然如此，就在两个图里统一用列表式图例，
 * 顺带满足无障碍要求里那条「填充色对比度低于 3:1 时必须以可见文字兜底」：
 * 本页的中危金（#d4b106）对比度约 2.0:1，正是靠这份带数字的文字图例兜底的。
 */
export function ChartLegend({ items }: { items: LegendItem[] }): ReactNode {
  return (
    <ul
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '6px 20px',
        listStyle: 'none',
        margin: 0,
        padding: 0,
      }}
    >
      {items.map((item) => (
        <li
          key={item.label}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 12,
            color: INK.secondary,
          }}
        >
          {/* 装饰性色块：语义由右侧文字承载，故对读屏隐藏 */}
          <span
            aria-hidden="true"
            style={{
              width: 10,
              height: 10,
              borderRadius: 2,
              background: item.color,
              flex: '0 0 auto',
            }}
          />
          <span>{item.label}</span>
          <strong style={{ color: INK.primary, fontWeight: 600 }}>{item.value}</strong>
        </li>
      ))}
    </ul>
  )
}
