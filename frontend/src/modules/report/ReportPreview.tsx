/**
 * 报告预览区。
 *
 * 两种渲染方式：
 *  1. Markdown —— 用 react-markdown + remark-gfm 渲染报告正文（表格依赖 gfm）。
 *  2. HTML —— 用 iframe 隔离渲染，见下方安全硬约束。
 *
 * 判定类结论不论用哪种方式渲染都来自同一份结构化数据，模型不参与。
 *
 * **正文来自后端的真实产物**（`reportApi.download` 取回文本），
 * 不是本地示例。原先这里渲染的是 `sampleReport.tsx` 里的固定 HTML/MD ——
 * 而那段文案是基于靶场一写的，于是靶场二（usercenter）的报告预览会显示
 * **另一个靶场的内容**。它当时在页面上标了「预览内容为示例正文」，
 * 所以不算撒谎，但一个报告中心显示的不是它自己的报告，本身就是缺陷。
 */
import { SafetyCertificateOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Alert, Segmented, Spin, Typography } from 'antd'
import { useState } from 'react'
import type { ReactNode } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

import { errorMessage } from '@/api/client'
import { reportApi } from '@/api/endpoints'
import type { Report } from '@/api/types'

// Markdown 元素没有内联样式，AntD reset 后表格无边框 —— 用一段作用域内的 style 补上。
// 作用域限定在 .asa-report-md 之内，避免污染全局。
const MARKDOWN_STYLE = `
.asa-report-md { font-size: 13px; line-height: 1.8; color: #1f2329; }
.asa-report-md h1 { font-size: 20px; margin: 0 0 12px; }
.asa-report-md h2 { font-size: 16px; margin: 22px 0 8px; padding-bottom: 6px; border-bottom: 1px solid #f0f0f0; }
.asa-report-md h3 { font-size: 14px; margin: 16px 0 6px; }
.asa-report-md blockquote { margin: 8px 0; padding: 8px 12px; background: #fafafa; border-left: 3px solid #d9d9d9; color: #595959; }
.asa-report-md table { border-collapse: collapse; width: 100%; margin: 10px 0; }
.asa-report-md th, .asa-report-md td { border: 1px solid #e5e7eb; padding: 6px 10px; text-align: left; }
.asa-report-md th { background: #fafafa; font-weight: 600; }
.asa-report-md code { background: #f5f5f5; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
.asa-report-md hr { border: none; border-top: 1px solid #f0f0f0; margin: 18px 0; }
.asa-report-md li { margin: 2px 0; }
`

type PreviewMode = 'markdown' | 'html'

export function ReportPreview({ report }: { report: Report }): ReactNode {
  const [mode, setMode] = useState<PreviewMode>('markdown')
  // 预览只取 md / html：PDF 要起一次 Chromium（见 `report.py` 的惰性设计），
  // 不该在"切个 tab"这种动作上触发。要 PDF 走导出按钮。
  const fmt: Report['format'] = mode === 'markdown' ? 'md' : 'html'

  const { data, isPending, isError, error } = useQuery({
    queryKey: ['report-content', report.assessment_id, fmt],
    queryFn: async () => {
      // 借下载接口取字节再转文本：报告正文本就是"文件"，不为预览另开一个
      // 返回 JSON 字符串的接口 —— 那会有两份正文的渲染来源。
      const blob = await reportApi.download(report.assessment_id, fmt)
      return await blob.text()
    },
    // 报告一旦落盘就是只读产物（`report_gen` 之后没人再改它），所以不轮询、
    // 不重取。这与 `ResourceMetrics` 每 5s 轮询形成对照 —— 那个是持续写入的。
    staleTime: Infinity,
    // 404 就是"这一格式还没生成"，重试三次不会让文件出现，只会让用户多等
    retry: false,
    enabled: report.status === 'ready',
  })

  const header = (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 16,
        marginBottom: 12,
      }}
    >
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        预览为本次评估的实际报告正文。判定结论（漏洞、等级、攻击链、整改顺序）由确定性代码产出，模型不参与。
      </Typography.Text>
      <Segmented
        value={mode}
        onChange={(v) => setMode(v as PreviewMode)}
        options={[
          { label: 'Markdown 渲染', value: 'markdown' },
          { label: 'HTML 隔离渲染', value: 'html' },
        ]}
      />
    </div>
  )

  // 报告记录存在但还没生成完（`status !== 'ready'`，此时 `content_path` 为 null）：
  // 这种情况下 `enabled` 为 false，`isPending` 会**永远**是 true ——
  // 所以必须在 isPending 之前拦掉，否则用户看到的是一个永不结束的转圈。
  if (report.status !== 'ready') {
    return (
      <div>
        <style>{MARKDOWN_STYLE}</style>
        {header}
        <Alert
          type="info"
          showIcon
          message={`报告尚未生成完成（status = ${report.status}）`}
          description="报告由 report_gen 阶段产出；该阶段完成后本页会自动可用。"
        />
      </div>
    )
  }

  let body: ReactNode
  if (isPending) {
    body = (
      <div style={{ textAlign: 'center', padding: 40 }}>
        <Spin />
      </div>
    )
  } else if (isError) {
    body = (
      <Alert
        type="error"
        showIcon
        message="报告正文加载失败"
        description={errorMessage(error)}
      />
    )
  } else if (mode === 'markdown') {
    body = (
      <div className="asa-report-md" style={{ maxHeight: 620, overflow: 'auto', paddingRight: 8 }}>
        <Markdown remarkPlugins={[remarkGfm]}>{data ?? ''}</Markdown>
      </div>
    )
  } else {
    body = <HtmlPreview html={data ?? ''} title={report.title} />
  }

  return (
    <div>
      <style>{MARKDOWN_STYLE}</style>
      {header}
      {body}
    </div>
  )
}

// ---------------------------------------------------------------------------
// HTML 隔离预览
// ---------------------------------------------------------------------------

function HtmlPreview({ html, title }: { html: string; title: string }): ReactNode {
  return (
    <div>
      <Alert
        type="success"
        showIcon
        icon={<SafetyCertificateOutlined />}
        style={{ marginBottom: 12 }}
        message={'HTML 报告在空沙箱内渲染（sandbox=""）'}
        description={
          <>
            报告 HTML 由后端渲染，一律按 <strong>不可信内容</strong> 处理。sandbox 属性刻意留空，等价于关闭全部能力：
            禁止脚本执行、禁止表单提交、禁止同源访问（iframe 运行在不透明源下）。
            <br />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              绝不添加 allow-scripts；尤其不能同时出现 allow-scripts 与 allow-same-origin ——
              二者并存时可绕过沙箱访问父页面 DOM 与 Cookie，等于沙箱形同虚设。
            </Typography.Text>
          </>
        }
      />
      {/*
        安全硬约束：sandbox 必须是空字符串。
        - sandbox=""  → 不透明源、无脚本、无表单、无同源，能挡住报告 HTML 里的任何脚本。
        - 若加 allow-scripts，报告内的脚本就能执行；若再叠加 allow-same-origin，
          脚本便可读写父页面（等于把整个前端交出去）。因此这两个 token 被永久禁止。
      */}
      <iframe
        title={`HTML 报告隔离预览 · ${title}`}
        srcDoc={html}
        sandbox=""
        referrerPolicy="no-referrer"
        style={{
          width: '100%',
          height: 520,
          border: '1px solid #f0f0f0',
          borderRadius: 6,
          background: '#fff',
        }}
      />
    </div>
  )
}
