/**
 * 报告导出按钮组：PDF / HTML / Markdown。
 *
 * 设计要点：
 *  - 导出是**显式的用户动作**，只在点击时才发起请求（PDF 尤其如此 —— 后端渲染 PDF 昂贵，
 *    绝不在列表加载或选中报告时预取）。因此这里用「点击触发」而非 useQuery 自动拉取。
 *  - 每个格式各自维护 loading，互不串扰；导出中禁用整组，避免并发重复导出。
 *  - **导出是两步：先生成，再把字节取回来。** 少了第二步，用户会看到一句
 *    「已导出」而磁盘上什么都没有 —— 见 `handleExport` 里的说明。
 */
import { FileMarkdownOutlined, FilePdfOutlined, FileTextOutlined } from '@ant-design/icons'
import { App, Button, Space } from 'antd'
import { useState } from 'react'
import type { ReactNode } from 'react'

import { errorMessage } from '@/api/client'
import { reportApi } from '@/api/endpoints'
import type { Report } from '@/api/types'

import { formatBytes, reportFileName } from './format'

interface Props {
  report: Report
}

/**
 * 触发浏览器下载。
 *
 * 用 `<a download>` + object URL，而不是 `window.open(url)`：后者会被弹窗拦截器
 * 拦掉，而**被拦掉时不会报任何错** —— 表现为"点了没反应"，正是最难查的那种失败。
 */
function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  // 立刻回收：字节已经交给下载器了，不 revoke 会让这份报告一直占着内存
  URL.revokeObjectURL(url)
}

/**
 * `format` 是存储值（`md` 不是 `markdown`），`name` 是给人看的显示名 —— 两者分开，
 * 提示语里才不会出现「已导出 MD」这种生硬措辞。
 */
const FORMATS: Array<{ format: Report['format']; name: string; label: string; icon: ReactNode }> = [
  { format: 'pdf', name: 'PDF', label: '导出 PDF', icon: <FilePdfOutlined /> },
  { format: 'html', name: 'HTML', label: '导出 HTML', icon: <FileTextOutlined /> },
  { format: 'md', name: 'Markdown', label: '导出 Markdown', icon: <FileMarkdownOutlined /> },
]

export function ExportButtons({ report }: Props): ReactNode {
  // 用 App.useApp() 而非 antd 的静态 message：静态方法不消费 ConfigProvider 上下文，
  // 拿不到本项目的主题与中文 locale。
  const { message } = App.useApp()
  // 记录当前正在导出哪个格式 —— 该按钮显示 loading，其余按钮禁用
  const [pending, setPending] = useState<Report['format'] | null>(null)

  const handleExport = async (format: Report['format'], name: string): Promise<void> => {
    setPending(format)
    try {
      // ① 让后端把这一格式生成出来（PDF 若是首次生成，贵的就是这一步）
      //    导出挂在评估任务下，故传 assessment_id 而不是 report.id
      await reportApi.export(report.assessment_id, format)

      // ② 再把字节取回来并落盘。
      //
      // **这一步原先是不存在的**，于是"导出"只弹了一句
      // 「已导出 PDF：14/report.pdf」—— 那个路径是**服务端**的
      // （`D:/myself_complete_code/.asa/reports/14/report.pdf`），
      // 浏览器根本够不着，用户点完什么都不会落下。
      // `reportApi.download` 一直写好了却没有任何地方调用它。
      //
      // 分成两个请求不是冗余：`export` 幂等（已生成就直接返回记录），
      // 而 `download` 只读文件，失败时能以 404/500 明确区分"没生成"与"读不出"。
      const blob = await reportApi.download(report.assessment_id, format)
      saveBlob(blob, reportFileName({ assessment_id: report.assessment_id, format }))
      message.success(`已下载 ${name}（${formatBytes(blob.size)}）`)
    } catch (e) {
      message.error(errorMessage(e))
    } finally {
      setPending(null)
    }
  }

  return (
    <Space>
      {FORMATS.map((f) => (
        <Button
          key={f.format}
          icon={f.icon}
          // PDF 懒加载：只有用户点了这个按钮才会向后端发请求
          loading={pending === f.format}
          disabled={pending !== null && pending !== f.format}
          onClick={() => void handleExport(f.format, f.name)}
        >
          {f.label}
        </Button>
      ))}
    </Space>
  )
}
