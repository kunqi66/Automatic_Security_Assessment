/**
 * 报告中心用到的纯展示辅助函数。
 * 不依赖 React，但按约束统一放在 report 模块下（* .tsx）。
 */
import dayjs from 'dayjs'

import type { Report } from '@/api/types'

/**
 * 导出时落盘的文件名。**必须与后端 `Content-Disposition` 的生成规则逐字一致**
 * （`reports.py::download_report` 用的是 `assessment-{id}-report.{fmt}`）——
 * 否则同一个报告经「下载接口」与「导出按钮」两条路拿到的文件会叫两个名字。
 *
 * 为什么不从响应头读 `Content-Disposition`：`reportApi.download` 只返回 Blob，
 * 响应头在这一层就被丢掉了；要读它就得把签名改成返回 `{ blob, filename }`。
 * 为一个字符串多加一层包装不划算 —— 但**这条约定两边要一起改**，所以写在这里。
 */
export function reportFileName(report: Pick<Report, 'assessment_id' | 'format'>): string {
  return `assessment-${report.assessment_id}-report.${report.format}`
}

/** 字节数转可读体积：B / KB / MB */
export function formatBytes(bytes: number | null): string {
  if (bytes === null || bytes === undefined) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`
}

/** ISO 时间戳转本地可读时间 */
export function formatDateTime(iso: string | null): string {
  if (!iso) return '—'
  return dayjs(iso).format('YYYY-MM-DD HH:mm:ss')
}
