/**
 * 安全报告中心（路由 /reports）。
 *
 * 职责：列出报告 → 选中一份 → 在预览区查看 → 按需导出。
 *
 * 设计原则（可控多智能体）：报告的判定结论全部来自后端确定性代码，大语言模型只把
 * 结构化事实转写成自然语言。模型不可用时报告降级为模板文案，**结论一字不变**。
 * 因此本页面只做「展示 + 导出」，不做任何结论计算。
 */
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  FileMarkdownOutlined,
  FilePdfOutlined,
  FileTextOutlined,
  SyncOutlined,
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Empty, Space, Table, Tag, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { useState } from 'react'
import type { ReactNode } from 'react'

import { errorMessage } from '@/api/client'
import { reportApi } from '@/api/endpoints'
import type { Report } from '@/api/types'

import { ExportButtons } from '@/modules/report/ExportButtons'
import { ReportPreview } from '@/modules/report/ReportPreview'
import { formatBytes, formatDateTime } from '@/modules/report/format'

// 报告格式：颜色 + 图标 + 文字三重编码，不靠颜色单独区分
const FORMAT_META: Record<Report['format'], { label: string; color: string; icon: ReactNode }> = {
  html: { label: 'HTML', color: 'geekblue', icon: <FileTextOutlined /> },
  pdf: { label: 'PDF', color: 'purple', icon: <FilePdfOutlined /> },
  md: { label: 'Markdown', color: 'cyan', icon: <FileMarkdownOutlined /> },
}

const STATUS_META: Record<Report['status'], { label: string; color: string; icon: ReactNode }> = {
  generating: { label: '生成中', color: 'processing', icon: <SyncOutlined spin /> },
  ready: { label: '已就绪', color: 'success', icon: <CheckCircleOutlined /> },
  // 失败必须红色（color="error"），且带文字，不能只靠颜色
  failed: { label: '失败', color: 'error', icon: <CloseCircleOutlined /> },
}

export default function ReportCenter(): ReactNode {
  const [selectedId, setSelectedId] = useState<number | null>(null)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['reports'],
    queryFn: reportApi.list,
  })

  const reports = data?.items ?? []
  const selected = reports.find((r) => r.id === selectedId) ?? null

  const columns: TableColumnsType<Report> = [
    {
      title: '报告标题',
      dataIndex: 'title',
      key: 'title',
      render: (title: string) => <Typography.Text strong>{title}</Typography.Text>,
    },
    { title: '所属项目', dataIndex: 'project_name', key: 'project_name' },
    {
      title: '格式',
      dataIndex: 'format',
      key: 'format',
      width: 120,
      render: (format: Report['format']) => {
        const m = FORMAT_META[format]
        return (
          <Tag color={m.color} icon={m.icon}>
            {m.label}
          </Tag>
        )
      },
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 110,
      render: (status: Report['status']) => {
        const m = STATUS_META[status]
        return (
          <Tag color={m.color} icon={m.icon}>
            {m.label}
          </Tag>
        )
      },
    },
    {
      title: '文件大小',
      dataIndex: 'size_bytes',
      key: 'size_bytes',
      width: 110,
      align: 'right',
      render: (size: number | null) => formatBytes(size),
    },
    {
      title: '生成时间',
      dataIndex: 'generated_at',
      key: 'generated_at',
      width: 180,
      render: (iso: string) => formatDateTime(iso),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        message="报告中的判定结论由确定性代码产出，模型只负责措辞"
        description="漏洞有无、类型、严重度、CVSS、验证状态、攻击链拓扑、项目综合等级与整改顺序均不经模型；模型不可用时报告降级为模板文案，结论不变。"
      />

      {isError && (
        <Alert type="error" showIcon message="报告列表加载失败" description={errorMessage(error)} />
      )}

      <Card
        title="报告列表"
        styles={{ body: { padding: 0 } }}
        extra={
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            点击任意一行查看预览
          </Typography.Text>
        }
      >
        <Table<Report>
          rowKey="id"
          loading={isLoading}
          columns={columns}
          dataSource={reports}
          pagination={false}
          locale={{
            emptyText: <Empty description="暂无报告 —— 完成一次评估后，报告会出现在这里" />,
          }}
          onRow={(record) => ({
            onClick: () => setSelectedId(record.id),
            style: {
              cursor: 'pointer',
              // 选中行高亮，与下方预览区呼应
              background: record.id === selectedId ? '#e6f4ff' : undefined,
            },
          })}
        />
      </Card>

      <Card
        title={selected ? `报告预览 · ${selected.title}` : '报告预览'}
        extra={selected ? <ExportButtons report={selected} /> : null}
      >
        {selected ? (
          <ReportPreview report={selected} />
        ) : (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description="尚未选中报告 —— 请在上方列表中点击一行"
          />
        )}
      </Card>
    </Space>
  )
}
