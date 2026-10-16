/**
 * 人工复核页签（Tab 3）。
 *
 * 引擎给出的四态是确定性代码算出来的，脚本不会自己改变结论；**人工复核是唯一
 * 被允许覆盖它的入口**，且这次覆盖会连同操作者一起被后端记录下来 —— 这样报告里
 * 「为什么这条被判成已排除」永远有据可查，而不是被模型悄悄改掉。
 */
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Divider, Popconfirm, Space, Typography } from 'antd'
import type { ReactNode } from 'react'

import { vulnApi } from '@/api/endpoints'
import type { Vulnerability, VulnStatus } from '@/api/types'
import { VulnStatusTag } from '@/components/tags'

const { Text, Paragraph } = Typography

export function ReviewPanel({ vuln }: { vuln: Vulnerability }): ReactNode {
  const queryClient = useQueryClient()
  // App.useApp() 而非静态 message —— 静态方法不消费 ConfigProvider 上下文
  const { message } = App.useApp()

  const mutation = useMutation({
    mutationFn: (status: VulnStatus) => vulnApi.updateStatus(vuln.id, status),
    onSuccess: () => {
      // 列表（表格 + 状态筛选）与当前详情都要失效，否则界面会停在旧状态上
      void queryClient.invalidateQueries({ queryKey: ['vulns'] })
      void queryClient.invalidateQueries({ queryKey: ['vuln', vuln.id] })
      message.success('复核结论已保存，列表与详情已刷新')
    },
    onError: (error: unknown) => {
      message.error(error instanceof Error ? error.message : '保存失败')
    },
  })

  const pending = (status: VulnStatus): boolean =>
    mutation.isPending && mutation.variables === status

  return (
    <div>
      <Space wrap size={8} align="center">
        <Text type="secondary">当前状态</Text>
        <VulnStatusTag value={vuln.status} />
      </Space>

      <Divider style={{ margin: '12px 0' }} />

      <Paragraph>
        这里给出的是<Text strong>人工判定</Text>
        ：它会覆盖引擎结论，并由后端记录操作者与时间。引擎不会因为这次点击而改变自己的算法 ——
        人工结论是叠加在引擎结论之上的一层，报告里两者分别可见。
      </Paragraph>

      <Space wrap>
        <Popconfirm
          title="确认排除该漏洞？"
          description="排除后这条不计入风险统计，请确认确属误报。"
          okText="确认排除"
          cancelText="取消"
          disabled={vuln.status === 'rejected'}
          onConfirm={() => mutation.mutate('rejected')}
        >
          <Button danger disabled={vuln.status === 'rejected'} loading={pending('rejected')}>
            标记为已排除
          </Button>
        </Popconfirm>

        <Button
          type="primary"
          ghost
          disabled={vuln.status === 'potential'}
          loading={pending('potential')}
          onClick={() => mutation.mutate('potential')}
        >
          标记为潜在
        </Button>
      </Space>

      <Alert
        style={{ marginTop: 16 }}
        type="info"
        showIcon
        message="什么时候该用这两个按钮"
        description="「已排除」用于静态命中的误报（例如上游已有净化函数）；「潜在」用于动态验证没能坐实、但风险依然存在的情况（例如被 HarmlessGuard 载荷闸门拦下）。"
      />
    </div>
  )
}
