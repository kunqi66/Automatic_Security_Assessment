/**
 * 沙箱与环境配置（路由 /settings）。
 *
 * 两个页签：
 *   1. 沙箱配置 —— **可编辑，而且真的生效**。`OrchestrationEngine` 在每次运行
 *      开始时读 `is_default` 那行，注入 `AssessmentContext.sandbox_config`，
 *      由 `poc_verify` 传给验证引擎（总纲 §6.1 的注入点）。
 *   2. 大模型推理参数 —— 可编辑；顶部明确声明 API Key 不在此处、也不入库。
 *
 * 贯穿本页的第一性原则（可控多智能体）：大语言模型只产出自然语言文本，
 * 绝不参与任何判定。因此 LLM 页签的参数只影响「措辞」，调不出（也改不掉）任何结论。
 *
 * ⚠️ **沙箱页签原先不是这样。** 它曾经是纯只读展示，docstring 写的理由是
 * 「重点是把网络策略为什么必须是 internal 讲清楚」。但后端早就备好了写接口
 * （`PUT /admin/sandbox/configs`，带审计留痕与网络硬闸门），前端从来没接上 ——
 * 于是那个接口控制着一个没有任何引擎代码读的表。改这里不生效，比没有这个页面更糟。
 * 现在接通了（见 `engine._resolve_sandbox_config`）。
 */
import {
  CheckCircleOutlined,
  InfoCircleOutlined,
  SaveOutlined,
  SettingOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App,
  Button,
  Card,
  Descriptions,
  Empty,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Slider,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { TableColumnsType } from 'antd'
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'

import { errorMessage } from '@/api/client'
import { adminApi } from '@/api/endpoints'
import { can } from '@/api/types'
import type { LlmConfig, NetworkPolicy, SandboxConfig } from '@/api/types'
import { useAuth } from '@/store/auth'

// ---------------------------------------------------------------------------
// 网络策略 —— 沙箱安全设计的核心
// ---------------------------------------------------------------------------

const NETWORK_POLICY_META: Record<
  NetworkPolicy,
  { label: string; color: string; tip: string }
> = {
  none: {
    label: '无网络',
    color: 'default',
    tip: '容器不挂载任何网络接口，连回环都没有。仅适用于完全离线的静态检查，通常不需动态验证。',
  },
  internal: {
    label: '仅内网 · 禁出站',
    color: 'success',
    tip: '仅回环 + 任务内网可通信，禁止任何出站流量。这是系统默认，也是安全设计的核心 —— 沙箱内的验证代码无法把数据外传。',
  },
  bridge: {
    label: '桥接（不采用）',
    color: 'warning',
    tip: 'Docker 默认桥接网络，容器可访问外部网络。本系统不采用 —— 一旦验证载荷被目标代码影响，数据即可外泄。写入侧有硬闸门直接拒绝。',
  },
}

function NetworkPolicyTag({ value }: { value: NetworkPolicy }): ReactNode {
  const m = NETWORK_POLICY_META[value]
  return (
    <Tooltip title={m.tip}>
      <Tag color={m.color} style={{ cursor: 'help' }}>
        {m.label}
      </Tag>
    </Tooltip>
  )
}

/** 403 与「服务挂了」是两回事，提示也该是两回事。 */
function isForbidden(error: unknown): boolean {
  return (error as { response?: { status?: number } })?.response?.status === 403
}

/**
 * 当前用户能否管理沙箱与推理参数。
 *
 * **必须在 `useQuery` 之前调用** —— 拿它当 `enabled`，让无权的人**根本不发请求**。
 * 一个注定 403 的请求不该发出去：除了白跑一趟，它还会在控制台留下一条
 * 红色报错，而那正是本页要避免的「把权限问题伪装成故障」。
 */
function useMayManage(): boolean {
  const user = useAuth((s) => s.user)
  return can(user, 'sandbox:manage')
}

/**
 * 本页的「没权限」判据 —— **两道都要留**：
 *
 * ① 权限集合里没有 → 不发请求，直接显示提示（上面的 `enabled`）；
 * ② 权限集合说有、服务端仍然回 403 → 说明前端手里这份权限**已经过期**
 *    （例如管理员刚被降权，而 token 里的权限是登录那一刻的快照）。以服务端为准。
 *
 * 本页原先只有 ②：那时 `/auth/me` 不返回 `permissions`，只能靠响应码反推。
 * 现在权限码是直接给的，就不该再靠猜 —— 猜错的代价是把「你没权限」
 * 显示成「服务出错了」，用户会去找运维而不是找管理员。
 */
function forbiddenFor(mayManage: boolean, isError: boolean, error: unknown): boolean {
  return !mayManage || (isError && isForbidden(error))
}

function ForbiddenNotice(): ReactNode {
  return (
    <Alert
      type="info"
      showIcon
      message="当前账号没有管理权限"
      description="沙箱配置与推理参数只对系统管理员开放。接口层会独立校验权限（不依赖前端是否显示了按钮），这里的提示只是让你不至于把它当成故障。"
    />
  )
}

// ---------------------------------------------------------------------------
// 编辑弹窗
// ---------------------------------------------------------------------------

/** 可改字段 —— 与 `SandboxConfigUpdate` 对齐。`max_concurrency` 刻意不在其中。 */
interface SandboxFormValues {
  name: string
  base_image: string
  cpu_limit: number
  memory_limit_mb: number
  timeout_seconds: number
  is_default: boolean
}

function SandboxEditModal({
  row,
  onClose,
}: {
  row: SandboxConfig | null
  onClose: () => void
}): ReactNode {
  const [form] = Form.useForm<SandboxFormValues>()
  const queryClient = useQueryClient()
  // App.useApp() 而非静态 message —— 静态方法不消费 ConfigProvider 上下文
  const { message } = App.useApp()
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (row) form.setFieldsValue(row)
  }, [row, form])

  const onFinish = async (values: SandboxFormValues): Promise<void> => {
    if (!row) return
    setSaving(true)
    try {
      // body 是**数组**：后端契约是 `list[SandboxConfigUpdate]`，按每项 id 定位。
      await adminApi.updateSandboxConfig([{ id: row.id, ...values }])
      await queryClient.invalidateQueries({ queryKey: ['sandbox-configs'] })
      message.success('已保存 —— 从下一次评估开始生效')
      onClose()
    } catch (e) {
      message.error(errorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={row !== null}
      title={row ? `配置沙箱：${row.name}` : '配置沙箱'}
      onCancel={onClose}
      onOk={() => form.submit()}
      confirmLoading={saving}
      okText="保存"
      cancelText="取消"
      width={560}
    >
      <Form<SandboxFormValues>
        form={form}
        layout="vertical"
        onFinish={(v) => void onFinish(v)}
        style={{ marginTop: 16 }}
      >
        <Form.Item label="名称" name="name" rules={[{ required: true, message: '请填写名称' }]}>
          <Input maxLength={64} />
        </Form.Item>

        <Form.Item
          label="基础镜像"
          name="base_image"
          rules={[{ required: true, message: '请填写镜像' }]}
          extra="靶场源码只读挂载进这个镜像运行。运行期不做 pip install —— 容器无出网而 pip 需要联网，二者互斥，依赖必须预置在镜像里。"
        >
          <Input maxLength={255} />
        </Form.Item>

        {/* 网络策略只读。理由见下方 Alert —— 引擎侧恒为无出网，做成下拉框
            会让人以为它能切换行为，那就是个假控件。 */}
        <Form.Item label="网络策略" extra="只读：引擎侧是硬编码的不变量，不可通过配置改变。">
          <Input
            readOnly
            value={row ? NETWORK_POLICY_META[row.network_policy].label : ''}
            suffix={
              <Tooltip title={row ? NETWORK_POLICY_META[row.network_policy].tip : ''}>
                <InfoCircleOutlined style={{ color: '#8c8c8c' }} />
              </Tooltip>
            }
          />
        </Form.Item>

        <Form.Item
          label="超时时间（秒）"
          name="timeout_seconds"
          rules={[{ required: true, message: '请填写超时时间' }]}
          extra="单个探针的上限，不是整批容器。填 1–3600 秒。"
        >
          <InputNumber min={1} max={3600} style={{ width: '100%' }} />
        </Form.Item>

        <Space size={16} wrap>
          <Form.Item
            label="CPU 限制（核）"
            name="cpu_limit"
            rules={[{ required: true, message: '请填写 CPU 限制' }]}
          >
            <InputNumber min={0.1} max={16} step={0.1} style={{ width: 150 }} />
          </Form.Item>
          <Form.Item
            label="内存限制（MB）"
            name="memory_limit_mb"
            rules={[{ required: true, message: '请填写内存限制' }]}
          >
            <InputNumber min={128} max={32768} step={128} style={{ width: 170 }} />
          </Form.Item>
        </Space>

        {/* 并发数看得见、改不了。理由同网络策略：调度由 worker 固定为 1，
            引擎侧没有对应的执行参数 —— 可编辑就是个假控件。 */}
        <Form.Item
          label="并发任务数"
          extra="只读：调度并发由 worker 固定为 1（总纲 §8.1）—— 2 vCPU 下并发只会让所有任务都变慢，并撞 OOM。把资源约束变成透明的事实，而不是隐藏的瓶颈。"
        >
          <InputNumber readOnly value={row?.max_concurrency ?? 1} style={{ width: 150 }} />
        </Form.Item>

        <Form.Item
          label="设为默认"
          name="is_default"
          valuePropName="checked"
          extra="引擎每次运行开始时读这一行。设为默认会自动取消其它行的默认 —— 两行同时为默认会让引擎挑哪一行取决于 id，是个不报错的歧义。"
        >
          <Switch checkedChildren="默认" unCheckedChildren="不默认" />
        </Form.Item>

        <Alert
          type="warning"
          showIcon
          icon={<WarningOutlined />}
          message="CPU 与内存这两个数会真的作用到容器上"
          description="部署机是 2 vCPU / 7.3G 且无 swap，而动态验证是要真起容器的。把内存调大是这儿唯一能一次性搞垮整台机器的操作 —— 调大前先确认当前没有评估在跑。"
        />
      </Form>
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// Tab 1 · 沙箱配置
// ---------------------------------------------------------------------------

function SandboxTab(): ReactNode {
  const mayManage = useMayManage()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['sandbox-configs'],
    queryFn: adminApi.sandboxConfigs,
    enabled: mayManage,
  })

  // 后端返回**裸数组**（不是 `Page<T>`）。原先这里读 `data?.items`，
  // 于是恒为 undefined，表格永远空着 —— 数据到了前端却没人接得住。
  const configs = data ?? []
  const [editing, setEditing] = useState<SandboxConfig | null>(null)
  const forbidden = forbiddenFor(mayManage, isError, error)

  const columns: TableColumnsType<SandboxConfig> = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record) => (
        <Space>
          <Typography.Text strong>{name}</Typography.Text>
          {record.is_default && <Tag color="blue">默认</Tag>}
        </Space>
      ),
    },
    {
      title: '基础镜像',
      dataIndex: 'base_image',
      key: 'base_image',
      render: (image: string) => <Typography.Text code>{image}</Typography.Text>,
    },
    {
      title: (
        <Tooltip title="沙箱容器的网络可达范围，决定验证代码能否把数据传出沙箱">
          <Space size={4}>
            网络策略
            <InfoCircleOutlined style={{ color: '#8c8c8c' }} />
          </Space>
        </Tooltip>
      ),
      dataIndex: 'network_policy',
      key: 'network_policy',
      width: 160,
      render: (policy: NetworkPolicy) => <NetworkPolicyTag value={policy} />,
    },
    {
      title: 'CPU 限制',
      dataIndex: 'cpu_limit',
      key: 'cpu_limit',
      width: 100,
      align: 'right',
      render: (v: number) => `${v} 核`,
    },
    {
      title: '内存限制',
      dataIndex: 'memory_limit_mb',
      key: 'memory_limit_mb',
      width: 110,
      align: 'right',
      render: (v: number) => `${v} MB`,
    },
    {
      title: '超时时间',
      dataIndex: 'timeout_seconds',
      key: 'timeout_seconds',
      width: 110,
      align: 'right',
      render: (v: number) => `${v} 秒`,
    },
    {
      title: (
        <Tooltip title="调度并发数。固定为 1，不可通过本页修改（总纲 §8.1）。">
          <Space size={4}>
            并发
            <InfoCircleOutlined style={{ color: '#8c8c8c' }} />
          </Space>
        </Tooltip>
      ),
      dataIndex: 'max_concurrency',
      key: 'max_concurrency',
      width: 80,
      align: 'right',
    },
    {
      title: '操作',
      key: 'action',
      width: 90,
      render: (_: unknown, record) => (
        <Button
          type="link"
          size="small"
          icon={<SettingOutlined />}
          disabled={forbidden}
          onClick={() => setEditing(record)}
        >
          配置
        </Button>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert
        type="success"
        showIcon
        message="沙箱网络策略必须是 internal：验证代码无法把数据外传"
        description={
          <>
            沙箱内的验证代码与被测目标同处一个容器。若给出站能力，一旦验证载荷被目标代码影响，
            数据（源码、口令、内网探测结果）就可能被发往外部地址。策略设为{' '}
            <Typography.Text strong>internal</Typography.Text>{' '}
            意味着仅回环与任务内网可达、<Typography.Text strong>出站被切断</Typography.Text>，
            这是本系统安全模型的基石，而非可调的性能选项。
            <br />
            <Typography.Text type="secondary">
              正因如此，本页<Typography.Text strong>不提供</Typography.Text>
              切换网络模式的控件：引擎侧容器恒为{' '}
              <Typography.Text code>network_disabled=True</Typography.Text>
              ，不读数据库里的这个字段。该字段的作用是记录意图，并让{' '}
              <Typography.Text code>bridge</Typography.Text>{' '}
              在写入前就被服务端拒绝（防御性设计，不是可选项）。
            </Typography.Text>
          </>
        }
      />

      {forbidden && <ForbiddenNotice />}

      {isError && !forbidden && (
        <Alert type="error" showIcon message="沙箱配置加载失败" description={errorMessage(error)} />
      )}

      {/* 没权限时**连表格都不渲染**。留着它的话，空表会显示
          「暂无沙箱配置。用 seed_sandbox 写入默认配置」—— 而真相是
          配置可能正躺在库里，只是你看不到。把「看不到」说成「没有」，
          会让人去重跑一次 seed，或者去查一个并不存在的故障。 */}
      {!forbidden && (
        <Table<SandboxConfig>
          rowKey="id"
          loading={isLoading}
          columns={columns}
          dataSource={configs}
          pagination={false}
          locale={{
            emptyText: (
              <Empty
                description={
                  <span>
                    暂无沙箱配置。用{' '}
                    <Typography.Text code>
                      uv run python -m app.scripts.seed_sandbox
                    </Typography.Text>{' '}
                    写入默认配置。
                  </span>
                }
              />
            ),
          }}
        />
      )}

      <Card size="small" title="网络策略说明">
        <Descriptions
          column={1}
          size="small"
          items={[
            {
              key: 'none',
              label: <NetworkPolicyTag value="none" />,
              children: '无网络。完全离线，仅用于纯静态检查，动态验证无法进行。',
            },
            {
              key: 'internal',
              label: <NetworkPolicyTag value="internal" />,
              children:
                '仅回环 + 任务内网，禁出站。系统默认，也是安全设计的核心：沙箱内代码拿不到外网，数据出不去。',
            },
            {
              key: 'bridge',
              label: <NetworkPolicyTag value="bridge" />,
              children:
                'Docker 默认桥接网络，可访问外网。本系统不采用 —— 写入接口会直接拒绝（HTTP 400），因为一旦验证载荷被目标代码影响，它就成了一条通往内网的路。',
            },
          ]}
        />
      </Card>

      <SandboxEditModal row={editing} onClose={() => setEditing(null)} />
    </Space>
  )
}

// ---------------------------------------------------------------------------
// Tab 2 · 大模型推理参数
// ---------------------------------------------------------------------------

const PROVIDER_OPTIONS = [
  { label: 'DeepSeek', value: 'deepseek' },
  { label: 'OpenAI', value: 'openai' },
  { label: 'Azure OpenAI', value: 'azure_openai' },
  { label: '通义千问（兼容模式）', value: 'qwen' },
  { label: '本地 Ollama', value: 'ollama' },
]

function LlmTab(): ReactNode {
  const [form] = Form.useForm<LlmConfig>()
  const queryClient = useQueryClient()
  // App.useApp() 而非静态 message —— 静态方法不消费 ConfigProvider 上下文
  const { message } = App.useApp()
  const [saving, setSaving] = useState(false)

  const mayManage = useMayManage()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['llm-config'],
    queryFn: adminApi.getLlmConfig,
    enabled: mayManage,
  })

  // 拉到配置后回填表单
  useEffect(() => {
    if (data) form.setFieldsValue(data)
  }, [data, form])

  const onFinish = async (values: LlmConfig): Promise<void> => {
    setSaving(true)
    try {
      await adminApi.updateLlmConfig(values)
      // 失效 ['llm-config']：本页与顶栏的可用性提示（AppLayout）用的是同一个 key，会一起刷新
      await queryClient.invalidateQueries({ queryKey: ['llm-config'] })
      message.success('推理参数已保存')
    } catch (e) {
      message.error(errorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const forbidden = forbiddenFor(mayManage, isError, error)

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        message="API Key 不在此处配置，也不存入数据库"
        description="它只从后端 .env 的 DEEPSEEK_API_KEY 读取，由部署者自行填写。这样设计是为了避免密钥随数据库备份或导出而泄露。"
      />

      {data && !data.available && (
        <Alert
          type="warning"
          showIcon
          icon={<WarningOutlined />}
          message="模型当前不可用，报告与描述将降级为模板生成"
          description="判定结论、等级、攻击链拓扑、整改排序均不受影响 —— 它们由确定性代码产出，不经过模型。降级只改变措辞。"
        />
      )}

      {data && data.available && (
        <Alert
          type="success"
          showIcon
          icon={<CheckCircleOutlined />}
          message="模型可用"
          description="当前由模型负责把结构化事实转写为自然语言。请注意：无论如何，模型都不参与任何判定。"
        />
      )}

      {forbidden && <ForbiddenNotice />}

      {isError && !forbidden && (
        <Alert type="error" showIcon message="推理参数加载失败" description={errorMessage(error)} />
      )}

      <Card loading={isLoading}>
        <Form<LlmConfig>
          form={form}
          layout="vertical"
          onFinish={(v) => void onFinish(v)}
          style={{ maxWidth: 640 }}
        >
          <Form.Item label="Provider" name="provider" rules={[{ required: true }]}>
            <Select options={PROVIDER_OPTIONS} />
          </Form.Item>

          <Form.Item
            label="Base URL"
            name="base_url"
            rules={[{ required: true, message: '请填写 Base URL' }]}
          >
            <Input placeholder="https://api.deepseek.com/v1" />
          </Form.Item>

          <Form.Item label="Model" name="model" rules={[{ required: true, message: '请填写模型名' }]}>
            <Input placeholder="deepseek-chat" />
          </Form.Item>

          <Form.Item
            label="Temperature"
            name="temperature"
            extra="默认 0.2。本系统的模型只负责写自然语言文案，不参与任何判定，因此低温度只是为了让措辞稳定。"
          >
            <Slider min={0} max={2} step={0.1} marks={{ 0: '0', 1: '1', 2: '2' }} />
          </Form.Item>

          <Space size={16} wrap>
            <Form.Item label="Max Tokens" name="max_tokens">
              <InputNumber min={1} max={32768} step={128} style={{ width: 160 }} />
            </Form.Item>
            <Form.Item label="超时（秒）" name="timeout_seconds">
              <InputNumber min={1} max={300} style={{ width: 160 }} />
            </Form.Item>
            <Form.Item label="最大重试" name="max_retries">
              <InputNumber min={0} max={10} style={{ width: 160 }} />
            </Form.Item>
          </Space>

          <Form.Item style={{ marginBottom: 0 }}>
            <Button
              type="primary"
              htmlType="submit"
              icon={<SaveOutlined />}
              loading={saving}
              disabled={forbidden}
            >
              保存
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </Space>
  )
}

// ---------------------------------------------------------------------------
// 页面
// ---------------------------------------------------------------------------

export default function SandboxConfig(): ReactNode {
  return (
    <Tabs
      items={[
        { key: 'sandbox', label: '沙箱配置', children: <SandboxTab /> },
        { key: 'llm', label: '大模型推理参数', children: <LlmTab /> },
      ]}
    />
  )
}
