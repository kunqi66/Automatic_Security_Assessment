/**
 * 「新建评估」—— 建档 / 选已有项目 → （补传源码）→ 启动，一个弹窗走完。
 *
 * ## 状态：已挂载，端到端跑通
 *
 * 入口在概览大盘右上角（`pages/Dashboard/index.tsx`），受 `assessment:create` 门控：
 * 安全工程师可点，管理员**看得到但禁用**，并说明缺的是哪个角色。
 * 全链路（点开 → 填表 → 选文件 → 启动 → 跳工作台）由
 * `frontend/scripts/_e2e_new_assessment.mjs` 在真实浏览器里验过，16 项全绿。
 *
 * 不想用界面时，`项目通读/如何评估一个新项目.md` 里有等价的接口步骤 ——
 * 三条接口后端一直都在。
 *
 * ## 为什么要有它
 *
 * 后端的三个接口（`POST /projects`、`POST /projects/{id}/upload`、
 * `POST /projects/{id}/assessments`）一直都存在，`api/endpoints.ts` 里也早就写好了
 * 对应的三个方法 —— **但没有任何页面调用过它们**。结果是这一页只能从大盘的
 * 「最近任务」点进一个已有的评估，**无法评估一个新项目**。
 *
 * ## 三步为什么不能拆成三个弹窗
 *
 * 拆开的话，用户会在「建了档但忘了传源码」的状态里迷路 ——
 * 而那个状态是**合法但不可用**的（`storage_path` 为 null，启动评估会被 400 拒绝）。
 * 一个弹窗走完，就没有中间态可以停下来。
 *
 * ## 每一步失败都要说清楚「已经发生了什么」
 *
 * 三步是**顺序副作用**：第 2 步失败时第 1 步的成果（项目行）已经落库了。
 * 只说一句「上传失败」，用户会以为什么都没发生，然后重来一遍 ——
 * 于是得到一个重复项目。所以错误提示里带上已建项目的 id。
 */
import { PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App,
  Button,
  Form,
  Input,
  Modal,
  Radio,
  Select,
  Space,
  Typography,
  Upload,
} from 'antd'
import type { UploadFile } from 'antd'
import { useState } from 'react'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'

import { errorMessage } from '@/api/client'
import { assessmentApi, projectApi } from '@/api/endpoints'
import type { Project } from '@/api/types'

/** 归档后缀白名单 —— **只用于文件选择器的过滤**。
 *
 * 真正的格式判定在后端按 magic bytes 做（`projects/fetcher.py`），
 * 因为扩展名是用户随手就能改的（把 zip 改名成 .tar.gz 是最省事的绕过手法）。
 * 这里**刻意不做**二次校验：抄一遍就是第二份实现，
 * 哪天后端加了一种格式，前端会安静地把它挡在门外。
 */
const ARCHIVE_ACCEPT = '.zip,.tar,.tar.gz,.tgz'

/** 表单值的形状。与 form item 的 name 一一对应。 */
interface FormValues {
  kind: 'new' | 'existing'
  name?: string
  new_source?: 'upload' | 'git'
  file?: UploadFile[]
  source_url?: string
  source_branch?: string
  project_id?: number
}

/** antd 的 Upload 在 Form 里要经这一步归一 —— 它给的是 event，不是 fileList。 */
function normFile(e: unknown): UploadFile[] {
  if (Array.isArray(e)) return e as UploadFile[]
  const list = (e as { fileList?: UploadFile[] } | undefined)?.fileList
  return list ?? []
}

export function NewAssessmentModal({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
}): ReactNode {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { message } = App.useApp()
  const [form] = Form.useForm<FormValues>()

  const [submitting, setSubmitting] = useState(false)
  /** 正在做哪一步 —— 克隆/上传可能几十秒，没有它界面就是「卡住了」 */
  const [progress, setProgress] = useState('')

  const kind = Form.useWatch('kind', form)
  const newSource = Form.useWatch('new_source', form)

  // 只在弹窗打开时拉项目列表：关着的时候没人看，白打一次请求。
  const projects = useQuery({
    queryKey: ['projects'],
    queryFn: projectApi.list,
    enabled: open,
  })

  async function submit(): Promise<void> {
    const v = await form.validateFields()
    setSubmitting(true)

    // 记录已建出来的项目：后面任何一步失败，提示里都要带上它。
    let createdProjectId: number | null = null

    try {
      let projectId: number

      if (v.kind === 'existing') {
        projectId = v.project_id as number
      } else {
        setProgress('正在建档…')
        const project = await projectApi.create({
          name: (v.name ?? '').trim(),
          source_type: v.new_source ?? 'upload',
          source_url: v.new_source === 'git' ? (v.source_url ?? '').trim() : null,
          source_branch: v.new_source === 'git' ? (v.source_branch ?? '').trim() || null : null,
        })
        projectId = project.id
        createdProjectId = project.id

        if (v.new_source === 'upload') {
          const file = v.file?.[0]?.originFileObj
          if (!file) throw new Error('没有拿到待上传的文件，请重新选择源码包')
          setProgress('正在上传并扫描源码…')
          await projectApi.upload(projectId, file)
        }
      }

      setProgress('正在启动评估…')
      const assessment = await assessmentApi.create(projectId)

      void queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] })
      void queryClient.invalidateQueries({ queryKey: ['projects'] })

      message.success(`评估已启动（任务 #${assessment.id}）`)
      form.resetFields()
      onClose()
      // 直接进工作台看它跑 —— 否则用户还得自己去「最近任务」里找刚建的那条
      navigate(`/workbench?assessmentId=${assessment.id}`)
    } catch (err) {
      // 项目已经建出来了但后续失败 —— 这句话必须说，否则用户会重来一遍，
      // 而重来的结果是第二个同名项目。
      const hint =
        createdProjectId === null
          ? ''
          : `（项目 #${createdProjectId} 已建好，可在「已有项目」里直接启动评估）`
      message.error(`${errorMessage(err)}${hint}`)
      // 让那个半成品项目立刻出现在「已有项目」下拉里，用户才有路可走。
      void queryClient.invalidateQueries({ queryKey: ['projects'] })
    } finally {
      setSubmitting(false)
      setProgress('')
    }
  }

  const projectOptions = (projects.data?.items ?? []).map((p: Project) => ({
    value: p.id,
    // 没源码的项目是**合法但不可用**的（后端会 400）。
    // 不隐藏、也不静默禁用 —— 直接写明原因，否则用户只会看到一个选不动的灰条。
    label: p.storage_path ? p.name : `${p.name}（未上传源码，不能启动）`,
    disabled: !p.storage_path,
  }))

  return (
    <Modal
      open={open}
      title="新建评估"
      okText="启动评估"
      cancelText="取消"
      confirmLoading={submitting}
      maskClosable={!submitting}
      closable={!submitting}
      onOk={() => void submit()}
      onCancel={() => {
        if (submitting) return
        form.resetFields()
        onClose()
      }}
      width={560}
      destroyOnHidden
    >
      <Form<FormValues>
        form={form}
        layout="vertical"
        initialValues={{ kind: 'new', new_source: 'upload' }}
        disabled={submitting}
      >
        <Form.Item name="kind" label="评估对象">
          <Radio.Group
            options={[
              { value: 'new', label: '一个新项目' },
              { value: 'existing', label: '已有项目' },
            ]}
            optionType="button"
          />
        </Form.Item>

        {kind === 'existing' ? (
          <Form.Item
            name="project_id"
            label="选择项目"
            rules={[{ required: true, message: '请选择一个项目' }]}
            extra={
              projects.isLoading
                ? '正在加载项目列表…'
                : `${projectOptions.length} 个项目；标灰的还没有源码`
            }
          >
            <Select
              placeholder="选择要评估的项目"
              options={projectOptions}
              loading={projects.isLoading}
              showSearch
              optionFilterProp="label"
            />
          </Form.Item>
        ) : (
          <>
            <Form.Item
              name="name"
              label="项目名称"
              rules={[
                { required: true, message: '请填写项目名称' },
                { max: 128, message: '最多 128 个字符' },
              ]}
            >
              <Input placeholder="例如：订单服务" maxLength={128} />
            </Form.Item>

            <Form.Item name="new_source" label="源码来源">
              <Radio.Group
                options={[
                  { value: 'upload', label: '上传源码包' },
                  { value: 'git', label: 'Git 仓库' },
                ]}
                optionType="button"
              />
            </Form.Item>

            {newSource === 'git' ? (
              <>
                <Alert
                  type="info"
                  showIcon
                  style={{ marginBottom: 16 }}
                  message="只允许克隆白名单内的仓库"
                  description="不在白名单内会被后端直接拒绝。白名单由部署时的 GIT_URL_ALLOWLIST 配置（PRD §12 风险 8）。大仓库浅克隆可能要几分钟，请勿关闭页面。"
                />
                <Form.Item
                  name="source_url"
                  label="仓库地址"
                  rules={[{ required: true, message: '请填写仓库地址' }]}
                >
                  <Input placeholder="https://github.com/example/repo.git" maxLength={512} />
                </Form.Item>
                <Form.Item name="source_branch" label="分支" extra="留空则用仓库的默认分支">
                  <Input placeholder="main" maxLength={128} />
                </Form.Item>
              </>
            ) : (
              <Form.Item
                name="file"
                label="源码包"
                valuePropName="fileList"
                getValueFromEvent={normFile}
                rules={[{ required: true, message: '请选择源码包' }]}
                extra="支持 zip / tar / tar.gz。后端按文件内容（magic bytes）判格式，不看扩展名。"
              >
                <Upload beforeUpload={() => false} maxCount={1} accept={ARCHIVE_ACCEPT}>
                  <Button icon={<PlusOutlined />}>选择文件</Button>
                </Upload>
              </Form.Item>
            )}
          </>
        )}

        {submitting ? (
          <Space>
            <Typography.Text type="secondary">{progress}</Typography.Text>
          </Space>
        ) : null}

        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          启动后五个阶段依次执行：接入爬取 → 代码审计 → 动态验证 → 攻击链推演 → 报告生成。
        </Typography.Text>
      </Form>
    </Modal>
  )
}
