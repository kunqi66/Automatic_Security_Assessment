/**
 * 补丁展示区 —— 本模块最需要「让人一眼分清结论与建议」的地方。
 *
 * 第一性原则（可控多智能体）：**LLM 只产出自然语言，绝不参与任何判定**。
 * 漏洞有无、类型、严重度、CVSS、验证状态、整改顺序全部由确定性代码产出。
 * 补丁是本系统里 LLM 唯一被允许「产出可执行物」的地方，因此它必须过四道校验，
 * 且**永远不自动应用** —— 这条约束在 UI 上被放在最醒目的位置。
 *
 * 补丁三态（PatchSource）在视觉上必须明显不同，尤其 template 与 validate_failed
 * 绝不能长成一个样子：
 *   llm             绿：正常产出，已过四道校验
 *   template        蓝/中性：模型不可用时的降级，**结论与整改排序不变，只有措辞不同**
 *   validate_failed 红：过了前三道但第 ④ 道没过 —— 补丁没真正修好漏洞
 */
import { CheckCircleFilled, CloseCircleFilled } from '@ant-design/icons'
import { DiffEditor } from '@monaco-editor/react'
import { Alert, Divider, Space, Tag, Typography } from 'antd'
import { useMemo } from 'react'
import type { ReactNode } from 'react'

import type { PatchSuggestion, PatchValidation } from '@/api/types'
import { applyUnifiedDiff, originalFromDiff } from './applyUnifiedDiff'

const { Title, Text } = Typography

// ---------------------------------------------------------------------------
// 四道校验清单
// ---------------------------------------------------------------------------

type CheckKey = 'valid_diff' | 'window_ok' | 'apply_check_ok' | 'taint_cleared'

interface CheckSpec {
  key: CheckKey
  title: string
  desc: string
  /** 第 ④ 道是唯一真正的验收标准，UI 上要单独强调 */
  decisive?: boolean
}

const CHECKS: CheckSpec[] = [
  {
    key: 'valid_diff',
    title: '① 是否为合法的 unified diff',
    desc: '能否解析出 @@ hunk 与 +/- 行 —— 格式不合法的话 git 根本读不懂。',
  },
  {
    key: 'window_ok',
    title: '② 是否只改动了 ±20 行窗口',
    desc: '改动必须落在漏洞位置上下 20 行内，防止模型顺手重构无关代码。',
  },
  {
    key: 'apply_check_ok',
    title: '③ git apply --check 干跑是否通过',
    desc: '在一份源码副本上干跑，确认补丁当前能无冲突地应用。',
  },
  {
    key: 'taint_cleared',
    title: '④ 打上补丁后污点路径是否消失',
    desc: '打上补丁、重跑污点引擎，看这条路径还在不在 —— 这是唯一真正的验收标准，前三道只是格式与可应用性检查。',
    decisive: true,
  },
]

function ValidationChecklist({ validation }: { validation: PatchValidation }): ReactNode {
  return (
    <div style={{ marginTop: 16 }}>
      <Text strong>四道校验结果</Text>
      <div style={{ marginTop: 8, border: '1px solid #f0f0f0', borderRadius: 6 }}>
        {CHECKS.map((check, index) => {
          const pass = validation[check.key]
          return (
            <div
              key={check.key}
              style={{
                display: 'flex',
                gap: 8,
                padding: '8px 12px',
                borderTop: index === 0 ? undefined : '1px solid #f0f0f0',
                // 第 ④ 道整行加浅黄底，和前三道拉开层级
                background: check.decisive ? '#fffbe6' : undefined,
              }}
            >
              {pass ? (
                <CheckCircleFilled style={{ color: '#52c41a', marginTop: 3 }} />
              ) : (
                <CloseCircleFilled style={{ color: '#ff4d4f', marginTop: 3 }} />
              )}
              <div>
                <Text strong={check.decisive}>{check.title}</Text>
                {check.decisive && (
                  <Tag color="gold" style={{ marginLeft: 6 }}>
                    唯一验收标准
                  </Tag>
                )}
                <div>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {check.desc}
                  </Text>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {validation.failure_reason && (
        <Alert
          style={{ marginTop: 8 }}
          type="warning"
          showIcon
          message="校验未通过原因"
          description={<span className="vuln-mono">{validation.failure_reason}</span>}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 三态来源标注 —— 三者视觉必须明显不同
// ---------------------------------------------------------------------------

function SourceBanner({ patch }: { patch: PatchSuggestion }): ReactNode {
  if (patch.source === 'llm') {
    return (
      <Alert
        type="success"
        showIcon
        message={
          <Space size={8} wrap>
            <Tag color="blue">大模型生成</Tag>
            <Text strong>由大模型生成，已通过四道校验</Text>
          </Space>
        }
        description="判定结论（漏洞有无、严重度、整改顺序）全部来自确定性代码，这里只是模型给出的修复草案。"
      />
    )
  }

  if (patch.source === 'template') {
    return (
      <Alert
        type="info"
        showIcon
        message={
          <Space size={8} wrap>
            <Tag>模板生成（模型不可用时的降级）</Tag>
          </Space>
        }
        description="模型不可用时由确定性模板产出。参数化查询这类整改方式本身是固定的，因此结论与整改排序不受影响，只有措辞不同。"
      />
    )
  }

  // source === 'validate_failed' —— 必须红字告警，绝不能和 template 混为一谈
  return (
    <Alert
      type="error"
      showIcon
      message={<Text strong>该补丁未通过第 ④ 道校验 —— 打上之后污点路径依然可达</Text>}
      description={
        <>
          <div>
            也就是说它并没有真正修好这个漏洞：前两道只检查格式与改动范围，第三道只证明「能应用」，
            只有第 ④ 道会真的重跑污点引擎复验。本补丁仅作为反面参考，请勿直接采用。
          </div>
          {patch.validation.failure_reason && (
            <div className="vuln-mono" style={{ marginTop: 6 }}>
              {patch.validation.failure_reason}
            </div>
          )}
        </>
      }
    />
  )
}

// ---------------------------------------------------------------------------
// 主体
// ---------------------------------------------------------------------------

export function PatchSection({ patch }: { patch: PatchSuggestion }): ReactNode {
  // 后端只给 unified diff，这里反推左右两份文本（能力与局限见 applyUnifiedDiff.ts）
  const original = useMemo(() => originalFromDiff(patch.diff), [patch.diff])
  const result = useMemo(() => applyUnifiedDiff(original, patch.diff), [original, patch.diff])

  return (
    <div>
      {/* 硬性设计约束：放在最上面，先于任何样式化的补丁内容 */}
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 12 }}
        message={
          <Text strong style={{ fontSize: 15 }}>
            建议补丁 · 绝不自动应用
          </Text>
        }
        description="补丁只是给开发者参考的草案。系统永远不会自动打补丁，是否采纳、怎么改，由人决定。"
      />

      <SourceBanner patch={patch} />

      <Space style={{ marginTop: 12 }} wrap size={8}>
        <Text type="secondary">目标文件</Text>
        <Text className="vuln-mono">{patch.target_file}</Text>
      </Space>

      <ValidationChecklist validation={patch.validation} />

      <Divider style={{ margin: '20px 0 12px' }} />

      <Title level={5} style={{ marginTop: 0 }}>
        补丁内容（只读）
      </Title>
      <Text type="secondary" style={{ fontSize: 12 }}>
        后端只下发 unified diff 文本：左侧「原始」由 diff 的上下文行与删除行反推得到，
        它只覆盖补丁的上下文窗口，不等同于完整文件。
      </Text>

      {result.degraded > 0 && (
        <Alert
          style={{ margin: '8px 0' }}
          type="warning"
          showIcon
          message="diff 与反推的原文未能逐字对齐"
          description={result.warnings.join('；')}
        />
      )}

      <div className="vuln-diff-wrap" style={{ marginTop: 8 }}>
        <DiffEditor
          height="380px"
          language="python"
          theme="vs-dark"
          original={result.original}
          modified={result.modified}
          options={{
            readOnly: true,
            renderSideBySide: true,
            minimap: { enabled: false },
            fontSize: 12,
            scrollBeyondLastLine: false,
            automaticLayout: true,
          }}
        />
      </div>
    </div>
  )
}
