/**
 * 评估任务日志流（SSE / Redis Stream 转发）。
 *
 * 刻意不用 `EventSource`：它无法设置请求头，只能把 JWT 塞进 URL 查询串，
 * 而查询串会被 nginx access log、浏览器历史、Referer 记录 —— 等于泄露凭证。
 * 这里用 `fetch` + ReadableStream 手动解析 SSE，从而能用 `Authorization` 头。
 *
 * 断线重连时回传 `Last-Event-ID`，后端从 Redis Stream 的该 ID 之后重放，
 * 保证断线期间不丢日志（总纲 §6.2）。
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import { STAGE_LABELS } from '@/constants'

import { USE_MOCK, tokenStore } from './client'
import { RUNNING_LOGS } from './fixtures'
import type { LogEvent, StageRecord, StreamEvent } from './types'

const MAX_LINES = 800

/** 阶段状态 → 日志级别。**`skipped` 是 warn 不是 error** —— 它是降级（总纲 §9.1 L3），
 *  渲染成红色会让用户以为整轮评估失败了。 */
const STAGE_LEVEL: Record<StageRecord['status'], LogEvent['level']> = {
  pending: 'debug',
  running: 'info',
  completed: 'info',
  skipped: 'warn',
  failed: 'error',
}

/** 阶段状态 → 中文。与 `STAGE_LABELS`（阶段名 → 中文）是两张不同的表，别混用。 */
const STAGE_STATUS_TEXT: Record<StageRecord['status'], string> = {
  pending: '等待中',
  running: '开始',
  completed: '完成',
  skipped: '已跳过',
  failed: '失败',
}

export interface LogStreamState {
  logs: LogEvent[]
  connected: boolean
  /** 流已结束（任务终态，服务端主动关闭） */
  finished: boolean
  error: string | null
  clear: () => void
}

/**
 * @param assessmentId 目标任务；null 时不连接
 * @param enabled      任务处于 running 态时才需要订阅
 */
export function useLogStream(assessmentId: number | null, enabled: boolean): LogStreamState {
  const [logs, setLogs] = useState<LogEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [finished, setFinished] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const lastIdRef = useRef<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)

  const clear = useCallback(() => setLogs([]), [])

  const append = useCallback((incoming: LogEvent[]) => {
    setLogs((prev) => {
      const seen = new Set(prev.map((l) => l.id))
      const fresh = incoming.filter((l) => !seen.has(l.id))
      if (fresh.length === 0) return prev
      const next = [...prev, ...fresh]
      return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
    })
  }, [])

  useEffect(() => {
    if (!enabled || assessmentId === null) {
      setConnected(false)
      return
    }

    let disposed = false
    let retry = 0
    let timer: ReturnType<typeof setTimeout> | undefined

    // --- Mock 模式：按节奏吐出预置日志，模拟进行中的任务 ---
    if (USE_MOCK) {
      setConnected(true)
      setError(null)
      let cursor = 0
      const tick = (): void => {
        if (disposed) return
        if (cursor >= RUNNING_LOGS.length) {
          setFinished(true)
          setConnected(false)
          return
        }
        const ev: LogEvent = { ...RUNNING_LOGS[cursor], ts: new Date().toISOString() }
        cursor += 1
        append([ev])
        timer = setTimeout(tick, 700 + Math.random() * 900)
      }
      timer = setTimeout(tick, 500)
      return () => {
        disposed = true
        if (timer) clearTimeout(timer)
      }
    }

    // --- 真实模式：fetch + 手动解析 SSE ---
    const connect = async (): Promise<void> => {
      const controller = new AbortController()
      abortRef.current = controller
      const base = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'

      try {
        const token = tokenStore.get()
        // 路径以 PRD §9 为准：SSE 端点是 /assessments/{id}/stream（不是 /logs）
        const res = await fetch(`${base}/assessments/${assessmentId}/stream`, {
          headers: {
            Accept: 'text/event-stream',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...(lastIdRef.current ? { 'Last-Event-ID': lastIdRef.current } : {}),
          },
          signal: controller.signal,
        })

        if (!res.ok || !res.body) {
          throw new Error(`日志流连接失败：HTTP ${res.status}`)
        }

        if (disposed) return
        setConnected(true)
        setError(null)
        retry = 0

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''

        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })

          const chunks = buffer.split('\n\n')
          buffer = chunks.pop() ?? ''
          const batch: LogEvent[] = []
          for (const chunk of chunks) {
            const { id, events } = parseSseChunk(chunk)
            if (!id) continue
            // **游标必须在过滤之前推进**。一条 metric 事件不渲染，但它仍占一个
            // Redis 消息 ID；跳过它不推进游标的话，重连时会从它之前重放，
            // 而重放又只会在前端被再次丢掉 —— 形成一段每次都重读的空转区间。
            lastIdRef.current = id
            batch.push(...events)
          }
          if (batch.length) append(batch)
        }

        if (disposed) return
        setConnected(false)
        setFinished(true)
      } catch (e) {
        if (disposed || controller.signal.aborted) return
        setConnected(false)
        setError(e instanceof Error ? e.message : '日志流异常')
        // 指数退避重连，最多 10 次；重连时靠 Last-Event-ID 补回断线期间的日志
        if (retry < 10) {
          const delay = Math.min(1000 * 2 ** retry, 15_000)
          retry += 1
          timer = setTimeout(() => void connect(), delay)
        }
      }
    }

    void connect()

    return () => {
      disposed = true
      if (timer) clearTimeout(timer)
      abortRef.current?.abort()
    }
  }, [assessmentId, enabled, append])

  return { logs, connected, finished, error, clear }
}

/**
 * 解析单个 SSE 事件块。形如：
 * ```
 * id: 1700000000000-0
 * data: {"type":"log","stage":"recon","level":"info","message":"...","ts":"..."}
 * ```
 *
 * **返回 `{ id, events }` 而不是一个可空的事件**：一条线上消息可能对应
 * 0 条（metric，不渲染）或 1 条渲染行，而 `id` 无论如何都要交回去推进游标。
 * 合成一个返回值会让「不渲染但已消费」这件事没地方表达 —— 那正是下面
 * `toLogEvents` 里 metric 分支要占用 `id` 的原因。
 */
function parseSseChunk(chunk: string): { id: string; events: LogEvent[] } {
  let id = ''
  const dataLines: string[] = []

  for (const rawLine of chunk.split('\n')) {
    const line = rawLine.trimEnd()
    if (!line || line.startsWith(':')) continue // 注释行（心跳）跳过
    if (line.startsWith('id:')) id = line.slice(3).trim()
    else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim())
  }

  if (dataLines.length === 0 || !id) return { id: '', events: [] }

  let parsed: unknown
  try {
    parsed = JSON.parse(dataLines.join('\n'))
  } catch {
    // 半条 JSON（连接在消息中间断掉）。**丢弃而不是猜** ——
    // 拼一个残破的事件进列表，用户看到的是一句读不通的话，
    // 而重连会靠 Last-Event-ID 把这条完整地重新推一遍。
    return { id, events: [] }
  }

  return { id, events: toLogEvents(parsed, id) }
}

/**
 * 线上信封 → 渲染模型。**这是两种事件格式之间唯一的转换点。**
 *
 * 服务端三种事件共用一个信封（`StreamEvent`），而日志面板只渲染一种东西
 * （`LogEvent`）。直接 spread 的后果是阶段事件带着 `level: null` 和
 * `message: null` 进列表，渲出几行没有文字的空白。
 */
function toLogEvents(raw: unknown, id: string): LogEvent[] {
  if (typeof raw !== 'object' || raw === null) return []
  const ev = raw as Partial<StreamEvent>
  const ts = ev.ts ?? new Date().toISOString()
  const stage = ev.stage ?? 'system'

  switch (ev.type) {
    case 'log':
      return [
        {
          id,
          ts,
          stage,
          level: ev.level ?? 'info',
          message: ev.message ?? '',
        },
      ]

    case 'stage': {
      // 阶段事件是**快照**不是增量，所以这里把状态译成一句人能读的话。
      // 不译的话前端拿到的只是 `{"status":"skipped"}`，而用户想知道的是
      // 「哪一步跳过了、为什么」—— 原因就在 `note` 里。
      const snap = ev.snapshot
      if (!snap) return []
      const status = STAGE_STATUS_TEXT[snap.status] ?? snap.status
      const line = `${STAGE_LABELS[snap.stage] ?? snap.stage} ${status}`
      return [
        {
          id,
          ts,
          stage,
          level: STAGE_LEVEL[snap.status] ?? 'info',
          // `note` 同时承载失败原因与降级原因（服务端就是一个字段），
          // 所以不区分地接在后面 —— 它就是「为什么」的答案。
          message: snap.note ? `${line}：${snap.note}` : line,
        },
      ]
    }

    case 'metric':
      // **不渲染**：资源曲线走图表面板，混进日志面板会把真正的阶段信息
      // 冲走（采样是每几秒一条，而日志是每阶段几条）。
      // 但 `id` 仍会被调用方用于推进游标 —— 见 `parseSseChunk`。
      return []

    default:
      return []
  }
}
