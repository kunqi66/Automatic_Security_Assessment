/**
 * unified diff → (original, modified) 两份文本，喂给 Monaco 的 DiffEditor。
 *
 * 为什么需要它：后端 `PatchSuggestion.diff` 只给一段 unified diff 文本，
 * 既不回传文件内容，前端也拿不到工作区源码（源码在后端的 workspace 里）。
 * 而 DiffEditor 要的是「原始文本 + 修改后文本」两份**整文**，所以必须把 diff
 * 拆回左右两边 —— 办法就是拿 hunk 里的上下文行（` `）与删除行（`-`）拼出原文窗口，
 * 再把新增行（`+`）替换进去得到修改后文本。后端的「±20 行窗口」约束（第 ② 道校验）
 * 保证了这份原文恰好覆盖被改动的位置。
 *
 * 于是整条数据流是：
 *     diff  ──originalFromDiff──▶ original ──applyUnifiedDiff──▶ modified
 *                                          └─▶ 逐 hunk 校验 + 退化告警
 *
 * ⚠️ 这是一个**能力有限**的纯函数，刻意不假装自己是 GNU patch。局限如下，
 *    在 UI 上也如实告知用户；它的输出**只用于渲染，永不写回任何文件**：
 *   1. 只认单文件 unified diff 的 `--- / +++ / @@` 三段式。多文件补丁只取其中出现的
 *      全部 hunk；`diff --git` / `index` / rename / binary / new file mode 一律忽略。
 *   2. 反推出的 original **只包含补丁覆盖的窗口**，不是完整文件；窗口与窗口之间的
 *      代码没有随 diff 下发，因此也不在结果里（UI 已注明）。
 *   3. 不做 fuzz 匹配：hunk 的旧侧必须在 original 中**逐字**找到，否则退化为
 *      「按当前位置直接拼接新侧内容」并记一条 warning —— 那种结果可能与真实文件不符。
 *      查找时从上一个 hunk 之后向后扫描、取第一个匹配，而不是信任 `@@ -a,b` 里的行号，
 *      因为行号是相对完整文件的，对我们手上的窗口拼接文本没有意义。
 *   4. `\ No newline at end of file` 被忽略；CRLF / LF 差异不做归一化。
 */

interface HunkLine {
  /** ' ' 上下文行 / '-' 删除行 / '+' 新增行（即 diff 行首那一个字符） */
  type: ' ' | '-' | '+'
  text: string
}

interface Hunk {
  /** 旧文件中的起始行号（1-based，取自 @@ -a,b +c,d @@）。只用于展示与告警，不用于定位 */
  old_start: number
  lines: HunkLine[]
}

const HUNK_HEADER = /^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@/

/** 把 diff 文本解析成 hunk 列表。解析不出 hunk 时返回空数组（调用方据此判空）。 */
function parseHunks(diff: string): Hunk[] {
  const hunks: Hunk[] = []
  let current: Hunk | null = null

  for (const raw of diff.split('\n')) {
    const header = HUNK_HEADER.exec(raw)
    if (header) {
      current = { old_start: Number(header[1]), lines: [] }
      hunks.push(current)
      continue
    }

    // hunk 之前的文件头（---/+++/diff --git/...）直接跳过
    if (current === null) continue
    if (raw.startsWith('\\')) continue // "\ No newline at end of file"

    const marker = raw[0]
    if (marker === ' ' || marker === '-' || marker === '+') {
      current.lines.push({ type: marker, text: raw.slice(1) })
      continue
    }
    if (raw === '') {
      // 有些实现把「内容为空的上下文行」写成空串而不是一个空格
      current.lines.push({ type: ' ', text: '' })
      continue
    }
    // 其他内容说明这个 hunk 结束了（单文件补丁里通常是下一段文件头）
    current = null
  }

  return hunks
}

/** 旧侧（上下文 + 删除行）—— 也就是补丁改动前的样子 */
const oldSideOf = (hunk: Hunk): HunkLine[] => hunk.lines.filter((l) => l.type !== '+')

/** 新侧（上下文 + 新增行）—— 也就是补丁改动后的样子 */
const newSideOf = (hunk: Hunk): string[] =>
  hunk.lines.filter((l) => l.type !== '-').map((l) => l.text)

/**
 * 由 diff 反推「原始文本」。
 *
 * 结果不按文件真实行号补齐（补不齐 —— 窗口之外的代码根本没下发），而是把所有 hunk
 * 的旧侧依次拼接起来。这样 DiffEditor 里看到的就只有补丁真正涉及的那几行，
 * 不会被上百行占位符淹没。
 */
export function originalFromDiff(diff: string): string {
  const lines: string[] = []
  for (const hunk of parseHunks(diff)) {
    for (const line of oldSideOf(hunk)) lines.push(line.text)
  }
  return lines.join('\n')
}

export interface ApplyUnifiedDiffResult {
  /** 反推出来的原始文本（原样带回，方便直接喂给 DiffEditor） */
  original: string
  /** 应用补丁后的文本 */
  modified: string
  /** 旧侧在原文中逐字找到、成功替换的 hunk 数 */
  applied: number
  /** 旧侧找不到、退化为直接拼接的 hunk 数（>0 时 UI 必须提示结果仅供参考） */
  degraded: number
  /** 退化时的说明 */
  warnings: string[]
}

/** 在 source 中从 from 起向后找 old 块；返回起点下标，找不到返回 -1 */
function findBlock(source: string[], old: HunkLine[], from: number): number {
  if (old.length === 0) return from
  for (let start = from; start + old.length <= source.length; start++) {
    let matched = true
    for (let offset = 0; offset < old.length; offset++) {
      if (source[start + offset] !== old[offset].text) {
        matched = false
        break
      }
    }
    if (matched) return start
  }
  return -1
}

/**
 * 把 `diff` 应用到 `original` 上，得到修改后的文本。
 *
 * 逐 hunk 处理：先在原文里找到该 hunk 的旧侧，替换成新侧；找不到就退化为
 * 「在当前位置直接拼接新侧」并留一条告警，绝不静默糊弄过去。
 * 纯函数、无副作用：同一组入参永远得到同一结果，便于单测与渲染复现。
 */
export function applyUnifiedDiff(original: string, diff: string): ApplyUnifiedDiffResult {
  const hunks = parseHunks(diff)
  const source = original.split('\n')

  const out: string[] = []
  const warnings: string[] = []
  let cursor = 0 // source 中下一个待输出行的下标
  let applied = 0
  let degraded = 0

  hunks.forEach((hunk, index) => {
    const oldSide = oldSideOf(hunk)
    const newSide = newSideOf(hunk)

    const found = findBlock(source, oldSide, cursor)
    if (found >= 0) {
      applied++
      while (cursor < found) {
        out.push(source[cursor])
        cursor++
      }
      out.push(...newSide)
      cursor = found + oldSide.length
      return
    }

    // —— 退化路径：旧侧找不到，只能把新侧直接拼在当前游标处 ——
    degraded++
    warnings.push(
      `第 ${index + 1} 个 hunk（@@ -${hunk.old_start}）的上下文没有在反推的原文里逐字找到，已退化为直接拼接 —— 展示结果可能与真实文件有出入`,
    )
    out.push(...newSide)
  })

  while (cursor < source.length) {
    out.push(source[cursor])
    cursor++
  }

  return { original, modified: out.join('\n'), applied, degraded, warnings }
}
