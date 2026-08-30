import type { ChangeFile, ChangesView, DiffCell, DiffRow, View } from "./protocol"

export type ChangesFocus = "files" | "diff" | "actions"
export type ChangesState = { focus: ChangesFocus; fileCursor: number; actionCursor: number; diffOffset: number; diffColumnOffset: number }
export type Tone = "plain" | "add" | "delete" | "muted"
export type Segment = { text: string; tone: Tone }
export type DisplayLine = Segment[]
export type ChangesDisplay = { lines: DisplayLine[]; diffPageSize: number; maxDiffOffset: number; maxHorizontalOffset: number; hunkOffsets: number[]; actionIndexes: number[] }

const plain = (text: string): Segment => ({ text, tone: "plain" })
const toned = (text: string, tone: Tone): Segment => ({ text, tone })

function characterWidth(character: string): number {
  const point = character.codePointAt(0) ?? 0
  if (point === 0 || point >= 0x300 && point <= 0x36f || point >= 0xfe00 && point <= 0xfe0f) return 0
  if (point >= 0x1100 && (point <= 0x115f || point === 0x2329 || point === 0x232a || point >= 0x2e80 && point <= 0xa4cf || point >= 0xac00 && point <= 0xd7a3 || point >= 0xf900 && point <= 0xfaff || point >= 0xfe10 && point <= 0xfe6f || point >= 0xff00 && point <= 0xff60 || point >= 0xffe0 && point <= 0xffe6 || point >= 0x1f300)) return 2
  return 1
}

function textWidth(value: string): number {
  let width = 0
  for (const character of value) width += characterWidth(character)
  return width
}

function fit(value: string, width: number): string {
  if (width <= 0) return ""
  if (textWidth(value) <= width) return value + " ".repeat(width - textWidth(value))
  if (width === 1) return "…"
  let output = ""
  let used = 0
  for (const character of value) {
    const next = characterWidth(character)
    if (used + next > width - 1) break
    output += character
    used += next
  }
  return output + "…" + " ".repeat(Math.max(0, width - used - 1))
}

function lineNumber(value: number): string {
  return value > 0 ? String(value).padStart(4) : "    "
}

function marker(kind: string): string {
  if (kind === "add") return "+"
  if (kind === "delete") return "-"
  return " "
}

function tone(kind: string): Tone {
  if (kind === "add") return "add"
  if (kind === "delete") return "delete"
  if (kind === "hunk") return "muted"
  return "plain"
}

function sliceColumns(value: string, offset: number, width: number): string {
  let skipped = 0
  let used = 0
  let result = ""
  for (const character of value) {
    const size = characterWidth(character)
    if (skipped < offset) {
      skipped += size
      continue
    }
    if (used + size > width) break
    result += character
    used += size
  }
  return result
}

function horizontalWindow(value: string, width: number, offset: number): string {
  if (width <= 0) return ""
  const total = textWidth(value)
  offset = Math.max(0, offset)
  const left = offset > 0
  let available = Math.max(0, width - (left ? 1 : 0))
  let right = offset + available < total
  if (right) available = Math.max(0, available - 1)
  const content = sliceColumns(value, offset, available)
  right = offset + textWidth(content) < total
  return fit(`${left ? "‹" : ""}${content}${right ? "›" : ""}`, width)
}

function maximumHorizontalOffset(value: string, width: number): number {
  const total = textWidth(value)
  return total > width ? total - width + 1 : 0
}

type UnifiedDisplayRow = { kind: "hunk" | "context" | "add" | "delete"; oldLine: number; newLine: number; text: string }
type DiffDisplay = { lines: DisplayLine[]; hunkOffsets: number[]; maxHorizontalOffset: number }

function unifiedLine(row: UnifiedDisplayRow, width: number, horizontalOffset: number): DisplayLine {
  if (row.kind === "hunk") return [toned(fit(row.text, width), "muted")]
  const prefix = `${lineNumber(row.oldLine)} ${lineNumber(row.newLine)} ${marker(row.kind)} `
  return [toned(prefix + horizontalWindow(row.text, Math.max(1, width - textWidth(prefix)), horizontalOffset), tone(row.kind))]
}

function cell(cell: DiffCell, width: number, horizontalOffset: number): Segment {
  if (cell.kind === "empty") return toned(" ".repeat(Math.max(0, width)), "muted")
  const prefix = `${lineNumber(cell.line)} ${marker(cell.kind)} `
  return toned(prefix + horizontalWindow(cell.text, Math.max(1, width - textWidth(prefix)), horizontalOffset), tone(cell.kind))
}

function sideColumns(width: number): { before: number; after: number } {
  const before = Math.max(12, Math.floor((width - 3) / 2))
  return { before, after: Math.max(1, width - before - 3) }
}

function emptySideLine(width: number): DisplayLine {
  const columns = sideColumns(width)
  return [plain(" ".repeat(columns.before)), plain(" │ "), plain(" ".repeat(columns.after))]
}

function sideLine(row: DiffRow, width: number, horizontalOffset: number): DisplayLine {
  const columns = sideColumns(width)
  if (row.kind === "hunk") {
    const label = `── ${row.header} `
    return [toned(fit(label, columns.before).replace(/ +$/, (spaces) => "─".repeat(spaces.length)), "muted"), plain("─┼─"), toned("─".repeat(columns.after), "muted")]
  }
  const after = row.before.kind === "context" && row.after.kind === "context" && row.after.text === "" ? { ...row.after, text: row.before.text } : row.after
  return [cell(row.before, columns.before, horizontalOffset), plain(" │ "), cell(after, columns.after, horizontalOffset)]
}

function diffDisplay(changes: ChangesView, width: number, sideBySide: boolean, horizontalOffset: number): DiffDisplay {
  if (sideBySide) {
    const columns = sideColumns(width)
    const bodyWidth = Math.max(1, Math.min(columns.before, columns.after) - textWidth(`${lineNumber(1)} + `))
    return {
      lines: [
        [plain(fit("BEFORE (original)", columns.before)), plain(" │ "), plain(fit("AFTER (proposed)", columns.after))],
        [plain("─".repeat(columns.before)), plain("─┼─"), plain("─".repeat(columns.after))],
        ...changes.rows.map((row) => sideLine(row, width, horizontalOffset)),
      ],
      hunkOffsets: changes.rows.flatMap((row, index) => row.kind === "hunk" ? [index + 2] : []),
      maxHorizontalOffset: Math.max(0, ...changes.rows.flatMap((row) => {
        if (row.kind !== "content") return [0]
        const afterText = row.before.kind === "context" && row.after.kind === "context" && row.after.text === "" ? row.before.text : row.after.text
        return [maximumHorizontalOffset(row.before.text, bodyWidth), maximumHorizontalOffset(afterText, bodyWidth)]
      })),
    }
  }
  const rows: UnifiedDisplayRow[] = []
  const hunkOffsets: number[] = []
  for (const row of changes.rows) {
    if (row.kind === "hunk") {
      hunkOffsets.push(rows.length)
      rows.push({ kind: "hunk", oldLine: 0, newLine: 0, text: row.header })
      continue
    }
    if (row.before.kind === "context") rows.push({ kind: "context", oldLine: row.before.line, newLine: row.after.line, text: row.before.text })
    else {
      if (row.before.kind === "delete") rows.push({ kind: "delete", oldLine: row.before.line, newLine: 0, text: row.before.text })
      if (row.after.kind === "add") rows.push({ kind: "add", oldLine: 0, newLine: row.after.line, text: row.after.text })
    }
  }
  const bodyWidth = Math.max(1, width - textWidth(`${lineNumber(1)} ${lineNumber(1)} + `))
  return {
    lines: rows.map((row) => unifiedLine(row, width, horizontalOffset)),
    hunkOffsets,
    maxHorizontalOffset: Math.max(0, ...rows.filter((row) => row.kind !== "hunk").map((row) => maximumHorizontalOffset(row.text, bodyWidth))),
  }
}

function fileLabel(file: ChangeFile, cursor: boolean, selected: boolean, width: number): string {
  const prefix = `${cursor ? ">" : " "}${selected ? "*" : " "} ${file.status}${file.detail ? "!" : " "} `
  return fit(prefix + file.path, width)
}

function statusLabel(status: ChangeFile["status"]): string {
  if (status === "A") return "ADDED"
  if (status === "M") return "MODIFIED"
  if (status === "D") return "DELETED"
  return "RENAMED"
}

function focused(name: string, active: boolean): string {
  return active ? `[${name}]` : ` ${name} `
}

function fileWindow(changes: ChangesView, cursor: number, rows: number): { start: number; files: ChangeFile[] } {
  const count = Math.max(1, rows)
  const start = Math.max(0, Math.min(cursor - Math.floor(count / 2), changes.files.length - count))
  return { start, files: changes.files.slice(start, start + count) }
}

export function initialChangesState(view: View): ChangesState {
  const selected = Math.max(0, view.changes?.files.findIndex((file) => file.action_id === view.changes?.selected_action_id) ?? 0)
  const diffOffset = view.changes?.initial_diff_position === "end" ? Number.MAX_SAFE_INTEGER : 0
  return { focus: view.changes?.initial_focus ?? "files", fileCursor: selected, actionCursor: 0, diffOffset, diffColumnOffset: 0 }
}

export function changesActionIndexes(view: View): number[] {
  const fileActions = new Set(view.changes?.files.map((file) => file.action_id) ?? [])
  const indexes: number[] = []
  for (let index = 0; index < view.actions.length; index++) if (!fileActions.has(view.actions[index].id) && !view.actions[index].id.startsWith("diff.")) indexes.push(index)
  return indexes
}

export function renderChanges(view: View, state: ChangesState, width: number, height: number): ChangesDisplay {
  const changes = view.changes
  if (!changes) return { lines: [], diffPageSize: 1, maxDiffOffset: 0, maxHorizontalOffset: 0, hunkOffsets: [], actionIndexes: [] }
  width = Math.max(1, width)
  height = Math.max(1, height)
  const actionIndexes = changesActionIndexes(view)
  const selectedFile = changes.files.find((file) => file.action_id === changes.selected_action_id) ?? changes.files[0]
  if (width < 40 || height < 12) {
    const compact: DisplayLine[] = [
      [plain(fit("sunaba · Changes", width))],
      [plain(fit("Terminal too small for safe review; enlarge it or press Escape.", width))],
      [plain(fit(`${selectedFile.status} ${selectedFile.path}`, width))],
      [plain(fit("Escape keep pending", width))],
    ]
    compact.splice(height)
    while (compact.length < height) compact.push([])
    return { lines: compact, diffPageSize: 1, maxDiffOffset: Math.max(0, changes.rows.length - 1), maxHorizontalOffset: 0, hunkOffsets: [], actionIndexes }
  }
  const useSideBySide = changes.layout === "side-by-side" && width >= 120
  const header: DisplayLine[] = [
    [plain(fit("sunaba · Changes", width))],
    [plain(fit(view.title, width))],
    [plain(fit(changes.summary, width))],
    [],
  ]
  const footerRows = 3
  const contentRows = Math.max(5, height - header.length - footerRows)
  const lines: DisplayLine[] = [...header]
  let availableDiffRows = contentRows
  let renderedDiff: DisplayLine[] = []
  let maxDiffOffset = 0
  let maxHorizontalOffset = 0
  let hunkOffsets: number[] = []

  if (width >= 100) {
    const leftWidth = Math.max(24, Math.min(36, Math.floor(width * 0.28)))
    const rightWidth = Math.max(20, width - leftWidth - 3)
    const sizing = diffDisplay(changes, rightWidth, useSideBySide, 0)
    maxHorizontalOffset = Math.max(sizing.maxHorizontalOffset, selectedFile.detail ? maximumHorizontalOffset(`DETAILS: ${selectedFile.detail}`, rightWidth) : 0)
    const horizontalOffset = Math.min(state.diffColumnOffset, maxHorizontalOffset)
    const rendered = horizontalOffset === 0 ? sizing : diffDisplay(changes, rightWidth, useSideBySide, horizontalOffset)
    const supplemental: DisplayLine[] = []
    if (selectedFile.detail) supplemental.push([toned(horizontalWindow(`DETAILS: ${selectedFile.detail}`, rightWidth, horizontalOffset), "muted")])
    if (changes.diff_total === 0) supplemental.push([toned(fit("No inline text diff for this file.", rightWidth), "muted")])
    const allDiff = [...supplemental, ...rendered.lines]
    hunkOffsets = rendered.hunkOffsets.map((offset) => offset + supplemental.length)
    availableDiffRows = Math.max(1, contentRows - 1)
    maxDiffOffset = Math.max(0, allDiff.length - availableDiffRows)
    const offset = Math.max(0, Math.min(state.diffOffset, maxDiffOffset))
    renderedDiff = allDiff.slice(offset, offset + availableDiffRows)
    const window = fileWindow(changes, state.fileCursor, availableDiffRows)
    const rowRange = changes.diff_total === 0 ? "no text rows" : `rows ${changes.diff_start + 1}-${changes.diff_start + changes.rows.length}/${changes.diff_total} · page ${changes.diff_page}/${changes.diff_pages}`
    const columnRange = maxHorizontalOffset > 0 ? ` · column ${horizontalOffset + 1}/${maxHorizontalOffset + 1}` : ""
    lines.push([
      plain(fit(`${focused("Files", state.focus === "files")} ${changes.page}/${changes.pages}`, leftWidth)), plain(" │ "),
      plain(fit(`${focused("Diff", state.focus === "diff")} ${statusLabel(selectedFile.status)} · ${useSideBySide ? "side-by-side" : "unified"} · ${rowRange}${columnRange} · ${selectedFile.path}`, rightWidth)),
    ])
    for (let row = 0; row < availableDiffRows; row++) {
      const fileIndex = window.start + row
      const file = window.files[row]
      const left = file ? fileLabel(file, fileIndex === state.fileCursor && state.focus === "files", file.action_id === changes.selected_action_id, leftWidth) : " ".repeat(leftWidth)
      lines.push([plain(left), plain(" │ "), ...(renderedDiff[row] ?? (useSideBySide ? emptySideLine(rightWidth) : [plain("")]))])
    }
  } else {
    const fileRows = Math.max(1, Math.min(5, changes.files.length, Math.floor(contentRows / 3)))
    const window = fileWindow(changes, state.fileCursor, fileRows)
    lines.push([plain(`${focused("Files", state.focus === "files")} ${changes.page}/${changes.pages}`)])
    for (let row = 0; row < fileRows; row++) {
      const fileIndex = window.start + row
      const file = window.files[row]
      if (file) lines.push([plain(fileLabel(file, fileIndex === state.fileCursor && state.focus === "files", file.action_id === changes.selected_action_id, width))])
    }
    const rowRange = changes.diff_total === 0 ? "no text rows" : `rows ${changes.diff_start + 1}-${changes.diff_start + changes.rows.length}/${changes.diff_total} · page ${changes.diff_page}/${changes.diff_pages}`
    lines.push([plain(fit(`${focused("Diff", state.focus === "diff")} ${statusLabel(selectedFile.status)} · unified · ${rowRange} · ${selectedFile.path}`, width))])
    availableDiffRows = Math.max(1, contentRows - fileRows - 2)
    const sizing = diffDisplay(changes, width, false, 0)
    maxHorizontalOffset = Math.max(sizing.maxHorizontalOffset, selectedFile.detail ? maximumHorizontalOffset(`DETAILS: ${selectedFile.detail}`, width) : 0)
    const horizontalOffset = Math.min(state.diffColumnOffset, maxHorizontalOffset)
    const rendered = horizontalOffset === 0 ? sizing : diffDisplay(changes, width, false, horizontalOffset)
    const supplemental: DisplayLine[] = []
    if (selectedFile.detail) supplemental.push([toned(horizontalWindow(`DETAILS: ${selectedFile.detail}`, width, horizontalOffset), "muted")])
    if (changes.diff_total === 0) supplemental.push([toned(fit("No inline text diff for this file.", width), "muted")])
    const allDiff = [...supplemental, ...rendered.lines]
    hunkOffsets = rendered.hunkOffsets.map((offset) => offset + supplemental.length)
    maxDiffOffset = Math.max(0, allDiff.length - availableDiffRows)
    const offset = Math.max(0, Math.min(state.diffOffset, maxDiffOffset))
    renderedDiff = allDiff.slice(offset, offset + availableDiffRows)
    lines.push(...renderedDiff)
  }

  while (lines.length < height - footerRows) lines.push([])
  lines.splice(height - footerRows)
  lines.push([plain("─".repeat(Math.max(1, width)))])
  let actionText = `${focused("Actions", state.focus === "actions")} `
  for (let index = 0; index < actionIndexes.length; index++) {
    const action = view.actions[actionIndexes[index]]
    actionText += `${state.focus === "actions" && index === state.actionCursor ? "[> " : "[ "}${action.label}${state.focus === "actions" && index === state.actionCursor ? " <]" : " ]"}${index + 1 < actionIndexes.length ? "  " : ""}`
  }
  if (textWidth(actionText) > width && actionIndexes.length) {
    const action = view.actions[actionIndexes[Math.min(state.actionCursor, actionIndexes.length - 1)]]
    actionText = `${focused("Actions", state.focus === "actions")} ${state.actionCursor + 1}/${actionIndexes.length} [> ${action.label} <]`
  }
  lines.push([plain(fit(actionText, width))])
  const help = state.focus === "diff" ? "Tab · ↑↓/PgUp/PgDn rows · ←→ columns · n/p hunks · Home/End · Enter files · Esc keep pending" : state.focus === "files" ? "Tab focus · ↑↓ choose file · Enter open diff · Escape keep pending" : "Tab focus · ←→ choose action · Enter confirm · Escape keep pending"
  lines.push([plain(fit(help, width))])
  return { lines, diffPageSize: availableDiffRows, maxDiffOffset, maxHorizontalOffset, hunkOffsets, actionIndexes }
}
