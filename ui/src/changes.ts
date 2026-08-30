import type { ChangeFile, ChangesView, DiffCell, SideBySideDiffRow, UnifiedDiffRow, View } from "./protocol"

export type ChangesFocus = "files" | "diff" | "actions"
export type ChangesState = { focus: ChangesFocus; fileCursor: number; actionCursor: number; diffOffset: number }
export type Tone = "plain" | "add" | "delete" | "muted"
export type Segment = { text: string; tone: Tone }
export type DisplayLine = Segment[]
export type ChangesDisplay = { lines: DisplayLine[]; diffPageSize: number; maxDiffOffset: number; actionIndexes: number[] }

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

function unifiedLine(row: UnifiedDiffRow, width: number): DisplayLine {
  if (row.kind === "hunk") return [toned(fit(row.text, width), "muted")]
  const prefix = `${lineNumber(row.old_line)} ${lineNumber(row.new_line)} ${marker(row.kind)} `
  return [toned(prefix + fit(row.text, Math.max(1, width - textWidth(prefix))), tone(row.kind))]
}

function cell(cell: DiffCell, width: number): Segment {
  if (cell.kind === "empty") return toned(" ".repeat(Math.max(0, width)), "muted")
  const prefix = `${lineNumber(cell.line)} ${marker(cell.kind)} `
  return toned(prefix + fit(cell.text, Math.max(1, width - textWidth(prefix))), tone(cell.kind))
}

function sideColumns(width: number): { before: number; after: number } {
  const before = Math.max(12, Math.floor((width - 3) / 2))
  return { before, after: Math.max(1, width - before - 3) }
}

function emptySideLine(width: number): DisplayLine {
  const columns = sideColumns(width)
  return [plain(" ".repeat(columns.before)), plain(" │ "), plain(" ".repeat(columns.after))]
}

function sideLine(row: SideBySideDiffRow, width: number): DisplayLine {
  const columns = sideColumns(width)
  if (row.kind === "hunk") {
    const label = `── ${row.header} `
    return [toned(fit(label, columns.before).replace(/ +$/, (spaces) => "─".repeat(spaces.length)), "muted"), plain("─┼─"), toned("─".repeat(columns.after), "muted")]
  }
  return [cell(row.before, columns.before), plain(" │ "), cell(row.after, columns.after)]
}

function diffLines(changes: ChangesView, width: number, sideBySide: boolean): DisplayLine[] {
  if (sideBySide) {
    const column = Math.max(12, Math.floor((width - 3) / 2))
    const remainder = Math.max(1, width - column - 3)
    return [
      [plain(fit("BEFORE (original)", column)), plain(" │ "), plain(fit("AFTER (proposed)", remainder))],
      [plain("─".repeat(column)), plain("─┼─"), plain("─".repeat(remainder))],
      ...changes.side_by_side.map((row) => sideLine(row, width)),
    ]
  }
  return changes.unified.map((row) => unifiedLine(row, width))
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
  return { focus: "files", fileCursor: selected, actionCursor: 0, diffOffset: 0 }
}

export function changesActionIndexes(view: View): number[] {
  const fileActions = new Set(view.changes?.files.map((file) => file.action_id) ?? [])
  const indexes: number[] = []
  for (let index = 0; index < view.actions.length; index++) if (!fileActions.has(view.actions[index].id)) indexes.push(index)
  return indexes
}

export function renderChanges(view: View, state: ChangesState, width: number, height: number): ChangesDisplay {
  const changes = view.changes
  if (!changes) return { lines: [], diffPageSize: 1, maxDiffOffset: 0, actionIndexes: [] }
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
    return { lines: compact, diffPageSize: 1, maxDiffOffset: Math.max(0, changes.unified.length - 1), actionIndexes }
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
  let renderedDiff: DisplayLine[]

  if (width >= 100) {
    const leftWidth = Math.max(24, Math.min(36, Math.floor(width * 0.28)))
    const rightWidth = Math.max(20, width - leftWidth - 3)
    const allDiff = diffLines(changes, rightWidth, useSideBySide)
    availableDiffRows = Math.max(1, contentRows - 1)
    const maxOffset = Math.max(0, allDiff.length - availableDiffRows)
    const offset = Math.max(0, Math.min(state.diffOffset, maxOffset))
    renderedDiff = allDiff.slice(offset, offset + availableDiffRows)
    const window = fileWindow(changes, state.fileCursor, availableDiffRows)
    lines.push([
      plain(fit(`${focused("Files", state.focus === "files")} ${changes.page}/${changes.pages}`, leftWidth)), plain(" │ "),
      plain(fit(`${focused("Diff", state.focus === "diff")} ${statusLabel(selectedFile.status)} · ${selectedFile.path} · ${useSideBySide ? "side-by-side" : "unified"} · ${offset + 1}-${Math.min(allDiff.length, offset + availableDiffRows)}/${allDiff.length}`, rightWidth)),
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
    lines.push([plain(`${focused("Diff", state.focus === "diff")} ${statusLabel(selectedFile.status)} · ${selectedFile.path} · unified`)])
    availableDiffRows = Math.max(1, contentRows - fileRows - 2)
    const allDiff = diffLines(changes, width, false)
    const maxOffset = Math.max(0, allDiff.length - availableDiffRows)
    const offset = Math.max(0, Math.min(state.diffOffset, maxOffset))
    renderedDiff = allDiff.slice(offset, offset + availableDiffRows)
    lines.push(...renderedDiff)
  }

  const allDiffCount = useSideBySide && width >= 100 ? changes.side_by_side.length + 2 : changes.unified.length
  const maxDiffOffset = Math.max(0, allDiffCount - availableDiffRows)
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
  const help = state.focus === "diff" ? "Tab focus · ↑↓/PgUp/PgDn scroll · Enter return to files · Escape keep pending" : state.focus === "files" ? "Tab focus · ↑↓ choose file · Enter open diff · Escape keep pending" : "Tab focus · ←→ choose action · Enter confirm · Escape keep pending"
  lines.push([plain(fit(help, width))])
  return { lines, diffPageSize: availableDiffRows, maxDiffOffset, actionIndexes }
}
