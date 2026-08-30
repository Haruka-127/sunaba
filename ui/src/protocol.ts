export const PROTOCOL_VERSION = 2
export const MAX_FRAME_BYTES = 256 << 10
export const MAX_TEXT_BYTES = 64 << 10
export const MAX_INPUT_BYTES = 4 << 10

const idPattern = /^[a-z][a-z0-9._-]{0,63}$/
const noncePattern = /^[0-9a-f]{64}$/
const screenIDs = new Set(["home", "project-selector", "setup", "settings", "changes", "recovery"])

export type Binding = { process_id: number; project_id: string; nonce: string }
export type TextField = { id: string; label: string; text: string }
export type InputSpec = { allowed: boolean; masked: boolean; max_bytes: number }
export type Action = { id: string; label: string; input: InputSpec }
export type ChangeFile = { action_id: string; status: "A" | "M" | "D" | "R"; path: string; detail: string }
export type UnifiedDiffRow = { kind: "hunk" | "context" | "add" | "delete"; old_line: number; new_line: number; text: string }
export type DiffCell = { kind: "empty" | "context" | "add" | "delete"; line: number; text: string }
export type SideBySideDiffRow = { kind: "hunk" | "content"; header: string; before: DiffCell; after: DiffCell }
export type ChangesView = {
  summary: string
  layout: "unified" | "side-by-side"
  page: number
  pages: number
  selected_action_id: string
  files: ChangeFile[]
  unified: UnifiedDiffRow[]
  side_by_side: SideBySideDiffRow[]
}
export type View = {
  version: number
  type: "view"
  screen_id: string
  revision: number
  binding: Binding
  title: string
  fields: TextField[]
  actions: Action[]
  changes: ChangesView | null
}
export type EventKind = "action" | "cancel" | "exit" | "terminal_error"
export type UIEvent = {
  version: number
  type: "event"
  screen_id: string
  revision: number
  binding: Binding
  kind: EventKind
  action_id: string
  input: string
  capability: { color: boolean; unicode: boolean }
  size: { width: number; height: number }
  error: string
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort()
  return keys.length === expected.length && keys.every((key, index) => key === [...expected].sort()[index])
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function safeText(value: unknown, max: number): value is string {
  if (typeof value !== "string" || new TextEncoder().encode(value).byteLength > max) return false
  for (const character of value) {
    const point = character.codePointAt(0)!
    if (point < 0x20 || (point >= 0x7f && point <= 0x9f) || point === 0x061c || point === 0x200e || point === 0x200f || (point >= 0x202a && point <= 0x202e) || (point >= 0x2066 && point <= 0x2069)) return false
  }
  return true
}

function validateBinding(value: unknown): value is Binding {
  return record(value) && exactKeys(value, ["process_id", "project_id", "nonce"]) &&
    Number.isSafeInteger(value.process_id) && value.process_id === process.pid &&
    safeText(value.project_id, 128) && noncePattern.test(String(value.nonce))
}

function validateInput(value: unknown): value is InputSpec {
  if (!record(value) || !exactKeys(value, ["allowed", "masked", "max_bytes"]) || typeof value.allowed !== "boolean" || typeof value.masked !== "boolean" || !Number.isSafeInteger(value.max_bytes)) return false
  return value.allowed ? Number(value.max_bytes) > 0 && Number(value.max_bytes) <= MAX_INPUT_BYTES : value.masked === false && value.max_bytes === 0
}

function validateDiffCell(value: unknown, allowed: readonly string[]): value is DiffCell {
  if (!record(value) || !exactKeys(value, ["kind", "line", "text"]) || !safeText(value.kind, 16) || !safeText(value.text, MAX_TEXT_BYTES) || !Number.isSafeInteger(value.line)) return false
  if (value.kind === "empty") return value.line === 0 && value.text === ""
  return allowed.includes(value.kind) && Number(value.line) > 0
}

function validateChanges(value: unknown, actions: Set<string>): value is ChangesView {
  if (!record(value) || !exactKeys(value, ["summary", "layout", "page", "pages", "selected_action_id", "files", "unified", "side_by_side"]) ||
    !safeText(value.summary, MAX_TEXT_BYTES) || !["unified", "side-by-side"].includes(String(value.layout)) ||
    !Number.isSafeInteger(value.page) || !Number.isSafeInteger(value.pages) || Number(value.page) <= 0 || Number(value.pages) < Number(value.page) ||
    !safeText(value.selected_action_id, 64) || !Array.isArray(value.files) || value.files.length === 0 || value.files.length > 28 ||
    !Array.isArray(value.unified) || value.unified.length > 1024 || !Array.isArray(value.side_by_side) || value.side_by_side.length > 1024) return false
  const fileActions = new Set<string>()
  for (const file of value.files) {
    if (!record(file) || !exactKeys(file, ["action_id", "status", "path", "detail"]) || !idPattern.test(String(file.action_id)) || !["A", "M", "D", "R"].includes(String(file.status)) || !safeText(file.path, MAX_TEXT_BYTES) || file.path === "" || !safeText(file.detail, MAX_TEXT_BYTES) || !actions.has(String(file.action_id)) || fileActions.has(String(file.action_id))) return false
    fileActions.add(String(file.action_id))
  }
  if (!fileActions.has(String(value.selected_action_id))) return false
  for (const row of value.unified) {
    if (!record(row) || !exactKeys(row, ["kind", "old_line", "new_line", "text"]) || !safeText(row.kind, 16) || !safeText(row.text, MAX_TEXT_BYTES) || !Number.isSafeInteger(row.old_line) || !Number.isSafeInteger(row.new_line)) return false
    if (row.kind === "hunk" ? row.text === "" || row.old_line !== 0 || row.new_line !== 0 :
      row.kind === "context" ? Number(row.old_line) <= 0 || Number(row.new_line) <= 0 :
      row.kind === "delete" ? Number(row.old_line) <= 0 || row.new_line !== 0 :
      row.kind === "add" ? row.old_line !== 0 || Number(row.new_line) <= 0 : true) return false
  }
  for (const row of value.side_by_side) {
    if (!record(row) || !exactKeys(row, ["kind", "header", "before", "after"]) || !safeText(row.kind, 16) || !safeText(row.header, MAX_TEXT_BYTES)) return false
    if (row.kind === "hunk") {
      if (row.header === "" || !validateDiffCell(row.before, []) || !validateDiffCell(row.after, [])) return false
    } else if (row.kind === "content") {
      if (row.header !== "" || !validateDiffCell(row.before, ["context", "delete"]) || !validateDiffCell(row.after, ["context", "add"]) || row.before.kind === "empty" && row.after.kind === "empty") return false
    } else return false
  }
  return true
}

export function parseView(payload: Uint8Array, expected: { projectID: string; nonce: string }): View {
  if (payload.byteLength === 0 || payload.byteLength > MAX_FRAME_BYTES) throw new Error("view exceeds its size bound")
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload))
  } catch {
    throw new Error("view is not valid UTF-8 JSON")
  }
  if (!record(value) || !exactKeys(value, ["version", "type", "screen_id", "revision", "binding", "title", "fields", "actions", "changes"])) throw new Error("view has unknown or missing fields")
  if (value.version !== PROTOCOL_VERSION || value.type !== "view" || !screenIDs.has(String(value.screen_id)) || !Number.isSafeInteger(value.revision) || Number(value.revision) <= 0 || !validateBinding(value.binding)) throw new Error("invalid view envelope")
  if (value.binding.project_id !== expected.projectID || value.binding.nonce !== expected.nonce || !safeText(value.title, MAX_TEXT_BYTES) || !Array.isArray(value.fields) || value.fields.length > 256 || !Array.isArray(value.actions) || value.actions.length > 32) throw new Error("unbound or oversized view")
  const fieldIDs = new Set<string>()
  for (const field of value.fields) {
    if (!record(field) || !exactKeys(field, ["id", "label", "text"]) || !idPattern.test(String(field.id)) || !safeText(field.label, MAX_TEXT_BYTES) || !safeText(field.text, MAX_TEXT_BYTES) || fieldIDs.has(String(field.id))) throw new Error("invalid view field")
    fieldIDs.add(String(field.id))
  }
  const actionIDs = new Set<string>()
  for (const action of value.actions) {
    if (!record(action) || !exactKeys(action, ["id", "label", "input"]) || !idPattern.test(String(action.id)) || !safeText(action.label, 256) || !validateInput(action.input) || actionIDs.has(String(action.id))) throw new Error("invalid view action")
    actionIDs.add(String(action.id))
  }
  if (value.changes !== null && (value.screen_id !== "changes" || !validateChanges(value.changes, actionIDs))) throw new Error("invalid structured Changes view")
  return value as View
}

export function decodeFrame(buffer: Uint8Array): { payload?: Uint8Array; consumed: number } {
  if (buffer.byteLength < 4) return { consumed: 0 }
  const size = new DataView(buffer.buffer, buffer.byteOffset, 4).getUint32(0, false)
  if (size === 0 || size > MAX_FRAME_BYTES) throw new Error("frame exceeds its size bound")
  if (buffer.byteLength < size + 4) return { consumed: 0 }
  if (buffer.byteLength !== size + 4) throw new Error("view contains trailing data")
  return { payload: buffer.slice(4), consumed: size + 4 }
}

export function encodeFrame(value: UIEvent): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(value))
  if (payload.byteLength === 0 || payload.byteLength > MAX_FRAME_BYTES) throw new Error("event exceeds its size bound")
  const frame = new Uint8Array(payload.byteLength + 4)
  new DataView(frame.buffer).setUint32(0, payload.byteLength, false)
  frame.set(payload, 4)
  return frame
}

export function makeEvent(view: View, kind: EventKind, actionID = "", input = "", error = ""): UIEvent {
  if (new TextEncoder().encode(input).byteLength > MAX_INPUT_BYTES || new TextEncoder().encode(error).byteLength > MAX_INPUT_BYTES) throw new Error("event input exceeds its size bound")
  return {
    version: PROTOCOL_VERSION,
    type: "event",
    screen_id: view.screen_id,
    revision: view.revision,
    binding: view.binding,
    kind,
    action_id: actionID,
    input,
    capability: { color: process.env.NO_COLOR === undefined, unicode: true },
    size: { width: Math.max(1, Math.min(1000, process.stdout.columns || 80)), height: Math.max(1, Math.min(1000, process.stdout.rows || 24)) },
    error,
  }
}
