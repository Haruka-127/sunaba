export const PROTOCOL_VERSION = 4
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
export type DiffCell = { kind: "empty" | "context" | "add" | "delete"; line: number; text: string }
export type DiffRow = { kind: "hunk" | "content"; header: string; before: DiffCell; after: DiffCell }
export type ChangesView = {
  summary: string
  layout: "unified" | "side-by-side"
  page: number
  pages: number
  selected_action_id: string
  initial_focus: "files" | "diff"
  initial_diff_position: "start" | "end"
  diff_start: number
  diff_total: number
  diff_page: number
  diff_pages: number
  files: ChangeFile[]
  rows: DiffRow[]
}
export type BulkItem = { action_id: string; bulk_id: string; root: string; reason: string; capture_state: string; disposition: string; retention: string; summary: string; digest_prefix: string }
export type BulkView = { page: number; pages: number; selected_action_id: string; items: BulkItem[] }
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
  bulk: BulkView | null
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
  if (!record(value) || !exactKeys(value, ["summary", "layout", "page", "pages", "selected_action_id", "initial_focus", "initial_diff_position", "diff_start", "diff_total", "diff_page", "diff_pages", "files", "rows"]) ||
    !safeText(value.summary, MAX_TEXT_BYTES) || value.layout !== "side-by-side" || !["files", "diff"].includes(String(value.initial_focus)) || !["start", "end"].includes(String(value.initial_diff_position)) ||
    !Number.isSafeInteger(value.page) || !Number.isSafeInteger(value.pages) || Number(value.page) <= 0 || Number(value.pages) < Number(value.page) ||
    !Number.isSafeInteger(value.diff_start) || !Number.isSafeInteger(value.diff_total) || !Number.isSafeInteger(value.diff_page) || !Number.isSafeInteger(value.diff_pages) || Number(value.diff_start) < 0 || Number(value.diff_total) < 0 || Number(value.diff_total) > 8192 || Number(value.diff_page) <= 0 || Number(value.diff_pages) < Number(value.diff_page) ||
    !safeText(value.selected_action_id, 64) || !Array.isArray(value.files) || value.files.length === 0 || value.files.length > 26 ||
    !Array.isArray(value.rows) || value.rows.length > 256) return false
  if (value.diff_total === 0 ? value.diff_start !== 0 || value.rows.length !== 0 || value.diff_page !== 1 || value.diff_pages !== 1 : value.rows.length === 0 || Number(value.diff_start) >= Number(value.diff_total) || Number(value.diff_start) + value.rows.length > Number(value.diff_total)) return false
  const fileActions = new Set<string>()
  for (const file of value.files) {
    if (!record(file) || !exactKeys(file, ["action_id", "status", "path", "detail"]) || !idPattern.test(String(file.action_id)) || !["A", "M", "D", "R"].includes(String(file.status)) || !safeText(file.path, MAX_TEXT_BYTES) || file.path === "" || !safeText(file.detail, MAX_TEXT_BYTES) || !actions.has(String(file.action_id)) || fileActions.has(String(file.action_id))) return false
    fileActions.add(String(file.action_id))
  }
  if (!fileActions.has(String(value.selected_action_id))) return false
  for (const row of value.rows) {
    if (!record(row) || !exactKeys(row, ["kind", "header", "before", "after"]) || !safeText(row.kind, 16) || !safeText(row.header, MAX_TEXT_BYTES)) return false
    if (row.kind === "hunk") {
      if (row.header === "" || !validateDiffCell(row.before, []) || !validateDiffCell(row.after, [])) return false
    } else if (row.kind === "content") {
      if (row.header !== "" || !validateDiffCell(row.before, ["context", "delete"]) || !validateDiffCell(row.after, ["context", "add"]) || row.before.kind === "empty" && row.after.kind === "empty") return false
    } else return false
  }
  return true
}

function validateBulk(value: unknown, actions: Set<string>): value is BulkView {
	if (!record(value) || !exactKeys(value, ["page", "pages", "selected_action_id", "items"]) || !Number.isSafeInteger(value.page) || !Number.isSafeInteger(value.pages) || Number(value.page) <= 0 || Number(value.pages) < Number(value.page) || !idPattern.test(String(value.selected_action_id)) || !Array.isArray(value.items) || value.items.length === 0 || value.items.length > 20) return false
	const seen = new Set<string>()
	for (const item of value.items) {
		if (!record(item) || !exactKeys(item, ["action_id", "bulk_id", "root", "reason", "capture_state", "disposition", "retention", "summary", "digest_prefix"]) || !idPattern.test(String(item.action_id)) || !actions.has(String(item.action_id)) || seen.has(String(item.action_id)) || !safeText(item.bulk_id, 128) || item.bulk_id === "" || !safeText(item.root, MAX_TEXT_BYTES) || item.root === "" || !safeText(item.reason, MAX_TEXT_BYTES) || item.reason === "" || !safeText(item.capture_state, 64) || item.capture_state === "" || !safeText(item.disposition, 64) || item.disposition === "" || !safeText(item.retention, MAX_TEXT_BYTES) || !safeText(item.summary, MAX_TEXT_BYTES) || item.summary === "" || !safeText(item.digest_prefix, 64)) return false
		seen.add(String(item.action_id))
	}
	return seen.has(String(value.selected_action_id))
}

export function parseView(payload: Uint8Array, expected: { projectID: string; nonce: string }): View {
  if (payload.byteLength === 0 || payload.byteLength > MAX_FRAME_BYTES) throw new Error("view exceeds its size bound")
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload))
  } catch {
    throw new Error("view is not valid UTF-8 JSON")
  }
  if (!record(value) || !exactKeys(value, ["version", "type", "screen_id", "revision", "binding", "title", "fields", "actions", "changes", "bulk"])) throw new Error("view has unknown or missing fields")
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
  if (value.bulk !== null && (value.screen_id !== "changes" || value.changes !== null || !validateBulk(value.bulk, actionIDs))) throw new Error("invalid structured Bulk view")
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

function boundedErrorText(value: string): string {
  let result = value.replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, "?")
  while (new TextEncoder().encode(result).byteLength > MAX_INPUT_BYTES) result = result.slice(0, -1)
  return result
}

// A rejected authority view cannot authorize an action, but if its immutable
// envelope is still bound to this helper process we can return a bounded
// terminal_error instead of closing the socket with an opaque EOF.
export function makeRejectedViewEvent(payload: Uint8Array, expected: { projectID: string; nonce: string }, message: string): UIEvent | undefined {
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload))
  } catch {
    return undefined
  }
  if (!record(value) || value.version !== PROTOCOL_VERSION || value.type !== "view" || !screenIDs.has(String(value.screen_id)) || !Number.isSafeInteger(value.revision) || Number(value.revision) <= 0 || !validateBinding(value.binding)) return undefined
  if (value.binding.project_id !== expected.projectID || value.binding.nonce !== expected.nonce) return undefined
  const safeError = boundedErrorText(`sunaba-ui rejected the authority view: ${message}`)
  return {
    version: PROTOCOL_VERSION,
    type: "event",
    screen_id: String(value.screen_id),
    revision: Number(value.revision),
    binding: value.binding,
    kind: "terminal_error",
    action_id: "",
    input: "",
    capability: { color: process.env.NO_COLOR === undefined, unicode: true },
    size: { width: Math.max(1, Math.min(1000, process.stdout.columns || 80)), height: Math.max(1, Math.min(1000, process.stdout.rows || 24)) },
    error: safeError,
  }
}
