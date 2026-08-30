export const PROTOCOL_VERSION = 1
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
export type View = {
  version: number
  type: "view"
  screen_id: string
  revision: number
  binding: Binding
  title: string
  fields: TextField[]
  actions: Action[]
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

export function parseView(payload: Uint8Array, expected: { projectID: string; nonce: string }): View {
  if (payload.byteLength === 0 || payload.byteLength > MAX_FRAME_BYTES) throw new Error("view exceeds its size bound")
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload))
  } catch {
    throw new Error("view is not valid UTF-8 JSON")
  }
  if (!record(value) || !exactKeys(value, ["version", "type", "screen_id", "revision", "binding", "title", "fields", "actions"])) throw new Error("view has unknown or missing fields")
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
