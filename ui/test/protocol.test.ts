import { describe, expect, test } from "bun:test"
import { MAX_FRAME_BYTES, PROTOCOL_VERSION, decodeFrame, encodeFrame, makeEvent, parseView, type View } from "../src/protocol"

const nonce = "a".repeat(64)
const view: View = {
  version: PROTOCOL_VERSION,
  type: "view",
  screen_id: "home",
  revision: 9,
  binding: { process_id: process.pid, project_id: "project-1", nonce },
  title: "Home",
  fields: [{ id: "status", label: "Status", text: "Ready" }],
  actions: [{ id: "start", label: "Start", input: { allowed: false, masked: false, max_bytes: 0 } }],
  changes: null,
}

describe("bounded protocol", () => {
  test("round trips one strict view and event", () => {
    const payload = new TextEncoder().encode(JSON.stringify(view))
    const parsed = parseView(payload, { projectID: "project-1", nonce })
    const frame = encodeFrame(makeEvent(parsed, "action", "start"))
    expect(decodeFrame(frame).consumed).toBe(frame.length)
  })

  test("rejects unknown fields, controls, stale identity and trailing bytes", () => {
    for (const changed of [
      { ...view, unknown: true },
      { ...view, title: "fake\nStart" },
      { ...view, binding: { ...view.binding, nonce: "b".repeat(64) } },
      { ...view, screen_id: "unknown" },
    ]) {
      expect(() => parseView(new TextEncoder().encode(JSON.stringify(changed)), { projectID: "project-1", nonce })).toThrow()
    }
    const event = encodeFrame(makeEvent(view, "exit"))
    const trailing = new Uint8Array(event.length + 1)
    trailing.set(event)
    expect(() => decodeFrame(trailing)).toThrow()
  })

  test("rejects oversize frame before allocation", () => {
    const header = new Uint8Array(4)
    new DataView(header.buffer).setUint32(0, MAX_FRAME_BYTES + 1, false)
    expect(() => decodeFrame(header)).toThrow()
  })

  test("accepts structured diff rows and rejects layout injection", () => {
    const structured: View = {
      ...view,
      screen_id: "changes",
      fields: [],
      actions: [
        { id: "file.0", label: "A test.txt", input: { allowed: false, masked: false, max_bytes: 0 } },
        { id: "back", label: "Back", input: { allowed: false, masked: false, max_bytes: 0 } },
      ],
      changes: {
        summary: "1 file · 1 added",
        layout: "side-by-side",
        page: 1,
        pages: 1,
        selected_action_id: "file.0",
        files: [{ action_id: "file.0", status: "A", path: "test.txt", detail: "" }],
        unified: [{ kind: "add", old_line: 0, new_line: 1, text: "test" }],
        side_by_side: [{ kind: "content", header: "", before: { kind: "empty", line: 0, text: "" }, after: { kind: "add", line: 1, text: "test" } }],
      },
    }
    expect(parseView(new TextEncoder().encode(JSON.stringify(structured)), { projectID: "project-1", nonce }).changes?.files[0].path).toBe("test.txt")
    const injected = structured.changes!
    expect(() => parseView(new TextEncoder().encode(JSON.stringify({ ...structured, changes: { ...injected, unified: [{ ...injected.unified[0], text: "test\nfake action" }] } })), { projectID: "project-1", nonce })).toThrow()
  })
})
