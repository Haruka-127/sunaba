import { describe, expect, test } from "bun:test"
import { initialChangesState, renderChanges } from "../src/changes"
import { PROTOCOL_VERSION, type SideBySideDiffRow, type UnifiedDiffRow, type View } from "../src/protocol"

function changesView(rows = 1): View {
  const unified: UnifiedDiffRow[] = [{ kind: "hunk", old_line: 0, new_line: 0, text: "@@ -0,0 +1,1 @@" }]
  const side: SideBySideDiffRow[] = [{ kind: "hunk", header: "@@ -0,0 +1,1 @@", before: { kind: "empty", line: 0, text: "" }, after: { kind: "empty", line: 0, text: "" } }]
  for (let line = 1; line <= rows; line++) {
    unified.push({ kind: "add", old_line: 0, new_line: line, text: line === 1 ? "test" : `line ${line}` })
    side.push({ kind: "content", header: "", before: { kind: "empty", line: 0, text: "" }, after: { kind: "add", line, text: line === 1 ? "test" : `line ${line}` } })
  }
  return {
    version: PROTOCOL_VERSION,
    type: "view",
    screen_id: "changes",
    revision: 1,
    binding: { process_id: process.pid, project_id: "project-1", nonce: "a".repeat(64) },
    title: "Review the host-generated Change Set",
    fields: [],
    actions: [
      { id: "file.0", label: "A test.txt", input: { allowed: false, masked: false, max_bytes: 0 } },
      { id: "apply-all", label: "Apply all 1 file", input: { allowed: false, masked: false, max_bytes: 0 } },
      { id: "back", label: "Keep pending and back", input: { allowed: false, masked: false, max_bytes: 0 } },
    ],
    changes: {
      summary: "1 file · 1 added · no warnings",
      layout: "side-by-side",
      page: 1,
      pages: 1,
      selected_action_id: "file.0",
      files: [{ action_id: "file.0", status: "A", path: "test.txt", detail: "" }],
      unified,
      side_by_side: side,
    },
  }
}

function plain(lines: ReturnType<typeof renderChanges>["lines"]): string {
  return lines.map((line) => line.map((segment) => segment.text).join("")).join("\n")
}

describe("Changes screen", () => {
  test("renders UI-owned multiline side-by-side structure with a fixed footer", () => {
    const view = changesView()
    const display = renderChanges(view, initialChangesState(view), 140, 24)
    const output = plain(display.lines)
    expect(display.lines).toHaveLength(24)
    expect(output).toContain("BEFORE (original)")
    expect(output).toContain("AFTER (proposed)")
    expect(output).toContain("── @@ -0,0 +1,1 @@")
    expect(output).toContain("+ test")
    expect(output).not.toContain("(empty)")
    expect(output).not.toContain("<U+000A>")
    const renderedLines = output.split("\n")
    const columns = renderedLines.findIndex((line) => line.includes("BEFORE (original)"))
    const footer = renderedLines.findIndex((line) => line.startsWith("─") && !line.includes("┼"))
    expect(columns).toBeGreaterThan(0)
    expect(footer).toBeGreaterThan(columns)
    for (const line of renderedLines.slice(columns, footer)) expect(line.split(/[│┼]/u)).toHaveLength(3)
    expect(output.split("\n").at(-1)).toContain("Enter open diff")
  })

  test("falls back to unified diff on a narrow terminal", () => {
    const view = changesView()
    const output = plain(renderChanges(view, initialChangesState(view), 80, 20).lines)
    expect(output).toContain("· unified")
    expect(output).toContain("+ test")
    expect(output).not.toContain("Before")
  })

  test("bounds the diff viewport and exposes page scrolling", () => {
    const view = changesView(80)
    const state = initialChangesState(view)
    state.focus = "diff"
    state.diffOffset = 40
    const display = renderChanges(view, state, 140, 18)
    expect(display.maxDiffOffset).toBeGreaterThan(0)
    expect(display.diffPageSize).toBeLessThan(80)
    expect(display.lines).toHaveLength(18)
    expect(plain(display.lines).split("\n").at(-1)).toContain("PgUp/PgDn")
  })

  test("does not overflow a terminal too small for safe review", () => {
    const view = changesView()
    const display = renderChanges(view, initialChangesState(view), 24, 4)
    expect(display.lines).toHaveLength(4)
    expect(display.lines.every((line) => line.map((segment) => segment.text).join("").length <= 24)).toBeTrue()
    expect(plain(display.lines)).toContain("Terminal too small")
  })
})
