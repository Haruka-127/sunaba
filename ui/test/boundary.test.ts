import { expect, test } from "bun:test"

test("helper exposes no Project, credential, network, shell, browser, clipboard, or editor access", async () => {
  const source = await Bun.file(new URL("../src/index.ts", import.meta.url)).text()
  for (const forbidden of [
    "fetch(", "Bun.serve", "Bun.spawn", "child_process", "node:http", "node:https",
    "clipboard", "openExternal", "exec(", "credentials", "policy.json", "project_root",
  ]) {
    expect(source.includes(forbidden)).toBeFalse()
  }
  expect(source).toContain("Bun.connect")
  expect(source).toContain("unix: launch.socket")
  expect(source.match(/from\s+["'][^"']+["']/g) ?? []).toEqual([
    'from "@opentui/core"',
    'from "./protocol"',
    'from "./lifecycle"',
  ])
})
