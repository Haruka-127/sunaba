import { describe, expect, test } from "bun:test"
import { createFinisher } from "../src/lifecycle"

describe("terminal lifecycle", () => {
  for (const path of ["normal", "escape", "panic", "SIGINT", "helper-error"]) {
    test(`restores before response on ${path}`, () => {
      const order: string[] = []
      const finish = createFinisher<string>(() => order.push("restore"), (event) => order.push(`send:${event}`))
      finish(path)
      finish("duplicate")
      expect(order).toEqual(["restore", `send:${path}`])
    })
  }

  test("still sends a fail-closed response when restore throws", () => {
    const order: string[] = []
    const finish = createFinisher<string>(() => { order.push("restore"); throw new Error("restore") }, (event) => order.push(`send:${event}`))
    expect(() => finish("terminal-error")).toThrow()
    expect(order).toEqual(["restore", "send:terminal-error"])
  })
})
