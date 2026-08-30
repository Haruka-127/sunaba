import { describe, expect, test } from "bun:test"
import { createFinisher } from "../src/lifecycle"

describe("terminal lifecycle", () => {
  for (const path of ["normal", "escape", "panic", "SIGINT", "helper-error"]) {
    test(`restores before response and awaits transport close on ${path}`, async () => {
      const order: string[] = []
      let closeTransport!: () => void
      const transportClosed = new Promise<void>((resolve) => { closeTransport = resolve })
      const finish = createFinisher<string>(() => order.push("restore"), async (event) => {
        order.push(`send:${event}`)
        await transportClosed
        order.push("closed")
      })
      const completion = finish(path)
      expect(finish("duplicate")).toBe(completion)
      expect(order).toEqual(["restore", `send:${path}`])
      closeTransport()
      await completion
      expect(order).toEqual(["restore", `send:${path}`, "closed"])
    })
  }

  test("still sends a fail-closed response when restore throws", async () => {
    const order: string[] = []
    const finish = createFinisher<string>(() => { order.push("restore"); throw new Error("restore") }, (event) => { order.push(`send:${event}`) })
    await expect(finish("terminal-error")).rejects.toThrow("restore")
    expect(order).toEqual(["restore", "send:terminal-error"])
  })
})
