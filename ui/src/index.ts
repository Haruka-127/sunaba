import { StyledText, TextRenderable, createCliRenderer, green, red, stringToStyledText, type CliRenderer, type KeyEvent, type TextChunk } from "@opentui/core"
import { MAX_FRAME_BYTES, decodeFrame, encodeFrame, makeEvent, parseView, type UIEvent, type View } from "./protocol"
import { createFinisher } from "./lifecycle"

type Launch = { socket: string; projectID: string; nonce: string }
type Transport = { socket: Bun.Socket<undefined>; view: View }

function launchArguments(args: string[]): Launch {
  const values = new Map<string, string>()
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]
    const value = args[index + 1]
    if (!value || !["--socket", "--project-id", "--nonce"].includes(name) || values.has(name)) throw new Error("invalid sunaba-ui launch arguments")
    values.set(name, value)
  }
  const socket = values.get("--socket") ?? ""
  const projectID = values.get("--project-id") ?? ""
  const nonce = values.get("--nonce") ?? ""
  if (values.size !== 3 || !socket.startsWith("/") || socket.length > 103 || socket.includes("\0") || projectID.length === 0 || projectID.length > 128 || !/^[0-9a-f]{64}$/.test(nonce)) throw new Error("invalid sunaba-ui launch binding")
  return { socket, projectID, nonce }
}

async function connect(launch: Launch): Promise<Transport> {
  return await new Promise((resolve, reject) => {
    let received = new Uint8Array()
    let settled = false
    void Bun.connect<undefined>({
      unix: launch.socket,
      socket: {
        data(socket, chunk) {
          if (settled) return
          if (received.byteLength + chunk.byteLength > MAX_FRAME_BYTES + 4) {
            settled = true
            socket.end()
            reject(new Error("view exceeds its size bound"))
            return
          }
          const combined = new Uint8Array(received.byteLength + chunk.byteLength)
          combined.set(received)
          combined.set(chunk, received.byteLength)
          received = combined
          try {
            const decoded = decodeFrame(received)
            if (!decoded.payload) return
            const view = parseView(decoded.payload, launch)
            settled = true
            resolve({ socket, view })
          } catch (error) {
            settled = true
            socket.end()
            reject(error)
          }
        },
        error(_socket, error) {
          if (!settled) reject(error)
        },
        close() {
          if (!settled) reject(new Error("Go authority closed before sending a view"))
        },
      },
    }).catch(reject)
  })
}

function screenName(screenID: string): string {
  switch (screenID) {
    case "home": return "Home"
    case "project-selector": return "Select a Project"
    case "setup": return "Setup"
    case "settings": return "Settings"
    case "changes": return "Changes"
    case "recovery": return "Recovery"
    default: return screenID
  }
}

function renderText(view: View, selected: number, inputMode: boolean, input: string): StyledText {
  const chunks: TextChunk[] = []
  const plain = (value: string) => chunks.push(...stringToStyledText(value).chunks)
  const diff = (value: string) => {
    for (const line of value.split(/(?<=\n)/u)) {
      if (process.env.NO_COLOR === undefined && line.startsWith("+ ")) chunks.push(green(line))
      else if (process.env.NO_COLOR === undefined && line.startsWith("- ")) chunks.push(red(line))
      else if (process.env.NO_COLOR === undefined && line.includes(" | ")) {
        const separator = line.indexOf(" | ")
        const before = line.slice(0, separator)
        const after = line.slice(separator + 3)
        if (before.startsWith("- ")) chunks.push(red(before)); else plain(before)
        plain(" | ")
        if (after.startsWith("+ ")) chunks.push(green(after)); else plain(after)
      } else plain(line)
    }
  }
  plain(`sunaba · ${screenName(view.screen_id)}\n${view.title}\n\n`)
  for (const field of view.fields) {
    plain(`${field.label}: `)
    if (view.screen_id === "changes" && field.id === "diff") diff(field.text)
    else plain(field.text)
    plain("\n")
  }
  if (view.fields.length) plain("\n")
  for (let index = 0; index < view.actions.length; index++) {
    const action = view.actions[index]
    plain(`${index === selected ? ">" : " "} ${action.label}\n`)
  }
  if (inputMode) {
    const action = view.actions[selected]
    plain(`\n${action.label}: ${action.input.masked ? "•".repeat([...input].length) : input}\n`)
  }
  plain(`\n${inputMode ? "Enter confirm · Escape cancel input" : "Arrow/Tab select · Enter confirm · Escape cancel"}`)
  return new StyledText(chunks)
}

async function run(transport: Transport): Promise<void> {
  let renderer: CliRenderer | undefined
  let finished = false
  let selected = 0
  let inputMode = false
  let input = ""

  const finishOnce = createFinisher<UIEvent>(() => renderer?.destroy(), (event) => transport.socket.end(encodeFrame(event)))
  const finish = (event: UIEvent) => { if (finished) return; finished = true; finishOnce(event) }

  try {
    renderer = await createCliRenderer({
      useMouse: false,
      enableMouseMovement: false,
      autoFocus: false,
      exitOnCtrlC: false,
      exitSignals: [],
      clearOnShutdown: true,
      useKittyKeyboard: null,
      openConsoleOnError: false,
    })
    const content = new TextRenderable(renderer, { content: renderText(transport.view, selected, inputMode, input) })
    renderer.root.add(content)
    const redraw = () => { content.content = renderText(transport.view, selected, inputMode, input) }
    const cancel = () => finish(makeEvent(transport.view, "cancel"))
    const signal = () => cancel()
    const panic = (error: unknown) => {
      const message = error instanceof Error ? error.message : "sunaba-ui failed"
      finish(makeEvent(transport.view, "terminal_error", "", "", message.slice(0, 4096).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, "?")))
    }
    process.once("SIGINT", signal)
    process.once("SIGTERM", signal)
    process.once("SIGHUP", signal)
    process.once("uncaughtException", panic)
    process.once("unhandledRejection", panic)
    renderer.keyInput.on("keypress", (key: KeyEvent) => {
      if (finished || key.eventType === "release") return
      if (key.name === "escape") {
        if (inputMode) {
          inputMode = false
          input = ""
          redraw()
        } else cancel()
        return
      }
      if (inputMode) {
        const action = transport.view.actions[selected]
        if (key.name === "return" || key.name === "enter") {
          finish(makeEvent(transport.view, "action", action.id, input))
        } else if (key.name === "backspace") {
          input = [...input].slice(0, -1).join("")
          redraw()
        } else if (!key.ctrl && !key.meta && key.sequence && new TextEncoder().encode(input + key.sequence).byteLength <= action.input.max_bytes && !/[\u0000-\u001f\u007f-\u009f]/u.test(key.sequence)) {
          input += key.sequence
          redraw()
        }
        return
      }
      if (key.name === "down" || key.name === "tab") {
        selected = transport.view.actions.length ? (selected + 1) % transport.view.actions.length : 0
        redraw()
      } else if (key.name === "up") {
        selected = transport.view.actions.length ? (selected + transport.view.actions.length - 1) % transport.view.actions.length : 0
        redraw()
      } else if ((key.name === "return" || key.name === "enter") && transport.view.actions[selected]) {
        const action = transport.view.actions[selected]
        if (action.input.allowed) {
          inputMode = true
          input = ""
          redraw()
        } else finish(makeEvent(transport.view, "action", action.id))
      }
    })
    if (transport.view.actions.length === 0) redraw()
  } catch (error) {
    const message = error instanceof Error ? error.message : "terminal initialization failed"
    finish(makeEvent(transport.view, "terminal_error", "", "", message.slice(0, 4096).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, "?")))
  }
}

async function main(): Promise<void> {
  const launch = launchArguments(Bun.argv.slice(2))
  await run(await connect(launch))
}

await main()
