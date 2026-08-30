import { CliRenderEvents, StyledText, TextRenderable, createCliRenderer, green, red, stringToStyledText, type CliRenderer, type KeyEvent, type TextChunk } from "@opentui/core"
import { MAX_FRAME_BYTES, decodeFrame, encodeFrame, makeEvent, makeRejectedViewEvent, parseView, type UIEvent, type View } from "./protocol"
import { createFinisher } from "./lifecycle"
import { changesActionIndexes, initialChangesState, renderChanges, type ChangesFocus, type ChangesState, type Segment } from "./changes"

type Launch = { socket: string; projectID: string; nonce: string }
type TransportBase = { socket: Bun.Socket<undefined>; closed: Promise<Error | undefined> }
type Transport = TransportBase & ({ kind: "view"; view: View } | { kind: "rejected"; event: UIEvent })

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
    let resolveClosed!: (error: Error | undefined) => void
    const closed = new Promise<Error | undefined>((closedResolve) => {
      resolveClosed = closedResolve
    })
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
          let decoded: ReturnType<typeof decodeFrame>
          try {
            decoded = decodeFrame(received)
          } catch (error) {
            settled = true
            socket.end()
            reject(error)
            return
          }
          if (!decoded.payload) return
          try {
            const view = parseView(decoded.payload, launch)
            settled = true
            socket.ref()
            resolve({ kind: "view", socket, view, closed })
          } catch (error) {
            settled = true
            const message = error instanceof Error ? error.message : "invalid authority view"
            const event = makeRejectedViewEvent(decoded.payload, launch, message)
            if (event) {
              socket.ref()
              resolve({ kind: "rejected", socket, event, closed })
            } else {
              socket.end()
              reject(error)
            }
          }
        },
        error(_socket, error) {
          if (!settled) {
            settled = true
            reject(error)
          } else resolveClosed(error)
        },
        close(_socket, error) {
          if (!settled) {
            settled = true
            reject(error ?? new Error("Go authority closed before sending a view"))
          } else resolveClosed(error)
        },
      },
    }).catch((error) => {
      if (!settled) {
        settled = true
        reject(error)
      }
    })
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

function renderText(view: View, selected: number, inputMode: boolean, input: string, changesState?: ChangesState, width = 80, height = 24): StyledText {
  const chunks: TextChunk[] = []
  const plain = (value: string) => chunks.push(...stringToStyledText(value).chunks)
  const styled = (segment: Segment) => {
    if (process.env.NO_COLOR === undefined && segment.tone === "add") chunks.push(green(segment.text))
    else if (process.env.NO_COLOR === undefined && segment.tone === "delete") chunks.push(red(segment.text))
    else plain(segment.text)
  }
  if (view.changes && changesState) {
    const display = renderChanges(view, changesState, width, height)
    for (let index = 0; index < display.lines.length; index++) {
      for (const segment of display.lines[index]) styled(segment)
      if (index + 1 < display.lines.length) plain("\n")
    }
    return new StyledText(chunks)
  }
  if (view.bulk) {
    const itemActions = new Set(view.bulk.items.map((item) => item.action_id))
    const otherActions = view.actions.filter((action) => !itemActions.has(action.id))
    const selectedAction = view.actions[selected]?.id
    const selectedItem = Math.max(0, view.bulk.items.findIndex((item) => item.action_id === selectedAction))
    const capacity = Math.max(1, Math.floor((Math.max(12, height) - 7 - otherActions.length) / 5))
    const start = Math.min(Math.max(0, selectedItem - capacity + 1), Math.max(0, view.bulk.items.length - capacity))
    const visible = view.bulk.items.slice(start, start + capacity)
    plain(`sunaba · Changes\n${view.title}\nBulk paths ${view.bulk.page}/${view.bulk.pages} · items ${start + 1}-${start + visible.length}/${view.bulk.items.length}\n\n`)
    for (const item of visible) {
      const actionIndex = view.actions.findIndex((action) => action.id === item.action_id)
      plain(`${actionIndex === selected ? ">" : " "} ${item.root}\n`)
      plain(`  ${item.summary} · ${item.capture_state}\n`)
      plain(`  Why: ${item.reason}\n`)
      plain(`  Host: ${item.disposition} · Data: ${item.retention}\n`)
      plain(`  Digest: ${item.digest_prefix}\n`)
    }
    for (let index = 0; index < view.actions.length; index++) {
      if (itemActions.has(view.actions[index].id)) continue
      plain(`${index === selected ? ">" : " "} ${view.actions[index].label}\n`)
    }
    plain(`\nArrow/Tab select · Enter details · Escape keep pending`)
    return new StyledText(chunks)
  }
  plain(`sunaba · ${screenName(view.screen_id)}\n${view.title}\n\n`)
  for (const field of view.fields) {
    plain(`${field.label}: `)
    plain(field.text)
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

async function run(transport: Extract<Transport, { kind: "view" }>): Promise<void> {
  let renderer: CliRenderer | undefined
  let finished = false
  let selected = 0
  let inputMode = false
  let input = ""
  let changesState = transport.view.changes ? initialChangesState(transport.view) : undefined
  let resolveCompletion!: () => void
  let rejectCompletion!: (error: unknown) => void
  const completion = new Promise<void>((resolve, reject) => {
    resolveCompletion = resolve
    rejectCompletion = reject
  })

  const finishOnce = createFinisher<UIEvent>(() => renderer?.destroy(), (event) => sendEventAndWaitForClose(transport, event))
  const finish = (event: UIEvent) => {
    if (finished) return
    finished = true
    void finishOnce(event).then(resolveCompletion, rejectCompletion)
  }

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
    const content = new TextRenderable(renderer, { content: renderText(transport.view, selected, inputMode, input, changesState, renderer.width, renderer.height) })
    renderer.root.add(content)
    const redraw = () => { content.content = renderText(transport.view, selected, inputMode, input, changesState, renderer!.width, renderer!.height) }
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
    renderer.on(CliRenderEvents.RESIZE, redraw)
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
      if (changesState && transport.view.changes) {
        const changes = transport.view.changes
        const focuses: ChangesFocus[] = ["files", "diff", "actions"]
        if (key.name === "tab") {
          changesState.focus = focuses[(focuses.indexOf(changesState.focus) + 1) % focuses.length]
          redraw()
          return
        }
        if (changesState.focus === "files") {
          if (key.name === "down") changesState.fileCursor = Math.min(changes.files.length - 1, changesState.fileCursor + 1)
          else if (key.name === "up") changesState.fileCursor = Math.max(0, changesState.fileCursor - 1)
          else if (key.name === "return" || key.name === "enter") {
            const actionID = changes.files[changesState.fileCursor]?.action_id
            const action = transport.view.actions.find((candidate) => candidate.id === actionID)
            if (action) finish(makeEvent(transport.view, "action", action.id))
            return
          }
          redraw()
          return
        }
        if (changesState.focus === "diff") {
          const display = renderChanges(transport.view, changesState, renderer!.width, renderer!.height)
          const currentOffset = Math.min(display.maxDiffOffset, changesState.diffOffset)
          const navigatePage = (actionID: "diff.prev" | "diff.next"): boolean => {
            const action = transport.view.actions.find((candidate) => candidate.id === actionID)
            if (!action) return false
            finish(makeEvent(transport.view, "action", action.id))
            return true
          }
          if (key.name === "down") {
            if (currentOffset < display.maxDiffOffset) changesState.diffOffset = currentOffset + 1
            else if (navigatePage("diff.next")) return
          } else if (key.name === "up") {
            if (currentOffset > 0) changesState.diffOffset = currentOffset - 1
            else if (navigatePage("diff.prev")) return
          } else if (key.name === "pagedown") {
            if (currentOffset < display.maxDiffOffset) changesState.diffOffset = Math.min(display.maxDiffOffset, currentOffset + display.diffPageSize)
            else if (navigatePage("diff.next")) return
          } else if (key.name === "pageup") {
            if (currentOffset > 0) changesState.diffOffset = Math.max(0, currentOffset - display.diffPageSize)
            else if (navigatePage("diff.prev")) return
          } else if (key.name === "right") changesState.diffColumnOffset = Math.min(display.maxHorizontalOffset, changesState.diffColumnOffset + 8)
          else if (key.name === "left") changesState.diffColumnOffset = Math.max(0, changesState.diffColumnOffset - 8)
          else if (key.name === "home") changesState.diffColumnOffset = 0
          else if (key.name === "end") changesState.diffColumnOffset = display.maxHorizontalOffset
          else if (!key.ctrl && !key.meta && key.sequence?.toLowerCase() === "n") {
            const next = display.hunkOffsets.find((offset) => offset > currentOffset)
            if (next !== undefined) changesState.diffOffset = Math.min(display.maxDiffOffset, next)
            else if (navigatePage("diff.next")) return
          } else if (!key.ctrl && !key.meta && key.sequence?.toLowerCase() === "p") {
            const previous = display.hunkOffsets.filter((offset) => offset < currentOffset).at(-1)
            if (previous !== undefined) changesState.diffOffset = previous
            else if (navigatePage("diff.prev")) return
          }
          else if (key.name === "return" || key.name === "enter") changesState.focus = "files"
          redraw()
          return
        }
        const actionIndexes = changesActionIndexes(transport.view)
        if (key.name === "right" || key.name === "down") changesState.actionCursor = actionIndexes.length ? (changesState.actionCursor + 1) % actionIndexes.length : 0
        else if (key.name === "left" || key.name === "up") changesState.actionCursor = actionIndexes.length ? (changesState.actionCursor + actionIndexes.length - 1) % actionIndexes.length : 0
        else if ((key.name === "return" || key.name === "enter") && actionIndexes.length) {
          const action = transport.view.actions[actionIndexes[changesState.actionCursor]]
          finish(makeEvent(transport.view, "action", action.id))
          return
        }
        redraw()
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
  await completion
}

async function sendEventAndWaitForClose(transport: TransportBase, event: UIEvent): Promise<void> {
  const frame = encodeFrame(event)
  const written = transport.socket.end(frame)
  if (written !== frame.byteLength) throw new Error("failed to write the complete UI response")
  const closeError = await transport.closed
  if (closeError) throw closeError
}

async function main(): Promise<void> {
  const launch = launchArguments(Bun.argv.slice(2))
  const transport = await connect(launch)
  if (transport.kind === "rejected") {
    await sendEventAndWaitForClose(transport, transport.event)
    return
  }
  await run(transport)
}

await main()
