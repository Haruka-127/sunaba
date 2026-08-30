// createFinisher centralizes terminal ownership: every completion path attempts
// restore exactly once before any protocol response leaves the process, and
// exposes the same completion promise to every caller so main can stay alive
// until the response transport has closed.
export function createFinisher<T>(restore: () => void, send: (event: T) => Promise<void> | void): (event: T) => Promise<void> {
  let completion: Promise<void> | undefined
  return (event: T) => {
    if (completion) return completion
    completion = (async () => {
      try {
        restore()
      } finally {
        await send(event)
      }
    })()
    return completion
  }
}
