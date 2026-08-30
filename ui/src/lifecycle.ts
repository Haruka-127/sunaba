// createFinisher centralizes terminal ownership: every completion path attempts
// restore exactly once before any protocol response leaves the process.
export function createFinisher<T>(restore: () => void, send: (event: T) => void): (event: T) => void {
  let finished = false
  return (event: T) => {
    if (finished) return
    finished = true
    try {
      restore()
    } finally {
      send(event)
    }
  }
}
