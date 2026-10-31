import { generateKeyPairSync } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const { state, FakeWorker } = await vi.hoisted(async () => {
  const { EventEmitter } = await import('node:events')
  const state = {
    workers: [] as FakeWorker[],
    failSpawn: false,
    failPost: false,
    failStop: false,
  }
  class FakeWorker extends EventEmitter {
    messages: { id: number; operation: string; input: unknown }[] = []
    ref = vi.fn()
    unref = vi.fn()
    postMessage(message: { id: number; operation: string; input: unknown }) {
      if (state.failPost) throw new Error('dispatch failure')
      this.messages.push(message)
    }
    terminate() {
      return state.failStop
        ? Promise.reject(new Error('stop failure'))
        : Promise.resolve(0)
    }
    reply(result: unknown = 'ok') {
      this.emit('message', { id: this.messages.at(-1)!.id, result })
    }
  }
  return { state, FakeWorker }
})
vi.mock('node:worker_threads', () => ({
  Worker: class extends FakeWorker {
    constructor() {
      super()
      if (state.failSpawn) throw new Error('spawn failure')
      state.workers.push(this)
    }
  },
}))
import { TraceabilityWorkerPool } from '../src/workers/pool.js'

const pools: TraceabilityWorkerPool[] = []
function pool(options: ConstructorParameters<typeof TraceabilityWorkerPool>[0] = {}) {
  const result = new TraceabilityWorkerPool(options)
  pools.push(result)
  return result
}
beforeEach(() => {
  state.workers = []
  state.failSpawn = false
  state.failPost = false
  state.failStop = false
})
afterEach(async () => {
  await Promise.all(pools.splice(0).map(item => item.close()))
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('worker pool transport and lifecycle', () => {
  it('transports plain snapshots, Ed25519 keys, and structured worker errors', async () => {
    const executor = pool({ concurrency: 1 })
    const value = Object.assign(Object.create(null) as Record<string, unknown>, {
      nested: [null, true, 2, 'x'],
      key: generateKeyPairSync('ed25519').privateKey,
    })
    const first = executor.execute('hashJSON', { value })
    expect(state.workers[0]!.messages[0]!.input).not.toBe(value)
    state.workers[0]!.emit('message', { id: 999, result: 'stale' })
    state.workers[0]!.reply('hash')
    await expect(first).resolves.toBe('hash')
    state.workers[0]!.reply('ignored idle response')
    const second = executor.execute('hashJSON', { value: 2 })
    state.workers[0]!.emit('message', {
      id: 2,
      error: { code: 'INVALID_NUMBER', message: 'Invalid number', context: {} },
    })
    await expect(second).rejects.toMatchObject({ code: 'INVALID_NUMBER' })
    expect(executor.stats).toMatchObject({
      active: 0,
      completed: 1,
      failed: 1,
      pendingBytes: 0,
    })
  })

  it.each(['spawn', 'post', 'error', 'exit'] as const)(
    'recovers after %s failure',
    async mode => {
      const executor = pool({ concurrency: 1 })
      state.failSpawn = mode === 'spawn'
      state.failPost = mode === 'post'
      const first = executor.execute('hashJSON', { value: 1 })
      const rejected = expect(first).rejects.toMatchObject({ code: 'WORKER_FAILURE' })
      if (mode === 'error')
        state.workers[0]!.emit('error', new Error('private failure details'))
      if (mode === 'exit') state.workers[0]!.emit('exit', 1)
      await rejected
      state.failSpawn = false
      state.failPost = false
      await Promise.resolve()
      const second = executor.execute('hashJSON', { value: 2 })
      state.workers.at(-1)!.reply()
      await expect(second).resolves.toBe('ok')
    }
  )

  it('handles an idle worker exit and idle error without losing queued work', async () => {
    const executor = pool({ concurrency: 1 })
    const first = executor.execute('hashJSON', { value: 1 })
    state.workers[0]!.reply()
    await first
    state.workers[0]!.emit('exit', 0)
    const second = executor.execute('hashJSON', { value: 2 })
    state.workers[1]!.reply()
    await second
    state.workers[1]!.emit('error', new Error('idle failure'))
    await Promise.resolve()
  })

  it('bounds queue length and total bytes without dropping accepted jobs', async () => {
    const executor = pool({
      concurrency: 1,
      maxQueuedJobs: 1,
      maxPendingBytes: 1000,
      maxTaskBytes: 1000,
    })
    const first = executor.execute('hashJSON', { value: 1 })
    const second = executor.execute('hashJSON', { value: 2 })
    await expect(executor.execute('hashJSON', { value: 3 })).rejects.toMatchObject({
      code: 'QUEUE_FULL',
    })
    expect(executor.stats.queued).toBe(1)
    state.workers[0]!.reply()
    await first
    state.workers[0]!.reply()
    await second
    const active = executor.execute('hashJSON', { value: 'x'.repeat(300) })
    await expect(
      executor.execute('hashJSON', { value: 'x'.repeat(300) })
    ).rejects.toMatchObject({ code: 'QUEUE_FULL' })
    state.workers[0]!.reply()
    await active
  })

  it('aborts queued and active tasks and supports disposal', async () => {
    const executor = pool({ concurrency: 1 })
    const a = new AbortController()
    const b = new AbortController()
    const first = executor.execute('hashJSON', { value: 1 }, { signal: a.signal })
    const second = executor.execute('hashJSON', { value: 2 }, { signal: b.signal })
    const checks = [
      expect(first).rejects.toMatchObject({ code: 'TASK_ABORTED' }),
      expect(second).rejects.toMatchObject({ code: 'TASK_ABORTED' }),
    ]
    b.abort()
    a.abort()
    state.workers[0]!.emit('exit', 1)
    await Promise.all(checks)
    await expect(
      executor.execute('hashJSON', { value: 1 }, { signal: AbortSignal.abort() })
    ).rejects.toMatchObject({ code: 'TASK_ABORTED' })
    state.failStop = true
    await executor[Symbol.asyncDispose]()
    await expect(executor.execute('hashJSON', { value: 1 })).rejects.toMatchObject({
      code: 'POOL_CLOSED',
    })
  })

  it('enforces preparation, queue, and execution deadlines', async () => {
    vi.useFakeTimers()
    const executor = pool({ concurrency: 1 })
    const first = executor.execute('hashJSON', { value: 1 }, { timeoutMs: 20 })
    const second = executor.execute('hashJSON', { value: 2 }, { timeoutMs: 10 })
    const a = expect(first).rejects.toMatchObject({ code: 'TASK_TIMEOUT' })
    const b = expect(second).rejects.toMatchObject({ code: 'TASK_TIMEOUT' })
    await vi.advanceTimersByTimeAsync(25)
    await Promise.all([a, b])
    vi.spyOn(performance, 'now').mockReturnValueOnce(0).mockReturnValueOnce(100)
    await expect(
      executor.execute('hashJSON', { value: 1 }, { timeoutMs: 1 })
    ).rejects.toMatchObject({ code: 'TASK_TIMEOUT' })
  })

  it('closes active and queued work even when termination rejects', async () => {
    state.failStop = true
    const executor = pool({ concurrency: 1 })
    const first = executor.execute('hashJSON', { value: 1 })
    const second = executor.execute('hashJSON', { value: 2 })
    const checks = [
      expect(first).rejects.toMatchObject({ code: 'POOL_CLOSED' }),
      expect(second).rejects.toMatchObject({ code: 'POOL_CLOSED' }),
    ]
    await Promise.all([executor.close(), executor.close(), ...checks])
    expect(executor.stats.pendingBytes).toBe(0)
  })

  it('rejects invalid settings and unsupported operations', async () => {
    for (const options of [
      { concurrency: 0 },
      { concurrency: 65 },
      { timeoutMs: NaN },
      { maxQueuedJobs: 0.5 },
    ]) {
      expect(() => pool(options)).toThrowError(
        expect.objectContaining({ code: 'INVALID_POOL_OPTIONS' })
      )
    }
    await expect(
      pool().execute('unknown' as 'hashJSON', { value: 1 })
    ).rejects.toMatchObject({ code: 'INVALID_OPERATION' })
  })

  it('rejects executable, cyclic, sparse, hidden, oversized and deep inputs', async () => {
    const executor = pool({ maxTaskBytes: 1000 })
    const cyclic: unknown[] = []
    cyclic.push(cyclic)
    const getter = vi.fn(() => 1)
    const hidden = Object.defineProperty({}, 'hidden', { value: 1 })
    const invalid = [
      undefined,
      () => {},
      new Proxy({}, {}),
      new Date(),
      new Set(),
      cyclic,
      new Array(2),
      { [Symbol()]: 1 },
      hidden,
      Object.defineProperty({}, 'a', { enumerable: true, get: getter }),
      Object.assign([], { x: 1 }),
      Object.assign(new Array(1), { '01': 1 }),
    ]
    for (const value of invalid)
      await expect(executor.execute('hashJSON', { value })).rejects.toMatchObject({
        code: 'INVALID_WORKER_INPUT',
      })
    expect(getter).not.toHaveBeenCalled()
    await expect(
      executor.execute('hashJSON', { value: 'x'.repeat(1000) })
    ).rejects.toMatchObject({ code: 'TASK_TOO_LARGE' })
    let deep: unknown = 1
    for (let i = 0; i < 82; i++) deep = [deep]
    await expect(pool().execute('hashJSON', { value: deep })).rejects.toMatchObject({
      code: 'INVALID_WORKER_INPUT',
    })
  })
})

describe('late cancellation events', () => {
  it('ignores a cancellation callback delivered after task completion', async () => {
    const executor = pool({ concurrency: 1 })
    const controller = new AbortController()
    const registration = vi.spyOn(controller.signal, 'addEventListener')
    const pending = executor.execute(
      'hashJSON',
      { value: 1 },
      { signal: controller.signal }
    )
    const callback = registration.mock.calls[0]?.[1] as (event: Event) => void
    state.workers[0]!.reply()
    await pending
    callback(new Event('abort'))
    expect(executor.stats).toMatchObject({ completed: 1, failed: 0, pendingBytes: 0 })
  })
})
