import { KeyObject } from 'node:crypto'
import { availableParallelism } from 'node:os'
import { types } from 'node:util'
import { Worker } from 'node:worker_threads'
import { TraceabilityError } from '../crypto/traceability.js'
import type {
  ExecutionOptions,
  TraceabilityExecutor,
  WorkerOperation,
  WorkerOperations,
} from './types.js'

export type WorkerPoolOptions = {
  concurrency?: number
  maxQueuedJobs?: number
  maxTaskBytes?: number
  maxPendingBytes?: number
  timeoutMs?: number
  maxWorkerHeapMb?: number
}

type Job = {
  id: number
  operation: WorkerOperation
  input: unknown
  bytes: number
  resolve: (value: unknown) => void
  reject: (error: unknown) => void
  timer?: ReturnType<typeof setTimeout>
  cleanup?: () => void
  settled: boolean
}
type Slot = { worker: Worker; job?: Job; stopping: boolean }
type Reply = {
  id: number
  result?: unknown
  error?: {
    code: string
    message: string
    context: Record<string, string | number | boolean | null>
  }
}
const operations = new Set<WorkerOperation>([
  'hashJSON',
  'createDocument',
  'validateDocument',
  'validateDocumentGraph',
  'buildAnchorBatch',
  'validateInclusionAgainstAnchor',
])

function integer(value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TraceabilityError(
      'INVALID_POOL_OPTIONS',
      'Worker limits must be integers within the supported range'
    )
  }
  return value
}

// Snapshot data before enqueueing: postMessage alone invokes getters and erases prototypes.
function snapshotInput(input: unknown, limit: number): { value: unknown; bytes: number } {
  let bytes = 0
  let nodes = 0
  const ancestors = new Set<object>()
  function add(size: number): void {
    bytes += size
    if (bytes > limit)
      throw new TraceabilityError(
        'TASK_TOO_LARGE',
        'Task exceeds its transport byte budget'
      )
  }
  function visit(value: unknown, depth: number): unknown {
    if (++nodes > 1_000_000 || depth > 80)
      throw new TraceabilityError(
        'INVALID_WORKER_INPUT',
        'Task structure exceeds allowed limits'
      )
    add(16)
    if (value === null || typeof value === 'boolean' || typeof value === 'number')
      return value
    if (typeof value === 'string') {
      add(value.length * 2)
      return value
    }
    if (typeof value !== 'object' || types.isProxy(value))
      throw new TraceabilityError(
        'INVALID_WORKER_INPUT',
        'Expected plain data without proxies or accessors'
      )
    if (value instanceof KeyObject && value.asymmetricKeyType === 'ed25519') {
      add(256)
      return value
    }
    if (ancestors.has(value))
      throw new TraceabilityError('INVALID_WORKER_INPUT', 'Cyclic worker input')
    const array = Array.isArray(value)
    const prototype: unknown = Object.getPrototypeOf(value)
    if (
      (array
        ? prototype !== Array.prototype
        : prototype !== Object.prototype && prototype !== null) ||
      Object.getOwnPropertySymbols(value).length > 0
    ) {
      throw new TraceabilityError('INVALID_WORKER_INPUT', 'Unsupported task object')
    }
    const names = Object.getOwnPropertyNames(value)
    if (array && names.length !== value.length + 1)
      throw new TraceabilityError(
        'INVALID_WORKER_INPUT',
        'Sparse or extended arrays are not supported'
      )
    add(names.length * 16)
    ancestors.add(value)
    try {
      const result: Record<string, unknown> | unknown[] = array ? [] : Object.create(null)
      for (const key of names) {
        if (array && key === 'length') continue
        if (array && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))
          throw new TraceabilityError('INVALID_WORKER_INPUT', 'Invalid array property')
        const descriptor = Object.getOwnPropertyDescriptor(value, key)!
        if (!descriptor.enumerable || !('value' in descriptor))
          throw new TraceabilityError(
            'INVALID_WORKER_INPUT',
            'Accessors and hidden properties are not supported'
          )
        add(key.length * 2)
        Object.defineProperty(result, key, {
          value: visit(descriptor.value, depth + 1),
          enumerable: true,
          writable: true,
          configurable: true,
        })
      }
      return result
    } finally {
      ancestors.delete(value)
    }
  }
  return { value: visit(input, 0), bytes }
}

/** Bounded, lazy worker pool. Always close it when the owning service shuts down. */
export class TraceabilityWorkerPool implements TraceabilityExecutor {
  private readonly options: Required<WorkerPoolOptions>
  private readonly slots = new Set<Slot>()
  private readonly queue: Job[] = []
  private readonly terminations = new Set<Promise<void>>()
  private pendingBytes = 0
  private nextId = 0
  private closed = false
  private completed = 0
  private failed = 0

  constructor(options: WorkerPoolOptions = {}) {
    this.options = {
      concurrency: integer(
        options.concurrency ?? Math.min(4, Math.max(1, availableParallelism() - 1)),
        1,
        64
      ),
      maxQueuedJobs: integer(options.maxQueuedJobs ?? 32, 0, 100_000),
      maxTaskBytes: integer(
        options.maxTaskBytes ?? 16 * 1024 * 1024,
        1,
        1024 * 1024 * 1024
      ),
      maxPendingBytes: integer(
        options.maxPendingBytes ?? 64 * 1024 * 1024,
        1,
        4 * 1024 * 1024 * 1024
      ),
      timeoutMs: integer(options.timeoutMs ?? 30_000, 1, 2_147_483_647),
      maxWorkerHeapMb: integer(options.maxWorkerHeapMb ?? 256, 32, 4096),
    }
  }

  get stats() {
    return {
      workers: this.slots.size,
      active: [...this.slots].filter(slot => slot.job).length,
      queued: this.queue.length,
      pendingBytes: this.pendingBytes,
      completed: this.completed,
      failed: this.failed,
      closed: this.closed,
    }
  }

  async execute<K extends WorkerOperation>(
    operation: K,
    input: WorkerOperations[K]['input'],
    options: ExecutionOptions = {}
  ): Promise<WorkerOperations[K]['output']> {
    if (this.closed) throw new TraceabilityError('POOL_CLOSED', 'Worker pool is closed')
    if (!operations.has(operation))
      throw new TraceabilityError('INVALID_OPERATION', 'Unknown worker operation')
    if (options.signal?.aborted)
      throw new TraceabilityError('TASK_ABORTED', 'Worker task was aborted')
    const timeoutMs = integer(
      options.timeoutMs ?? this.options.timeoutMs,
      1,
      2_147_483_647
    )
    const active = [...this.slots].filter(slot => slot.job || slot.stopping).length
    if (
      this.queue.length >= this.options.maxQueuedJobs &&
      active >= this.options.concurrency
    ) {
      throw new TraceabilityError('QUEUE_FULL', 'Worker queue is full')
    }
    const started = performance.now()
    const snapshot = snapshotInput(
      input,
      Math.min(this.options.maxTaskBytes, this.options.maxPendingBytes)
    )
    if (this.pendingBytes + snapshot.bytes > this.options.maxPendingBytes)
      throw new TraceabilityError(
        'QUEUE_FULL',
        'Pending tasks exceed the total byte budget'
      )
    const remaining = timeoutMs - (performance.now() - started)
    if (remaining <= 0)
      throw new TraceabilityError(
        'TASK_TIMEOUT',
        'Worker task deadline expired during input preparation'
      )
    return new Promise<unknown>((resolve, reject) => {
      const job: Job = {
        id: ++this.nextId,
        operation,
        input: snapshot.value,
        bytes: snapshot.bytes,
        resolve,
        reject,
        settled: false,
      }
      this.pendingBytes += job.bytes
      job.timer = setTimeout(() => this.cancel(job, 'TASK_TIMEOUT'), remaining)
      if (options.signal) {
        const signal = options.signal
        const abort = () => this.cancel(job, 'TASK_ABORTED')
        signal.addEventListener('abort', abort, { once: true })
        job.cleanup = () => signal.removeEventListener('abort', abort)
      }
      this.queue.push(job)
      this.pump()
    }) as Promise<WorkerOperations[K]['output']>
  }

  private finish(job: Job, error?: TraceabilityError, result?: unknown): void {
    job.settled = true
    clearTimeout(job.timer)
    job.cleanup?.()
    job.input = undefined
    this.pendingBytes -= job.bytes
    if (error) {
      this.failed++
      job.reject(error)
    } else {
      this.completed++
      job.resolve(result)
    }
  }

  private cancel(job: Job, code: string): void {
    if (job.settled) return
    const index = this.queue.indexOf(job)
    if (index >= 0) this.queue.splice(index, 1)
    const slot = [...this.slots].find(item => item.job === job)
    this.finish(
      job,
      new TraceabilityError(
        code,
        code === 'TASK_TIMEOUT'
          ? 'Worker task deadline expired'
          : 'Worker task was aborted'
      )
    )
    if (slot) {
      delete slot.job
      this.stop(slot)
    }
    this.pump()
  }

  private spawn(): Slot {
    const worker = new Worker(new URL('./runtime.js', import.meta.url), {
      // Inherited preload flags can recursively spawn workers or run application code.
      execArgv: [],
      resourceLimits: { maxOldGenerationSizeMb: this.options.maxWorkerHeapMb },
    })
    const slot: Slot = { worker, stopping: false }
    this.slots.add(slot)
    worker.on('message', (reply: Reply) => {
      const job = slot.job
      if (!job || reply.id !== job.id || slot.stopping) return
      delete slot.job
      const error = reply.error
        ? new TraceabilityError(
            reply.error.code,
            reply.error.message,
            reply.error.context
          )
        : undefined
      this.finish(job, error, reply.result)
      worker.unref()
      this.pump()
    })
    worker.on('error', () => {
      if (slot.job) {
        this.finish(
          slot.job,
          new TraceabilityError('WORKER_FAILURE', 'Worker terminated unexpectedly')
        )
        delete slot.job
      }
      this.stop(slot)
    })
    worker.on('exit', () => {
      if (slot.stopping) return
      if (slot.job)
        this.finish(
          slot.job,
          new TraceabilityError(
            'WORKER_FAILURE',
            'Worker exited before completing its task'
          )
        )
      this.slots.delete(slot)
      this.pump()
    })
    worker.unref()
    return slot
  }

  private pump(): void {
    if (this.closed) return
    while (this.queue.length > 0) {
      let slot = [...this.slots].find(item => !item.job && !item.stopping)
      if (!slot && this.slots.size >= this.options.concurrency) return
      const job = this.queue.shift()!
      try {
        slot ??= this.spawn()
        slot.job = job
        slot.worker.ref()
        slot.worker.postMessage({
          id: job.id,
          operation: job.operation,
          input: job.input,
        })
        job.input = undefined
      } catch {
        this.finish(
          job,
          new TraceabilityError('WORKER_FAILURE', 'Could not dispatch worker task')
        )
        if (slot) {
          delete slot.job
          this.stop(slot)
        }
      }
    }
  }

  private stop(slot: Slot): void {
    if (slot.stopping) return
    slot.stopping = true
    // Wait for termination before replacing the worker, preserving the concurrency bound.
    const termination = slot.worker
      .terminate()
      .then(
        () => {},
        () => {}
      )
      .finally(() => {
        this.slots.delete(slot)
        this.terminations.delete(termination)
        this.pump()
      })
    this.terminations.add(termination)
  }

  /** Reject pending work and wait until all worker threads have terminated. */
  async close(): Promise<void> {
    this.closed = true
    const error = new TraceabilityError('POOL_CLOSED', 'Worker pool was closed')
    for (const job of this.queue.splice(0)) this.finish(job, error)
    for (const slot of this.slots) {
      if (slot.job) {
        this.finish(slot.job, error)
        delete slot.job
      }
      this.stop(slot)
    }
    await Promise.all(this.terminations)
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close()
  }
}
