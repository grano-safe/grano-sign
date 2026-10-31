import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { test } from 'node:test'
import {
  TraceabilityWorkerPool,
  createDocument,
  hashJSON,
  buildAnchorBatch,
  createKeyResolver,
  validateInclusionAgainstAnchor,
} from '../dist/main.js'

function fixture() {
  const keys = generateKeyPairSync('ed25519')
  const identity = {
    actorId: 'producer',
    keyId: 'key-1',
    publicKeyPem: keys.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  }
  const document = createDocument(
    { actorId: identity.actorId, keyId: identity.keyId, payload: { kg: 20 } },
    keys.privateKey
  )
  return { keys, identity, document, identities: [identity] }
}

const matches = code => error => error?.code === code

test('all worker operations match synchronous signatures, graphs, and anchored proofs', async () => {
  const pool = new TraceabilityWorkerPool({ concurrency: 2 })
  try {
    const { keys, identity, document, identities } = fixture()
    assert.equal(
      await pool.execute('hashJSON', { value: { b: 2, a: 1 } }),
      hashJSON({ a: 1, b: 2 })
    )
    const child = await pool.execute('createDocument', {
      document: {
        actorId: identity.actorId,
        keyId: identity.keyId,
        payload: { received: true },
        parents: [document.hash],
      },
      privateKey: keys.privateKey,
    })
    assert.equal(
      (await pool.execute('validateDocument', { document: child, identities })).hash,
      child.hash
    )
    const documents = [document, child]
    assert.equal(
      (await pool.execute('validateDocumentGraph', { documents, identities })).length,
      2
    )
    const batch = await pool.execute('buildAnchorBatch', {
      documents,
      identities,
      proofHashes: documents.map(doc => doc.hash),
    })
    assert.equal(
      batch.root,
      buildAnchorBatch(documents, createKeyResolver(identities)).root
    )
    assert.equal(batch.proofs.length, 2)
    const proof = batch.proofs[1]
    const inclusion = { document: child, ...proof }
    validateInclusionAgainstAnchor(inclusion, batch.root, createKeyResolver(identities))
    assert.equal(
      await pool.execute('validateInclusionAgainstAnchor', {
        inclusion,
        trustedGlobalRoot: batch.root,
        identities,
      }),
      undefined
    )
    await assert.rejects(
      pool.execute('validateInclusionAgainstAnchor', {
        inclusion,
        trustedGlobalRoot: `0x${'ff'.repeat(32)}`,
        identities,
      }),
      matches('ANCHOR_ROOT_MISMATCH')
    )
    assert.equal(pool.stats.pendingBytes, 0)
  } finally {
    await pool.close()
  }
})

test('snapshots queued input and bounds queued jobs and bytes', async () => {
  const pool = new TraceabilityWorkerPool({ concurrency: 1, maxQueuedJobs: 1 })
  try {
    const first = pool.execute('hashJSON', { value: 'x'.repeat(100_000) })
    const data = { a: 1 }
    const second = pool.execute('hashJSON', { value: data })
    data.a = 2
    await assert.rejects(pool.execute('hashJSON', { value: 3 }), matches('QUEUE_FULL'))
    assert.equal(await second, hashJSON({ a: 1 }))
    await first
    assert.equal(pool.stats.queued, 0)
    assert.equal(pool.stats.pendingBytes, 0)
  } finally {
    await pool.close()
  }
  const tiny = new TraceabilityWorkerPool({ maxTaskBytes: 1000, maxPendingBytes: 200 })
  try {
    await assert.rejects(
      tiny.execute('hashJSON', { value: 'x'.repeat(1000) }),
      matches('TASK_TOO_LARGE')
    )
    const first = tiny.execute('hashJSON', { value: 'x'.repeat(30) })
    await assert.rejects(
      tiny.execute('hashJSON', { value: 'x'.repeat(30) }),
      matches('QUEUE_FULL')
    )
    await first
  } finally {
    await tiny.close()
  }
})

test('rejects executable objects before cloning and preserves validation errors', async () => {
  const pool = new TraceabilityWorkerPool({ concurrency: 1 })
  try {
    let calls = 0
    const accessor = {
      get secret() {
        calls++
        return 1
      },
    }
    await assert.rejects(
      pool.execute('hashJSON', { value: accessor }),
      matches('INVALID_WORKER_INPUT')
    )
    await assert.rejects(
      pool.execute('hashJSON', { value: new Proxy({}, {}) }),
      matches('INVALID_WORKER_INPUT')
    )
    await assert.rejects(
      pool.execute('hashJSON', { value: new Date() }),
      matches('INVALID_WORKER_INPUT')
    )
    await assert.rejects(
      pool.execute('hashJSON', { value: Object.assign([], { map: () => [] }) }),
      matches('INVALID_WORKER_INPUT')
    )
    await assert.rejects(
      pool.execute('hashJSON', { value: Number.NaN }),
      matches('INVALID_NUMBER')
    )
    await assert.rejects(pool.execute('invalid', {}), matches('INVALID_OPERATION'))
    assert.equal(calls, 0)
    const { document, identities } = fixture()
    await assert.rejects(
      pool.execute('validateDocument', {
        document: { ...document, signature: 'invalid' },
        identities,
      }),
      matches('INVALID_SIGNATURE')
    )
    await assert.rejects(
      pool.execute('buildAnchorBatch', {
        documents: [document],
        identities,
        proofHashes: [document.hash, document.hash],
      }),
      matches('INVALID_PROOF_REQUEST')
    )
    await assert.rejects(
      pool.execute('buildAnchorBatch', {
        documents: [document],
        identities,
        proofHashes: [`0x${'22'.repeat(32)}`],
      }),
      matches('DOCUMENT_NOT_IN_BATCH')
    )
  } finally {
    await pool.close()
  }
})

test('cancels active and queued jobs, replaces terminated workers, and includes queue wait in deadlines', async () => {
  const pool = new TraceabilityWorkerPool({ concurrency: 1 })
  try {
    const aborted = AbortSignal.abort()
    await assert.rejects(
      pool.execute('hashJSON', { value: 1 }, { signal: aborted }),
      matches('TASK_ABORTED')
    )
    const runningController = new AbortController()
    const queuedController = new AbortController()
    const running = pool.execute(
      'hashJSON',
      { value: 'x'.repeat(100_000) },
      { signal: runningController.signal }
    )
    const queued = pool.execute(
      'hashJSON',
      { value: 2 },
      { signal: queuedController.signal }
    )
    const runningCheck = assert.rejects(running, matches('TASK_ABORTED'))
    const queuedCheck = assert.rejects(queued, matches('TASK_ABORTED'))
    queuedController.abort()
    runningController.abort()
    await Promise.all([runningCheck, queuedCheck])
    assert.equal(await pool.execute('hashJSON', { value: 42 }), hashJSON(42))
    const slow = pool.execute('hashJSON', { value: 'x'.repeat(1_000_000) })
    const expired = pool.execute('hashJSON', { value: 2 }, { timeoutMs: 1 })
    await assert.rejects(expired, matches('TASK_TIMEOUT'))
    await slow
    assert.equal(pool.stats.pendingBytes, 0)
  } finally {
    await pool.close()
  }
  const cold = new TraceabilityWorkerPool({ concurrency: 1 })
  try {
    await assert.rejects(
      cold.execute('hashJSON', { value: 1 }, { timeoutMs: 1 }),
      matches('TASK_TIMEOUT')
    )
    assert.equal(await cold.execute('hashJSON', { value: 2 }), hashJSON(2))
  } finally {
    await cold.close()
  }
})

test('close is idempotent, rejects outstanding work, and prohibits new jobs', async () => {
  const pool = new TraceabilityWorkerPool({ concurrency: 1 })
  const first = pool.execute('hashJSON', { value: 1 })
  const second = pool.execute('hashJSON', { value: 2 })
  const checks = [
    assert.rejects(first, matches('POOL_CLOSED')),
    assert.rejects(second, matches('POOL_CLOSED')),
  ]
  await Promise.all([pool.close(), pool.close(), ...checks])
  await assert.rejects(pool.execute('hashJSON', { value: 3 }), matches('POOL_CLOSED'))
  assert.deepEqual(pool.stats, {
    workers: 0,
    active: 0,
    queued: 0,
    pendingBytes: 0,
    completed: 0,
    failed: 2,
    closed: true,
  })
  await pool[Symbol.asyncDispose]()
})

test('rejects invalid pool settings', () => {
  for (const options of [
    { concurrency: 0 },
    { maxQueuedJobs: -1 },
    { timeoutMs: Infinity },
    { maxWorkerHeapMb: 1 },
  ]) {
    assert.throws(
      () => new TraceabilityWorkerPool(options),
      matches('INVALID_POOL_OPTIONS')
    )
  }
})

test('uses multiple workers and preserves concurrent result ordering', async () => {
  const pool = new TraceabilityWorkerPool({ concurrency: 2, maxQueuedJobs: 32 })
  try {
    const inputs = Array.from({ length: 12 }, (_, index) => ({
      index,
      payload: 'x'.repeat(1000),
    }))
    const results = await Promise.all(
      inputs.map(value => pool.execute('hashJSON', { value }))
    )
    assert.deepEqual(results, inputs.map(hashJSON))
    assert.equal(pool.stats.workers, 2)
    assert.equal(pool.stats.completed, inputs.length)
    assert.equal(pool.stats.pendingBytes, 0)
  } finally {
    await pool.close()
  }
})
