import type { Hex } from 'viem'
import { generateKeyPairSync } from 'node:crypto'
import { TraceabilityWorkerPool, type TraceabilityExecutor } from '../dist/main.js'

// A demo adapter only: replace it with independently verified Ethereum reads.
class DemoAnchorRegistry {
  #roots = new Map<string, Hex>()
  async publish(batchId: string, root: Hex) {
    const previous = this.#roots.get(batchId)
    if (previous && previous !== root)
      throw new Error('Batch ID already anchored to a different root')
    this.#roots.set(batchId, root)
  }
  async readTrustedRoot(batchId: string) {
    const root = this.#roots.get(batchId)
    if (!root) throw new Error('Unknown anchor')
    return root
  }
}

// Any implementation of TraceabilityExecutor can replace this local pool.
const pool = new TraceabilityWorkerPool({ concurrency: 1 })
const executor: TraceabilityExecutor = pool
const anchors = new DemoAnchorRegistry()
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const identity = {
  actorId: 'exporter',
  keyId: 'key-1',
  publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
}
try {
  const document = await executor.execute('createDocument', {
    document: {
      actorId: identity.actorId,
      keyId: identity.keyId,
      payload: { event: 'EXPORT', lot: 'LOT-001' },
    },
    privateKey,
  })
  const batch = await executor.execute('buildAnchorBatch', {
    documents: [document],
    identities: [identity],
    proofHashes: [document.hash],
  })
  await anchors.publish('batch-001', batch.root)

  // The verifier reads its trust root separately from the supplied proof.
  const trustedGlobalRoot = await anchors.readTrustedRoot('batch-001')
  const proof = batch.proofs[0]
  if (!proof) throw new Error('Expected an inclusion proof')

  await executor.execute('validateInclusionAgainstAnchor', {
    inclusion: { document, ...proof },
    identities: [identity],
    trustedGlobalRoot,
  })
  console.log('Inclusion verified against the demo registry:', trustedGlobalRoot)
} finally {
  await pool.close()
}
