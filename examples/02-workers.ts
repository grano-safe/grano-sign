import { generateKeyPairSync } from 'node:crypto'
import { TraceabilityWorkerPool } from '../dist/main.js'

const pool = new TraceabilityWorkerPool({
  concurrency: 2,
  maxQueuedJobs: 8,
  timeoutMs: 30_000,
})
function actor(actorId: string) {
  const keys = generateKeyPairSync('ed25519')
  return {
    ...keys,
    identity: {
      actorId,
      keyId: `${actorId}-key`,
      publicKeyPem: keys.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    },
  }
}
const farm = actor('farm-1')
const warehouse = actor('warehouse-1')
const identities = [farm.identity, warehouse.identity]

try {
  const harvest = await pool.execute('createDocument', {
    document: {
      actorId: farm.identity.actorId,
      keyId: farm.identity.keyId,
      payload: { event: 'HARVEST', kg: 2500 },
    },
    privateKey: farm.privateKey,
  })
  const reception = await pool.execute('createDocument', {
    document: {
      actorId: warehouse.identity.actorId,
      keyId: warehouse.identity.keyId,
      parents: [harvest.hash],
      payload: { event: 'RECEPTION', kg: 2500 },
    },
    privateKey: warehouse.privateKey,
  })
  // Request proofs while building: workers do not retain batches between jobs.
  const batch = await pool.execute('buildAnchorBatch', {
    documents: [harvest, reception],
    identities,
    proofHashes: [reception.hash],
  })
  console.log('Batch root:', batch.root)
  console.log('Reception proof:', batch.proofs[0])
  console.log('Pool metrics:', pool.stats)
} finally {
  await pool.close()
}
