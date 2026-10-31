import { generateKeyPairSync } from 'node:crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createDocument, hashJSON } from '../src/crypto/traceability.js'

const transport = await vi.hoisted(async () => {
  const { EventEmitter } = await import('node:events')
  return Object.assign(new EventEmitter(), { postMessage: vi.fn() })
})
vi.mock('node:worker_threads', () => ({ parentPort: transport }))
await import('../src/workers/runtime.js')

beforeEach(() => {
  transport.postMessage.mockClear()
})
function request(operation: string, input: unknown) {
  transport.emit('message', { id: 1, operation, input })
  return transport.postMessage.mock.calls.at(-1)?.[0] as {
    result?: unknown
    error?: { code: string }
  }
}
function fixture() {
  const keys = generateKeyPairSync('ed25519')
  const identity = {
    actorId: 'actor',
    keyId: 'key',
    publicKeyPem: keys.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  }
  const document = createDocument(
    { actorId: 'actor', keyId: 'key', payload: {} },
    keys.privateKey
  )
  return { keys, document, identities: [identity] }
}

describe('worker operation dispatch', () => {
  it('executes all supported operations and reuses actor proofs', () => {
    const { keys, document, identities } = fixture()
    expect(request('hashJSON', { value: { x: 1 } }).result).toBe(hashJSON({ x: 1 }))
    const child = request('createDocument', {
      document: { actorId: 'actor', keyId: 'key', payload: {}, parents: [document.hash] },
      privateKey: keys.privateKey,
    }).result as typeof document
    expect(
      request('validateDocument', { document: child, identities }).result
    ).toMatchObject({ hash: child.hash })
    const documents = [document, child]
    expect(
      request('validateDocumentGraph', { documents, identities }).result
    ).toHaveLength(2)
    const batch = request('buildAnchorBatch', {
      documents,
      identities,
      proofHashes: documents.map(doc => doc.hash),
    }).result as { root: string; proofs: unknown[] }
    expect(batch.proofs).toHaveLength(2)
    expect(
      request('validateInclusionAgainstAnchor', {
        inclusion: { document: child, ...(batch.proofs[1] as object) },
        trustedGlobalRoot: batch.root,
        identities,
      })
    ).toEqual({ id: 1, result: undefined })
    expect(request('buildAnchorBatch', { documents, identities }).result).toMatchObject({
      proofs: [],
    })
  })

  it('reports invalid proof requests, unknown operations, and unexpected errors safely', () => {
    const { document, identities } = fixture()
    expect(
      request('buildAnchorBatch', {
        documents: [document],
        identities,
        proofHashes: [document.hash, document.hash],
      }).error?.code
    ).toBe('INVALID_PROOF_REQUEST')
    const another = createDocument(
      { actorId: 'actor', keyId: 'key', payload: {} },
      fixture().keys.privateKey
    )
    expect(
      request('buildAnchorBatch', {
        documents: [document],
        identities,
        proofHashes: [another.hash],
      }).error?.code
    ).toBe('DOCUMENT_NOT_IN_BATCH')
    expect(request('unknown', {}).error?.code).toBe('INVALID_OPERATION')
    expect(request('validateDocument', {}).error?.code).toBe('WORKER_FAILURE')
    expect(request('hashJSON', { value: NaN }).error?.code).toBe('INVALID_NUMBER')
  })
})
