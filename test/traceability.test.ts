import {
  createPrivateKey,
  generateKeyPairSync,
  sign as signBytes,
  type KeyObject,
} from 'node:crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { isCuid } from '@paralleldrive/cuid2'
import type { Hex } from 'viem'
import {
  TraceabilityError,
  buildAnchorBatch,
  createDocument,
  createInclusionProof,
  executeTraceability,
  executeTraceabilityAsync,
  hashJSON,
  validateDocument,
  validateDocumentGraph,
  validateInclusion,
  validateInclusionAgainstAnchor,
  type KeyResolver,
  type SignedDocument,
  type DocumentContent,
  type TrustedKey,
  createKeyResolver,
  SystemKeyStore,
} from '../src/main.js'

const fakeKeyring = vi.hoisted(() => ({
  passwords: new Map<string, string>(),
  unavailable: false,
  linuxStore: '' as string,
  failOn: '' as '' | 'get' | 'set' | 'delete',
  corruptWrite: false,
  existingEntry: false,
}))

vi.mock('@napi-rs/keyring', () => ({
  Entry: class {
    private readonly account: string

    constructor(
      service: string,
      account: string,
      options: { linux?: { store?: string } } = {}
    ) {
      this.account = JSON.stringify([service, account])
      fakeKeyring.linuxStore = options.linux?.store ?? ''
    }

    getPassword(): string | null {
      if (fakeKeyring.unavailable || fakeKeyring.failOn === 'get')
        throw new Error('Credential store unavailable')
      if (fakeKeyring.existingEntry) return 'existing-private-key'
      return fakeKeyring.passwords.get(this.account) ?? null
    }

    setPassword(password: string): void {
      if (fakeKeyring.unavailable || fakeKeyring.failOn === 'set')
        throw new Error('Credential store unavailable')
      fakeKeyring.passwords.set(
        this.account,
        fakeKeyring.corruptWrite ? 'corrupted' : password
      )
    }

    deletePassword(): boolean {
      if (fakeKeyring.unavailable || fakeKeyring.failOn === 'delete')
        throw new Error('Credential store unavailable')
      return fakeKeyring.passwords.delete(this.account)
    }
  },
}))

type TestParticipant = {
  actorId: string
  keyId: string
  privateKey: KeyObject
  publicKey: KeyObject
}

function participant(actorId: string): TestParticipant {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  return { actorId, keyId: `key-${actorId}`, privateKey, publicKey }
}

function keyResolver(...participants: TestParticipant[]): KeyResolver {
  const trustedKeys = new Map<string, TrustedKey>()

  for (const { actorId, keyId, publicKey } of participants) {
    trustedKeys.set(`${actorId}:${keyId}`, { actorId, keyId, publicKey })
  }

  return (actorId, keyId) => {
    const key = trustedKeys.get(`${actorId}:${keyId}`)
    if (!key) {
      throw new TraceabilityError('KEY_NOT_FOUND', 'No trusted public key', {
        actorId,
        keyId,
      })
    }
    return key
  }
}

function signDocument(
  signer: TestParticipant,
  payload: unknown,
  parents: readonly Hex[] = []
): SignedDocument {
  return createDocument(
    {
      actorId: signer.actorId,
      keyId: signer.keyId,
      payload,
      parents,
    },
    signer.privateKey
  )
}

function scenario() {
  const producerA = participant('producer-A')
  const producerB = participant('producer-B')
  const warehouse = participant('warehouse')
  const industry = participant('industry')
  const resolveKey = keyResolver(producerA, producerB, warehouse, industry)

  const harvestA = signDocument(producerA, { operation: 'HARVEST', kg: 20000 })
  const harvestB = signDocument(producerB, { operation: 'HARVEST', kg: 15000 })
  const reception = signDocument(warehouse, { operation: 'RECEPTION', kg: 35000 }, [
    harvestA.hash,
    harvestB.hash,
  ])
  const drying = signDocument(warehouse, { operation: 'DRYING', moisture: 13 }, [
    reception.hash,
  ])
  const inspection = signDocument(
    industry,
    { operation: 'QUALITY_CHECK', approved: true },
    [reception.hash, drying.hash]
  )
  const processing = signDocument(
    industry,
    { operation: 'PROCESSING', product: 'RICE' },
    [drying.hash, inspection.hash]
  )

  const documents = [harvestA, harvestB, reception, drying, inspection, processing]

  return {
    producerA,
    producerB,
    warehouse,
    industry,
    resolveKey,
    documents,
    harvestA,
    harvestB,
    reception,
    drying,
    inspection,
    processing,
  }
}

function expectTraceabilityError(operation: () => unknown, code: string): void {
  try {
    operation()
    expect.fail(`Expected TraceabilityError(${code})`)
  } catch (error) {
    expect(error).toBeInstanceOf(TraceabilityError)
    expect((error as TraceabilityError).code).toBe(code)
  }
}

beforeEach(() => {
  fakeKeyring.passwords.clear()
  fakeKeyring.unavailable = false
  fakeKeyring.linuxStore = ''
  fakeKeyring.failOn = ''
  fakeKeyring.corruptWrite = false
  fakeKeyring.existingEntry = false
})

// Sign controlled fixtures to test DAG invariants without invalidating signatures.
function signWithContent(
  signer: TestParticipant,
  content: DocumentContent
): SignedDocument {
  const hash = hashJSON({ domain: 'grano.traceability.document.v1', content })
  const signature = signBytes(
    null,
    Buffer.from(hash.slice(2), 'hex'),
    signer.privateKey
  ).toString('base64')
  return { content, hash, signature }
}

describe('JSON canonicalization and hashing', () => {
  it('produces the same hash regardless of object property order', () => {
    expect(hashJSON({ z: 2, nested: { b: true, a: 'x' } })).toBe(
      hashJSON({ nested: { a: 'x', b: true }, z: 2 })
    )
  })

  it('preserves array order in the hash', () => {
    expect(hashJSON({ items: [1, 2] })).not.toBe(hashJSON({ items: [2, 1] }))
  })

  it.each([
    { name: 'undefined property', value: { value: undefined }, code: 'INVALID_JSON' },
    { name: 'NaN', value: { value: NaN }, code: 'INVALID_NUMBER' },
    { name: 'Infinity', value: { value: Infinity }, code: 'INVALID_NUMBER' },
    { name: 'negative zero', value: { value: -0 }, code: 'INVALID_NUMBER' },
    {
      name: 'unsafe integer',
      value: { value: Number.MAX_SAFE_INTEGER + 2 },
      code: 'UNSAFE_INTEGER',
    },
    { name: 'BigInt', value: { value: 9n }, code: 'INVALID_JSON' },
    { name: 'Date instance', value: { value: new Date(0) }, code: 'INVALID_JSON' },
    { name: 'invalid Unicode', value: { value: '\ud800' }, code: 'INVALID_UNICODE' },
  ])('rejects $name', ({ value, code }) => {
    expectTraceabilityError(() => hashJSON(value), code)
  })

  it('rejects cyclic structures', () => {
    const cyclic: { self?: unknown } = {}
    cyclic.self = cyclic
    expectTraceabilityError(() => hashJSON(cyclic), 'CYCLIC_JSON')
  })

  it('does not invoke getters when inspecting JSON', () => {
    const read = vi.fn(() => 'secret')
    const object = Object.defineProperty({}, 'value', {
      enumerable: true,
      get: read,
    })

    expectTraceabilityError(() => hashJSON(object), 'INVALID_JSON')
    expect(read).not.toHaveBeenCalled()
  })

  it('rejects arrays with missing elements', () => {
    expectTraceabilityError(() => hashJSON(new Array(2)), 'INVALID_JSON')
  })

  it('accepts valid JSON larger than the previous 1 MiB limit', () => {
    expect(hashJSON({ data: 'a'.repeat(2 * 1024 * 1024) })).toMatch(/^0x[0-9a-f]{64}$/)
  }, 30_000)

  it('enforces JSON nesting limits', () => {
    let nested: unknown = null
    for (let index = 0; index < 70; index++) nested = { child: nested }
    expectTraceabilityError(() => hashJSON(nested), 'JSON_LIMIT')
  })
})

describe('signed documents', () => {
  it('creates CUID2 identifiers and validates an Ed25519 signature', () => {
    const signer = participant('producer-A')
    const document = signDocument(signer, { operation: 'HARVEST' })
    const validated = validateDocument(document, keyResolver(signer))

    expect(document.content.documentId).toHaveLength(24)
    expect(isCuid(document.content.documentId)).toBe(true)
    expect(document.hash).toMatch(/^0x[0-9a-f]{64}$/)
    expect(validated.hash).toBe(document.hash)
  })

  it('generates distinct identifiers for identical payloads', () => {
    const signer = participant('producer-A')
    const first = signDocument(signer, { value: 10 })
    const second = signDocument(signer, { value: 10 })

    expect(first.content.documentId).not.toBe(second.content.documentId)
    expect(first.hash).not.toBe(second.hash)
  })

  it('rejects changed payloads', () => {
    const signer = participant('producer-A')
    const document = signDocument(signer, { kg: 100 })
    const changed = {
      ...document,
      content: { ...document.content, payload: { kg: 999 } },
    }

    expectTraceabilityError(
      () => validateDocument(changed, keyResolver(signer)),
      'HASH_MISMATCH'
    )
  })

  it('rejects forged signatures and wrong trusted keys', () => {
    const signer = participant('producer-A')
    const wrongSigner = participant('producer-A')
    const document = signDocument(signer, { kg: 100 })
    const forged = {
      ...document,
      signature: Buffer.alloc(64, 1).toString('base64'),
    }

    expectTraceabilityError(
      () => validateDocument(forged, keyResolver(signer)),
      'INVALID_SIGNATURE'
    )
    expectTraceabilityError(
      () => validateDocument(document, keyResolver(wrongSigner)),
      'INVALID_SIGNATURE'
    )
  })

  it('rejects revoked and unidentified signers', () => {
    const signer = participant('producer-A')
    const document = signDocument(signer, { kg: 100 })

    expectTraceabilityError(
      () =>
        validateDocument(document, () => ({
          actorId: signer.actorId,
          keyId: signer.keyId,
          publicKey: signer.publicKey,
          revoked: true,
        })),
      'UNTRUSTED_KEY'
    )

    expectTraceabilityError(
      () => validateDocument(document, keyResolver()),
      'KEY_NOT_FOUND'
    )
  })

  it('rejects duplicate parent references and invalid signing keys', () => {
    const signer = participant('producer-A')
    const parent = signDocument(signer, { stage: 'FIRST' })

    expectTraceabilityError(
      () => signDocument(signer, { stage: 'SECOND' }, [parent.hash, parent.hash]),
      'INVALID_PARENTS'
    )
    expectTraceabilityError(
      () =>
        createDocument(
          { actorId: signer.actorId, keyId: signer.keyId, payload: {} },
          signer.publicKey
        ),
      'INVALID_PRIVATE_KEY'
    )
  })
})

describe('dependency graph', () => {
  it('validates independent actors, multiple parents and shared ancestors', () => {
    const { documents, resolveKey } = scenario()
    const validated = validateDocumentGraph(documents, resolveKey)

    expect(validated).toHaveLength(6)
    expect(validated.at(-1)?.content.parents).toHaveLength(2)
  })

  it('rejects missing dependencies', () => {
    const { harvestA, harvestB, processing, resolveKey } = scenario()

    expectTraceabilityError(
      () => validateDocumentGraph([harvestA, harvestB, processing], resolveKey),
      'MISSING_PARENT'
    )
  })

  it('rejects duplicate document hashes and IDs', () => {
    const { harvestA, resolveKey } = scenario()

    expectTraceabilityError(
      () => validateDocumentGraph([harvestA, harvestA], resolveKey),
      'DUPLICATE_DOCUMENT'
    )
  })

  it('rejects an empty graph', () => {
    expectTraceabilityError(
      () => validateDocumentGraph([], keyResolver()),
      'INVALID_GRAPH_SIZE'
    )
  })
})

describe('Merkle anchor and inclusion proofs', () => {
  it('anchors all signed documents from all participants', () => {
    const { documents, resolveKey } = scenario()
    const batch = buildAnchorBatch(documents, resolveKey)

    expect(batch.documents).toHaveLength(6)
    expect(batch.actorRoots.size).toBe(4)
    expect(batch.root).toMatch(/^0x[0-9a-f]{64}$/)

    for (const document of documents) {
      const proof = createInclusionProof(batch, document)
      expect(() =>
        validateInclusionAgainstAnchor({ document, ...proof }, batch.root, resolveKey)
      ).not.toThrow()
    }
  })

  it('reproduces the same global root independent of input document order', () => {
    const { documents, resolveKey } = scenario()
    const first = buildAnchorBatch(documents, resolveKey)
    const reversed = buildAnchorBatch([...documents].reverse(), resolveKey)

    expect(first.root).toBe(reversed.root)
  })

  it('rejects a document outside the batch', () => {
    const { documents, producerA, resolveKey } = scenario()
    const batch = buildAnchorBatch(documents, resolveKey)
    const outsider = signDocument(producerA, { operation: 'OTHER' })

    expectTraceabilityError(
      () => createInclusionProof(batch, outsider),
      'DOCUMENT_NOT_IN_BATCH'
    )
  })

  it('rejects a proof created for another document', () => {
    const { documents, harvestA, processing, resolveKey } = scenario()
    const batch = buildAnchorBatch(documents, resolveKey)
    const proof = createInclusionProof(batch, processing)

    expectTraceabilityError(
      () => validateInclusion({ document: harvestA, ...proof }, resolveKey),
      'INVALID_DOCUMENT_PROOF'
    )
  })

  it('rejects an altered actor proof', () => {
    const { documents, processing, resolveKey } = scenario()
    const batch = buildAnchorBatch(documents, resolveKey)
    const proof = createInclusionProof(batch, processing)

    expect(proof.actorProof.length).toBeGreaterThan(0)
    expectTraceabilityError(
      () =>
        validateInclusion(
          {
            document: processing,
            ...proof,
            actorProof: proof.actorProof.map(() => `0x${'00'.repeat(32)}`),
          },
          resolveKey
        ),
      'INVALID_ACTOR_PROOF'
    )
  })

  it('rejects a global root different from the trusted Ethereum anchor', () => {
    const { documents, processing, resolveKey } = scenario()
    const batch = buildAnchorBatch(documents, resolveKey)

    expectTraceabilityError(
      () =>
        validateInclusionAgainstAnchor(
          { document: processing, ...createInclusionProof(batch, processing) },
          `0x${'00'.repeat(32)}` as Hex,
          resolveKey
        ),
      'ANCHOR_ROOT_MISMATCH'
    )
  })

  it('rejects malformed Merkle proof hashes', () => {
    const { documents, processing, resolveKey } = scenario()
    const batch = buildAnchorBatch(documents, resolveKey)

    expectTraceabilityError(
      () =>
        validateInclusion(
          {
            document: processing,
            ...createInclusionProof(batch, processing),
            actorProof: ['not-a-hash'],
          },
          resolveKey
        ),
      'INVALID_HASH'
    )
  })
})

describe('system credential store adapter', () => {
  it('generates a keypair, stores only the private key and signs without exposing it', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    const identity = store.createParticipant('producer-A')
    const resolver = createKeyResolver([identity])
    const document = store.createSignedDocument({
      actorId: identity.actorId,
      keyId: identity.keyId,
      payload: { operation: 'HARVEST' },
    })

    expect(identity.keyId).toHaveLength(24)
    expect(isCuid(identity.keyId)).toBe(true)
    expect(identity.publicKeyPem).toContain('BEGIN PUBLIC KEY')
    expect(identity).not.toHaveProperty('privateKey')
    expect(fakeKeyring.passwords.size).toBe(1)
    expect([...fakeKeyring.passwords.values()][0]).toContain('BEGIN PRIVATE KEY')
    expect(fakeKeyring.linuxStore).toBe('secret-service')
    expect(() => validateDocument(document, resolver)).not.toThrow()
  })

  it('deletes a stored private key and rejects subsequent signatures', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    const identity = store.createParticipant('producer-A')

    expect(store.deletePrivateKey(identity.actorId, identity.keyId)).toBe(true)
    expectTraceabilityError(
      () =>
        store.createSignedDocument({
          actorId: identity.actorId,
          keyId: identity.keyId,
          payload: { operation: 'HARVEST' },
        }),
      'PRIVATE_KEY_NOT_FOUND'
    )
  })

  it('rejects duplicate key registrations and invalid public keys', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    const identity = store.createParticipant('producer-A')

    expectTraceabilityError(
      () => createKeyResolver([identity, identity]),
      'DUPLICATE_KEY'
    )
    expectTraceabilityError(
      () => createKeyResolver([{ ...identity, publicKeyPem: 'invalid PEM' }]),
      'INVALID_PUBLIC_KEY'
    )
  })

  it('reports unavailable OS keychain without silently falling back to memory', () => {
    fakeKeyring.unavailable = true
    const store = new SystemKeyStore('grano.traceability.tests')

    expectTraceabilityError(
      () => store.createParticipant('producer-A'),
      'KEYCHAIN_UNAVAILABLE'
    )
  })
})

describe('error reporting boundaries', () => {
  it('reports the context once and rethrows the same traceability exception', () => {
    const error = new TraceabilityError('CUSTOM_ERROR', 'Validation failed', {
      actorId: 'producer-A',
    })
    const reporter = vi.fn()

    expect(() =>
      executeTraceability(() => {
        throw error
      }, reporter)
    ).toThrow(error)
    expect(reporter).toHaveBeenCalledTimes(1)
    expect(reporter).toHaveBeenCalledWith(
      expect.objectContaining({
        code: 'CUSTOM_ERROR',
        context: expect.objectContaining({
          actorId: 'producer-A',
          traceId: expect.any(String),
        }),
      })
    )
  })

  it('wraps unexpected errors and survives failures in the reporting system', () => {
    const reporter = vi.fn(() => {
      throw new Error('Reporter unavailable')
    })

    expectTraceabilityError(
      () =>
        executeTraceability(() => {
          throw new Error('Unexpected')
        }, reporter),
      'UNEXPECTED_ERROR'
    )
    expect(reporter).toHaveBeenCalledOnce()
  })

  it('captures asynchronous errors without swallowing them', async () => {
    const reporter = vi.fn()

    await expect(
      executeTraceabilityAsync(async () => {
        throw new TraceabilityError('ASYNC_FAILED', 'Async operation failed')
      }, reporter)
    ).rejects.toMatchObject({ code: 'ASYNC_FAILED' })

    expect(reporter).toHaveBeenCalledOnce()
  })
})

// Additional validation, security boundaries, and regression tests

describe('strict JSON inputs and canonicalization', () => {
  it.each([
    ['null', null],
    ['booleans', [true, false]],
    ['empty structures', { empty: [], object: {}, value: null }],
    ['Unicode supplementary characters', { value: '🌾🚜' }],
    ['Unicode combining sequences', { value: 'a\u0301' }],
    ['safe integers', { max: Number.MAX_SAFE_INTEGER, min: Number.MIN_SAFE_INTEGER }],
    ['finite decimals', { value: 1.75 }],
  ])('accepts %s', (_name, value) => {
    expect(hashJSON(value)).toMatch(/^0x[0-9a-f]{64}$/)
  })

  it('treats repeated references as valid when they do not create a cycle', () => {
    const shared = { value: 10 }
    expect(hashJSON({ first: shared, second: shared })).toBe(
      hashJSON({ second: { value: 10 }, first: { value: 10 } })
    )
  })

  it('does not implicitly normalize visually equivalent Unicode strings', () => {
    expect(hashJSON('é')).not.toBe(hashJSON('e\u0301'))
  })

  it.each([
    ['root undefined', undefined, 'INVALID_JSON'],
    ['function', { value: () => true }, 'INVALID_JSON'],
    ['symbol value', { value: Symbol('x') }, 'INVALID_JSON'],
    ['negative infinity', { value: -Infinity }, 'INVALID_NUMBER'],
    [
      'unsafe negative integer',
      { value: -(Number.MAX_SAFE_INTEGER + 2) },
      'UNSAFE_INTEGER',
    ],
    ['invalid surrogate pair', { value: '\ud800x' }, 'INVALID_UNICODE'],
    ['invalid trailing surrogate', { value: '\udc00' }, 'INVALID_UNICODE'],
    ['map', new Map([['a', 1]]), 'INVALID_JSON'],
    ['set', new Set([1]), 'INVALID_JSON'],
    ['buffer', Buffer.from('hello'), 'INVALID_JSON'],
    [
      'class instance',
      new (class Sample {
        value = 1
      })(),
      'INVALID_JSON',
    ],
    ['sparse array', [1, , 3], 'INVALID_JSON'],
  ])('rejects %s', (_name, value, code) => {
    expectTraceabilityError(() => hashJSON(value), code)
  })

  it('rejects non-enumerable JSON properties and never calls getters', () => {
    const hidden = Object.defineProperty({}, 'secret', { value: 'x', enumerable: false })
    expectTraceabilityError(() => hashJSON(hidden), 'INVALID_JSON')

    const getter = vi.fn(() => 10)
    const array = [1]
    Object.defineProperty(array, '0', { enumerable: true, get: getter })
    expectTraceabilityError(() => hashJSON(array), 'INVALID_JSON')
    expect(getter).not.toHaveBeenCalled()
  })

  it('rejects non-enumerable array elements and non-indexed array properties', () => {
    const hiddenArray = [1]
    Object.defineProperty(hiddenArray, '0', { value: 1, enumerable: false })
    expectTraceabilityError(() => hashJSON(hiddenArray), 'INVALID_JSON')

    const extra = [1] as number[] & { custom?: boolean }
    extra.custom = true
    expectTraceabilityError(() => hashJSON(extra), 'INVALID_JSON')
  })

  it('rejects symbol properties and invalid Unicode in property names', () => {
    const symbolProperty = { data: 1, [Symbol('invisible')]: true }
    expectTraceabilityError(() => hashJSON(symbolProperty), 'INVALID_JSON')
    expectTraceabilityError(() => hashJSON({ '\ud800': 'value' }), 'INVALID_UNICODE')
  })

  it('rejects a structure containing more than 100000 nodes', () => {
    expectTraceabilityError(() => hashJSON(Array(100_001).fill(null)), 'JSON_LIMIT')
  })

  it('rejects JSON deeper than 64 levels but accepts the boundary depth', () => {
    let allowed: unknown = true
    for (let level = 0; level < 64; level++) allowed = [allowed]
    expect(hashJSON(allowed)).toMatch(/^0x[0-9a-f]{64}$/)
    expectTraceabilityError(() => hashJSON([allowed]), 'JSON_LIMIT')
  })

  it('accepts a 4 MiB JSON document during ordinary test runs', () => {
    expect(hashJSON({ payload: 'q'.repeat(4 * 1024 * 1024) })).toMatch(/^0x[0-9a-f]{64}$/)
  }, 60_000)
})

const MAX_JSON_BYTES = 100 * 1024 * 1024
const runHeavyPayloadTests = process.env.RUN_LARGE_PAYLOAD_TESTS === '1'

describe('100 MiB canonical JSON limit (opt-in)', () => {
  it.skipIf(!runHeavyPayloadTests)(
    'accepts exactly 100 MiB of canonical UTF-8 JSON',
    () => {
      const payload = 'x'.repeat(MAX_JSON_BYTES - 2)
      expect(hashJSON(payload)).toMatch(/^0x[0-9a-f]{64}$/)
    },
    300_000
  )

  it.skipIf(!runHeavyPayloadTests)(
    'rejects even one byte above 100 MiB',
    () => {
      const payload = 'x'.repeat(MAX_JSON_BYTES - 1)
      expectTraceabilityError(() => hashJSON(payload), 'JSON_TOO_LARGE')
    },
    300_000
  )

  it.skipIf(!runHeavyPayloadTests)(
    'counts UTF-8 bytes rather than JavaScript characters',
    () => {
      const payload = 'é'.repeat(Math.ceil(MAX_JSON_BYTES / 2))
      expectTraceabilityError(() => hashJSON(payload), 'JSON_TOO_LARGE')
    },
    300_000
  )
})

describe('strict signed-document envelope', () => {
  it.each([
    [
      'missing signature',
      (document: SignedDocument) => ({ content: document.content, hash: document.hash }),
      'INVALID_FIELDS',
    ],
    [
      'unexpected top-level field',
      (document: SignedDocument) => ({ ...document, debug: true }),
      'INVALID_FIELDS',
    ],
    [
      'unexpected content field',
      (document: SignedDocument) => ({
        ...document,
        content: { ...document.content, extra: 1 },
      }),
      'INVALID_FIELDS',
    ],
    [
      'incorrect document type',
      (document: SignedDocument) => ({
        ...document,
        content: { ...document.content, type: 'untrusted' },
      }),
      'INVALID_VERSION',
    ],
    [
      'incorrect protocol version',
      (document: SignedDocument) => ({
        ...document,
        content: { ...document.content, version: '99.0.0' },
      }),
      'INVALID_VERSION',
    ],
    [
      'invalid CUID2',
      (document: SignedDocument) => ({
        ...document,
        content: { ...document.content, documentId: 'not-cuid2' },
      }),
      'INVALID_DOCUMENT_ID',
    ],
    [
      'empty actor ID',
      (document: SignedDocument) => ({
        ...document,
        content: { ...document.content, actorId: '' },
      }),
      'INVALID_IDENTIFIER',
    ],
    [
      'whitespace in key ID',
      (document: SignedDocument) => ({
        ...document,
        content: { ...document.content, keyId: ' bad ' },
      }),
      'INVALID_IDENTIFIER',
    ],
    [
      'parent not hex',
      (document: SignedDocument) => ({
        ...document,
        content: { ...document.content, parents: ['bad'] },
      }),
      'INVALID_HASH',
    ],
    [
      'signature has wrong length',
      (document: SignedDocument) => ({ ...document, signature: 'AQ==' }),
      'INVALID_SIGNATURE',
    ],
    [
      'signature has invalid alphabet',
      (document: SignedDocument) => ({ ...document, signature: '%'.repeat(88) }),
      'INVALID_SIGNATURE',
    ],
    [
      'hash not hex',
      (document: SignedDocument) => ({ ...document, hash: 'bad' }),
      'INVALID_HASH',
    ],
  ] as const)('rejects %s', (_name, transform, code) => {
    const signer = participant('producer-A')
    const document = signDocument(signer, { value: 1 })
    expectTraceabilityError(
      () => validateDocument(transform(document), keyResolver(signer)),
      code
    )
  })

  it('rejects unsorted and duplicate parent references on validation', () => {
    const signer = participant('actor-A')
    const first = signDocument(signer, { number: 1 })
    const second = signDocument(signer, { number: 2 })
    const child = signDocument(signer, { number: 3 }, [first.hash, second.hash])
    const reversed = [...child.content.parents].reverse()

    expectTraceabilityError(
      () =>
        validateDocument(
          {
            ...child,
            content: { ...child.content, parents: reversed },
          },
          keyResolver(signer)
        ),
      'INVALID_PARENTS'
    )

    expectTraceabilityError(
      () =>
        validateDocument(
          {
            ...child,
            content: { ...child.content, parents: [first.hash, first.hash] },
          },
          keyResolver(signer)
        ),
      'INVALID_PARENTS'
    )
  })

  it('returns normalized documents without mutating the originals', () => {
    const signer = participant('actor-A')
    const document = signDocument(signer, { nested: { a: 1 }, list: [1, 2] })
    const snapshot = structuredClone(document)
    const normalized = validateDocument(document, keyResolver(signer))

    expect(normalized).toEqual(document)
    expect(document).toEqual(snapshot)
    expect(normalized).not.toBe(document)
  })

  it('rejects a mismatched resolved actor/key even with a valid public key', () => {
    const signer = participant('actor-A')
    const document = signDocument(signer, { value: 1 })
    expectTraceabilityError(
      () =>
        validateDocument(document, () => ({
          actorId: 'actor-B',
          keyId: signer.keyId,
          publicKey: signer.publicKey,
        })),
      'UNTRUSTED_KEY'
    )
  })

  it('rejects RSA public keys and invalid key objects', () => {
    const signer = participant('actor-A')
    const document = signDocument(signer, { value: 1 })
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    expectTraceabilityError(
      () =>
        validateDocument(document, () => ({
          actorId: signer.actorId,
          keyId: signer.keyId,
          publicKey: rsa.publicKey,
        })),
      'UNTRUSTED_KEY'
    )
  })

  it('rejects private keys from unsupported algorithms and invalid identifiers', () => {
    const signer = participant('actor-A')
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    expectTraceabilityError(
      () =>
        createDocument(
          { actorId: signer.actorId, keyId: signer.keyId, payload: {} },
          rsa.privateKey
        ),
      'INVALID_PRIVATE_KEY'
    )
    expectTraceabilityError(
      () =>
        createDocument(
          { actorId: ' ', keyId: signer.keyId, payload: {} },
          signer.privateKey
        ),
      'INVALID_IDENTIFIER'
    )
    expectTraceabilityError(
      () =>
        createDocument(
          { actorId: 'x'.repeat(129), keyId: signer.keyId, payload: {} },
          signer.privateKey
        ),
      'INVALID_IDENTIFIER'
    )
  })

  it('sorts parent hashes deterministically before signing', () => {
    const signer = participant('actor-A')
    const a = signDocument(signer, { number: 1 })
    const b = signDocument(signer, { number: 2 })
    const child = signDocument(signer, { number: 3 }, [b.hash, a.hash])
    expect(child.content.parents).toEqual([a.hash, b.hash].sort())
    expect(() => validateDocument(child, keyResolver(signer))).not.toThrow()
  })
})

describe('graph attack surfaces', () => {
  it('accepts the same valid DAG regardless of the input order', () => {
    const graph = scenario()
    expect(
      validateDocumentGraph([...graph.documents].reverse(), graph.resolveKey)
    ).toHaveLength(graph.documents.length)
  })

  it('rejects graph sizes above 20000 before validating content', () => {
    expectTraceabilityError(
      () => validateDocumentGraph(Array(20_001).fill(null), keyResolver()),
      'INVALID_GRAPH_SIZE'
    )
  })

  it('rejects an invalid signature anywhere in the graph', () => {
    const graph = scenario()
    const altered = graph.documents.map(document =>
      document === graph.drying
        ? { ...document, signature: Buffer.alloc(64, 7).toString('base64') }
        : document
    )
    expectTraceabilityError(
      () => validateDocumentGraph(altered, graph.resolveKey),
      'INVALID_SIGNATURE'
    )
  })

  it('rejects a missing ancestor in a shared dependency graph', () => {
    const graph = scenario()
    const missingReception = graph.documents.filter(
      document => document.hash !== graph.reception.hash
    )
    expectTraceabilityError(
      () => validateDocumentGraph(missingReception, graph.resolveKey),
      'MISSING_PARENT'
    )
  })
})

describe('Merkle tree construction and proof validation', () => {
  it('constructs actor and global trees directly', async () => {
    const {
      createActorTree,
      createGlobalTree,
      treeRoot,
      createActorProof,
      createDocumentProof,
    } = await import('../src/main.js')
    const graph = scenario()
    const tree = createActorTree(
      [graph.harvestA],
      graph.producerA.actorId,
      graph.resolveKey
    )
    const root = treeRoot(tree)
    const globalTree = createGlobalTree([{ actorId: graph.producerA.actorId, root }])
    const globalRoot = treeRoot(globalTree)

    expect(root).toMatch(/^0x[0-9a-f]{64}$/)
    expect(globalRoot).toMatch(/^0x[0-9a-f]{64}$/)
    expect(createDocumentProof(tree, graph.harvestA)).toEqual([])
    expect(
      createActorProof(globalTree, { actorId: graph.producerA.actorId, root })
    ).toEqual([])
  })

  it('rejects building an actor tree with another actor document', async () => {
    const { createActorTree } = await import('../src/main.js')
    const graph = scenario()
    expectTraceabilityError(
      () =>
        createActorTree(
          [graph.harvestA, graph.harvestB],
          graph.producerA.actorId,
          graph.resolveKey
        ),
      'ACTOR_MISMATCH'
    )
  })

  it('rejects empty actor and global trees, duplicate actors and documents', async () => {
    const { createActorTree, createGlobalTree } = await import('../src/main.js')
    const graph = scenario()
    expectTraceabilityError(
      () => createActorTree([], graph.producerA.actorId, graph.resolveKey),
      'EMPTY_ACTOR_TREE'
    )
    expectTraceabilityError(() => createGlobalTree([]), 'EMPTY_GLOBAL_TREE')
    expectTraceabilityError(
      () =>
        createActorTree(
          [graph.harvestA, graph.harvestA],
          graph.producerA.actorId,
          graph.resolveKey
        ),
      'DUPLICATE_DOCUMENT'
    )
    expectTraceabilityError(
      () =>
        createGlobalTree([
          { actorId: 'actor-A', root: graph.harvestA.hash },
          { actorId: 'actor-A', root: graph.harvestB.hash },
        ]),
      'DUPLICATE_ACTOR'
    )
  })

  it('rejects invalid actor root and invalid actor IDs', async () => {
    const { createGlobalTree } = await import('../src/main.js')
    expectTraceabilityError(
      () => createGlobalTree([{ actorId: 'actor-A', root: 'not-hex' as Hex }]),
      'INVALID_HASH'
    )
    expectTraceabilityError(
      () => createGlobalTree([{ actorId: '', root: `0x${'00'.repeat(32)}` as Hex }]),
      'INVALID_IDENTIFIER'
    )
  })

  it('rejects a modified signed-document envelope during proof generation', () => {
    const graph = scenario()
    const batch = buildAnchorBatch(graph.documents, graph.resolveKey)
    const modified = {
      ...graph.processing,
      signature: Buffer.alloc(64, 1).toString('base64'),
    }
    expectTraceabilityError(
      () => createInclusionProof(batch, modified),
      'DOCUMENT_MISMATCH'
    )
  })

  it('rejects proof values that exceed the allowed proof depth', () => {
    const graph = scenario()
    const batch = buildAnchorBatch(graph.documents, graph.resolveKey)
    const proof = createInclusionProof(batch, graph.processing)
    expectTraceabilityError(
      () =>
        validateInclusion(
          {
            document: graph.processing,
            ...proof,
            actorProof: Array(65).fill(`0x${'00'.repeat(32)}`),
          },
          graph.resolveKey
        ),
      'INVALID_PROOF'
    )
  })

  it('rejects proofs whose actor root has been changed', () => {
    const graph = scenario()
    const batch = buildAnchorBatch(graph.documents, graph.resolveKey)
    const proof = createInclusionProof(batch, graph.processing)
    expectTraceabilityError(
      () =>
        validateInclusion(
          {
            document: graph.processing,
            ...proof,
            actorRoot: `0x${'11'.repeat(32)}` as Hex,
          },
          graph.resolveKey
        ),
      'INVALID_DOCUMENT_PROOF'
    )
  })

  it('rejects a root that is not on-chain trusted even if the Merkle proof is internally valid', () => {
    const graph = scenario()
    const batch = buildAnchorBatch(graph.documents, graph.resolveKey)
    const proof = createInclusionProof(batch, graph.processing)
    expectTraceabilityError(
      () =>
        validateInclusionAgainstAnchor(
          {
            document: graph.processing,
            ...proof,
          },
          `0x${'ff'.repeat(32)}` as Hex,
          graph.resolveKey
        ),
      'ANCHOR_ROOT_MISMATCH'
    )
  })

  it('anchors every document regardless of multiple dependencies and overlapping ancestors', () => {
    const graph = scenario()
    const batch = buildAnchorBatch(graph.documents, graph.resolveKey)
    for (const document of graph.documents) {
      const proof = createInclusionProof(batch, document)
      expect(() =>
        validateInclusion({ document, ...proof }, graph.resolveKey)
      ).not.toThrow()
    }
  })
})

describe('participant identities and OS credential-store failure modes', () => {
  it('refuses to sign with an unknown key identifier', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    expectTraceabilityError(
      () =>
        store.createSignedDocument({
          actorId: 'producer-A',
          keyId: 'nonexistent',
          payload: {},
        }),
      'PRIVATE_KEY_NOT_FOUND'
    )
  })

  it('returns false when trying to remove a key that does not exist', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    expect(store.deletePrivateKey('producer-A', 'missing')).toBe(false)
  })

  it('rejects an empty keychain service and actor identifier', () => {
    expectTraceabilityError(() => new SystemKeyStore(''), 'INVALID_IDENTIFIER')
    expectTraceabilityError(
      () => new SystemKeyStore('valid').createParticipant(''),
      'INVALID_IDENTIFIER'
    )
  })

  it('does not silently accept a keychain that corrupts the stored private key', () => {
    fakeKeyring.corruptWrite = true
    const store = new SystemKeyStore('grano.traceability.tests')
    expectTraceabilityError(
      () => store.createParticipant('producer-A'),
      'KEY_STORAGE_FAILED'
    )
  })

  it.each(['get', 'set', 'delete'] as const)(
    'reports failed %s operations as keychain unavailable',
    action => {
      const store = new SystemKeyStore('grano.traceability.tests')
      const identity = store.createParticipant('producer-A')
      fakeKeyring.failOn = action

      const operation =
        action === 'delete'
          ? () => store.deletePrivateKey(identity.actorId, identity.keyId)
          : action === 'get'
            ? () =>
                store.createSignedDocument({
                  actorId: identity.actorId,
                  keyId: identity.keyId,
                  payload: {},
                })
            : () => store.createParticipant('producer-B')

      expectTraceabilityError(operation, 'KEYCHAIN_UNAVAILABLE')
    }
  )

  it('rejects malformed private keys stored in the OS keychain', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    const identity = store.createParticipant('producer-A')
    const entryKey = JSON.stringify([
      'grano.traceability.tests',
      JSON.stringify([identity.actorId, identity.keyId]),
    ])
    fakeKeyring.passwords.set(entryKey, 'not-a-private-key')
    expectTraceabilityError(
      () =>
        store.createSignedDocument({
          actorId: identity.actorId,
          keyId: identity.keyId,
          payload: {},
        }),
      'KEYCHAIN_UNAVAILABLE'
    )
  })

  it('rejects a stored private key of the wrong algorithm', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    const identity = store.createParticipant('producer-A')
    const entryKey = JSON.stringify([
      'grano.traceability.tests',
      JSON.stringify([identity.actorId, identity.keyId]),
    ])
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const rsaPem = rsa.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    expect(createPrivateKey(rsaPem).asymmetricKeyType).toBe('rsa')
    fakeKeyring.passwords.set(entryKey, rsaPem)
    expectTraceabilityError(
      () =>
        store.createSignedDocument({
          actorId: identity.actorId,
          keyId: identity.keyId,
          payload: {},
        }),
      'INVALID_PRIVATE_KEY'
    )
  })

  it('rejects duplicate public-key registrations and invalid PEM formats', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    const identity = store.createParticipant('producer-A')
    expectTraceabilityError(
      () => createKeyResolver([identity, identity]),
      'DUPLICATE_KEY'
    )
    expectTraceabilityError(
      () => createKeyResolver([{ ...identity, publicKeyPem: 'invalid' }]),
      'INVALID_PUBLIC_KEY'
    )
    expectTraceabilityError(
      () => createKeyResolver([{ ...identity, actorId: ' ' }]),
      'INVALID_IDENTIFIER'
    )
  })

  it('rejects a public key whose algorithm is RSA', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    const identity = store.createParticipant('producer-A')
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    expectTraceabilityError(
      () =>
        createKeyResolver([
          {
            ...identity,
            publicKeyPem: rsa.publicKey
              .export({ format: 'pem', type: 'spki' })
              .toString(),
          },
        ]),
      'INVALID_PUBLIC_KEY'
    )
  })

  it('revokes trust without invalidating the historical signed bytes', () => {
    const store = new SystemKeyStore('grano.traceability.tests')
    const identity = store.createParticipant('producer-A')
    const document = store.createSignedDocument({
      actorId: identity.actorId,
      keyId: identity.keyId,
      payload: { operation: 'RECEPTION' },
    })
    const trustedResolver = createKeyResolver([identity])
    expect(() => validateDocument(document, trustedResolver)).not.toThrow()
    const revokedResolver = createKeyResolver([{ ...identity, revoked: true }])
    expectTraceabilityError(
      () => validateDocument(document, revokedResolver),
      'UNTRUSTED_KEY'
    )
  })
})

describe('error reporting lifecycle', () => {
  it('returns the successful result without reporting an error', () => {
    const reporter = vi.fn()
    expect(executeTraceability(() => ({ status: 'ok' }), reporter)).toEqual({
      status: 'ok',
    })
    expect(reporter).not.toHaveBeenCalled()
  })

  it('captures nested context and preserves the underlying traceability code', () => {
    const signer = participant('actor-A')
    const reporter = vi.fn()
    expectTraceabilityError(
      () =>
        executeTraceability(
          () =>
            createDocument(
              {
                actorId: signer.actorId,
                keyId: signer.keyId,
                payload: { invalid: undefined },
              },
              signer.privateKey
            ),
          reporter
        ),
      'INVALID_JSON'
    )

    expect(reporter).toHaveBeenCalledOnce()
    expect(reporter).toHaveBeenCalledWith(
      expect.objectContaining({
        code: 'INVALID_JSON',
        context: expect.objectContaining({
          step: expect.stringContaining('CREATE_DOCUMENT'),
          traceId: expect.any(String),
        }),
      })
    )
  })

  it('returns resolved asynchronous results without error reports', async () => {
    const reporter = vi.fn()
    await expect(executeTraceabilityAsync(async () => 42, reporter)).resolves.toBe(42)
    expect(reporter).not.toHaveBeenCalled()
  })

  it('does not mask the original async error when reporting itself fails', async () => {
    const reporter = vi.fn(() => {
      throw new Error('telemetry offline')
    })
    await expect(
      executeTraceabilityAsync(async () => {
        throw new TraceabilityError(
          'SIGNED_DOCUMENT_FAILURE',
          'Signature verification failed'
        )
      }, reporter)
    ).rejects.toMatchObject({ code: 'SIGNED_DOCUMENT_FAILURE' })
    expect(reporter).toHaveBeenCalledOnce()
  })

  it('captures unexpected errors without leaking their raw message as the public error message', () => {
    const reporter = vi.fn()
    expectTraceabilityError(
      () =>
        executeTraceability(() => {
          throw new Error('secret database connection string')
        }, reporter),
      'UNEXPECTED_ERROR'
    )
    expect(reporter).toHaveBeenCalledWith(
      expect.objectContaining({
        code: 'UNEXPECTED_ERROR',
        message: 'Unexpected traceability failure',
      })
    )
  })
})

describe('cryptographic regression vectors', () => {
  it('hashes the canonical UTF-8 bytes using Keccak-256', async () => {
    const { keccak256, toHex } = await import('viem')
    expect(hashJSON({ b: 2, a: 1 })).toBe(keccak256(toHex('{"a":1,"b":2}')))
  })

  it('changes a signed-document hash when only the CUID2 identifier changes', () => {
    const signer = participant('producer-A')
    const first = signDocument(signer, { quantity: 20 })
    const second = signDocument(signer, { quantity: 20 })
    expect(first.content.payload).toEqual(second.content.payload)
    expect(first.hash).not.toBe(second.hash)
  })

  it('rejects proxies before invoking their traps', () => {
    const broken = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('untrusted access')
        },
      }
    )
    expectTraceabilityError(() => hashJSON(broken), 'INVALID_JSON')
  })
})

describe('logging and error context', () => {
  it('serializes a structured error without requiring an external telemetry provider', async () => {
    const { consoleErrorReporter } = await import('../src/main.js')
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    try {
      consoleErrorReporter({
        timestamp: '2026-10-31T00:00:00.000Z',
        code: 'TEST_ERROR',
        message: 'Synthetic error',
        context: { actorId: 'A' },
        causeType: null,
        stack: undefined,
      })
      const message = String(consoleSpy.mock.calls[0]?.[0])
      expect(JSON.parse(message)).toMatchObject({
        level: 'error',
        code: 'TEST_ERROR',
        context: { actorId: 'A' },
      })
    } finally {
      consoleSpy.mockRestore()
    }
  })

  it('preserves nested error causes and operation names', () => {
    const signer = participant('producer-A')
    let caught: unknown
    try {
      createDocument(
        { actorId: signer.actorId, keyId: signer.keyId, payload: { invalid: undefined } },
        signer.privateKey
      )
    } catch (error) {
      caught = error
    }
    expect(caught).toBeInstanceOf(TraceabilityError)
    const failure = caught as TraceabilityError
    expect(failure.code).toBe('INVALID_JSON')
    expect(failure.context.step).toBe('CREATE_DOCUMENT')
    expect(failure.stack).toContain('TraceabilityError')
  })
})

describe('advanced adversarial document validation', () => {
  it('rejects malformed envelope structures before accessing document fields', () => {
    const signer = participant('source')
    const doc = signDocument(signer, { qty: 7 })
    const resolve = keyResolver(signer)
    for (const input of [null, undefined, [], new Date(), 'payload']) {
      expectTraceabilityError(() => validateDocument(input, resolve), 'INVALID_STRUCTURE')
    }
    const withSymbol = { ...doc, [Symbol('tamper')]: 1 }
    expectTraceabilityError(
      () => validateDocument(withSymbol, resolve),
      'INVALID_STRUCTURE'
    )
    const hidden = Object.defineProperty({ ...doc }, 'invisible', {
      value: true,
      enumerable: false,
    })
    expectTraceabilityError(() => validateDocument(hidden, resolve), 'INVALID_STRUCTURE')
    const getter = vi.fn(() => doc.signature)
    const accessor = Object.defineProperty({ ...doc }, 'signature', {
      enumerable: true,
      get: getter,
    })
    expectTraceabilityError(
      () => validateDocument(accessor, resolve),
      'INVALID_STRUCTURE'
    )
    expect(getter).not.toHaveBeenCalled()
  })

  it('rejects missing nested fields, invalid parents and noncanonical signatures', () => {
    const signer = participant('source')
    const doc = signDocument(signer, { qty: 7 })
    const resolve = keyResolver(signer)
    const withoutPayload: Record<string, unknown> = { ...doc.content }
    delete withoutPayload.payload
    expectTraceabilityError(
      () => validateDocument({ ...doc, content: withoutPayload }, resolve),
      'INVALID_FIELDS'
    )
    expectTraceabilityError(
      () =>
        validateDocument({ ...doc, content: { ...doc.content, parents: null } }, resolve),
      'INVALID_PARENTS'
    )
    expectTraceabilityError(
      () =>
        validateDocument(
          { ...doc, content: { ...doc.content, parents: [doc.hash.toUpperCase()] } },
          resolve
        ),
      'INVALID_HASH'
    )
    expectTraceabilityError(
      () =>
        validateDocument(
          { ...doc, signature: doc.signature.slice(0, -1) + 'A' },
          resolve
        ),
      'INVALID_SIGNATURE'
    )
  })

  it('detects a duplicated CUID2 even if both documents have distinct valid hashes and signatures', () => {
    const signer = participant('source')
    const first = signDocument(signer, { action: 'A' })
    const second = signWithContent(signer, { ...first.content, payload: { action: 'B' } })
    expect(second.hash).not.toBe(first.hash)
    const resolve = keyResolver(signer)
    expect(() => validateDocument(second, resolve)).not.toThrow()
    expectTraceabilityError(
      () => validateDocumentGraph([first, second], resolve),
      'DUPLICATE_DOCUMENT'
    )
  })

  it('rejects oversized parent collections on creation and validation', () => {
    const signer = participant('source')
    const doc = signDocument(signer, { qty: 7 })
    const hugeParents = Array(20_001).fill(doc.hash) as Hex[]
    expectTraceabilityError(
      () => signDocument(signer, { qty: 8 }, hugeParents),
      'INVALID_PARENTS'
    )
    expectTraceabilityError(
      () =>
        validateDocument(
          {
            ...doc,
            content: { ...doc.content, parents: hugeParents },
          },
          keyResolver(signer)
        ),
      'INVALID_PARENTS'
    )
  })

  it('rejects invalid Ed25519 key resolver responses', () => {
    const signer = participant('source')
    const doc = signDocument(signer, { qty: 7 })
    expectTraceabilityError(
      () => validateDocument(doc, () => undefined as unknown as TrustedKey),
      'UNTRUSTED_KEY'
    )
    expectTraceabilityError(
      () =>
        validateDocument(doc, () => ({
          actorId: signer.actorId,
          keyId: 'another-key',
          publicKey: signer.publicKey,
        })),
      'UNTRUSTED_KEY'
    )
    expectTraceabilityError(
      () =>
        validateDocument(doc, () => ({
          actorId: signer.actorId,
          keyId: signer.keyId,
          publicKey: signer.privateKey,
        })),
      'UNTRUSTED_KEY'
    )
  })
})

describe('additional Merkle proof adversarial cases', () => {
  it('rejects a proof from a different actor before trusting the global root', () => {
    const graph = scenario()
    const batch = buildAnchorBatch(graph.documents, graph.resolveKey)
    const proof = createInclusionProof(batch, graph.processing)
    expectTraceabilityError(
      () =>
        validateInclusion(
          {
            document: graph.harvestA,
            ...proof,
          },
          graph.resolveKey
        ),
      'INVALID_DOCUMENT_PROOF'
    )
  })

  it('rejects invalid or oversized proofs of either tier', () => {
    const graph = scenario()
    const batch = buildAnchorBatch(graph.documents, graph.resolveKey)
    const proof = createInclusionProof(batch, graph.processing)
    expectTraceabilityError(
      () =>
        validateInclusion(
          {
            document: graph.processing,
            ...proof,
            documentProof: Array(65).fill(graph.processing.hash),
          },
          graph.resolveKey
        ),
      'INVALID_PROOF'
    )
    expectTraceabilityError(
      () =>
        validateInclusion(
          {
            document: graph.processing,
            ...proof,
            documentProof: null as unknown as Hex[],
          },
          graph.resolveKey
        ),
      'INVALID_PROOF'
    )
    expectTraceabilityError(
      () =>
        validateInclusion(
          {
            document: graph.processing,
            ...proof,
            globalRoot: 'invalid' as Hex,
          },
          graph.resolveKey
        ),
      'INVALID_HASH'
    )
    expectTraceabilityError(
      () =>
        validateInclusionAgainstAnchor(
          {
            document: graph.processing,
            ...proof,
          },
          'invalid' as Hex,
          graph.resolveKey
        ),
      'INVALID_HASH'
    )
  })

  it('refuses to generate an inclusion proof when an actor tree or root is missing', () => {
    const graph = scenario()
    const batch = buildAnchorBatch(graph.documents, graph.resolveKey)
    const brokenBatch = { ...batch, actorRoots: new Map(batch.actorRoots) }
    brokenBatch.actorRoots.delete(graph.processing.content.actorId)
    expectTraceabilityError(
      () => createInclusionProof(brokenBatch, graph.processing),
      'ACTOR_NOT_IN_BATCH'
    )
  })

  it('rejects requesting a Merkle leaf that was never committed', async () => {
    const {
      createActorTree,
      createGlobalTree,
      createDocumentProof,
      createActorProof,
      treeRoot,
    } = await import('../src/main.js')
    const graph = scenario()
    const actorTree = createActorTree(
      [graph.harvestA],
      graph.producerA.actorId,
      graph.resolveKey
    )
    const globalTree = createGlobalTree([
      { actorId: graph.producerA.actorId, root: treeRoot(actorTree) },
    ])
    expectTraceabilityError(
      () => createDocumentProof(actorTree, graph.harvestB),
      'UNEXPECTED_ERROR'
    )
    expectTraceabilityError(
      () =>
        createActorProof(globalTree, {
          actorId: 'not-committed',
          root: graph.harvestA.hash,
        }),
      'UNEXPECTED_ERROR'
    )
  })
})

describe('credential store identity separation and error context', () => {
  it('isolates identical actor IDs between independent credential services', () => {
    const first = new SystemKeyStore('service-alpha')
    const second = new SystemKeyStore('service-beta')
    const a = first.createParticipant('producer')
    const b = second.createParticipant('producer')
    expect(a.keyId).not.toBe(b.keyId)
    expect(fakeKeyring.passwords.size).toBe(2)
    expect(() =>
      validateDocument(
        first.createSignedDocument({
          actorId: a.actorId,
          keyId: a.keyId,
          payload: { x: 1 },
        }),
        createKeyResolver([a])
      )
    ).not.toThrow()
    expect(() =>
      validateDocument(
        second.createSignedDocument({
          actorId: b.actorId,
          keyId: b.keyId,
          payload: { x: 1 },
        }),
        createKeyResolver([b])
      )
    ).not.toThrow()
  })

  it('preserves operation and actor context when the OS keychain fails', () => {
    fakeKeyring.unavailable = true
    const store = new SystemKeyStore('service-test')
    try {
      store.createParticipant('producer')
      expect.fail('expected keychain exception')
    } catch (error) {
      expect(error).toBeInstanceOf(TraceabilityError)
      expect(error).toMatchObject({
        code: 'KEYCHAIN_UNAVAILABLE',
        context: { action: 'CREATE_KEY', actorId: 'producer', keyId: expect.any(String) },
      })
      expect((error as TraceabilityError).cause).toBeInstanceOf(Error)
    }
  })

  it('rejects keys with invalid IDs before constructing the platform keyring entry', () => {
    const store = new SystemKeyStore('service-test')
    expectTraceabilityError(
      () => store.deletePrivateKey('', 'some-key'),
      'INVALID_IDENTIFIER'
    )
    expectTraceabilityError(
      () => store.deletePrivateKey('actor', ' '),
      'INVALID_IDENTIFIER'
    )
    expectTraceabilityError(
      () =>
        createKeyResolver([
          {
            actorId: 'actor',
            keyId: '',
            publicKeyPem: 'invalid',
          },
        ]),
      'INVALID_IDENTIFIER'
    )
  })
})

describe('audit security regressions', () => {
  it('keeps revoked trust records immutable when exposed by a resolver', () => {
    const signer = participant('actor')
    const resolve = createKeyResolver([
      {
        actorId: signer.actorId,
        keyId: signer.keyId,
        publicKeyPem: signer.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        revoked: true,
      },
    ])
    const trusted = resolve(signer.actorId, signer.keyId)
    expect(Reflect.set(trusted, 'revoked', false)).toBe(false)
    expect(Reflect.set(trusted, 'publicKey', participant('attacker').publicKey)).toBe(
      false
    )
    expectTraceabilityError(
      () => validateDocument(signDocument(signer, {}), resolve),
      'UNTRUSTED_KEY'
    )
  })

  it('rejects an alternating anchor root without invoking its getter', () => {
    const signer = participant('actor')
    const resolve = keyResolver(signer)
    const doc = signDocument(signer, {})
    const batch = buildAnchorBatch([doc], resolve)
    const trusted = `0x${'11'.repeat(32)}` as Hex
    const getter = vi.fn().mockReturnValueOnce(trusted).mockReturnValue(batch.root)
    const input = Object.defineProperty(
      { document: doc, ...createInclusionProof(batch, doc) },
      'globalRoot',
      {
        enumerable: true,
        get: getter,
      }
    )
    expectTraceabilityError(
      () => validateInclusionAgainstAnchor(input, trusted, resolve),
      'INVALID_STRUCTURE'
    )
    expect(getter).not.toHaveBeenCalled()
  })

  it('rejects overridden parent methods and accessor elements without calling them', () => {
    const signer = participant('actor')
    const doc = signDocument(signer, {})
    const map = vi.fn(() => [])
    const parents = Object.assign([doc.hash], { map })
    expectTraceabilityError(
      () =>
        validateDocument(
          { ...doc, content: { ...doc.content, parents } },
          keyResolver(signer)
        ),
      'INVALID_PARENTS'
    )
    expect(map).not.toHaveBeenCalled()
    const getter = vi.fn(() => doc.hash)
    const accessors = Object.defineProperty([], '0', { enumerable: true, get: getter })
    expectTraceabilityError(() => signDocument(signer, {}, accessors), 'INVALID_PARENTS')
    expect(getter).not.toHaveBeenCalled()
  })

  it('rejects custom proof methods before executing them', () => {
    const signer = participant('actor')
    const resolve = keyResolver(signer)
    const doc = signDocument(signer, {})
    const batch = buildAnchorBatch([doc], resolve)
    const map = vi.fn(() => [])
    const proof = createInclusionProof(batch, doc)
    expectTraceabilityError(
      () =>
        validateInclusion(
          { document: doc, ...proof, documentProof: Object.assign([], { map }) },
          resolve
        ),
      'INVALID_PROOF'
    )
    expect(map).not.toHaveBeenCalled()
  })

  it('rejects malformed graph collections with structured errors', () => {
    for (const values of [null, undefined, {}, new Array(1)]) {
      expectTraceabilityError(
        () =>
          validateDocumentGraph(values as unknown as unknown[], () => {
            throw new Error('must not resolve')
          }),
        'INVALID_GRAPH_SIZE'
      )
    }
  })

  it('rejects invalid Unicode identifiers before storing credentials', () => {
    expectTraceabilityError(
      () => new SystemKeyStore().createParticipant('\ud800'),
      'INVALID_IDENTIFIER'
    )
    expect(fakeKeyring.passwords.size).toBe(0)
  })

  it('counts JSON escapes and multibyte characters consistently', () => {
    const value = {
      '\n': '\u0000\b\t\n\f\r"\\é😀',
      empty: [],
      nested: { a: true, b: null },
    }
    expect(hashJSON(value)).toMatch(/^0x[0-9a-f]{64}$/)
  })
})

describe('credential collision and missing trust boundaries', () => {
  it('refuses existing credentials instead of overwriting them', () => {
    fakeKeyring.existingEntry = true
    expectTraceabilityError(
      () => new SystemKeyStore().createParticipant('actor'),
      'KEY_ALREADY_EXISTS'
    )
    expect(fakeKeyring.passwords.size).toBe(0)
  })

  it('reports absent actors and absent keys in a registered actor', () => {
    const identity = new SystemKeyStore().createParticipant('actor')
    const resolve = createKeyResolver([identity])
    expectTraceabilityError(() => resolve('unknown', 'key'), 'KEY_NOT_FOUND')
    expectTraceabilityError(() => resolve(identity.actorId, 'unknown'), 'KEY_NOT_FOUND')
  })

  it('hashes three-byte UTF-8 characters consistently', () => {
    expect(hashJSON({ text: '漢字' })).toMatch(/^0x[0-9a-f]{64}$/)
  })
})

describe('non-Error failure reporting', () => {
  it('reports the type of a primitive cause without disclosing its value', () => {
    const reporter = vi.fn()
    expectTraceabilityError(
      () =>
        executeTraceability(() => {
          throw 'private detail'
        }, reporter),
      'UNEXPECTED_ERROR'
    )
    expect(reporter).toHaveBeenCalledWith(
      expect.objectContaining({
        causeType: 'string',
        message: 'Unexpected traceability failure',
      })
    )
  })
})

describe('aggregate graph budgets', () => {
  it('limits total references before resolving the graph', () => {
    const signer = participant('actor')
    const parents = Array.from(
      { length: 20_000 },
      (_, index) => `0x${index.toString(16).padStart(64, '0')}` as Hex
    )
    const documents = Array.from({ length: 6 }, (_, index) =>
      signDocument(signer, { index }, parents)
    )
    expectTraceabilityError(
      () => validateDocumentGraph(documents, keyResolver(signer)),
      'GRAPH_LIMIT'
    )
    expectTraceabilityError(
      () => validateDocumentGraph(documents.slice(0, 5), keyResolver(signer)),
      'MISSING_PARENT'
    )
  }, 60_000)

  it.skipIf(!runHeavyPayloadTests)(
    'limits aggregate bytes even when each document is individually valid',
    () => {
      const signer = participant('actor')
      const payload = 'x'.repeat(51 * 1024 * 1024)
      const documents = [signDocument(signer, payload), signDocument(signer, payload)]
      expectTraceabilityError(
        () => validateDocumentGraph(documents, keyResolver(signer)),
        'GRAPH_LIMIT'
      )
    },
    300_000
  )
})
