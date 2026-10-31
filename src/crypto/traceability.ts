import { KeyObject, sign, verify } from 'node:crypto'
import { types } from 'node:util'
import { createId, isCuid } from '@paralleldrive/cuid2'
import canonicalize from 'canonicalize'
import { keccak256, type Hex } from 'viem'
import { StandardMerkleTree } from '@openzeppelin/merkle-tree'

const VERSION = '1.0.0'
const DOCUMENT_DOMAIN = 'grano.traceability.document.v1'
const LEAF_DOMAIN = 'grano.traceability.signed-document.v1'
const MAX_JSON_BYTES = 100 * 1024 * 1024
const MAX_DEPTH = 64
const MAX_NODES = 100_000
const MAX_DOCUMENTS = 20_000
const MAX_GRAPH_EDGES = 100_000

type ErrorContext = Record<string, string | number | boolean | null>
export type JsonValue =
  null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export class TraceabilityError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly context: ErrorContext = {},
    cause?: unknown
  ) {
    super(message, { cause })
    this.name = 'TraceabilityError'
  }
}

function ensure(
  condition: unknown,
  code: string,
  message: string,
  context: ErrorContext = {}
): asserts condition {
  if (!condition) throw new TraceabilityError(code, message, context)
}

function protectedStep<T>(step: string, context: ErrorContext, operation: () => T): T {
  try {
    return operation()
  } catch (cause) {
    if (cause instanceof TraceabilityError) {
      const path = cause.context.step ? `${step} > ${cause.context.step}` : step
      throw new TraceabilityError(
        cause.code,
        cause.message,
        { ...context, ...cause.context, step: path },
        cause
      )
    }
    throw new TraceabilityError(
      'UNEXPECTED_ERROR',
      `Unexpected failure in ${step}`,
      { ...context, step },
      cause
    )
  }
}

function validUnicode(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i)
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false
    }
  }
  return true
}

function normalizeJSON(value: unknown): JsonValue {
  const ancestors = new Set<object>()
  let nodes = 0
  let bytes = 0

  function consume(size: number): void {
    bytes += size
    ensure(bytes <= MAX_JSON_BYTES, 'JSON_TOO_LARGE', 'Canonical JSON exceeds 100 MiB')
  }

  // Count escaped UTF-8 bytes before serialization can allocate an oversized string.
  function consumeString(value: string): void {
    consume(2)
    for (let i = 0; i < value.length; i++) {
      const code = value.charCodeAt(i)
      if (code === 34 || code === 92 || [8, 9, 10, 12, 13].includes(code)) consume(2)
      else if (code < 32) consume(6)
      else if (code < 128) consume(1)
      else if (code < 2048) consume(2)
      else if (code >= 0xd800 && code <= 0xdbff) {
        consume(4)
        i++
      } else consume(3)
    }
  }

  function visit(current: unknown, depth: number): JsonValue {
    ensure(
      ++nodes <= MAX_NODES && depth <= MAX_DEPTH,
      'JSON_LIMIT',
      'JSON structure exceeds allowed limits'
    )
    if (current === null || typeof current === 'boolean') {
      consume(current === null ? 4 : current ? 4 : 5)
      return current
    }
    if (typeof current === 'string') {
      ensure(validUnicode(current), 'INVALID_UNICODE', 'JSON contains invalid Unicode')
      consumeString(current)
      return current
    }
    if (typeof current === 'number') {
      ensure(
        Number.isFinite(current) && !Object.is(current, -0),
        'INVALID_NUMBER',
        'Invalid JSON number'
      )
      ensure(
        !Number.isInteger(current) || Number.isSafeInteger(current),
        'UNSAFE_INTEGER',
        'Represent large integers as strings'
      )
      consume(String(current).length)
      return current
    }
    ensure(
      typeof current === 'object' && current !== null,
      'INVALID_JSON',
      'Non-JSON value'
    )
    ensure(!types.isProxy(current), 'INVALID_JSON', 'Proxy objects are not allowed')
    ensure(!ancestors.has(current), 'CYCLIC_JSON', 'Cyclic JSON structure')
    ancestors.add(current)

    try {
      if (Array.isArray(current)) {
        consume(2 + Math.max(0, current.length - 1))
        ensure(
          Object.getPrototypeOf(current) === Array.prototype,
          'INVALID_JSON',
          'Array subclass is not allowed'
        )
        ensure(
          Object.getOwnPropertySymbols(current).length === 0,
          'INVALID_JSON',
          'Symbol properties are not allowed'
        )
        ensure(
          Object.getOwnPropertyNames(current).length === current.length + 1,
          'INVALID_JSON',
          'Sparse arrays or additional array properties'
        )
        const result: JsonValue[] = []
        for (let i = 0; i < current.length; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(current, String(i))
          ensure(
            descriptor && descriptor.enumerable && 'value' in descriptor,
            'INVALID_JSON',
            'Sparse, hidden or accessor array element'
          )
          result.push(visit(descriptor.value, depth + 1))
        }
        return result
      }

      const prototype: unknown = Object.getPrototypeOf(current)
      ensure(
        prototype === Object.prototype || prototype === null,
        'INVALID_JSON',
        'Expected a plain JSON object'
      )
      ensure(
        Object.getOwnPropertySymbols(current).length === 0,
        'INVALID_JSON',
        'Symbol properties are not allowed'
      )
      const names = Object.getOwnPropertyNames(current)
      consume(2 + Math.max(0, names.length - 1))
      const result: { [key: string]: JsonValue } = Object.create(null)

      for (const key of names) {
        ensure(validUnicode(key), 'INVALID_UNICODE', 'Invalid Unicode in property name')
        consumeString(key)
        consume(1)
        const descriptor = Object.getOwnPropertyDescriptor(current, key)
        ensure(
          descriptor?.enumerable && 'value' in descriptor,
          'INVALID_JSON',
          'Accessors and hidden properties are not allowed'
        )
        result[key] = visit(descriptor.value, depth + 1)
      }
      return result
    } finally {
      ancestors.delete(current)
    }
  }
  return visit(value, 0)
}

function canonicalJSON(value: unknown): string {
  const normalized = normalizeJSON(value)
  const serialized = canonicalize(normalized)
  ensure(typeof serialized === 'string', 'INVALID_JSON', 'Could not canonicalize JSON')
  ensure(
    Buffer.byteLength(serialized, 'utf8') <= MAX_JSON_BYTES,
    'JSON_TOO_LARGE',
    'Canonical JSON exceeds 100 MiB'
  )
  return serialized
}

export function hashJSON(value: unknown): Hex {
  return protectedStep('HASH_JSON', {}, () =>
    keccak256(Buffer.from(canonicalJSON(value), 'utf8'))
  )
}

function requireHash(value: unknown): Hex {
  ensure(
    typeof value === 'string' && /^0x[0-9a-f]{64}$/.test(value),
    'INVALID_HASH',
    'Expected a lowercase 32-byte hexadecimal hash'
  )
  return value as Hex
}

function requireIdentifier(value: unknown, field: string): string {
  ensure(
    typeof value === 'string' &&
      value.length > 0 &&
      value.length <= 128 &&
      value.trim() === value &&
      validUnicode(value),
    'INVALID_IDENTIFIER',
    `Invalid ${field}`
  )
  return value
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  ensure(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    'INVALID_STRUCTURE',
    `Expected object: ${field}`
  )
  ensure(!types.isProxy(value), 'INVALID_STRUCTURE', 'Proxy objects are not allowed')
  const prototype: unknown = Object.getPrototypeOf(value)
  ensure(
    prototype === Object.prototype || prototype === null,
    'INVALID_STRUCTURE',
    `Expected plain object: ${field}`
  )
  ensure(
    Object.getOwnPropertySymbols(value).length === 0,
    'INVALID_STRUCTURE',
    `Symbol properties: ${field}`
  )
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const snapshot: Record<string, unknown> = Object.create(null)
  for (const [key, descriptor] of Object.entries(descriptors)) {
    ensure(
      descriptor.enumerable && 'value' in descriptor,
      'INVALID_STRUCTURE',
      `Accessor or hidden field: ${field}`
    )
    snapshot[key] = descriptor.value
  }
  return snapshot
}

function requireFields(value: Record<string, unknown>, fields: readonly string[]): void {
  const actual = Object.keys(value)
  ensure(
    actual.length === fields.length && actual.every(key => fields.includes(key)),
    'INVALID_FIELDS',
    'Missing or unexpected fields'
  )
}

// Read data descriptors instead of invoking methods supplied by the caller.
function requireArray(value: unknown, limit: number, code: string): unknown[] {
  ensure(Array.isArray(value) && !types.isProxy(value), code, 'Expected a plain array')
  ensure(value.length <= limit, code, 'Array exceeds allowed limits')
  ensure(
    Object.getPrototypeOf(value) === Array.prototype &&
      Object.getOwnPropertySymbols(value).length === 0 &&
      Object.getOwnPropertyNames(value).length === value.length + 1,
    code,
    'Expected a dense array without additional properties'
  )
  const result: unknown[] = []
  for (let i = 0; i < value.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i))
    ensure(descriptor?.enumerable && 'value' in descriptor, code, 'Invalid array element')
    result.push(descriptor.value)
  }
  return result
}

function requireParents(value: unknown): Hex[] {
  const parents = requireArray(value, MAX_DOCUMENTS, 'INVALID_PARENTS').map(requireHash)
  for (let i = 1; i < parents.length; i++) {
    const previous = parents[i - 1]
    const current = parents[i]
    ensure(
      previous !== undefined && current !== undefined && previous < current,
      'INVALID_PARENTS',
      'Parents must be unique and sorted'
    )
  }
  return parents
}

export type DocumentContent = {
  type: 'grano.document'
  version: '1.0.0'
  documentId: string
  actorId: string
  keyId: string
  parents: Hex[]
  payload: JsonValue
}

export type SignedDocument = {
  content: DocumentContent
  hash: Hex
  signature: string
}

export type TrustedKey = {
  readonly actorId: string
  readonly keyId: string
  readonly publicKey: KeyObject
  readonly revoked?: boolean
}

export type KeyResolver = (actorId: string, keyId: string) => TrustedKey

function documentHash(content: DocumentContent): Hex {
  return hashJSON({ domain: DOCUMENT_DOMAIN, content })
}

function signedDocumentCommitment(document: SignedDocument): Hex {
  return hashJSON({ domain: LEAF_DOMAIN, document })
}

function signatureBytes(signature: unknown): Buffer {
  ensure(
    typeof signature === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(signature),
    'INVALID_SIGNATURE',
    'Invalid Ed25519 signature encoding'
  )
  const bytes = Buffer.from(signature, 'base64')
  ensure(
    bytes.length === 64 && bytes.toString('base64') === signature,
    'INVALID_SIGNATURE',
    'Non-canonical Ed25519 signature'
  )
  return bytes
}

function parseSignedDocument(input: unknown): SignedDocument {
  const document = requireRecord(input, 'document')
  requireFields(document, ['content', 'hash', 'signature'])
  const source = requireRecord(document.content, 'content')
  requireFields(source, [
    'type',
    'version',
    'documentId',
    'actorId',
    'keyId',
    'parents',
    'payload',
  ])
  ensure(
    source.type === 'grano.document' && source.version === VERSION,
    'INVALID_VERSION',
    'Unknown document protocol'
  )
  ensure(
    typeof source.documentId === 'string' &&
      source.documentId.length === 24 &&
      isCuid(source.documentId),
    'INVALID_DOCUMENT_ID',
    'Expected a 24-character CUID2'
  )
  const content: DocumentContent = {
    type: 'grano.document',
    version: VERSION,
    documentId: source.documentId,
    actorId: requireIdentifier(source.actorId, 'actorId'),
    keyId: requireIdentifier(source.keyId, 'keyId'),
    parents: requireParents(source.parents),
    payload: normalizeJSON(source.payload),
  }
  const hash = requireHash(document.hash)
  const signature = document.signature
  signatureBytes(signature)
  ensure(typeof signature === 'string', 'INVALID_SIGNATURE', 'Expected base64 signature')
  ensure(
    documentHash(content) === hash,
    'HASH_MISMATCH',
    'Document content has changed',
    { documentId: content.documentId }
  )
  return { content, hash, signature }
}

export function createDocument(
  input: {
    actorId: string
    keyId: string
    payload: unknown
    parents?: readonly Hex[]
  },
  privateKey: KeyObject
): SignedDocument {
  return protectedStep('CREATE_DOCUMENT', {}, () => {
    ensure(
      privateKey instanceof KeyObject &&
        privateKey.type === 'private' &&
        privateKey.asymmetricKeyType === 'ed25519',
      'INVALID_PRIVATE_KEY',
      'Expected Ed25519 private key'
    )
    const actorId = requireIdentifier(input.actorId, 'actorId')
    const keyId = requireIdentifier(input.keyId, 'keyId')
    const parents = requireParents(
      requireArray(input.parents ?? [], MAX_DOCUMENTS, 'INVALID_PARENTS')
        .map(requireHash)
        .sort()
    )
    const payload = normalizeJSON(input.payload)
    canonicalJSON(payload)
    const content: DocumentContent = {
      type: 'grano.document',
      version: VERSION,
      documentId: createId(),
      actorId,
      keyId,
      parents,
      payload,
    }
    const hash = documentHash(content)
    const signature = sign(null, Buffer.from(hash.slice(2), 'hex'), privateKey).toString(
      'base64'
    )
    const document = { content, hash, signature }
    // Reserve room for the signed envelope so every created document is anchorable.
    canonicalJSON({ domain: LEAF_DOMAIN, document })
    return document
  })
}

export function validateDocument(
  value: unknown,
  resolveKey: KeyResolver
): SignedDocument {
  return protectedStep('VALIDATE_DOCUMENT', {}, () => {
    const document = parseSignedDocument(value)
    const { actorId, keyId, documentId } = document.content
    const trusted = resolveKey(actorId, keyId)
    ensure(
      trusted && trusted.actorId === actorId && trusted.keyId === keyId,
      'UNTRUSTED_KEY',
      'Key does not belong to actor',
      { actorId, keyId, documentId }
    )
    ensure(
      (trusted.revoked === undefined || trusted.revoked === false) &&
        trusted.publicKey instanceof KeyObject &&
        trusted.publicKey.type === 'public' &&
        trusted.publicKey.asymmetricKeyType === 'ed25519',
      'UNTRUSTED_KEY',
      'Key is revoked or invalid',
      { actorId, keyId }
    )
    const valid = verify(
      null,
      Buffer.from(document.hash.slice(2), 'hex'),
      trusted.publicKey,
      signatureBytes(document.signature)
    )
    ensure(valid, 'INVALID_SIGNATURE', 'Document signature verification failed', {
      actorId,
      keyId,
      documentId,
    })
    return document
  })
}

export function validateDocumentGraph(
  values: readonly unknown[],
  resolveKey: KeyResolver
): SignedDocument[] {
  return protectedStep('VALIDATE_GRAPH', {}, () => {
    const inputs = requireArray(values, MAX_DOCUMENTS, 'INVALID_GRAPH_SIZE')
    ensure(inputs.length > 0, 'INVALID_GRAPH_SIZE', 'Invalid document count')
    let totalBytes = 0
    let totalEdges = 0
    const documents = inputs.map(value => {
      const document = validateDocument(value, resolveKey)
      totalBytes += Buffer.byteLength(
        canonicalJSON({ domain: LEAF_DOMAIN, document }),
        'utf8'
      )
      totalEdges += document.content.parents.length
      ensure(
        totalBytes <= MAX_JSON_BYTES && totalEdges <= MAX_GRAPH_EDGES,
        'GRAPH_LIMIT',
        'Graph exceeds its total byte or parent-reference budget'
      )
      return document
    })
    const byHash = new Map<Hex, SignedDocument>()
    const ids = new Set<string>()
    for (const document of documents) {
      ensure(
        !byHash.has(document.hash) && !ids.has(document.content.documentId),
        'DUPLICATE_DOCUMENT',
        'Duplicate document hash or ID',
        { documentId: document.content.documentId }
      )
      byHash.set(document.hash, document)
      ids.add(document.content.documentId)
    }
    for (const document of documents) {
      for (const parent of document.content.parents) {
        ensure(byHash.has(parent), 'MISSING_PARENT', 'Referenced document not supplied', {
          documentId: document.content.documentId,
          parentHash: parent,
        })
      }
    }
    const states = new Map<Hex, 'visiting' | 'done'>()

    for (const document of documents) {
      if (states.get(document.hash) === 'done') continue

      const stack: { hash: Hex; nextParentIndex: number }[] = [
        { hash: document.hash, nextParentIndex: 0 },
      ]

      while (stack.length > 0) {
        const frame = stack[stack.length - 1]
        ensure(frame !== undefined, 'INVALID_GRAPH', 'Invalid graph stack')

        const current = byHash.get(frame.hash)
        ensure(current !== undefined, 'MISSING_PARENT', 'Referenced document is missing')
        states.set(frame.hash, 'visiting')

        if (frame.nextParentIndex === current.content.parents.length) {
          states.set(frame.hash, 'done')
          stack.pop()
          continue
        }

        const parentHash = current.content.parents[frame.nextParentIndex]
        ensure(parentHash !== undefined, 'MISSING_PARENT', 'Missing parent hash')
        frame.nextParentIndex++

        const parentState = states.get(parentHash)
        ensure(parentState !== 'visiting', 'CYCLIC_GRAPH', 'Cyclic document dependency')
        if (parentState !== 'done') {
          stack.push({ hash: parentHash, nextParentIndex: 0 })
        }
      }
    }
    return documents
  })
}

export type MerkleTree = ReturnType<typeof StandardMerkleTree.of>
export type ActorRoot = { actorId: string; root: Hex }

export function treeRoot(tree: MerkleTree): Hex {
  return requireHash(tree.root)
}

export function createActorTree(
  values: readonly unknown[],
  actorId: string,
  resolveKey: KeyResolver
): MerkleTree {
  return protectedStep('CREATE_ACTOR_TREE', { actorId }, () => {
    requireIdentifier(actorId, 'actorId')
    ensure(
      values.length > 0 && values.length <= MAX_DOCUMENTS,
      'EMPTY_ACTOR_TREE',
      'Invalid actor document count'
    )
    const inputs = requireArray(values, MAX_DOCUMENTS, 'EMPTY_ACTOR_TREE')
    return actorTreeFromDocuments(
      inputs.map(value => validateDocument(value, resolveKey)),
      actorId
    )
  })
}

// Only callers that have authenticated every document may use this internal path.
function actorTreeFromDocuments(
  documents: readonly SignedDocument[],
  actorId: string
): MerkleTree {
  const seen = new Set<Hex>()
  const ids = new Set<string>()
  const leaves = documents.map(document => {
    ensure(
      document.content.actorId === actorId,
      'ACTOR_MISMATCH',
      'Document signed by another actor'
    )
    ensure(
      !seen.has(document.hash) && !ids.has(document.content.documentId),
      'DUPLICATE_DOCUMENT',
      'Duplicate actor document'
    )
    seen.add(document.hash)
    ids.add(document.content.documentId)
    return [actorId, signedDocumentCommitment(document)]
  })
  return StandardMerkleTree.of(leaves, ['string', 'bytes32'])
}

export function createGlobalTree(actors: readonly ActorRoot[]): MerkleTree {
  return protectedStep('CREATE_GLOBAL_TREE', {}, () => {
    ensure(
      actors.length > 0 && actors.length <= MAX_DOCUMENTS,
      'EMPTY_GLOBAL_TREE',
      'Invalid actor root count'
    )
    const seen = new Set<string>()
    const leaves = requireArray(actors, MAX_DOCUMENTS, 'EMPTY_GLOBAL_TREE').map(value => {
      const actor = requireRecord(value, 'actor root')
      const actorId = requireIdentifier(actor.actorId, 'actorId')
      ensure(!seen.has(actorId), 'DUPLICATE_ACTOR', 'Duplicate actor root', { actorId })
      seen.add(actorId)
      return [actorId, requireHash(actor.root)]
    })
    return StandardMerkleTree.of(leaves, ['string', 'bytes32'])
  })
}

export function createDocumentProof(
  tree: MerkleTree,
  document: SignedDocument
): string[] {
  return protectedStep(
    'CREATE_DOCUMENT_PROOF',
    { documentId: document.content.documentId },
    () => tree.getProof([document.content.actorId, signedDocumentCommitment(document)])
  )
}

export function createActorProof(tree: MerkleTree, actor: ActorRoot): string[] {
  return protectedStep('CREATE_ACTOR_PROOF', { actorId: actor.actorId }, () =>
    tree.getProof([actor.actorId, requireHash(actor.root)])
  )
}

export type AnchorBatch = {
  documents: SignedDocument[]
  actorTrees: Map<string, MerkleTree>
  actorRoots: Map<string, Hex>
  globalTree: MerkleTree
  root: Hex
}

export function buildAnchorBatch(
  values: readonly unknown[],
  resolveKey: KeyResolver
): AnchorBatch {
  return protectedStep('BUILD_ANCHOR_BATCH', {}, () => {
    const documents = validateDocumentGraph(values, resolveKey)
    const grouped = new Map<string, SignedDocument[]>()
    for (const document of documents) {
      const actorId = document.content.actorId
      const group = grouped.get(actorId) ?? []
      group.push(document)
      grouped.set(actorId, group)
    }
    const actorTrees = new Map<string, MerkleTree>()
    const actorRoots = new Map<string, Hex>()
    for (const [actorId, group] of grouped) {
      const tree = actorTreeFromDocuments(group, actorId)
      actorTrees.set(actorId, tree)
      actorRoots.set(actorId, treeRoot(tree))
    }
    const globalTree = createGlobalTree(
      [...actorRoots].map(([actorId, root]) => ({ actorId, root }))
    )
    return { documents, actorTrees, actorRoots, globalTree, root: treeRoot(globalTree) }
  })
}

export function createInclusionProof(batch: AnchorBatch, value: SignedDocument) {
  return protectedStep(
    'CREATE_INCLUSION_PROOF',
    { documentId: value.content.documentId },
    () => {
      const document = batch.documents.find(item => item.hash === value.hash)
      ensure(
        document !== undefined,
        'DOCUMENT_NOT_IN_BATCH',
        'Document is not part of this anchor batch'
      )
      ensure(
        signedDocumentCommitment(value) === signedDocumentCommitment(document),
        'DOCUMENT_MISMATCH',
        'Signed document differs from the anchored document'
      )
      const actorId = document.content.actorId
      const tree = batch.actorTrees.get(actorId)
      const root = batch.actorRoots.get(actorId)
      ensure(
        tree !== undefined && root !== undefined,
        'ACTOR_NOT_IN_BATCH',
        'Actor root not found',
        { actorId }
      )
      return {
        actorRoot: root,
        globalRoot: batch.root,
        documentProof: createDocumentProof(tree, document),
        actorProof: createActorProof(batch.globalTree, { actorId, root }),
      }
    }
  )
}

function requireProof(proof: readonly string[]): Hex[] {
  return requireArray(proof, 64, 'INVALID_PROOF').map(requireHash)
}

export function validateInclusion(
  input: {
    document: unknown
    actorRoot: Hex
    globalRoot: Hex
    documentProof: readonly string[]
    actorProof: readonly string[]
  },
  resolveKey: KeyResolver
): void {
  protectedStep('VALIDATE_INCLUSION', {}, () => {
    const snapshot = requireRecord(input, 'inclusion')
    const document = validateDocument(snapshot.document, resolveKey)
    const actorRoot = requireHash(snapshot.actorRoot)
    const globalRoot = requireHash(snapshot.globalRoot)
    const documentIncluded = StandardMerkleTree.verify(
      actorRoot,
      ['string', 'bytes32'],
      [document.content.actorId, signedDocumentCommitment(document)],
      requireProof(snapshot.documentProof as readonly string[])
    )
    ensure(
      documentIncluded,
      'INVALID_DOCUMENT_PROOF',
      'Document is not included in actor tree',
      { documentId: document.content.documentId }
    )
    const actorIncluded = StandardMerkleTree.verify(
      globalRoot,
      ['string', 'bytes32'],
      [document.content.actorId, actorRoot],
      requireProof(snapshot.actorProof as readonly string[])
    )
    ensure(actorIncluded, 'INVALID_ACTOR_PROOF', 'Actor is not included in global tree', {
      actorId: document.content.actorId,
    })
  })
}

export type ErrorReporter = (event: {
  timestamp: string
  code: string
  message: string
  context: ErrorContext
  causeType: string | null
  stack: string | undefined
}) => void

export const consoleErrorReporter: ErrorReporter = event => {
  console.error(JSON.stringify({ level: 'error', ...event }, null, 2))
}

function reportFailure(cause: unknown, reporter: ErrorReporter): never {
  const error =
    cause instanceof TraceabilityError
      ? cause
      : new TraceabilityError(
          'UNEXPECTED_ERROR',
          'Unexpected traceability failure',
          {},
          cause
        )
  try {
    reporter({
      timestamp: new Date().toISOString(),
      code: error.code,
      message: error.message,
      context: { traceId: createId(), ...error.context },
      causeType:
        error.cause instanceof Error
          ? error.cause.name
          : error.cause === undefined
            ? null
            : typeof error.cause,
      stack: error.stack,
    })
  } catch {
    // Reporting must never replace the original error.
  }
  throw error
}

export function executeTraceability<T>(
  operation: () => T,
  reporter: ErrorReporter = consoleErrorReporter
): T {
  try {
    return operation()
  } catch (cause) {
    return reportFailure(cause, reporter)
  }
}

export async function executeTraceabilityAsync<T>(
  operation: () => Promise<T>,
  reporter: ErrorReporter = consoleErrorReporter
): Promise<T> {
  try {
    return await operation()
  } catch (cause) {
    return reportFailure(cause, reporter)
  }
}

export function validateInclusionAgainstAnchor(
  input: Parameters<typeof validateInclusion>[0],
  trustedGlobalRoot: Hex,
  resolveKey: KeyResolver
): void {
  protectedStep('VALIDATE_ANCHORED_INCLUSION', {}, () => {
    // Compare and verify the same root; accessors must not change it between reads.
    const snapshot = requireRecord(input, 'inclusion')
    ensure(
      requireHash(snapshot.globalRoot) === requireHash(trustedGlobalRoot),
      'ANCHOR_ROOT_MISMATCH',
      'Global root differs from the trusted anchored root'
    )
    validateInclusion(snapshot as Parameters<typeof validateInclusion>[0], resolveKey)
  })
}
