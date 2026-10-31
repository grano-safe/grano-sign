export {
  TraceabilityError,
  hashJSON,
  createDocument,
  validateDocument,
  validateDocumentGraph,
  createActorTree,
  createGlobalTree,
  treeRoot,
  createDocumentProof,
  createActorProof,
  buildAnchorBatch,
  createInclusionProof,
  validateInclusion,
  validateInclusionAgainstAnchor,
  consoleErrorReporter,
  executeTraceability,
  executeTraceabilityAsync,
} from './crypto/traceability.js'

export type {
  JsonValue,
  DocumentContent,
  SignedDocument,
  TrustedKey,
  KeyResolver,
  MerkleTree,
  ActorRoot,
  AnchorBatch,
  ErrorReporter,
} from './crypto/traceability.js'

export { SystemKeyStore, createKeyResolver } from './crypto/key-storage.js'

export type { ParticipantIdentity, NewDocument } from './crypto/key-storage.js'

export { TraceabilityWorkerPool } from './workers/pool.js'
export type { WorkerPoolOptions } from './workers/pool.js'
export type {
  TraceabilityExecutor,
  WorkerOperations,
  WorkerOperation,
  ExecutionOptions,
  BatchResult,
  InclusionProof,
} from './workers/types.js'
