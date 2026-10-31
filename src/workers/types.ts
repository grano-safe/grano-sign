import type { KeyObject } from 'node:crypto'
import type { Hex } from 'viem'
import type { NewDocument, ParticipantIdentity } from '../crypto/key-storage.js'
import type {
  ActorRoot,
  SignedDocument,
  validateInclusion,
} from '../crypto/traceability.js'

export type InclusionProof = {
  documentHash: Hex
  actorRoot: Hex
  globalRoot: Hex
  documentProof: string[]
  actorProof: string[]
}

/** Portable output: persist proofs outside the pool before releasing the result. */
export type BatchResult = {
  root: Hex
  actorRoots: ActorRoot[]
  documentHashes: Hex[]
  proofs: InclusionProof[]
}

type Trust = { identities: readonly ParticipantIdentity[] }

export type WorkerOperations = {
  hashJSON: { input: { value: unknown }; output: Hex }
  createDocument: {
    input: { document: NewDocument; privateKey: KeyObject }
    output: SignedDocument
  }
  validateDocument: { input: Trust & { document: unknown }; output: SignedDocument }
  validateDocumentGraph: {
    input: Trust & { documents: readonly unknown[] }
    output: SignedDocument[]
  }
  buildAnchorBatch: {
    input: Trust & { documents: readonly unknown[]; proofHashes?: readonly Hex[] }
    output: BatchResult
  }
  validateInclusionAgainstAnchor: {
    input: Trust & {
      inclusion: Parameters<typeof validateInclusion>[0]
      trustedGlobalRoot: Hex
    }
    output: void
  }
}

export type WorkerOperation = keyof WorkerOperations
export type ExecutionOptions = { signal?: AbortSignal; timeoutMs?: number }

/** Implement this interface to route the same operations to an external service. */
export interface TraceabilityExecutor {
  execute<K extends WorkerOperation>(
    operation: K,
    input: WorkerOperations[K]['input'],
    options?: ExecutionOptions
  ): Promise<WorkerOperations[K]['output']>
}
