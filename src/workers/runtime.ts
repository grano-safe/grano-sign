import { parentPort } from 'node:worker_threads'
import { createKeyResolver } from '../crypto/key-storage.js'
import {
  TraceabilityError,
  hashJSON,
  createDocument,
  validateDocument,
  validateDocumentGraph,
  buildAnchorBatch,
  createDocumentProof,
  createActorProof,
  validateInclusionAgainstAnchor,
} from '../crypto/traceability.js'
import type { BatchResult, WorkerOperation, WorkerOperations } from './types.js'

type Request = {
  id: number
  operation: WorkerOperation
  input: WorkerOperations[WorkerOperation]['input']
}

function run(request: Request): unknown {
  // The transport strips prototypes; each cryptographic operation still validates its input.
  const { operation } = request
  switch (operation) {
    case 'hashJSON':
      return hashJSON((request.input as WorkerOperations['hashJSON']['input']).value)
    case 'createDocument': {
      const input = request.input as WorkerOperations['createDocument']['input']
      return createDocument(input.document, input.privateKey)
    }
    case 'validateDocument': {
      const input = request.input as WorkerOperations['validateDocument']['input']
      return validateDocument(input.document, createKeyResolver(input.identities))
    }
    case 'validateDocumentGraph': {
      const input = request.input as WorkerOperations['validateDocumentGraph']['input']
      return validateDocumentGraph(input.documents, createKeyResolver(input.identities))
    }
    case 'buildAnchorBatch': {
      const input = request.input as WorkerOperations['buildAnchorBatch']['input']
      const batch = buildAnchorBatch(input.documents, createKeyResolver(input.identities))
      const byHash = new Map(batch.documents.map(document => [document.hash, document]))
      const requested = input.proofHashes ?? []
      if (
        requested.length > batch.documents.length ||
        new Set(requested).size !== requested.length
      ) {
        throw new TraceabilityError(
          'INVALID_PROOF_REQUEST',
          'Proof hashes must be unique and bounded by the batch size'
        )
      }
      const actorProofs = new Map<string, string[]>()
      const result: BatchResult = {
        root: batch.root,
        actorRoots: [...batch.actorRoots].map(([actorId, root]) => ({ actorId, root })),
        documentHashes: batch.documents.map(document => document.hash),
        proofs: requested.map(hash => {
          const document = byHash.get(hash)
          if (!document)
            throw new TraceabilityError(
              'DOCUMENT_NOT_IN_BATCH',
              'Requested document is not in the batch'
            )
          const actorId = document.content.actorId
          const actorRoot = batch.actorRoots.get(actorId)!
          const tree = batch.actorTrees.get(actorId)!
          let actorProof = actorProofs.get(actorId)
          if (!actorProof) {
            actorProof = createActorProof(batch.globalTree, { actorId, root: actorRoot })
            actorProofs.set(actorId, actorProof)
          }
          return {
            documentHash: hash,
            actorRoot,
            globalRoot: batch.root,
            documentProof: createDocumentProof(tree, document),
            actorProof,
          }
        }),
      }
      return result
    }
    case 'validateInclusionAgainstAnchor': {
      const input =
        request.input as WorkerOperations['validateInclusionAgainstAnchor']['input']
      return validateInclusionAgainstAnchor(
        input.inclusion,
        input.trustedGlobalRoot,
        createKeyResolver(input.identities)
      )
    }
    default:
      throw new TraceabilityError('INVALID_OPERATION', 'Unknown worker operation')
  }
}

parentPort?.on('message', (request: Request) => {
  try {
    parentPort!.postMessage({ id: request.id, result: run(request) })
  } catch (cause) {
    const error =
      cause instanceof TraceabilityError
        ? cause
        : new TraceabilityError('WORKER_FAILURE', 'Worker operation failed')
    // Do not transfer raw causes or stacks that may contain caller secrets.
    parentPort!.postMessage({
      id: request.id,
      error: { code: error.code, message: error.message, context: error.context },
    })
  }
})
