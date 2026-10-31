# grano-sign

A TypeScript library for signing JSON documents, validating document dependencies, and producing two-level Merkle inclusion proofs. It uses Ed25519 signatures, Keccak-256 hashes, canonical JSON, and the operating system credential store.

## Requirements

- Node.js 22.12 or later, with ESM support.
- pnpm 10.12.1, as specified in `package.json`.
- An available OS credential store when using `SystemKeyStore`. Linux uses Secret Service; headless environments may require additional setup.

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm run check
```

## Usage

Build the package with `pnpm run build`, then import it from your consuming application:

```ts
import {
  SystemKeyStore,
  createKeyResolver,
  validateDocumentGraph,
  buildAnchorBatch,
  createInclusionProof,
  validateInclusionAgainstAnchor,
} from 'grano-sign'

const keyStore = new SystemKeyStore()
const producer = keyStore.createParticipant('producer-1')
const warehouse = keyStore.createParticipant('warehouse-1')
const resolveKey = createKeyResolver([producer, warehouse])

const harvest = keyStore.createSignedDocument({
  actorId: producer.actorId,
  keyId: producer.keyId,
  payload: { operation: 'HARVEST', kg: 20000 },
})

const reception = keyStore.createSignedDocument({
  actorId: warehouse.actorId,
  keyId: warehouse.keyId,
  parents: [harvest.hash],
  payload: { operation: 'RECEPTION', kg: 20000 },
})

validateDocumentGraph([harvest, reception], resolveKey)
const batch = buildAnchorBatch([harvest, reception], resolveKey)
const proof = createInclusionProof(batch, reception)

// Local demonstration only. Production must obtain this root independently.
const trustedGlobalRoot = batch.root
validateInclusionAgainstAnchor(
  { document: reception, ...proof },
  trustedGlobalRoot,
  resolveKey
)
```

Persist participant identities separately from private keys. `createParticipant` generates a new key each time; it is not an identity lookup. Rebuild the resolver from your trusted identity registry when keys are rotated or revoked. Returned trust records are immutable snapshots.

`createDocument` also accepts an Ed25519 `KeyObject` directly for applications that manage keys outside `SystemKeyStore`.

## Asynchronous workers

```ts
import { TraceabilityWorkerPool } from 'grano-sign'

const pool = new TraceabilityWorkerPool({ concurrency: 2, maxQueuedJobs: 16 })
try {
  const hash = await pool.execute('hashJSON', { value: { event: 'HARVEST' } })
  console.log(hash)
} finally {
  await pool.close()
}
```

The pool supports hashing, signing, document and graph validation, batch construction, and anchored proof verification. It bounds queued work and estimated bytes, supports deadlines and `AbortSignal`, and exposes metrics through `pool.stats`. No database or network service is required.

See [WORKERS.md](WORKERS.md) for defaults, lifecycle, and the external executor interface. The [TypeScript examples](examples/README.md) cover basic signing, multi-actor workers, OS key storage, and an external anchoring adapter.

## Security model

- **Integrity:** canonical JSON is hashed with Keccak-256. Unsupported values, unsafe integers, invalid Unicode, accessors, proxies, cycles, and non-JSON object instances are rejected.
- **Cryptographic authorship:** Ed25519 authenticates possession of the registered private key. Identity enrollment and legal identity verification are application responsibilities.
- **Dependencies:** parent hashes form a directed acyclic graph. Graph validation requires every referenced document to be supplied and rejects duplicate hashes and document IDs.
- **Inclusion:** each actor has a document tree, and actor roots form a global tree. A proof commits to the signed document, including its signature.
- **Key storage:** private keys are stored in the OS credential store and are not returned as participant identity data. This is software-backed signing, not a guarantee of hardware-protected or non-exportable keys.

A valid signature does not establish the truth of a recorded event. `validateInclusion` only checks consistency with the supplied root. Use `validateInclusionAgainstAnchor` with an independently trusted root to establish anchored inclusion. Neither inclusion method validates all ancestors; use `validateDocumentGraph` for complete graph validation.

This package does not publish transactions or verify blockchain network, contract, finality, or events. Those checks belong to the anchoring integration. See [SECURITY.md](SECURITY.md) for operational requirements and review limitations.

## Protocol

```text
documentHash = Keccak256(UTF8(canonicalJSON({
  domain: "grano.traceability.document.v1", content
})))

signature = Ed25519.sign(privateKey, bytes32(documentHash))

leafCommitment = Keccak256(UTF8(canonicalJSON({
  domain: "grano.traceability.signed-document.v1", document
})))
```

The document contains `content`, `hash`, and a canonical Base64 `signature`. Content includes the protocol type and version, a 24-character CUID2 `documentId`, `actorId`, `keyId`, sorted unique `parents`, and `payload`.

Both trees use OpenZeppelin `StandardMerkleTree` with ABI types `['string', 'bytes32']`. Actor leaves contain `(actorId, leafCommitment)`; global leaves contain `(actorId, actorRoot)`. Standard leaves are double-hashed. Preserve domain strings, protocol version, encoding, and canonicalization rules across implementations.

## Resource limits

| Resource                                                        | Limit                             |
| --------------------------------------------------------------- | --------------------------------- |
| Canonical JSON per hash operation                               | 100 MiB (104,857,600 UTF-8 bytes) |
| JSON nesting depth                                              | 64                                |
| JSON nodes visited                                              | 100,000                           |
| Documents per graph or tree                                     | 20,000                            |
| Parent references per document                                  | 20,000                            |
| Total parent references per validated graph                     | 100,000                           |
| Total canonical signed commitment envelopes per validated graph | 100 MiB                           |
| Siblings per Merkle proof                                       | 64                                |

Canonical byte size includes JSON escaping and structural characters. Byte accounting takes place during normalization, before canonical serialization. Document creation also checks the signed commitment envelope, so metadata and signatures count toward the limit.

These limits bound accepted data, not peak RAM or execution time. The core API is synchronous and creates intermediate objects and strings. The worker API moves cryptographic execution off the caller thread. Apply request-size limits before parsing JSON, limit concurrency, and use workers or dedicated processes for large inputs. Public tree-building helpers are lower-level operations; use `buildAnchorBatch` to enforce graph-wide budgets and dependency validation.

## Development

```sh
pnpm run check           # Formatting, types, build, and standard coverage
pnpm test                # Standard tests
pnpm run test:all        # Includes the 100 MiB boundary tests
pnpm run test:watch      # Watch mode
pnpm run format         # Format maintained files
pnpm audit              # All dependency advisories
pnpm audit --prod        # Production dependency advisories
pnpm pack               # Build and package the library
```

The production build excludes tests and publishes `dist`, TypeScript examples, documentation, package metadata, and license. All tests live in `test/`. Coverage is available in `coverage/index.html`; the check enforces 100% of lines, functions, statements, and branches across `src/`. Worker integration tests also run against the compiled package. Coverage is not proof of security.

CI checks supported Node.js versions, formatting, types, build, coverage, dependency advisories, and the extended test suite. Credential-store tests use a mock: validate real persistence, locking, permissions, and availability on every deployment platform.

For higher-volume deployments, see [SCALABILITY.md](SCALABILITY.md).

## License

[Apache License 2.0](LICENSE).
