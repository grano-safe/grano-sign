# Worker execution

`TraceabilityWorkerPool` uses Node.js `worker_threads` and implements `TraceabilityExecutor`. The synchronous API remains available. The pool is lazy: it starts workers when needed and reuses idle workers.

## Operations

| Operation                        | Input                                             | Result                                                        |
| -------------------------------- | ------------------------------------------------- | ------------------------------------------------------------- |
| `hashJSON`                       | `value`                                           | Keccak-256 hash                                               |
| `createDocument`                 | `document`, Ed25519 `privateKey`                  | Signed document                                               |
| `validateDocument`               | `document`, `identities`                          | Normalized signed document                                    |
| `validateDocumentGraph`          | `documents`, `identities`                         | Validated documents                                           |
| `buildAnchorBatch`               | `documents`, `identities`, optional `proofHashes` | Portable root, actor roots, document hashes, requested proofs |
| `validateInclusionAgainstAnchor` | `inclusion`, `identities`, `trustedGlobalRoot`    | Resolves on success; rejects on failure                       |

Identity registrations contain public PEM keys and revocation status. Resolver functions cannot cross the worker boundary. Supply trusted identity snapshots for each operation. Private signing keys are cloned as Node.js `KeyObject` instances, never included in results or error messages.

Batch results contain only requested proofs; omitted `proofHashes` means no proofs. Workers retain neither batches nor identity registries between jobs. Persist the documents, roots, proofs, and trust metadata in the consuming application. Repeated actor proofs are calculated once per batch.

## Defaults

| Option            | Default                                               |
| ----------------- | ----------------------------------------------------- |
| `concurrency`     | Available parallelism minus one, clamped to 1–4       |
| `maxQueuedJobs`   | 32 waiting jobs                                       |
| `maxTaskBytes`    | 16 MiB estimated transport size                       |
| `maxPendingBytes` | 64 MiB across queued and executing jobs               |
| `timeoutMs`       | 30,000 ms, including input preparation and queue wait |
| `maxWorkerHeapMb` | 256 MiB V8 old-generation heap per worker             |

Transport estimates count UTF-16 string storage and structural overhead. They are admission budgets, not exact RSS limits. Node's worker heap limits do not bound all native or buffer allocations. Increase budgets only after measuring representative workloads.

Inputs are copied and checked on the caller thread before enqueueing to reject accessors, proxies, cycles, and unsupported instances. Structured cloning also incurs caller-thread work; the pool does not make submission of huge inputs free. No custom worker code or arbitrary operation names are accepted.

## Cancellation and lifecycle

Pass `{ signal, timeoutMs }` as the third argument to `execute`. Cancelling queued work removes it immediately. Cancelling executing work terminates that worker; replacement waits for termination to preserve the concurrency bound. Work is not retried automatically.

Always call `await pool.close()` in service shutdown or a `finally` block. It rejects queued and executing work and waits for thread termination. Repeated calls are safe. `Symbol.asyncDispose` is also supported. Idle workers do not keep the process alive.

Common rejection codes include `QUEUE_FULL`, `TASK_TOO_LARGE`, `TASK_TIMEOUT`, `TASK_ABORTED`, `POOL_CLOSED`, `WORKER_FAILURE`, and the underlying cryptographic validation codes. Monitor `pool.stats` for active work, queue length, pending estimated bytes, completion count, and failures.

## Extension points

Accept a `TraceabilityExecutor` in application services rather than constructing a pool inside each request. Another implementation can forward the typed operations to a dedicated service. Authentication, transport encryption, identity-registry revisions, retry policy, and idempotency then belong to that adapter.

An Ethereum adapter should independently publish and retrieve trusted roots, checking chain ID, contract address, relevant events, and finality. It must not treat the root supplied alongside a proof as independently trusted. The library does not manage accounts, submit transactions, or store data.

Implementation references: [Node.js worker threads](https://nodejs.org/api/worker_threads.html) and [available parallelism](https://nodejs.org/api/os.html#osavailableparallelism).
