# Scaling deployments

The library deliberately owns signing, validation, and proofs. Storage, scheduling, identity enrollment, and external anchoring belong to the consuming application.

## Recommended architecture

1. Authenticate and size-limit requests before parsing. Validate business permissions separately from signatures.
2. Send cryptographic jobs to a bounded worker pool. Limit queued bytes as well as job count, and terminate dedicated workers when deadlines expire.
3. Store signed documents by hash, with indexes on actor, key, document ID, and parent hash. Preserve canonical protocol data without rewriting signed fields.
4. Build bounded batches and persist their roots and proofs. Cache by document commitment and batch root; avoid reconstructing trees on each read.
5. Publish roots through an idempotent anchoring queue with retry, finality tracking, and explicit network/contract configuration.
6. Keep a versioned public-key registry. Include the registry revision and revocation policy in any validation-cache key.

The current graph validator requires all ancestors in the supplied graph. Splitting a dependency graph across batches therefore requires a separately designed protocol for trusted external references; do not simply omit missing parents.

## Capacity planning

Measure throughput, peak RSS, event-loop delay, queue depth, and p95/p99 latency across representative payload sizes and graph shapes. Dense dependency graphs and near-limit payloads need separate benchmarks. The 100 MiB acceptance limit is not a recommended batch size for interactive services.

Increase capacity through bounded parallel workers and smaller batches before raising protocol limits. OS key-store access may serialize or require an interactive session; a centralized signing service may be more appropriate for unattended workloads.

## Future protocol changes

Streaming payload commitments, content-addressed external blobs, incremental trees, and cross-batch references can reduce memory and recomputation. Each changes validation or proof semantics and should receive a new protocol version, independent test vectors, migration rules, and security review.
