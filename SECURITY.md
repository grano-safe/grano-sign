# Security considerations

## Trust boundaries

Treat incoming documents, proofs, and participant registrations as untrusted data. Enroll public keys through an authenticated process and persist the actor/key association. A valid signature proves control of a key, not factual accuracy or legal identity.

`createKeyResolver` captures an immutable snapshot. Updating the original registration does not update the resolver; construct a new resolver after changing the registry. Revocation rejects validation with that key, including historical documents. Define any historical-validation policy outside this library.

Provide plain JSON-compatible inputs. Accessors, proxies, and custom collection methods are not supported. Use the normalized document returned by validation when passing authenticated data to downstream code. Custom key resolvers are trusted application code and must not modify verification inputs.

Keep the trusted anchor root independent of the proof provider. Persist its provenance, including the network, contract, transaction, and confirmation policy when using a blockchain. Inclusion verification does not establish ancestor validity or business authorization.

## Operational controls

- Reject oversized requests before JSON parsing and apply concurrency limits.
- Perform expensive synchronous cryptographic work in bounded worker pools.
- Restrict OS credential-store access and avoid logging private material.
- Back up public identities and define a recovery policy for private keys.
- Test the actual credential-store service on each supported deployment platform.
- Keep the lockfile and run dependency audits before release.

Deleting a credential does not erase existing copies or backups. JavaScript strings containing PEM material cannot be reliably zeroized; use a dedicated signing service or hardware-backed provider if that property is required.

## Repository review

The October 31, 2026 review identified mutable resolver records, repeated reads of caller-controlled anchor fields, overridable array methods, and late size checks. These boundaries are hardened and covered by regression tests. Graph validation also enforces aggregate byte and edge budgets.

The dependency review identified advisories in `uuid`, `glob`, and `minimatch`. The build now uses Node's filesystem API instead of `rimraf`, and a scoped override selects a patched `uuid` version compatible with the transitive consumer. Review this override when updating OpenZeppelin or MetaMask dependencies.

This review is not an independent cryptographic certification. Real credential-store integration, external anchoring, and production workload capacity must be validated in the deployment environment.

## Reporting a vulnerability

Contact the repository maintainer through a private channel. Include the affected version, reproduction steps, expected behavior, and impact. Do not include live private keys or credentials. A dedicated security contact has not yet been configured.
