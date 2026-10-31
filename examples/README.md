# Examples

From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm run build:examples
node .examples/01-basic.js
node .examples/02-workers.js
node .examples/03-anchoring-adapter.js
```

| Example                   | Demonstrates                                                                                         |
| ------------------------- | ---------------------------------------------------------------------------------------------------- |
| `01-basic.ts`             | Sign a document, verify it, and reject tampering.                                                    |
| `02-workers.ts`           | Sign linked events from two actors and build a batch with inclusion proofs in a bounded worker pool. |
| `03-anchoring-adapter.ts` | Separate execution from external anchor publication and independent root retrieval.                  |
| `04-os-key-store.ts`      | Sign through the real OS credential store and clean up the demo key.                                 |

The first three examples use ephemeral keys and run automatically with `pnpm run test:examples`. They do not access a database, network, or blockchain.

Run `node .examples/04-os-key-store.js` manually in an environment with an unlocked credential store. It creates and deletes a temporary credential. Linux requires Secret Service.

The anchoring adapter is an in-memory demonstration, not Ethereum integration. A production adapter must validate the chain ID, contract address, transaction/event data, and finality before returning a trusted root. Persist documents, public identities, proofs, and anchor provenance in your application's storage.

For public package consumers, replace `../dist/main.js` imports with `grano-sign`.
