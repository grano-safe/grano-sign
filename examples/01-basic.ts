import { generateKeyPairSync } from 'node:crypto'
import {
  TraceabilityError,
  createDocument,
  createKeyResolver,
  validateDocument,
} from '../dist/main.js'

// Ephemeral keys keep this example self-contained. Persist keys securely in production.
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const identity = {
  actorId: 'farm-1',
  keyId: 'harvest-key-1',
  publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
}
const resolveKey = createKeyResolver([identity])
const document = createDocument(
  {
    actorId: identity.actorId,
    keyId: identity.keyId,
    payload: { event: 'HARVEST', product: 'rice', quantityKg: 2500 },
  },
  privateKey
)

const verified = validateDocument(document, resolveKey)
console.log('Verified harvest:', verified.hash)

// Changing signed data must fail, even when the signature itself is unchanged.
try {
  validateDocument(
    { ...document, content: { ...document.content, payload: { quantityKg: 9999 } } },
    resolveKey
  )
  throw new Error('Tampered data was accepted')
} catch (error) {
  if (!(error instanceof TraceabilityError) || error.code !== 'HASH_MISMATCH') throw error
  console.log('Tampering correctly rejected:', error.code)
}
