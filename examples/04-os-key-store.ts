import { SystemKeyStore, createKeyResolver, validateDocument } from '../dist/main.js'

// This example writes a temporary key to the actual OS credential store.
const store = new SystemKeyStore('grano.traceability.example')
const identity = store.createParticipant('demo-farm')
try {
  const document = store.createSignedDocument({
    actorId: identity.actorId,
    keyId: identity.keyId,
    payload: { event: 'DEMO' },
  })
  validateDocument(document, createKeyResolver([identity]))
  console.log('Signed using the OS credential store:', document.hash)
} finally {
  // Demo cleanup only. Keep production keys according to your retention policy.
  store.deletePrivateKey(identity.actorId, identity.keyId)
}
