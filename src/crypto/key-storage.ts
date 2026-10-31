import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto'
import { createId } from '@paralleldrive/cuid2'
import { Entry } from '@napi-rs/keyring'
import type { Hex } from 'viem'
import {
  TraceabilityError,
  createDocument,
  type KeyResolver,
  type SignedDocument,
  type TrustedKey,
} from './traceability.js'

export type ParticipantIdentity = {
  actorId: string
  keyId: string
  publicKeyPem: string
  revoked?: boolean
}

export type NewDocument = {
  actorId: string
  keyId: string
  payload: unknown
  parents?: readonly Hex[]
}

function ensureIdentifier(value: string, field: string): void {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 128 ||
    value.trim() !== value ||
    Buffer.from(value, 'utf8').toString('utf8') !== value
  ) {
    throw new TraceabilityError('INVALID_IDENTIFIER', `Invalid ${field}`)
  }
}

function withKeychainError<T>(
  action: string,
  actorId: string,
  keyId: string | null,
  operation: () => T
): T {
  try {
    return operation()
  } catch (cause) {
    if (cause instanceof TraceabilityError) throw cause

    throw new TraceabilityError(
      'KEYCHAIN_UNAVAILABLE',
      'Operating system credential store is unavailable',
      { action, actorId, keyId },
      cause
    )
  }
}

export class SystemKeyStore {
  constructor(private readonly service = 'grano.traceability.v1') {
    ensureIdentifier(service, 'service')
  }

  private entry(actorId: string, keyId: string): Entry {
    ensureIdentifier(actorId, 'actorId')
    ensureIdentifier(keyId, 'keyId')

    return new Entry(this.service, JSON.stringify([actorId, keyId]), {
      linux: { store: 'secret-service' },
    })
  }

  createParticipant(actorId: string): ParticipantIdentity {
    ensureIdentifier(actorId, 'actorId')
    const keyId = createId()

    return withKeychainError('CREATE_KEY', actorId, keyId, () => {
      const entry = this.entry(actorId, keyId)

      if (entry.getPassword() !== null) {
        throw new TraceabilityError(
          'KEY_ALREADY_EXISTS',
          'Refusing to overwrite an existing private key',
          { actorId, keyId }
        )
      }

      const { privateKey, publicKey } = generateKeyPairSync('ed25519')
      const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
      const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()

      entry.setPassword(privateKeyPem)

      if (entry.getPassword() !== privateKeyPem) {
        throw new TraceabilityError(
          'KEY_STORAGE_FAILED',
          'Stored private key could not be verified',
          { actorId, keyId }
        )
      }

      return { actorId, keyId, publicKeyPem }
    })
  }

  private loadPrivateKey(actorId: string, keyId: string): KeyObject {
    return withKeychainError('LOAD_KEY', actorId, keyId, () => {
      const privateKeyPem = this.entry(actorId, keyId).getPassword()

      if (privateKeyPem === null) {
        throw new TraceabilityError(
          'PRIVATE_KEY_NOT_FOUND',
          'Private key was not found in the OS credential store',
          { actorId, keyId }
        )
      }

      const privateKey = createPrivateKey(privateKeyPem)

      if (privateKey.asymmetricKeyType !== 'ed25519') {
        throw new TraceabilityError(
          'INVALID_PRIVATE_KEY',
          'Stored private key is not Ed25519',
          { actorId, keyId }
        )
      }

      return privateKey
    })
  }

  createSignedDocument(input: NewDocument): SignedDocument {
    const privateKey = this.loadPrivateKey(input.actorId, input.keyId)
    return createDocument(input, privateKey)
  }

  deletePrivateKey(actorId: string, keyId: string): boolean {
    return withKeychainError('DELETE_KEY', actorId, keyId, () =>
      this.entry(actorId, keyId).deletePassword()
    )
  }
}

export function createKeyResolver(
  participants: readonly ParticipantIdentity[]
): KeyResolver {
  const keys = new Map<string, Map<string, TrustedKey>>()

  for (const participant of participants) {
    ensureIdentifier(participant.actorId, 'actorId')
    ensureIdentifier(participant.keyId, 'keyId')

    const actorKeys = keys.get(participant.actorId) ?? new Map<string, TrustedKey>()

    if (actorKeys.has(participant.keyId)) {
      throw new TraceabilityError('DUPLICATE_KEY', 'Duplicate participant key', {
        actorId: participant.actorId,
        keyId: participant.keyId,
      })
    }

    let publicKey: KeyObject

    try {
      publicKey = createPublicKey(participant.publicKeyPem)
    } catch (cause) {
      throw new TraceabilityError(
        'INVALID_PUBLIC_KEY',
        'Participant public key is invalid',
        { actorId: participant.actorId, keyId: participant.keyId },
        cause
      )
    }

    if (publicKey.asymmetricKeyType !== 'ed25519') {
      throw new TraceabilityError('INVALID_PUBLIC_KEY', 'Expected Ed25519 public key', {
        actorId: participant.actorId,
        keyId: participant.keyId,
      })
    }

    // Keep trust decisions immutable after registration.
    actorKeys.set(
      participant.keyId,
      Object.freeze({
        actorId: participant.actorId,
        keyId: participant.keyId,
        publicKey,
        revoked: participant.revoked ?? false,
      })
    )
    keys.set(participant.actorId, actorKeys)
  }

  return (actorId, keyId) => {
    const key = keys.get(actorId)?.get(keyId)

    if (!key) {
      throw new TraceabilityError(
        'KEY_NOT_FOUND',
        'No trusted public key found for participant',
        { actorId, keyId }
      )
    }

    return key
  }
}
