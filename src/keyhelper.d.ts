import type { KeyPairType } from './curve';

export function generateIdentityKeyPair(): KeyPairType;

export function generateRegistrationId(): number;

export function generateSignedPreKey(
  identityKeyPair: KeyPairType,
  signedKeyId: number
): {
  keyId: number;
  keyPair: KeyPairType;
  signature: Buffer;
};

export function generatePreKey(keyId: number): {
  keyId: number;
  keyPair: KeyPairType;
};

