import type { KeyPairType } from './curve.js';

export function generateIdentityKeyPair(): KeyPairType;

export function generateRegistrationId(): number;

export function generateSignedPreKey(
  identityKeyPair: KeyPairType,
  signedKeyId: number
): {
  keyId: number;
  keyPair: KeyPairType;
  signature: Uint8Array;
};

export function generatePreKey(keyId: number): {
  keyId: number;
  keyPair: KeyPairType;
};