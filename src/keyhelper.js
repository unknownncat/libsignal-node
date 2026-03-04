import * as curve from './curve.js';
import native from './native.js';
import { assertUint8Array } from './bytes.js';

function isNonNegativeInteger(number) {
  return typeof number === 'number' && number % 1 === 0 && number >= 0;
}

export const generateIdentityKeyPair = curve.generateKeyPair;

export function generateRegistrationId() {
  return native.generateRegistrationId14();
}

export function generateSignedPreKey(identityKeyPair, signedKeyId) {
  if (
    !identityKeyPair ||
    !(identityKeyPair.privKey instanceof Uint8Array) ||
    identityKeyPair.privKey.byteLength !== 32 ||
    !(identityKeyPair.pubKey instanceof Uint8Array) ||
    identityKeyPair.pubKey.byteLength !== 33
  ) {
    throw new TypeError('Invalid argument for identityKeyPair');
  }
  if (!isNonNegativeInteger(signedKeyId)) {
    throw new TypeError(`Invalid argument for signedKeyId: ${signedKeyId}`);
  }

  const keyPair = curve.generateKeyPair();
  const signature = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey);
  assertUint8Array(signature, 'signature');

  return {
    keyId: signedKeyId,
    keyPair,
    signature,
  };
}

export function generatePreKey(keyId) {
  if (!isNonNegativeInteger(keyId)) {
    throw new TypeError(`Invalid argument for keyId: ${keyId}`);
  }
  return {
    keyId,
    keyPair: curve.generateKeyPair(),
  };
}

export default {
  generateIdentityKeyPair,
  generateRegistrationId,
  generateSignedPreKey,
  generatePreKey,
};
