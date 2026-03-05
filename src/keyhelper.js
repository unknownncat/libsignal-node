import native from './native.js';
export const generateIdentityKeyPair = native.keyhelperGenerateIdentityKeyPair;

export function generateRegistrationId() {
  return native.generateRegistrationId14();
}

export function generateSignedPreKey(identityKeyPair, signedKeyId) {
  return native.keyhelperGenerateSignedPreKey(identityKeyPair, signedKeyId);
}

export function generatePreKey(keyId) {
  return native.keyhelperGeneratePreKey(keyId);
}

export default {
  generateIdentityKeyPair,
  generateRegistrationId,
  generateSignedPreKey,
  generatePreKey,
};
