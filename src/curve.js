import native from './native.js';
import { asUint8Array } from './bytes.js';

export function getPublicFromPrivateKey(privKey) {
  return native.curveGetPublicFromPrivateKey(asUint8Array(privKey, 'private key'));
}

export function generateKeyPair() {
  return native.curveGenerateKeyPair();
}

export function calculateAgreement(pubKey, privKey) {
  return native.curveCalculateAgreement(
    asUint8Array(pubKey, 'public key'),
    asUint8Array(privKey, 'private key')
  );
}

export function calculateSignature(privKey, message) {
  return native.curveCalculateSignature(
    asUint8Array(privKey, 'private key'),
    asUint8Array(message, 'message')
  );
}

export function verifySignature(pubKey, msg, sig) {
  return native.curveVerifySignature(
    asUint8Array(pubKey, 'public key'),
    asUint8Array(msg, 'message'),
    asUint8Array(sig, 'signature')
  );
}

export default {
  getPublicFromPrivateKey,
  generateKeyPair,
  calculateAgreement,
  calculateSignature,
  verifySignature,
};
