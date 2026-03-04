import { axlsign } from '@unknownncat/curve25519-node';
import nodeCrypto from 'node:crypto';

import { asUint8Array, assertUint8Array } from './bytes.js';

const KEY_BUNDLE_TYPE = new Uint8Array([5]);

function prefixKeyInPublicKey(pubKey) {
  const out = new Uint8Array(KEY_BUNDLE_TYPE.length + pubKey.length);
  out.set(KEY_BUNDLE_TYPE, 0);
  out.set(pubKey, KEY_BUNDLE_TYPE.length);
  return out;
}

function validatePrivKey(privKey) {
  if (privKey === undefined) {
    throw new Error('Undefined private key');
  }
  const typed = assertUint8Array(privKey, 'private key');
  if (typed.byteLength !== 32) {
    throw new Error(`Incorrect private key length: ${typed.byteLength}`);
  }
}

function scrubPubKeyFormat(pubKey) {
  if (pubKey === undefined) {
    throw new Error('Undefined public key');
  }
  const typed = assertUint8Array(pubKey, 'public key');
  if ((typed.byteLength !== 33 || typed[0] !== 5) && typed.byteLength !== 32) {
    throw new Error('Invalid public key');
  }
  if (typed.byteLength === 33) {
    return typed.slice(1);
  }
  console.error(
    'WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey'
  );
  return typed;
}

function unclampEd25519PrivateKey(clampedSk) {
  const unclampedSk = new Uint8Array(clampedSk);
  unclampedSk[0] |= 6;
  unclampedSk[31] |= 128;
  unclampedSk[31] &= ~64;
  return unclampedSk;
}

export function getPublicFromPrivateKey(privKey) {
  const normalized = asUint8Array(privKey, 'private key');
  const unclampedPK = unclampEd25519PrivateKey(normalized);
  const keyPair = axlsign.generateKeyPair(unclampedPK);
  return prefixKeyInPublicKey(asUint8Array(keyPair.public, 'generated public key'));
}

export function generateKeyPair() {
  const keyPair = axlsign.generateKeyPair(nodeCrypto.randomBytes(32));
  return {
    privKey: asUint8Array(keyPair.private, 'private key'),
    pubKey: prefixKeyInPublicKey(asUint8Array(keyPair.public, 'public key')),
  };
}

export function calculateAgreement(pubKey, privKey) {
  const normalizedPubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);
  if (!normalizedPubKey || normalizedPubKey.byteLength !== 32) {
    throw new Error('Invalid public key');
  }

  const secret = axlsign.sharedKey(privKey, normalizedPubKey);
  return asUint8Array(secret, 'agreement secret');
}

export function calculateSignature(privKey, message) {
  validatePrivKey(privKey);
  const normalizedMessage = asUint8Array(message, 'message');
  return asUint8Array(axlsign.sign(privKey, normalizedMessage), 'signature');
}

export function verifySignature(pubKey, msg, sig) {
  const normalizedPubKey = scrubPubKeyFormat(pubKey);
  const normalizedMsg = asUint8Array(msg, 'message');
  const normalizedSig = asUint8Array(sig, 'signature');
  if (!normalizedPubKey || normalizedPubKey.byteLength !== 32) {
    throw new Error('Invalid public key');
  }
  if (normalizedSig.byteLength !== 64) {
    throw new Error('Invalid signature');
  }
  return axlsign.verify(normalizedPubKey, normalizedMsg, normalizedSig);
}

export default {
  getPublicFromPrivateKey,
  generateKeyPair,
  calculateAgreement,
  calculateSignature,
  verifySignature,
};