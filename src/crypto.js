import assert from 'node:assert';
import native from './native.js';
import { assertUint8Array } from './bytes.js';

function assertBytes(value, name) {
  return assertUint8Array(value, name);
}

export function encrypt(key, data, iv) {
  assertBytes(key, 'key');
  assertBytes(data, 'data');
  assertBytes(iv, 'iv');
  return native.encryptAes256Cbc(key, data, iv);
}

export function decrypt(key, data, iv) {
  assertBytes(key, 'key');
  assertBytes(data, 'data');
  assertBytes(iv, 'iv');
  return native.decryptAes256Cbc(key, data, iv);
}

export function calculateMAC(key, data) {
  assertBytes(key, 'key');
  assertBytes(data, 'data');
  return native.calculateMacSha256(key, data);
}

export function hash(data) {
  assertBytes(data, 'data');
  return native.hashSha512(data);
}

export function deriveSecrets(input, salt, info, chunks) {
  assertBytes(input, 'input');
  assertBytes(salt, 'salt');
  assertBytes(info, 'info');
  if (salt.byteLength !== 32) {
    throw new Error('Got salt of incorrect length');
  }
  const resolvedChunks = chunks || 3;
  assert(resolvedChunks >= 1 && resolvedChunks <= 3);
  return native.deriveSecrets(input, salt, info, resolvedChunks);
}

export function verifyMAC(data, key, mac, length) {
  assertBytes(data, 'data');
  assertBytes(key, 'key');
  assertBytes(mac, 'mac');
  const calculatedMac = calculateMAC(key, data).slice(0, length);
  if (mac.length !== length || calculatedMac.length !== length) {
    throw new Error('Bad MAC length');
  }
  if (!native.timingSafeEqual(mac, calculatedMac)) {
    throw new Error('Bad MAC');
  }
}