export function decrypt(key: Uint8Array, ciphertext: Uint8Array, iv: Uint8Array): Uint8Array;

export function encrypt(key: Uint8Array, plaintext: Uint8Array, iv: Uint8Array): Uint8Array;

export function calculateMAC(key: Uint8Array, data: Uint8Array): Uint8Array;

export function hash(data: Uint8Array): Uint8Array;

export function deriveSecrets(
  key: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  chunks?: 1 | 2 | 3
): Uint8Array[];

export function verifyMAC(
  data: Uint8Array,
  key: Uint8Array,
  mac: Uint8Array,
  length: number
): void;