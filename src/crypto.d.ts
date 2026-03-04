export function decrypt(key: Buffer, ciphertext: Buffer, iv: Buffer): Buffer;

export function encrypt(key: Buffer, plaintext: Buffer, iv: Buffer): Buffer;

export function calculateMAC(key: Buffer, data: Buffer): Buffer;

export function hash(data: Buffer): Buffer;

export function deriveSecrets(
  key: Buffer,
  salt: Buffer,
  info: Buffer,
  chunks?: 1 | 2 | 3
): Buffer[];

export function verifyMAC(
  data: Buffer,
  key: Buffer,
  mac: Buffer,
  length: number
): void;

