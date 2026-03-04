export interface KeyPairType {
  pubKey: Buffer;
  privKey: Buffer;
}

export function getPublicFromPrivateKey(privateKey: Buffer): Buffer;

export function generateKeyPair(): KeyPairType;

export function calculateAgreement(publicKey: Buffer, privateKey: Buffer): Buffer;

export function calculateSignature(privateKey: Buffer, message: Buffer): Buffer;

export function verifySignature(
  publicKey: Buffer,
  message: Buffer,
  signature: Buffer
): boolean;

