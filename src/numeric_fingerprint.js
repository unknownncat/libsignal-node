import native from './native.js';
import { asUint8Array } from './bytes.js';

export class FingerprintGenerator {
  constructor(iterations) {
    if (!Number.isInteger(iterations) || iterations < 1) {
      throw new TypeError('iterations must be a positive integer');
    }
    this.iterations = iterations;
  }

  createFor(localIdentifier, localIdentityKey, remoteIdentifier, remoteIdentityKey) {
    if (typeof localIdentifier !== 'string' || typeof remoteIdentifier !== 'string') {
      throw new Error('Invalid arguments');
    }

    return Promise.resolve(
      native.numericFingerprint(
        localIdentifier,
        asUint8Array(localIdentityKey, 'localIdentityKey'),
        remoteIdentifier,
        asUint8Array(remoteIdentityKey, 'remoteIdentityKey'),
        this.iterations
      )
    );
  }
}