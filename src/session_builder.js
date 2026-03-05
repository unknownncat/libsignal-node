import SessionRecord from './session_record.js';
import { UntrustedIdentityKeyError, PreKeyError } from './errors.js';
import native from './native.js';
import queueJob from './queue_job.js';

export default class SessionBuilder {
  constructor(storage, protocolAddress) {
    this.addr = protocolAddress;
    this.storage = storage;
  }

  async initOutgoing(device) {
    const fullyQualifiedAddress = this.addr.toString();
    return queueJob(fullyQualifiedAddress, async () => {
      try {
        await native.sessionBuilderInitOutgoing(
          this.storage,
          fullyQualifiedAddress,
          this.addr.id,
          device,
          SessionRecord
        );
      } catch (error) {
        if (error && error.message === 'UNTRUSTED_IDENTITY') {
          throw new UntrustedIdentityKeyError(this.addr.id, device.identityKey);
        }
        throw error;
      }
    });
  }

  async initIncoming(record, message) {
    try {
      return await native.sessionBuilderInitIncoming(this.storage, this.addr.id, record, message);
    } catch (error) {
      if (error && error.message === 'UNTRUSTED_IDENTITY') {
        throw new UntrustedIdentityKeyError(this.addr.id, message.identityKey);
      }
      if (error && error.message === 'INVALID_PREKEY_ID') {
        throw new PreKeyError('Invalid PreKey ID');
      }
      if (error && error.message === 'MISSING_SIGNED_PREKEY') {
        throw new PreKeyError('Missing SignedPreKey');
      }
      throw error;
    }
  }

  async initSession(
    isInitiator,
    ourEphemeralKey,
    ourSignedKey,
    theirIdentityPubKey,
    theirEphemeralPubKey,
    theirSignedPubKey,
    registrationId
  ) {
    const ourIdentityKey = await native.adapterGetOurIdentity(this.storage);
    return native.sessionBuilderInitSession(
      isInitiator,
      ourEphemeralKey,
      ourSignedKey,
      theirIdentityPubKey,
      theirEphemeralPubKey,
      theirSignedPubKey,
      registrationId,
      ourIdentityKey
    );
  }

  calculateSendingRatchet(session, remoteKey) {
    native.sessionBuilderCalculateSendingRatchet(session, remoteKey);
  }
}
