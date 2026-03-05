import ProtocolAddress from './protocol_address.js';
import SessionBuilder from './session_builder.js';
import SessionRecord from './session_record.js';
import { MessageCounterError, SessionError, UntrustedIdentityKeyError } from './errors.js';
import native from './native.js';
import queueJob from './queue_job.js';
import { assertUint8Array } from './bytes.js';

const VERSION = 3;

export default class SessionCipher {
  constructor(storage, protocolAddress) {
    if (!(protocolAddress instanceof ProtocolAddress)) {
      throw new TypeError('protocolAddress must be a ProtocolAddress');
    }

    this.addr = protocolAddress;
    this.storage = storage;
  }

  toString() {
    return `<SessionCipher(${this.addr.toString()})>`;
  }

  async getRecord() {
    const record = await native.adapterLoadSession(this.storage, this.addr.toString());
    if (record && !(record instanceof SessionRecord)) {
      throw new TypeError('SessionRecord type expected from loadSession');
    }
    return record;
  }

  async storeRecord(record) {
    record.removeOldSessions();
    await native.adapterStoreSession(this.storage, this.addr.toString(), record);
  }

  async queueJob(awaitable) {
    return queueJob(this.addr.toString(), awaitable);
  }

  async encrypt(data) {
    assertUint8Array(data, 'data');
    const ourIdentityKey = await native.adapterGetOurIdentity(this.storage);

    return this.queueJob(async () => {
      const record = await this.getRecord();
      if (!record) {
        throw new SessionError('No sessions');
      }

      const session = record.getOpenSession();
      if (!session) {
        throw new SessionError('No open session');
      }

      const remoteIdentityKey = session.indexInfo.remoteIdentityKey;
      if (!(await native.adapterIsTrustedIdentity(this.storage, this.addr.id, remoteIdentityKey))) {
        throw new UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
      }

      const result = native.sessionCipherEncryptWhisperMessage(
        session,
        data,
        ourIdentityKey.pubKey,
        VERSION
      );

      await this.storeRecord(record);

      if (session.pendingPreKey) {
        const preKeyMessage = {
          identityKey: ourIdentityKey.pubKey,
          registrationId: await native.adapterGetOurRegistrationId(this.storage),
          baseKey: session.pendingPreKey.baseKey,
          signedPreKeyId: session.pendingPreKey.signedKeyId,
          message: result,
        };

        if (session.pendingPreKey.preKeyId) {
          preKeyMessage.preKeyId = session.pendingPreKey.preKeyId;
        }

        return {
          type: 3,
          body: native.sessionCipherEncodePreKeyWhisperMessage(preKeyMessage, VERSION),
          registrationId: session.registrationId,
        };
      }

      return {
        type: 1,
        body: result,
        registrationId: session.registrationId,
      };
    });
  }

  async decryptWithSessions(data, sessions) {
    try {
      return await native.sessionCipherDecryptWithSessions(this.storage, data, sessions, VERSION);
    } catch (error) {
      if (
        error &&
        (error.message === 'No sessions available' ||
          error.message === 'No matching sessions found for message')
      ) {
        throw new SessionError(error.message);
      }
      throw error;
    }
  }

  async decryptWhisperMessage(data) {
    assertUint8Array(data, 'ciphertext');

    return this.queueJob(async () => {
      const record = await this.getRecord();
      if (!record) {
        throw new SessionError('No session record');
      }

      const result = await this.decryptWithSessions(data, record.getSessions());
      const remoteIdentityKey = result.session.indexInfo.remoteIdentityKey;
      if (!(await native.adapterIsTrustedIdentity(this.storage, this.addr.id, remoteIdentityKey))) {
        throw new UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
      }

      if (record.isClosed(result.session)) {
        console.warn('Decrypted message with closed session.');
      }

      await this.storeRecord(record);
      return result.plaintext;
    });
  }

  async decryptPreKeyWhisperMessage(data) {
    assertUint8Array(data, 'ciphertext');

    return this.queueJob(async () => {
      let record = await this.getRecord();
      const preKeyProto = native.sessionCipherDecodePreKeyWhisperMessage(data, VERSION);

      if (!record) {
        if (preKeyProto.registrationId == null) {
          throw new Error('No registrationId');
        }
        record = new SessionRecord();
      }

      const builder = new SessionBuilder(this.storage, this.addr);
      const preKeyId = await builder.initIncoming(record, preKeyProto);
      const session = record.getSession(preKeyProto.baseKey);
      const plaintext = await this.doDecryptWhisperMessage(preKeyProto.message, session);

      await this.storeRecord(record);
      if (preKeyId) {
        await native.adapterRemovePreKey(this.storage, preKeyId);
      }

      return plaintext;
    });
  }

  async doDecryptWhisperMessage(messageBuffer, session) {
    assertUint8Array(messageBuffer, 'messageBuffer');

    if (!session) {
      throw new TypeError('session required');
    }

    const ourIdentityKey = await native.adapterGetOurIdentity(this.storage);
    try {
      return native.sessionCipherDecryptWhisperMessage(
        session,
        messageBuffer,
        ourIdentityKey.pubKey,
        VERSION
      );
    } catch (error) {
      if (error && error.message === 'Key used already or never filled') {
        throw new MessageCounterError('Key used already or never filled');
      }
      throw error;
    }
  }

  fillMessageKeys(chain, counter) {
    try {
      native.fillMessageKeys(chain, counter);
    } catch (error) {
      if (
        error &&
        (error.message === 'Over 2000 messages into the future!' || error.message === 'Chain closed')
      ) {
        throw new SessionError(error.message);
      }
      throw error;
    }
  }

  maybeStepRatchet(session, remoteKey, previousCounter) {
    native.sessionCipherMaybeStepRatchet(session, remoteKey, previousCounter);
  }

  calculateRatchet(session, remoteKey, sending) {
    native.sessionCipherCalculateRatchet(session, remoteKey, sending);
  }

  async hasOpenSession() {
    return this.queueJob(async () => {
      const record = await this.getRecord();
      if (!record) {
        return false;
      }
      return record.haveOpenSession();
    });
  }

  async closeOpenSession() {
    return this.queueJob(async () => {
      const record = await this.getRecord();
      if (!record) {
        return;
      }

      const openSession = record.getOpenSession();
      if (openSession) {
        record.closeSession(openSession);
        await this.storeRecord(record);
      }
    });
  }
}
