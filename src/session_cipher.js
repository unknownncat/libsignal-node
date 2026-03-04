import ChainType from './chain_type.js';
import ProtocolAddress from './protocol_address.js';
import SessionBuilder from './session_builder.js';
import SessionRecord from './session_record.js';
import * as crypto from './crypto.js';
import * as curve from './curve.js';
import { MessageCounterError, SessionError, UntrustedIdentityKeyError } from './errors.js';
import native from './native.js';
import * as protobufs from './protobufs.js';
import queueJob from './queue_job.js';
import { assertUint8Array } from './bytes.js';

const VERSION = 3;
const ZERO_SALT = new Uint8Array(32);
const WHISPER_MESSAGE_KEYS_INFO = new TextEncoder().encode('WhisperMessageKeys');
const WHISPER_RATCHET_INFO = new TextEncoder().encode('WhisperRatchet');

function concatBytes(...parts) {
  const totalLength = parts.reduce((total, part) => total + part.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export default class SessionCipher {
  constructor(storage, protocolAddress) {
    if (!(protocolAddress instanceof ProtocolAddress)) {
      throw new TypeError('protocolAddress must be a ProtocolAddress');
    }

    this.addr = protocolAddress;
    this.storage = storage;
  }

  _encodeTupleByte(number1, number2) {
    return native.encodeTupleByte(number1, number2);
  }

  _decodeTupleByte(byte) {
    return native.decodeTupleByte(byte);
  }

  toString() {
    return `<SessionCipher(${this.addr.toString()})>`;
  }

  async getRecord() {
    const record = await this.storage.loadSession(this.addr.toString());
    if (record && !(record instanceof SessionRecord)) {
      throw new TypeError('SessionRecord type expected from loadSession');
    }
    return record;
  }

  async storeRecord(record) {
    record.removeOldSessions();
    await this.storage.storeSession(this.addr.toString(), record);
  }

  async queueJob(awaitable) {
    return queueJob(this.addr.toString(), awaitable);
  }

  async encrypt(data) {
    assertUint8Array(data, 'data');
    const ourIdentityKey = await this.storage.getOurIdentity();

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
      if (!(await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey))) {
        throw new UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
      }

      const chain = session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey);
      if (chain.chainType === ChainType.RECEIVING) {
        throw new Error('Tried to encrypt on a receiving chain');
      }

      this.fillMessageKeys(chain, chain.chainKey.counter + 1);

      const keys = crypto.deriveSecrets(
        chain.messageKeys[chain.chainKey.counter],
        ZERO_SALT,
        WHISPER_MESSAGE_KEYS_INFO
      );
      delete chain.messageKeys[chain.chainKey.counter];

      const message = protobufs.WhisperMessage.create({
        ephemeralKey: session.currentRatchet.ephemeralKeyPair.pubKey,
        counter: chain.chainKey.counter,
        previousCounter: session.currentRatchet.previousCounter,
        ciphertext: crypto.encrypt(keys[0], data, keys[2].slice(0, 16)),
      });

      const messageProto = protobufs.WhisperMessage.encode(message).finish();
      const versionTuple = this._encodeTupleByte(VERSION, VERSION);
      const macInput = await native.buildWhisperMacInputAsync(
        ourIdentityKey.pubKey,
        session.indexInfo.remoteIdentityKey,
        versionTuple,
        messageProto
      );
      const mac = crypto.calculateMAC(keys[1], macInput);
      const result = await native.assembleWhisperFrameAsync(versionTuple, messageProto, mac, 8);

      await this.storeRecord(record);

      if (session.pendingPreKey) {
        const preKeyMessage = protobufs.PreKeyWhisperMessage.create({
          identityKey: ourIdentityKey.pubKey,
          registrationId: await this.storage.getOurRegistrationId(),
          baseKey: session.pendingPreKey.baseKey,
          signedPreKeyId: session.pendingPreKey.signedKeyId,
          message: result,
        });

        if (session.pendingPreKey.preKeyId) {
          preKeyMessage.preKeyId = session.pendingPreKey.preKeyId;
        }

        return {
          type: 3,
          body: concatBytes(
            new Uint8Array([this._encodeTupleByte(VERSION, VERSION)]),
            protobufs.PreKeyWhisperMessage.encode(preKeyMessage).finish()
          ),
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
    if (!sessions.length) {
      throw new SessionError('No sessions available');
    }

    const errors = [];
    for (const session of sessions) {
      try {
        const plaintext = await this.doDecryptWhisperMessage(data, session);
        session.indexInfo.used = Date.now();
        return {
          session,
          plaintext,
        };
      } catch (error) {
        errors.push(error);
      }
    }

    console.error('Failed to decrypt message with any known session...');
    for (const error of errors) {
      console.error(`Session error:${error}`, error.stack);
    }
    throw new SessionError('No matching sessions found for message');
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
      if (!(await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey))) {
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

    const versions = this._decodeTupleByte(data[0]);
    if (versions[1] > 3 || versions[0] < 3) {
      throw new Error('Incompatible version number on PreKeyWhisperMessage');
    }

    return this.queueJob(async () => {
      let record = await this.getRecord();
      const preKeyProto = protobufs.PreKeyWhisperMessage.decode(data.slice(1));

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
        await this.storage.removePreKey(preKeyId);
      }

      return plaintext;
    });
  }

  async doDecryptWhisperMessage(messageBuffer, session) {
    assertUint8Array(messageBuffer, 'messageBuffer');

    if (!session) {
      throw new TypeError('session required');
    }

    const versions = this._decodeTupleByte(messageBuffer[0]);
    if (versions[1] > 3 || versions[0] < 3) {
      throw new Error('Incompatible version number on WhisperMessage');
    }

    const messageProto = messageBuffer.slice(1, -8);
    const message = protobufs.WhisperMessage.decode(messageProto);

    this.maybeStepRatchet(session, message.ephemeralKey, message.previousCounter);

    const chain = session.getChain(message.ephemeralKey);
    if (chain.chainType === ChainType.SENDING) {
      throw new Error('Tried to decrypt on a sending chain');
    }

    this.fillMessageKeys(chain, message.counter);

    if (!Object.prototype.hasOwnProperty.call(chain.messageKeys, message.counter)) {
      throw new MessageCounterError('Key used already or never filled');
    }

    const messageKey = chain.messageKeys[message.counter];
    delete chain.messageKeys[message.counter];

    const keys = crypto.deriveSecrets(messageKey, ZERO_SALT, WHISPER_MESSAGE_KEYS_INFO);

    const ourIdentityKey = await this.storage.getOurIdentity();
    const versionTuple = this._encodeTupleByte(VERSION, VERSION);
    const macInput = await native.buildWhisperMacInputAsync(
      session.indexInfo.remoteIdentityKey,
      ourIdentityKey.pubKey,
      versionTuple,
      messageProto
    );

    crypto.verifyMAC(macInput, keys[1], messageBuffer.slice(-8), 8);

    const plaintext = crypto.decrypt(keys[0], message.ciphertext, keys[2].slice(0, 16));
    delete session.pendingPreKey;
    return plaintext;
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
    if (session.getChain(remoteKey)) {
      return;
    }

    const ratchet = session.currentRatchet;
    const previousRatchet = session.getChain(ratchet.lastRemoteEphemeralKey);
    if (previousRatchet) {
      this.fillMessageKeys(previousRatchet, previousCounter);
      delete previousRatchet.chainKey.key;
    }

    this.calculateRatchet(session, remoteKey, false);

    const previousCounterChain = session.getChain(ratchet.ephemeralKeyPair.pubKey);
    if (previousCounterChain) {
      ratchet.previousCounter = previousCounterChain.chainKey.counter;
      session.deleteChain(ratchet.ephemeralKeyPair.pubKey);
    }

    ratchet.ephemeralKeyPair = curve.generateKeyPair();
    this.calculateRatchet(session, remoteKey, true);
    ratchet.lastRemoteEphemeralKey = remoteKey;
  }

  calculateRatchet(session, remoteKey, sending) {
    const ratchet = session.currentRatchet;
    const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey);
    const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey, WHISPER_RATCHET_INFO, 2);

    const chainKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
    session.addChain(chainKey, {
      messageKeys: {},
      chainKey: {
        counter: -1,
        key: masterKey[1],
      },
      chainType: sending ? ChainType.SENDING : ChainType.RECEIVING,
    });

    ratchet.rootKey = masterKey[0];
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