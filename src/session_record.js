import BaseKeyType from './base_key_type.js';
import native from './native.js';
import { assertUint8Array, toBase64 } from './bytes.js';

const CLOSED_SESSIONS_MAX = 40;
const SESSION_RECORD_VERSION = 'v1';

function fromBase64(value) {
  return new Uint8Array(Buffer.from(value, 'base64'));
}

class SessionEntry {
  constructor() {
    this._chains = {};
  }

  toString() {
    const baseKey = this.indexInfo && this.indexInfo.baseKey && toBase64(this.indexInfo.baseKey, 'indexInfo.baseKey');
    return `<SessionEntry [baseKey=${baseKey}]>`;
  }

  inspect() {
    return this.toString();
  }

  addChain(key, value) {
    assertUint8Array(key, 'chain key');
    native.sessionEntryAddChain(this._chains, key, value);
  }

  getChain(key) {
    assertUint8Array(key, 'chain key');
    return native.sessionEntryGetChain(this._chains, key);
  }

  deleteChain(key) {
    assertUint8Array(key, 'chain key');
    native.sessionEntryDeleteChain(this._chains, key);
  }

  *chains() {
    for (const [key, value] of Object.entries(this._chains)) {
      yield [fromBase64(key), value];
    }
  }

  serialize() {
    const data = {
      registrationId: this.registrationId,
      currentRatchet: {
        ephemeralKeyPair: {
          pubKey: toBase64(this.currentRatchet.ephemeralKeyPair.pubKey, 'currentRatchet.ephemeralKeyPair.pubKey'),
          privKey: toBase64(this.currentRatchet.ephemeralKeyPair.privKey, 'currentRatchet.ephemeralKeyPair.privKey'),
        },
        lastRemoteEphemeralKey: toBase64(this.currentRatchet.lastRemoteEphemeralKey, 'currentRatchet.lastRemoteEphemeralKey'),
        previousCounter: this.currentRatchet.previousCounter,
        rootKey: toBase64(this.currentRatchet.rootKey, 'currentRatchet.rootKey'),
      },
      indexInfo: {
        baseKey: toBase64(this.indexInfo.baseKey, 'indexInfo.baseKey'),
        baseKeyType: this.indexInfo.baseKeyType,
        closed: this.indexInfo.closed,
        used: this.indexInfo.used,
        created: this.indexInfo.created,
        remoteIdentityKey: toBase64(this.indexInfo.remoteIdentityKey, 'indexInfo.remoteIdentityKey'),
      },
      _chains: this._serializeChains(this._chains),
    };

    if (this.pendingPreKey) {
      data.pendingPreKey = {
        ...this.pendingPreKey,
        baseKey: toBase64(this.pendingPreKey.baseKey, 'pendingPreKey.baseKey'),
      };
    }

    return data;
  }

  static deserialize(data) {
    const entry = new this();
    entry.registrationId = data.registrationId;
    entry.currentRatchet = {
      ephemeralKeyPair: {
        pubKey: fromBase64(data.currentRatchet.ephemeralKeyPair.pubKey),
        privKey: fromBase64(data.currentRatchet.ephemeralKeyPair.privKey),
      },
      lastRemoteEphemeralKey: fromBase64(data.currentRatchet.lastRemoteEphemeralKey),
      previousCounter: data.currentRatchet.previousCounter,
      rootKey: fromBase64(data.currentRatchet.rootKey),
    };
    entry.indexInfo = {
      baseKey: fromBase64(data.indexInfo.baseKey),
      baseKeyType: data.indexInfo.baseKeyType,
      closed: data.indexInfo.closed,
      used: data.indexInfo.used,
      created: data.indexInfo.created,
      remoteIdentityKey: fromBase64(data.indexInfo.remoteIdentityKey),
    };
    entry._chains = this._deserializeChains(data._chains);

    if (data.pendingPreKey) {
      entry.pendingPreKey = {
        ...data.pendingPreKey,
        baseKey: fromBase64(data.pendingPreKey.baseKey),
      };
    }

    return entry;
  }

  _serializeChains(chains) {
    const result = {};
    for (const key of Object.keys(chains)) {
      const chain = chains[key];
      const messageKeys = {};
      for (const [index, value] of Object.entries(chain.messageKeys)) {
        messageKeys[index] = toBase64(value, `chain.messageKeys.${index}`);
      }
      result[key] = {
        chainKey: {
          counter: chain.chainKey.counter,
          key: chain.chainKey.key && toBase64(chain.chainKey.key, 'chain.chainKey.key'),
        },
        chainType: chain.chainType,
        messageKeys,
      };
    }
    return result;
  }

  static _deserializeChains(chainsData) {
    const result = {};
    for (const key of Object.keys(chainsData)) {
      const chain = chainsData[key];
      const messageKeys = {};
      for (const [index, value] of Object.entries(chain.messageKeys)) {
        messageKeys[index] = fromBase64(value);
      }
      result[key] = {
        chainKey: {
          counter: chain.chainKey.counter,
          key: chain.chainKey.key && fromBase64(chain.chainKey.key),
        },
        chainType: chain.chainType,
        messageKeys,
      };
    }
    return result;
  }
}

const migrations = [
  {
    version: 'v1',
    migrate(data) {
      const sessions = data._sessions;
      if (data.registrationId) {
        for (const key in sessions) {
          if (!sessions[key].registrationId) {
            sessions[key].registrationId = data.registrationId;
          }
        }
      } else {
        for (const key in sessions) {
          if (sessions[key].indexInfo.closed === -1) {
            console.error(
              'V1 session storage migration error: registrationId',
              data.registrationId,
              'for open session version',
              data.version
            );
          }
        }
      }
    },
  },
];

export default class SessionRecord {
  static createEntry() {
    return new SessionEntry();
  }

  static migrate(data) {
    let run = data.version === undefined;
    for (let index = 0; index < migrations.length; index += 1) {
      if (run) {
        console.info('Migrating session to:', migrations[index].version);
        migrations[index].migrate(data);
      } else if (migrations[index].version === data.version) {
        run = true;
      }
    }
    if (!run) {
      throw new Error('Error migrating SessionRecord');
    }
  }

  static deserialize(data) {
    if (data.version !== SESSION_RECORD_VERSION) {
      this.migrate(data);
    }

    const record = new this();
    if (data._sessions) {
      for (const [key, entry] of Object.entries(data._sessions)) {
        record.sessions[key] = SessionEntry.deserialize(entry);
      }
    }
    return record;
  }

  constructor() {
    this.sessions = {};
    this.version = SESSION_RECORD_VERSION;
  }

  serialize() {
    const sessions = {};
    for (const [key, entry] of Object.entries(this.sessions)) {
      sessions[key] = entry.serialize();
    }
    return {
      _sessions: sessions,
      version: this.version,
    };
  }

  haveOpenSession() {
    return native.sessionRecordHaveOpenSession(this.sessions);
  }

  getSession(key) {
    assertUint8Array(key, 'session key');
    return native.sessionRecordGetSessionByBaseKey(this.sessions, key, BaseKeyType.OURS);
  }

  getOpenSession() {
    return native.sessionRecordGetOpenSession(this.sessions);
  }

  setSession(session) {
    this.sessions[toBase64(session.indexInfo.baseKey, 'indexInfo.baseKey')] = session;
  }

  getSessions() {
    return native.sessionRecordGetSessionsSorted(this.sessions);
  }

  closeSession(session) {
    if (this.isClosed(session)) {
      console.warn('Session already closed', session);
      return;
    }
    console.info('Closing session:', session);
    session.indexInfo.closed = Date.now();
  }

  openSession(session) {
    if (!this.isClosed(session)) {
      console.warn('Session already open');
    }
    console.info('Opening session:', session);
    session.indexInfo.closed = -1;
  }

  isClosed(session) {
    return session.indexInfo.closed !== -1;
  }

  removeOldSessions() {
    native.sessionRecordRemoveOldSessions(this.sessions, CLOSED_SESSIONS_MAX);
  }

  deleteAllSessions() {
    native.sessionRecordDeleteAllSessions(this.sessions);
  }
}