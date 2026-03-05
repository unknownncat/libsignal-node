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
    return native.sessionEntrySerialize(this);
  }

  static deserialize(data) {
    const entry = new this();
    Object.assign(entry, native.sessionEntryDeserialize(data));
    return entry;
  }
}

export default class SessionRecord {
  static createEntry() {
    return new SessionEntry();
  }

  static migrate(data) {
    native.sessionRecordMigrate(data, SESSION_RECORD_VERSION);
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
    let normalized = session;
    if (!(normalized instanceof SessionEntry)) {
      normalized = new SessionEntry();
      Object.assign(normalized, session);
    }
    native.sessionRecordSetSession(this.sessions, normalized);
  }

  getSessions() {
    return native.sessionRecordGetSessionsSorted(this.sessions);
  }

  closeSession(session) {
    if (!native.sessionRecordCloseSession(session)) {
      console.warn('Session already closed', session);
      return;
    }
    console.info('Closing session:', session);
  }

  openSession(session) {
    if (!native.sessionRecordOpenSession(session)) {
      console.warn('Session already open');
      return;
    }
    console.info('Opening session:', session);
  }

  isClosed(session) {
    return native.sessionRecordIsClosed(session);
  }

  removeOldSessions() {
    native.sessionRecordRemoveOldSessions(this.sessions, CLOSED_SESSIONS_MAX);
  }

  deleteAllSessions() {
    native.sessionRecordDeleteAllSessions(this.sessions);
  }
}
