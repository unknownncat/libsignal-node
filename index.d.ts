import type { KeyPairType } from './src/curve.js';

export interface E2ESession {
  registrationId: number;
  identityKey: Uint8Array;
  signedPreKey: {
    keyId: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  };
  preKey?: {
    keyId: number;
    publicKey: Uint8Array;
  };
}

export interface SerializedSessionRecord {
  version?: string;
  _sessions?: Record<string, unknown>;
  registrationId?: number;
  [key: string]: unknown;
}

export interface SessionEntryLike {
  [key: string]: unknown;
}

export interface CiphertextMessage {
  type: number;
  body: Uint8Array;
  registrationId: number;
}

export interface SignalStorage {
  loadSession(
    id: string
  ): Promise<SessionRecord | null | undefined> | SessionRecord | null | undefined;
  storeSession(id: string, session: SessionRecord): Promise<void> | void;
  isTrustedIdentity(
    identifier: string,
    identityKey: Uint8Array,
    direction?: number
  ): Promise<boolean> | boolean;
  loadPreKey(
    id: number | string
  ): Promise<KeyPairType | undefined> | KeyPairType | undefined;
  removePreKey(id: number): Promise<void> | void;
  loadSignedPreKey(
    id: number | string
  ): Promise<KeyPairType | undefined> | KeyPairType | undefined;
  getOurRegistrationId(): Promise<number> | number;
  getOurIdentity(): Promise<KeyPairType> | KeyPairType;
}

export class ProtocolAddress {
  static from(encodedAddress: string): ProtocolAddress;
  constructor(name: string, deviceId: number);
  public id: string;
  public deviceId: number;
  public toString(): string;
  public is(other: ProtocolAddress): boolean;
}

export class SessionRecord {
  static createEntry(): SessionEntryLike;
  static migrate(serialized: SerializedSessionRecord): void;
  static deserialize(serialized: SerializedSessionRecord): SessionRecord;
  public serialize(): SerializedSessionRecord;
  public haveOpenSession(): boolean;
  public getSession(key: Uint8Array): SessionEntryLike | undefined;
  public getOpenSession(): SessionEntryLike | undefined;
  public setSession(session: SessionEntryLike): void;
  public getSessions(): SessionEntryLike[];
  public closeSession(session: SessionEntryLike): void;
  public openSession(session: SessionEntryLike): void;
  public isClosed(session: SessionEntryLike): boolean;
  public removeOldSessions(): void;
  public deleteAllSessions(): void;
}

export class SessionCipher {
  constructor(storage: SignalStorage, remoteAddress: ProtocolAddress);
  public toString(): string;
  public getRecord(): Promise<SessionRecord | undefined>;
  public storeRecord(record: SessionRecord): Promise<void>;
  public queueJob<T>(awaitable: () => Promise<T> | T): Promise<T>;
  public decryptWithSessions(
    ciphertext: Uint8Array,
    sessions: SessionEntryLike[]
  ): Promise<{ session: SessionEntryLike; plaintext: Uint8Array }>;
  public decryptPreKeyWhisperMessage(ciphertext: Uint8Array): Promise<Uint8Array>;
  public decryptWhisperMessage(ciphertext: Uint8Array): Promise<Uint8Array>;
  public doDecryptWhisperMessage(
    messageBuffer: Uint8Array,
    session: SessionEntryLike
  ): Promise<Uint8Array>;
  public fillMessageKeys(chain: Record<string, unknown>, counter: number): void;
  public maybeStepRatchet(
    session: SessionEntryLike,
    remoteKey: Uint8Array,
    previousCounter: number
  ): void;
  public calculateRatchet(session: SessionEntryLike, remoteKey: Uint8Array, sending: boolean): void;
  public encrypt(data: Uint8Array): Promise<CiphertextMessage>;
  public hasOpenSession(): Promise<boolean>;
  public closeOpenSession(): Promise<void>;
}

export class SessionBuilder {
  constructor(storage: SignalStorage, remoteAddress: ProtocolAddress);
  public initOutgoing(session: E2ESession): Promise<void>;
  public initIncoming(record: SessionRecord, message: Record<string, unknown>): Promise<number | undefined>;
  public initSession(
    isInitiator: boolean,
    ourEphemeralKey: KeyPairType | undefined,
    ourSignedKey: KeyPairType | undefined,
    theirIdentityPubKey: Uint8Array,
    theirEphemeralPubKey: Uint8Array | undefined,
    theirSignedPubKey: Uint8Array | undefined,
    registrationId: number
  ): Promise<SessionEntryLike>;
  public calculateSendingRatchet(session: SessionEntryLike, remoteKey: Uint8Array): void;
}

export class FingerprintGenerator {
  constructor(iterations: number);
  public createFor(
    localIdentifier: string,
    localIdentityKey: Uint8Array,
    remoteIdentifier: string,
    remoteIdentityKey: Uint8Array
  ): Promise<string>;
}

export class SignalError extends Error { }
export class UntrustedIdentityKeyError extends SignalError {
  addr: string;
  identityKey: Uint8Array;
}
export class SessionError extends SignalError { }
export class MessageCounterError extends SessionError { }
export class PreKeyError extends SessionError { }

export * as crypto from './src/crypto.js';
export * as curve from './src/curve.js';
export * as keyhelper from './src/keyhelper.js';
export * as protobuf from "./src/protobufs.js";
