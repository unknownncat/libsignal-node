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
  static deserialize(serialized: SerializedSessionRecord): SessionRecord;
  public serialize(): SerializedSessionRecord;
  public haveOpenSession(): boolean;
  public deleteAllSessions(): void;
}

export class SessionCipher {
  constructor(storage: SignalStorage, remoteAddress: ProtocolAddress);
  public decryptPreKeyWhisperMessage(ciphertext: Uint8Array): Promise<Uint8Array>;
  public decryptWhisperMessage(ciphertext: Uint8Array): Promise<Uint8Array>;
  public encrypt(
    data: Uint8Array
  ): Promise<{ type: number; body: Uint8Array; registrationId: number }>;
  public hasOpenSession(): Promise<boolean>;
  public closeOpenSession(): Promise<void>;
}

export class SessionBuilder {
  constructor(storage: SignalStorage, remoteAddress: ProtocolAddress);
  public initOutgoing(session: E2ESession): Promise<void>;
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
export { PreKeyWhisperMessage, WhisperMessage } from "./src/protobufs.js"