import type { KeyPairType } from './src/curve';

export interface E2ESession {
  registrationId: number;
  identityKey: Buffer;
  signedPreKey: {
    keyId: number;
    publicKey: Buffer;
    signature: Buffer;
  };
  preKey?: {
    keyId: number;
    publicKey: Buffer;
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
    identityKey: Buffer | Uint8Array,
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
  public decryptPreKeyWhisperMessage(ciphertext: Buffer): Promise<Buffer>;
  public decryptWhisperMessage(ciphertext: Buffer): Promise<Buffer>;
  public encrypt(
    data: Buffer | Uint8Array
  ): Promise<{ type: number; body: Buffer; registrationId: number }>;
  public hasOpenSession(): Promise<boolean>;
  public closeOpenSession(): Promise<void>;
}

export class SessionBuilder {
  constructor(storage: SignalStorage, remoteAddress: ProtocolAddress);
  public initOutgoing(session: E2ESession): Promise<void>;
}

export class SignalError extends Error {}
export class UntrustedIdentityKeyError extends SignalError {
  addr: string;
  identityKey: Buffer | Uint8Array;
}
export class SessionError extends SignalError {}
export class MessageCounterError extends SessionError {}
export class PreKeyError extends SessionError {}

export const crypto: typeof import('./src/crypto');
export const curve: typeof import('./src/curve');
export const keyhelper: typeof import('./src/keyhelper');

