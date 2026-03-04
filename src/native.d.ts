export interface NativeProtocolAddressParsed {
  id: string;
  deviceId: number;
}

export interface NativeKeyPairLike {
  pubKey: Buffer;
  privKey: Buffer;
}

export interface NativeChainKeyState {
  counter: number;
  key?: Buffer;
}

export interface NativeSessionChainState {
  chainKey: NativeChainKeyState;
  chainType: number;
  messageKeys: Record<string, Buffer>;
}

export type NativeSessionChains = Record<string, NativeSessionChainState>;

export interface NativeSessionIndexInfo {
  baseKey: Buffer;
  baseKeyType: number;
  closed: number;
  used: number;
  created: number;
  remoteIdentityKey: Buffer;
}

export interface NativeSessionCurrentRatchet {
  ephemeralKeyPair: NativeKeyPairLike;
  lastRemoteEphemeralKey: Buffer;
  previousCounter: number;
  rootKey: Buffer;
}

export interface NativePendingPreKey {
  signedKeyId: number;
  baseKey: Buffer;
  preKeyId?: number;
}

export interface NativeSessionEntryLike {
  registrationId?: number;
  currentRatchet?: NativeSessionCurrentRatchet;
  indexInfo: NativeSessionIndexInfo;
  pendingPreKey?: NativePendingPreKey;
}

export type NativeSessionMap = Record<string, NativeSessionEntryLike>;

export interface NativeAddon {
  generateRegistrationId14(): number;
  parseProtocolAddress(encodedAddress: string): NativeProtocolAddressParsed;

  encryptAes256Cbc(key: Buffer, data: Buffer, iv: Buffer): Buffer;
  decryptAes256Cbc(key: Buffer, data: Buffer, iv: Buffer): Buffer;
  calculateMacSha256(key: Buffer, data: Buffer): Buffer;
  hashSha512(data: Buffer): Buffer;
  timingSafeEqual(a: Buffer, b: Buffer): boolean;
  deriveSecrets(input: Buffer, salt: Buffer, info: Buffer, chunks?: 1 | 2 | 3): Buffer[];
  numericFingerprint(
    localId: string,
    localKey: Buffer,
    remoteId: string,
    remoteKey: Buffer,
    iterations: number
  ): string;

  queueJobByBucket<T = unknown>(bucket: string, awaitable: () => T | Promise<T>): Promise<T>;

  sessionEntryAddChain(
    chains: NativeSessionChains,
    key: Buffer,
    value: NativeSessionChainState
  ): void;
  sessionEntryGetChain(
    chains: NativeSessionChains,
    key: Buffer
  ): NativeSessionChainState | undefined;
  sessionEntryDeleteChain(chains: NativeSessionChains, key: Buffer): void;

  sessionRecordGetSessionByBaseKey(
    sessions: NativeSessionMap,
    key: Buffer,
    ourBaseKeyType: number
  ): NativeSessionEntryLike | undefined;
  sessionRecordGetOpenSession(sessions: NativeSessionMap): NativeSessionEntryLike | undefined;
  sessionRecordHaveOpenSession(sessions: NativeSessionMap): boolean;
  sessionRecordGetSessionsSorted(sessions: NativeSessionMap): NativeSessionEntryLike[];
  sessionRecordRemoveOldSessions(sessions: NativeSessionMap, maxClosedSessions: number): void;
  sessionRecordDeleteAllSessions(sessions: NativeSessionMap): void;

  buildSessionSharedSecret(
    isInitiator: boolean,
    a1: Buffer,
    a2: Buffer,
    a3: Buffer,
    a4?: Buffer
  ): Buffer;
  buildSessionSharedSecretAsync(
    isInitiator: boolean,
    a1: Buffer,
    a2: Buffer,
    a3: Buffer,
    a4?: Buffer
  ): Promise<Buffer>;

  fillMessageKeys(chain: NativeSessionChainState, counter: number): void;

  encodeTupleByte(number1: number, number2: number): number;
  decodeTupleByte(byte: number): [number, number];

  buildWhisperMacInput(
    leftIdentityKey: Buffer,
    rightIdentityKey: Buffer,
    versionByte: number,
    messageProto: Buffer
  ): Buffer;
  buildWhisperMacInputAsync(
    leftIdentityKey: Buffer,
    rightIdentityKey: Buffer,
    versionByte: number,
    messageProto: Buffer
  ): Promise<Buffer>;

  assembleWhisperFrame(
    versionByte: number,
    messageProto: Buffer,
    mac: Buffer,
    macLength?: number
  ): Buffer;
  assembleWhisperFrameAsync(
    versionByte: number,
    messageProto: Buffer,
    mac: Buffer,
    macLength?: number
  ): Promise<Buffer>;
}

declare const nativeAddon: NativeAddon | null;

export default nativeAddon;
