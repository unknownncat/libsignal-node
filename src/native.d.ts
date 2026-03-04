export interface NativeProtocolAddressParsed {
  id: string;
  deviceId: number;
}

export interface NativeKeyPairLike {
  pubKey: Uint8Array;
  privKey: Uint8Array;
}

export interface NativeChainKeyState {
  counter: number;
  key?: Uint8Array;
}

export interface NativeSessionChainState {
  chainKey: NativeChainKeyState;
  chainType: number;
  messageKeys: Record<string, Uint8Array>;
}

export type NativeSessionChains = Record<string, NativeSessionChainState>;

export interface NativeSessionIndexInfo {
  baseKey: Uint8Array;
  baseKeyType: number;
  closed: number;
  used: number;
  created: number;
  remoteIdentityKey: Uint8Array;
}

export interface NativeSessionCurrentRatchet {
  ephemeralKeyPair: NativeKeyPairLike;
  lastRemoteEphemeralKey: Uint8Array;
  previousCounter: number;
  rootKey: Uint8Array;
}

export interface NativePendingPreKey {
  signedKeyId: number;
  baseKey: Uint8Array;
  preKeyId?: number;
}

export interface NativeSessionEntryLike {
  registrationId?: number;
  currentRatchet?: NativeSessionCurrentRatchet;
  indexInfo: NativeSessionIndexInfo;
  pendingPreKey?: NativePendingPreKey;
}

export type NativeSessionMap = Record<string, NativeSessionEntryLike>;

export interface NativeWhisperMessageLike {
  ephemeralKey?: Uint8Array;
  counter?: number;
  previousCounter?: number;
  ciphertext?: Uint8Array;
}

export interface NativePreKeyWhisperMessageLike {
  registrationId?: number;
  preKeyId?: number;
  signedPreKeyId?: number;
  baseKey?: Uint8Array;
  identityKey?: Uint8Array;
  message?: Uint8Array;
}

export interface NativeAddon {
  generateRegistrationId14(): number;
  parseProtocolAddress(encodedAddress: string): NativeProtocolAddressParsed;

  encryptAes256Cbc(key: Uint8Array, data: Uint8Array, iv: Uint8Array): Uint8Array;
  decryptAes256Cbc(key: Uint8Array, data: Uint8Array, iv: Uint8Array): Uint8Array;
  calculateMacSha256(key: Uint8Array, data: Uint8Array): Uint8Array;
  hashSha512(data: Uint8Array): Uint8Array;
  timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
  deriveSecrets(
    input: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    chunks?: 1 | 2 | 3
  ): Uint8Array[];
  numericFingerprint(
    localId: string,
    localKey: Uint8Array,
    remoteId: string,
    remoteKey: Uint8Array,
    iterations: number
  ): string;

  queueJobByBucket<T = unknown>(bucket: string, awaitable: () => T | Promise<T>): Promise<T>;

  sessionEntryAddChain(chains: NativeSessionChains, key: Uint8Array, value: NativeSessionChainState): void;
  sessionEntryGetChain(chains: NativeSessionChains, key: Uint8Array): NativeSessionChainState | undefined;
  sessionEntryDeleteChain(chains: NativeSessionChains, key: Uint8Array): void;

  sessionRecordGetSessionByBaseKey(
    sessions: NativeSessionMap,
    key: Uint8Array,
    ourBaseKeyType: number
  ): NativeSessionEntryLike | undefined;
  sessionRecordGetOpenSession(sessions: NativeSessionMap): NativeSessionEntryLike | undefined;
  sessionRecordHaveOpenSession(sessions: NativeSessionMap): boolean;
  sessionRecordGetSessionsSorted(sessions: NativeSessionMap): NativeSessionEntryLike[];
  sessionRecordRemoveOldSessions(sessions: NativeSessionMap, maxClosedSessions: number): void;
  sessionRecordDeleteAllSessions(sessions: NativeSessionMap): void;

  buildSessionSharedSecret(
    isInitiator: boolean,
    a1: Uint8Array,
    a2: Uint8Array,
    a3: Uint8Array,
    a4?: Uint8Array
  ): Uint8Array;
  buildSessionSharedSecretAsync(
    isInitiator: boolean,
    a1: Uint8Array,
    a2: Uint8Array,
    a3: Uint8Array,
    a4?: Uint8Array
  ): Promise<Uint8Array>;

  fillMessageKeys(chain: NativeSessionChainState, counter: number): void;

  encodeTupleByte(number1: number, number2: number): number;
  decodeTupleByte(byte: number): [number, number];

  buildWhisperMacInput(
    leftIdentityKey: Uint8Array,
    rightIdentityKey: Uint8Array,
    versionByte: number,
    messageProto: Uint8Array
  ): Uint8Array;
  buildWhisperMacInputAsync(
    leftIdentityKey: Uint8Array,
    rightIdentityKey: Uint8Array,
    versionByte: number,
    messageProto: Uint8Array
  ): Promise<Uint8Array>;

  assembleWhisperFrame(
    versionByte: number,
    messageProto: Uint8Array,
    mac: Uint8Array,
    macLength?: number
  ): Uint8Array;
  assembleWhisperFrameAsync(
    versionByte: number,
    messageProto: Uint8Array,
    mac: Uint8Array,
    macLength?: number
  ): Promise<Uint8Array>;

  protobufEncodeWhisperMessage(message: NativeWhisperMessageLike): Uint8Array;
  protobufDecodeWhisperMessage(data: Uint8Array): NativeWhisperMessageLike;

  protobufEncodePreKeyWhisperMessage(message: NativePreKeyWhisperMessageLike): Uint8Array;
  protobufDecodePreKeyWhisperMessage(data: Uint8Array): NativePreKeyWhisperMessageLike;
}

declare const nativeAddon: NativeAddon;

export default nativeAddon;