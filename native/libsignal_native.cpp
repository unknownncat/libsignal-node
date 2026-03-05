#include "libsignal_native.h"

namespace libsignal_native {

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("generateRegistrationId14", Napi::Function::New(env, GenerateRegistrationId14));
  exports.Set("parseProtocolAddress", Napi::Function::New(env, ParseProtocolAddress));
  exports.Set("curveGetPublicFromPrivateKey",
              Napi::Function::New(env, CurveGetPublicFromPrivateKey));
  exports.Set("curveGenerateKeyPair", Napi::Function::New(env, CurveGenerateKeyPair));
  exports.Set("curveCalculateAgreement", Napi::Function::New(env, CurveCalculateAgreement));
  exports.Set("curveCalculateSignature", Napi::Function::New(env, CurveCalculateSignature));
  exports.Set("curveVerifySignature", Napi::Function::New(env, CurveVerifySignature));
  exports.Set("keyhelperGenerateIdentityKeyPair",
              Napi::Function::New(env, KeyhelperGenerateIdentityKeyPair));
  exports.Set("keyhelperGenerateSignedPreKey",
              Napi::Function::New(env, KeyhelperGenerateSignedPreKey));
  exports.Set("keyhelperGeneratePreKey", Napi::Function::New(env, KeyhelperGeneratePreKey));
  exports.Set("sessionBuilderInitSession", Napi::Function::New(env, SessionBuilderInitSession));
  exports.Set("sessionBuilderCalculateSendingRatchet",
              Napi::Function::New(env, SessionBuilderCalculateSendingRatchet));
  exports.Set("sessionCipherCalculateRatchet",
              Napi::Function::New(env, SessionCipherCalculateRatchet));
  exports.Set("sessionCipherMaybeStepRatchet",
              Napi::Function::New(env, SessionCipherMaybeStepRatchet));
  exports.Set("sessionCipherEncryptWhisperMessage",
              Napi::Function::New(env, SessionCipherEncryptWhisperMessage));
  exports.Set("sessionCipherDecryptWhisperMessage",
              Napi::Function::New(env, SessionCipherDecryptWhisperMessage));
  exports.Set("encryptAes256Cbc", Napi::Function::New(env, EncryptAes256Cbc));
  exports.Set("decryptAes256Cbc", Napi::Function::New(env, DecryptAes256Cbc));
  exports.Set("calculateMacSha256", Napi::Function::New(env, CalculateMacSha256));
  exports.Set("hashSha512", Napi::Function::New(env, HashSha512));
  exports.Set("timingSafeEqual", Napi::Function::New(env, TimingSafeEqual));
  exports.Set("deriveSecrets", Napi::Function::New(env, DeriveSecrets));
  exports.Set("numericFingerprint", Napi::Function::New(env, NumericFingerprint));

  exports.Set("queueJobByBucket", Napi::Function::New(env, QueueJobByBucket));
  exports.Set("adapterIsTrustedIdentity", Napi::Function::New(env, AdapterIsTrustedIdentity));
  exports.Set("adapterLoadSession", Napi::Function::New(env, AdapterLoadSession));
  exports.Set("adapterStoreSession", Napi::Function::New(env, AdapterStoreSession));
  exports.Set("adapterLoadPreKey", Napi::Function::New(env, AdapterLoadPreKey));
  exports.Set("adapterRemovePreKey", Napi::Function::New(env, AdapterRemovePreKey));
  exports.Set("adapterLoadSignedPreKey", Napi::Function::New(env, AdapterLoadSignedPreKey));
  exports.Set("adapterGetOurRegistrationId",
              Napi::Function::New(env, AdapterGetOurRegistrationId));
  exports.Set("adapterGetOurIdentity", Napi::Function::New(env, AdapterGetOurIdentity));
  exports.Set("sessionBuilderInitOutgoing", Napi::Function::New(env, SessionBuilderInitOutgoing));
  exports.Set("sessionBuilderInitIncoming", Napi::Function::New(env, SessionBuilderInitIncoming));
  exports.Set("sessionCipherDecryptWithSessions",
              Napi::Function::New(env, SessionCipherDecryptWithSessions));

  exports.Set("sessionEntryAddChain", Napi::Function::New(env, SessionEntryAddChain));
  exports.Set("sessionEntryGetChain", Napi::Function::New(env, SessionEntryGetChain));
  exports.Set("sessionEntryDeleteChain", Napi::Function::New(env, SessionEntryDeleteChain));
  exports.Set("sessionEntrySerialize", Napi::Function::New(env, SessionEntrySerialize));
  exports.Set("sessionEntryDeserialize", Napi::Function::New(env, SessionEntryDeserialize));

  exports.Set("sessionRecordGetSessionByBaseKey",
              Napi::Function::New(env, SessionRecordGetSessionByBaseKey));
  exports.Set("sessionRecordGetOpenSession", Napi::Function::New(env, SessionRecordGetOpenSession));
  exports.Set("sessionRecordHaveOpenSession",
              Napi::Function::New(env, SessionRecordHaveOpenSession));
  exports.Set("sessionRecordGetSessionsSorted",
              Napi::Function::New(env, SessionRecordGetSessionsSorted));
  exports.Set("sessionRecordRemoveOldSessions",
              Napi::Function::New(env, SessionRecordRemoveOldSessions));
  exports.Set("sessionRecordDeleteAllSessions",
              Napi::Function::New(env, SessionRecordDeleteAllSessions));
  exports.Set("sessionRecordSetSession", Napi::Function::New(env, SessionRecordSetSession));
  exports.Set("sessionRecordCloseSession", Napi::Function::New(env, SessionRecordCloseSession));
  exports.Set("sessionRecordOpenSession", Napi::Function::New(env, SessionRecordOpenSession));
  exports.Set("sessionRecordIsClosed", Napi::Function::New(env, SessionRecordIsClosed));
  exports.Set("sessionRecordMigrate", Napi::Function::New(env, SessionRecordMigrate));

  exports.Set("buildSessionSharedSecret", Napi::Function::New(env, BuildSessionSharedSecret));
  exports.Set("buildSessionSharedSecretAsync",
              Napi::Function::New(env, BuildSessionSharedSecretAsync));

  exports.Set("fillMessageKeys", Napi::Function::New(env, FillMessageKeys));
  exports.Set("encodeTupleByte", Napi::Function::New(env, EncodeTupleByte));
  exports.Set("decodeTupleByte", Napi::Function::New(env, DecodeTupleByte));

  exports.Set("buildWhisperMacInput", Napi::Function::New(env, BuildWhisperMacInput));
  exports.Set("buildWhisperMacInputAsync", Napi::Function::New(env, BuildWhisperMacInputAsync));

  exports.Set("assembleWhisperFrame", Napi::Function::New(env, AssembleWhisperFrame));
  exports.Set("assembleWhisperFrameAsync", Napi::Function::New(env, AssembleWhisperFrameAsync));

  exports.Set("protobufEncodeWhisperMessage",
              Napi::Function::New(env, ProtobufEncodeWhisperMessage));
  exports.Set("protobufDecodeWhisperMessage",
              Napi::Function::New(env, ProtobufDecodeWhisperMessage));
  exports.Set("protobufEncodePreKeyWhisperMessage",
              Napi::Function::New(env, ProtobufEncodePreKeyWhisperMessage));
  exports.Set("protobufDecodePreKeyWhisperMessage",
              Napi::Function::New(env, ProtobufDecodePreKeyWhisperMessage));
  exports.Set("sessionCipherEncodePreKeyWhisperMessage",
              Napi::Function::New(env, SessionCipherEncodePreKeyWhisperMessage));
  exports.Set("sessionCipherDecodePreKeyWhisperMessage",
              Napi::Function::New(env, SessionCipherDecodePreKeyWhisperMessage));
  return exports;
}

}  // namespace libsignal_native

Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
  return libsignal_native::Init(env, exports);
}

NODE_API_MODULE(libsignal_native, InitModule)
