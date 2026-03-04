#include "libsignal_native.h"

namespace libsignal_native {

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("generateRegistrationId14", Napi::Function::New(env, GenerateRegistrationId14));
  exports.Set("parseProtocolAddress", Napi::Function::New(env, ParseProtocolAddress));
  exports.Set("encryptAes256Cbc", Napi::Function::New(env, EncryptAes256Cbc));
  exports.Set("decryptAes256Cbc", Napi::Function::New(env, DecryptAes256Cbc));
  exports.Set("calculateMacSha256", Napi::Function::New(env, CalculateMacSha256));
  exports.Set("hashSha512", Napi::Function::New(env, HashSha512));
  exports.Set("timingSafeEqual", Napi::Function::New(env, TimingSafeEqual));
  exports.Set("deriveSecrets", Napi::Function::New(env, DeriveSecrets));
  exports.Set("numericFingerprint", Napi::Function::New(env, NumericFingerprint));

  exports.Set("queueJobByBucket", Napi::Function::New(env, QueueJobByBucket));

  exports.Set("sessionEntryAddChain", Napi::Function::New(env, SessionEntryAddChain));
  exports.Set("sessionEntryGetChain", Napi::Function::New(env, SessionEntryGetChain));
  exports.Set("sessionEntryDeleteChain", Napi::Function::New(env, SessionEntryDeleteChain));

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
  return exports;
}

}  // namespace libsignal_native

Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
  return libsignal_native::Init(env, exports);
}

NODE_API_MODULE(libsignal_native, InitModule)
