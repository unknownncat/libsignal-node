#ifndef LIBSIGNAL_NATIVE_H_
#define LIBSIGNAL_NATIVE_H_

#include <napi.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace libsignal_native {

Napi::Object RequireModule(const Napi::Env& env, const char* name);
Napi::Object EnsureObject(const Napi::Value& value, const char* name);
Napi::Buffer<uint8_t> EnsureBuffer(const Napi::Value& value, const char* name);
Napi::Function EnsureFunction(const Napi::Value& value, const char* name);
Napi::Buffer<uint8_t> BufferConcat(const Napi::Env& env, std::initializer_list<Napi::Value> values);
std::string BufferToBase64(const Napi::Buffer<uint8_t>& buffer);
std::vector<uint8_t> CopyBufferToVector(const Napi::Buffer<uint8_t>& buffer);

void SecureZeroMemory(void* ptr, size_t len);
void SecureZeroVector(std::vector<uint8_t>& data);

Napi::Buffer<uint8_t> CalculateMacRawWithCrypto(const Napi::Env& env,
                                                const Napi::Object& crypto,
                                                const Napi::Function& createHmac,
                                                const Napi::String& algorithm,
                                                const Napi::Buffer<uint8_t>& key,
                                                const Napi::Buffer<uint8_t>& data);
Napi::Buffer<uint8_t> CalculateMacRaw(const Napi::Env& env,
                                      const Napi::Buffer<uint8_t>& key,
                                      const Napi::Buffer<uint8_t>& data);
Napi::Buffer<uint8_t> HashRawWithCrypto(const Napi::Env& env,
                                        const Napi::Object& crypto,
                                        const Napi::Function& createHash,
                                        const Napi::String& algorithm,
                                        const Napi::Buffer<uint8_t>& data);
Napi::Buffer<uint8_t> HashRaw(const Napi::Env& env, const Napi::Buffer<uint8_t>& data);

Napi::Object GetIndexInfo(const Napi::Object& session);
bool IsClosedSession(const Napi::Object& session);
double SessionUsedAt(const Napi::Object& session);
double SessionClosedAt(const Napi::Object& session);
Napi::Value FindOpenSessionValue(const Napi::Env& env, const Napi::Object& sessions);

Napi::Value QueueJobByBucket(const Napi::CallbackInfo& info);
Napi::Value AdapterIsTrustedIdentity(const Napi::CallbackInfo& info);
Napi::Value AdapterLoadSession(const Napi::CallbackInfo& info);
Napi::Value AdapterStoreSession(const Napi::CallbackInfo& info);
Napi::Value AdapterLoadPreKey(const Napi::CallbackInfo& info);
Napi::Value AdapterRemovePreKey(const Napi::CallbackInfo& info);
Napi::Value AdapterLoadSignedPreKey(const Napi::CallbackInfo& info);
Napi::Value AdapterGetOurRegistrationId(const Napi::CallbackInfo& info);
Napi::Value AdapterGetOurIdentity(const Napi::CallbackInfo& info);
Napi::Value SessionBuilderInitOutgoing(const Napi::CallbackInfo& info);
Napi::Value SessionBuilderInitIncoming(const Napi::CallbackInfo& info);
Napi::Value SessionCipherDecryptWithSessions(const Napi::CallbackInfo& info);

Napi::Value SessionEntryAddChain(const Napi::CallbackInfo& info);
Napi::Value SessionEntryGetChain(const Napi::CallbackInfo& info);
Napi::Value SessionEntryDeleteChain(const Napi::CallbackInfo& info);
Napi::Value SessionEntrySerialize(const Napi::CallbackInfo& info);
Napi::Value SessionEntryDeserialize(const Napi::CallbackInfo& info);

Napi::Value SessionRecordGetSessionByBaseKey(const Napi::CallbackInfo& info);
Napi::Value SessionRecordGetOpenSession(const Napi::CallbackInfo& info);
Napi::Value SessionRecordHaveOpenSession(const Napi::CallbackInfo& info);
Napi::Value SessionRecordGetSessionsSorted(const Napi::CallbackInfo& info);
Napi::Value SessionRecordRemoveOldSessions(const Napi::CallbackInfo& info);
Napi::Value SessionRecordDeleteAllSessions(const Napi::CallbackInfo& info);
Napi::Value SessionRecordSetSession(const Napi::CallbackInfo& info);
Napi::Value SessionRecordCloseSession(const Napi::CallbackInfo& info);
Napi::Value SessionRecordOpenSession(const Napi::CallbackInfo& info);
Napi::Value SessionRecordIsClosed(const Napi::CallbackInfo& info);
Napi::Value SessionRecordMigrate(const Napi::CallbackInfo& info);

Napi::Value GenerateRegistrationId14(const Napi::CallbackInfo& info);
Napi::Value ParseProtocolAddress(const Napi::CallbackInfo& info);
Napi::Value CurveGetPublicFromPrivateKey(const Napi::CallbackInfo& info);
Napi::Value CurveGenerateKeyPair(const Napi::CallbackInfo& info);
Napi::Value CurveCalculateAgreement(const Napi::CallbackInfo& info);
Napi::Value CurveCalculateSignature(const Napi::CallbackInfo& info);
Napi::Value CurveVerifySignature(const Napi::CallbackInfo& info);
Napi::Value KeyhelperGenerateIdentityKeyPair(const Napi::CallbackInfo& info);
Napi::Value KeyhelperGenerateSignedPreKey(const Napi::CallbackInfo& info);
Napi::Value KeyhelperGeneratePreKey(const Napi::CallbackInfo& info);
Napi::Value SessionBuilderInitSession(const Napi::CallbackInfo& info);
Napi::Value SessionBuilderCalculateSendingRatchet(const Napi::CallbackInfo& info);
Napi::Value SessionCipherCalculateRatchet(const Napi::CallbackInfo& info);
Napi::Value SessionCipherMaybeStepRatchet(const Napi::CallbackInfo& info);
Napi::Value SessionCipherEncryptWhisperMessage(const Napi::CallbackInfo& info);
Napi::Value SessionCipherDecryptWhisperMessage(const Napi::CallbackInfo& info);
Napi::Value EncryptAes256Cbc(const Napi::CallbackInfo& info);
Napi::Value DecryptAes256Cbc(const Napi::CallbackInfo& info);
Napi::Value CalculateMacSha256(const Napi::CallbackInfo& info);
Napi::Value HashSha512(const Napi::CallbackInfo& info);
Napi::Value TimingSafeEqual(const Napi::CallbackInfo& info);
Napi::Value DeriveSecrets(const Napi::CallbackInfo& info);
Napi::Value NumericFingerprint(const Napi::CallbackInfo& info);

Napi::Value BuildSessionSharedSecret(const Napi::CallbackInfo& info);
Napi::Value BuildSessionSharedSecretAsync(const Napi::CallbackInfo& info);

Napi::Value FillMessageKeys(const Napi::CallbackInfo& info);
Napi::Value EncodeTupleByte(const Napi::CallbackInfo& info);
Napi::Value DecodeTupleByte(const Napi::CallbackInfo& info);

Napi::Value BuildWhisperMacInput(const Napi::CallbackInfo& info);
Napi::Value BuildWhisperMacInputAsync(const Napi::CallbackInfo& info);

Napi::Value AssembleWhisperFrame(const Napi::CallbackInfo& info);
Napi::Value AssembleWhisperFrameAsync(const Napi::CallbackInfo& info);

Napi::Value ProtobufEncodeWhisperMessage(const Napi::CallbackInfo& info);
Napi::Value ProtobufDecodeWhisperMessage(const Napi::CallbackInfo& info);
Napi::Value ProtobufEncodePreKeyWhisperMessage(const Napi::CallbackInfo& info);
Napi::Value ProtobufDecodePreKeyWhisperMessage(const Napi::CallbackInfo& info);
Napi::Value SessionCipherEncodePreKeyWhisperMessage(const Napi::CallbackInfo& info);
Napi::Value SessionCipherDecodePreKeyWhisperMessage(const Napi::CallbackInfo& info);

Napi::Object Init(Napi::Env env, Napi::Object exports);

}  // namespace libsignal_native

#endif  // LIBSIGNAL_NATIVE_H_
