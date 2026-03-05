#include "libsignal_native.h"
#include "proto/WhisperTextProtocol.pb.h"

#include <uv.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace libsignal_native {

Napi::Value GenerateRegistrationId14(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  uint16_t registrationId = 0;
  if (uv_random(nullptr, nullptr, &registrationId, sizeof(registrationId), 0, nullptr) != 0) {
    Napi::Error::New(env, "Failed to generate secure random bytes").ThrowAsJavaScriptException();
    return env.Null();
  }
  registrationId = static_cast<uint16_t>(registrationId & 0x3fffU);
  return Napi::Number::New(env, registrationId);
}

Napi::Value ParseProtocolAddress(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "encodedAddress must be a string").ThrowAsJavaScriptException();
    return env.Null();
  }

  const std::string encoded = info[0].As<Napi::String>().Utf8Value();
  const std::size_t sep = encoded.rfind('.');
  if (sep == std::string::npos || sep == 0 || sep == encoded.size() - 1) {
    Napi::Error::New(env, "Invalid address encoding").ThrowAsJavaScriptException();
    return env.Null();
  }

  const std::string id = encoded.substr(0, sep);
  const std::string devicePart = encoded.substr(sep + 1);
  if (!std::all_of(devicePart.begin(), devicePart.end(),
                   [](unsigned char c) { return std::isdigit(c) != 0; })) {
    Napi::Error::New(env, "Invalid address encoding").ThrowAsJavaScriptException();
    return env.Null();
  }

  unsigned long long parsed = 0;
  try {
    parsed = std::stoull(devicePart);
  } catch (...) {
    Napi::Error::New(env, "Invalid address encoding").ThrowAsJavaScriptException();
    return env.Null();
  }

  constexpr unsigned long long kMaxSafeInteger = 9007199254740991ULL;
  if (parsed > kMaxSafeInteger) {
    Napi::Error::New(env, "Invalid address encoding").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object out = Napi::Object::New(env);
  out.Set("id", Napi::String::New(env, id));
  out.Set("deviceId", Napi::Number::New(env, static_cast<double>(parsed)));
  return out;
}

namespace {

constexpr uint8_t kCurvePublicKeyPrefix = 5;

Napi::Object RequireAxlSign(const Napi::Env& env) {
  Napi::Object curveModule = RequireModule(env, "@unknownncat/curve25519-node");
  Napi::Value axlsignValue = curveModule.Get("axlsign");
  if (!axlsignValue.IsObject()) {
    Napi::Error::New(env, "Unable to load curve implementation").ThrowAsJavaScriptException();
    return Napi::Object();
  }
  return axlsignValue.As<Napi::Object>();
}

bool ParseNonNegativeInteger(const Napi::Env& env,
                             const Napi::Value& value,
                             const char* name,
                             uint32_t* out) {
  if (!value.IsNumber()) {
    Napi::TypeError::New(env, std::string("Invalid argument for ") + name)
        .ThrowAsJavaScriptException();
    return false;
  }
  const double number = value.As<Napi::Number>().DoubleValue();
  if (!std::isfinite(number) || number < 0 || std::floor(number) != number) {
    Napi::TypeError::New(env, std::string("Invalid argument for ") + name + ": " +
                                  std::to_string(number))
        .ThrowAsJavaScriptException();
    return false;
  }
  if (number > static_cast<double>((std::numeric_limits<uint32_t>::max)())) {
    Napi::RangeError::New(env, std::string(name) + " is out of range")
        .ThrowAsJavaScriptException();
    return false;
  }
  *out = static_cast<uint32_t>(number);
  return true;
}

Napi::Buffer<uint8_t> EnsurePrivateKey(const Napi::Value& value, const char* name) {
  Napi::Env env = value.Env();
  Napi::Buffer<uint8_t> privateKey = EnsureBuffer(value, name);
  if (env.IsExceptionPending()) {
    return Napi::Buffer<uint8_t>();
  }
  if (privateKey.Length() != 32) {
    Napi::Error::New(env, "Incorrect private key length: " + std::to_string(privateKey.Length()))
        .ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }
  return privateKey;
}

Napi::Buffer<uint8_t> NormalizePublicKey(const Napi::Value& value, const char* name) {
  Napi::Env env = value.Env();
  Napi::Buffer<uint8_t> publicKey = EnsureBuffer(value, name);
  if (env.IsExceptionPending()) {
    return Napi::Buffer<uint8_t>();
  }

  if (publicKey.Length() == 32) {
    return publicKey;
  }
  if (publicKey.Length() == 33 && publicKey.Data()[0] == kCurvePublicKeyPrefix) {
    return Napi::Buffer<uint8_t>::Copy(env, publicKey.Data() + 1, 32);
  }

  Napi::Error::New(env, "Invalid public key").ThrowAsJavaScriptException();
  return Napi::Buffer<uint8_t>();
}

Napi::Buffer<uint8_t> PrefixPublicKey(const Napi::Env& env,
                                      const Napi::Buffer<uint8_t>& publicKey32) {
  if (publicKey32.Length() != 32) {
    Napi::Error::New(env, "Invalid public key").ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }

  Napi::Buffer<uint8_t> prefixed = Napi::Buffer<uint8_t>::New(env, 33);
  prefixed.Data()[0] = kCurvePublicKeyPrefix;
  std::memcpy(prefixed.Data() + 1, publicKey32.Data(), 32);
  return prefixed;
}

Napi::Object CreateCurveKeyPairFromRaw(const Napi::Env& env,
                                       const Napi::Buffer<uint8_t>& privateKey32,
                                       const Napi::Buffer<uint8_t>& publicKey32) {
  if (privateKey32.Length() != 32) {
    Napi::Error::New(env, "Incorrect private key length: " + std::to_string(privateKey32.Length()))
        .ThrowAsJavaScriptException();
    return Napi::Object();
  }

  Napi::Buffer<uint8_t> prefixedPublic = PrefixPublicKey(env, publicKey32);
  if (env.IsExceptionPending()) {
    return Napi::Object();
  }

  Napi::Object out = Napi::Object::New(env);
  out.Set("privKey", Napi::Buffer<uint8_t>::Copy(env, privateKey32.Data(), privateKey32.Length()));
  out.Set("pubKey", prefixedPublic);
  return out;
}

Napi::Object GenerateCurveKeyPairInternal(const Napi::Env& env) {
  std::vector<uint8_t> randomSeed(32);
  if (uv_random(nullptr, nullptr, randomSeed.data(), randomSeed.size(), 0, nullptr) != 0) {
    SecureZeroVector(randomSeed);
    Napi::Error::New(env, "Failed to generate secure random bytes").ThrowAsJavaScriptException();
    return Napi::Object();
  }

  Napi::Object axlsign = RequireAxlSign(env);
  if (env.IsExceptionPending()) {
    SecureZeroVector(randomSeed);
    return Napi::Object();
  }
  Napi::Function generateKeyPair = EnsureFunction(axlsign.Get("generateKeyPair"), "axlsign.generateKeyPair");
  if (env.IsExceptionPending()) {
    SecureZeroVector(randomSeed);
    return Napi::Object();
  }

  Napi::Buffer<uint8_t> seed = Napi::Buffer<uint8_t>::Copy(env, randomSeed.data(), randomSeed.size());
  Napi::Value keyPairValue = generateKeyPair.Call(axlsign, {seed});
  SecureZeroVector(randomSeed);
  Napi::Object keyPair = EnsureObject(keyPairValue, "generated key pair");
  if (env.IsExceptionPending()) {
    return Napi::Object();
  }

  Napi::Buffer<uint8_t> privateKey = EnsurePrivateKey(keyPair.Get("private"), "generated key pair.private");
  Napi::Buffer<uint8_t> publicKey = EnsureBuffer(keyPair.Get("public"), "generated key pair.public");
  if (env.IsExceptionPending()) {
    return Napi::Object();
  }
  return CreateCurveKeyPairFromRaw(env, privateKey, publicKey);
}

Napi::Buffer<uint8_t> CalculateSignatureInternal(const Napi::Env& env,
                                                 const Napi::Buffer<uint8_t>& privateKey,
                                                 const Napi::Buffer<uint8_t>& message) {
  Napi::Object axlsign = RequireAxlSign(env);
  if (env.IsExceptionPending()) {
    return Napi::Buffer<uint8_t>();
  }
  Napi::Function sign = EnsureFunction(axlsign.Get("sign"), "axlsign.sign");
  if (env.IsExceptionPending()) {
    return Napi::Buffer<uint8_t>();
  }

  Napi::Value signatureValue = sign.Call(axlsign, {privateKey, message});
  Napi::Buffer<uint8_t> signature = EnsureBuffer(signatureValue, "signature");
  if (env.IsExceptionPending()) {
    return Napi::Buffer<uint8_t>();
  }
  return signature;
}

constexpr int32_t kChainTypeSending = 1;
constexpr int32_t kChainTypeReceiving = 2;
constexpr int32_t kBaseKeyTypeOurs = 1;
constexpr int32_t kBaseKeyTypeTheirs = 2;

constexpr uint8_t kZeroSaltBytes[32] = {0};
constexpr char kWhisperTextInfo[] = "WhisperText";
constexpr char kWhisperRatchetInfo[] = "WhisperRatchet";
constexpr char kWhisperMessageKeysInfo[] = "WhisperMessageKeys";

void ZeroBuffer(const Napi::Buffer<uint8_t>& buffer) {
  if (buffer.Length() > 0) {
    SecureZeroMemory(buffer.Data(), buffer.Length());
  }
}

double UnixTimeMsNow() {
  using namespace std::chrono;
  return static_cast<double>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

Napi::Object EnsureSessionChains(const Napi::Env& env, const Napi::Object& session) {
  Napi::Value chainsVal = session.Get("_chains");
  if (chainsVal.IsObject()) {
    return chainsVal.As<Napi::Object>();
  }
  Napi::Object chains = Napi::Object::New(env);
  session.Set("_chains", chains);
  return chains;
}

Napi::Value GetSessionChainByKey(const Napi::Env& env,
                                 const Napi::Object& session,
                                 const Napi::Buffer<uint8_t>& key) {
  Napi::Object chains = EnsureSessionChains(env, session);
  return chains.Get(BufferToBase64(key));
}

bool AddSessionChainNoOverwrite(const Napi::Env& env,
                                const Napi::Object& session,
                                const Napi::Buffer<uint8_t>& key,
                                const Napi::Object& value) {
  Napi::Object chains = EnsureSessionChains(env, session);
  const std::string id = BufferToBase64(key);
  if (chains.Has(id)) {
    Napi::Error::New(env, "Overwrite attempt").ThrowAsJavaScriptException();
    return false;
  }
  chains.Set(id, value);
  return true;
}

void DeleteSessionChainByKey(const Napi::Env& env,
                             const Napi::Object& session,
                             const Napi::Buffer<uint8_t>& key) {
  Napi::Object chains = EnsureSessionChains(env, session);
  chains.Delete(BufferToBase64(key));
}

Napi::Buffer<uint8_t> CalculateAgreementInternal(const Napi::Env& env,
                                                 const Napi::Buffer<uint8_t>& publicKey,
                                                 const Napi::Buffer<uint8_t>& privateKey) {
  Napi::Object axlsign = RequireAxlSign(env);
  if (env.IsExceptionPending()) {
    return Napi::Buffer<uint8_t>();
  }
  Napi::Function sharedKey = EnsureFunction(axlsign.Get("sharedKey"), "axlsign.sharedKey");
  if (env.IsExceptionPending()) {
    return Napi::Buffer<uint8_t>();
  }
  Napi::Value sharedSecretValue = sharedKey.Call(axlsign, {privateKey, publicKey});
  Napi::Buffer<uint8_t> sharedSecret = EnsureBuffer(sharedSecretValue, "agreement secret");
  if (env.IsExceptionPending()) {
    return Napi::Buffer<uint8_t>();
  }
  return sharedSecret;
}

std::vector<Napi::Buffer<uint8_t>> DeriveSecretsInternal(const Napi::Env& env,
                                                         const Napi::Buffer<uint8_t>& input,
                                                         const Napi::Buffer<uint8_t>& salt,
                                                         const char* info,
                                                         uint32_t chunks) {
  std::vector<Napi::Buffer<uint8_t>> out;
  if (salt.Length() != 32) {
    Napi::Error::New(env, "Got salt of incorrect length").ThrowAsJavaScriptException();
    return out;
  }
  if (chunks < 1 || chunks > 3) {
    Napi::RangeError::New(env, "chunks must be between 1 and 3").ThrowAsJavaScriptException();
    return out;
  }

  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createHmac = crypto.Get("createHmac").As<Napi::Function>();
  Napi::String sha256 = Napi::String::New(env, "sha256");

  Napi::Buffer<uint8_t> infoBuf = Napi::Buffer<uint8_t>::Copy(
      env, reinterpret_cast<const uint8_t*>(info), std::strlen(info));
  Napi::Buffer<uint8_t> prk = CalculateMacRawWithCrypto(env, crypto, createHmac, sha256, salt, input);
  std::vector<uint8_t> infoArray(infoBuf.Length() + 1 + 32, 0);
  std::memcpy(infoArray.data() + 32, infoBuf.Data(), infoBuf.Length());
  infoArray[infoArray.size() - 1] = 1;

  Napi::Buffer<uint8_t> t1 = CalculateMacRawWithCrypto(
      env, crypto, createHmac, sha256, prk,
      Napi::Buffer<uint8_t>::Copy(env, infoArray.data() + 32, infoArray.size() - 32));
  out.push_back(t1);

  if (chunks > 1) {
    std::memcpy(infoArray.data(), t1.Data(), 32);
    infoArray[infoArray.size() - 1] = 2;
    Napi::Buffer<uint8_t> t2 = CalculateMacRawWithCrypto(
        env, crypto, createHmac, sha256, prk,
        Napi::Buffer<uint8_t>::Copy(env, infoArray.data(), infoArray.size()));
    out.push_back(t2);

    if (chunks > 2) {
      std::memcpy(infoArray.data(), t2.Data(), 32);
      infoArray[infoArray.size() - 1] = 3;
      Napi::Buffer<uint8_t> t3 = CalculateMacRawWithCrypto(
          env, crypto, createHmac, sha256, prk,
          Napi::Buffer<uint8_t>::Copy(env, infoArray.data(), infoArray.size()));
      out.push_back(t3);
    }
  }

  ZeroBuffer(prk);
  SecureZeroVector(infoArray);
  return out;
}

Napi::Buffer<uint8_t> BuildSessionSharedSecretRawInternal(const Napi::Env& env,
                                                          bool isInitiator,
                                                          const Napi::Buffer<uint8_t>& a1,
                                                          const Napi::Buffer<uint8_t>& a2,
                                                          const Napi::Buffer<uint8_t>& a3,
                                                          const Napi::Buffer<uint8_t>* a4) {
  if (a1.Length() != 32 || a2.Length() != 32 || a3.Length() != 32) {
    Napi::Error::New(env, "a1, a2 and a3 must be 32-byte buffers").ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }

  const bool hasA4 = a4 != nullptr;
  if (hasA4 && a4->Length() != 32) {
    Napi::Error::New(env, "a4 must be a 32-byte buffer").ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }

  const size_t totalLength = hasA4 ? 160 : 128;
  Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, totalLength);
  std::memset(out.Data(), 0, out.Length());
  std::memset(out.Data(), 0xff, 32);

  if (isInitiator) {
    std::memcpy(out.Data() + 32, a1.Data(), 32);
    std::memcpy(out.Data() + 64, a2.Data(), 32);
  } else {
    std::memcpy(out.Data() + 64, a1.Data(), 32);
    std::memcpy(out.Data() + 32, a2.Data(), 32);
  }

  std::memcpy(out.Data() + 96, a3.Data(), 32);
  if (hasA4) {
    std::memcpy(out.Data() + 128, a4->Data(), 32);
  }
  return out;
}

bool FillMessageKeysInternal(const Napi::Env& env, const Napi::Object& chain, int64_t targetCounter) {
  if (!chain.Get("chainKey").IsObject()) {
    Napi::TypeError::New(env, "chain.chainKey must be an object").ThrowAsJavaScriptException();
    return false;
  }
  Napi::Object chainKey = chain.Get("chainKey").As<Napi::Object>();
  Napi::Value currentCounterVal = chainKey.Get("counter");
  if (!currentCounterVal.IsNumber()) {
    Napi::TypeError::New(env, "chain.chainKey.counter must be a number")
        .ThrowAsJavaScriptException();
    return false;
  }

  int64_t currentCounter = currentCounterVal.As<Napi::Number>().Int64Value();
  if (currentCounter >= targetCounter) {
    return true;
  }
  if (targetCounter - currentCounter > 2000) {
    Napi::Error::New(env, "Over 2000 messages into the future!").ThrowAsJavaScriptException();
    return false;
  }

  Napi::Value currentKeyVal = chainKey.Get("key");
  if (currentKeyVal.IsUndefined()) {
    Napi::Error::New(env, "Chain closed").ThrowAsJavaScriptException();
    return false;
  }
  Napi::Buffer<uint8_t> currentKey = EnsureBuffer(currentKeyVal, "chain.chainKey.key");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Object messageKeys;
  if (chain.Get("messageKeys").IsObject()) {
    messageKeys = chain.Get("messageKeys").As<Napi::Object>();
  } else {
    messageKeys = Napi::Object::New(env);
    chain.Set("messageKeys", messageKeys);
  }

  constexpr uint8_t oneByte[1] = {1};
  constexpr uint8_t twoByte[1] = {2};
  Napi::Buffer<uint8_t> one = Napi::Buffer<uint8_t>::Copy(env, oneByte, 1);
  Napi::Buffer<uint8_t> two = Napi::Buffer<uint8_t>::Copy(env, twoByte, 1);
  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createHmac = crypto.Get("createHmac").As<Napi::Function>();
  Napi::String sha256 = Napi::String::New(env, "sha256");

  while (currentCounter < targetCounter) {
    Napi::Buffer<uint8_t> messageKey =
        CalculateMacRawWithCrypto(env, crypto, createHmac, sha256, currentKey, one);
    Napi::Buffer<uint8_t> nextKey =
        CalculateMacRawWithCrypto(env, crypto, createHmac, sha256, currentKey, two);
    ++currentCounter;
    messageKeys.Set(std::to_string(currentCounter), messageKey);
    currentKey = nextKey;
  }

  chainKey.Set("counter", Napi::Number::New(env, static_cast<double>(currentCounter)));
  chainKey.Set("key", currentKey);
  return true;
}

bool CalculateRatchetInternal(const Napi::Env& env,
                              const Napi::Object& session,
                              const Napi::Buffer<uint8_t>& remoteKey,
                              bool sending) {
  Napi::Object ratchet = EnsureObject(session.Get("currentRatchet"), "session.currentRatchet");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Object ephemeralKeyPair =
      EnsureObject(ratchet.Get("ephemeralKeyPair"), "session.currentRatchet.ephemeralKeyPair");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Buffer<uint8_t> ephemeralPriv =
      EnsurePrivateKey(ephemeralKeyPair.Get("privKey"), "session.currentRatchet.ephemeralKeyPair.privKey");
  Napi::Buffer<uint8_t> ephemeralPub =
      EnsureBuffer(ephemeralKeyPair.Get("pubKey"), "session.currentRatchet.ephemeralKeyPair.pubKey");
  Napi::Buffer<uint8_t> rootKey = EnsureBuffer(ratchet.Get("rootKey"), "session.currentRatchet.rootKey");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Buffer<uint8_t> normalizedRemote = NormalizePublicKey(remoteKey, "remoteKey");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Buffer<uint8_t> sharedSecret = CalculateAgreementInternal(env, normalizedRemote, ephemeralPriv);
  if (env.IsExceptionPending()) {
    return false;
  }

  std::vector<Napi::Buffer<uint8_t>> masterKey =
      DeriveSecretsInternal(env, sharedSecret, rootKey, kWhisperRatchetInfo, 2);
  ZeroBuffer(sharedSecret);
  if (env.IsExceptionPending() || masterKey.size() < 2) {
    return false;
  }

  const Napi::Buffer<uint8_t> chainKeyPub = sending ? ephemeralPub : remoteKey;
  Napi::Object chain = Napi::Object::New(env);
  chain.Set("messageKeys", Napi::Object::New(env));
  Napi::Object chainKeyState = Napi::Object::New(env);
  chainKeyState.Set("counter", Napi::Number::New(env, -1));
  chainKeyState.Set("key", masterKey[1]);
  chain.Set("chainKey", chainKeyState);
  chain.Set("chainType", Napi::Number::New(env, sending ? kChainTypeSending : kChainTypeReceiving));

  if (!AddSessionChainNoOverwrite(env, session, chainKeyPub, chain)) {
    return false;
  }

  ratchet.Set("rootKey", masterKey[0]);
  return true;
}

bool CalculateSendingRatchetInternal(const Napi::Env& env,
                                     const Napi::Object& session,
                                     const Napi::Buffer<uint8_t>& remoteKey) {
  Napi::Object ratchet = EnsureObject(session.Get("currentRatchet"), "session.currentRatchet");
  if (env.IsExceptionPending()) {
    return false;
  }
  Napi::Object ephemeralKeyPair =
      EnsureObject(ratchet.Get("ephemeralKeyPair"), "session.currentRatchet.ephemeralKeyPair");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Buffer<uint8_t> ephemeralPriv =
      EnsurePrivateKey(ephemeralKeyPair.Get("privKey"), "session.currentRatchet.ephemeralKeyPair.privKey");
  Napi::Buffer<uint8_t> ephemeralPub =
      EnsureBuffer(ephemeralKeyPair.Get("pubKey"), "session.currentRatchet.ephemeralKeyPair.pubKey");
  Napi::Buffer<uint8_t> rootKey = EnsureBuffer(ratchet.Get("rootKey"), "session.currentRatchet.rootKey");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Buffer<uint8_t> normalizedRemote = NormalizePublicKey(remoteKey, "remoteKey");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Buffer<uint8_t> sharedSecret = CalculateAgreementInternal(env, normalizedRemote, ephemeralPriv);
  if (env.IsExceptionPending()) {
    return false;
  }

  std::vector<Napi::Buffer<uint8_t>> masterKey =
      DeriveSecretsInternal(env, sharedSecret, rootKey, kWhisperRatchetInfo, 3);
  ZeroBuffer(sharedSecret);
  if (env.IsExceptionPending() || masterKey.size() < 2) {
    return false;
  }

  Napi::Object chain = Napi::Object::New(env);
  chain.Set("messageKeys", Napi::Object::New(env));
  Napi::Object chainKeyState = Napi::Object::New(env);
  chainKeyState.Set("counter", Napi::Number::New(env, -1));
  chainKeyState.Set("key", masterKey[1]);
  chain.Set("chainKey", chainKeyState);
  chain.Set("chainType", Napi::Number::New(env, kChainTypeSending));

  if (!AddSessionChainNoOverwrite(env, session, ephemeralPub, chain)) {
    return false;
  }
  ratchet.Set("rootKey", masterKey[0]);
  return true;
}

bool MaybeStepRatchetInternal(const Napi::Env& env,
                              const Napi::Object& session,
                              const Napi::Buffer<uint8_t>& remoteKey,
                              int64_t previousCounter) {
  Napi::Value existingChainVal = GetSessionChainByKey(env, session, remoteKey);
  if (existingChainVal.IsObject()) {
    return true;
  }

  Napi::Object ratchet = EnsureObject(session.Get("currentRatchet"), "session.currentRatchet");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Buffer<uint8_t> lastRemoteEphemeral =
      EnsureBuffer(ratchet.Get("lastRemoteEphemeralKey"), "session.currentRatchet.lastRemoteEphemeralKey");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Value previousRatchetVal = GetSessionChainByKey(env, session, lastRemoteEphemeral);
  if (previousRatchetVal.IsObject()) {
    Napi::Object previousRatchet = previousRatchetVal.As<Napi::Object>();
    if (!FillMessageKeysInternal(env, previousRatchet, previousCounter)) {
      return false;
    }
    Napi::Object chainKey = EnsureObject(previousRatchet.Get("chainKey"), "chain.chainKey");
    if (env.IsExceptionPending()) {
      return false;
    }
    chainKey.Delete("key");
  }

  if (!CalculateRatchetInternal(env, session, remoteKey, false)) {
    return false;
  }

  Napi::Object ephemeralKeyPair =
      EnsureObject(ratchet.Get("ephemeralKeyPair"), "session.currentRatchet.ephemeralKeyPair");
  if (env.IsExceptionPending()) {
    return false;
  }
  Napi::Buffer<uint8_t> localEphemeralPub =
      EnsureBuffer(ephemeralKeyPair.Get("pubKey"), "session.currentRatchet.ephemeralKeyPair.pubKey");
  if (env.IsExceptionPending()) {
    return false;
  }

  Napi::Value previousCounterChainVal = GetSessionChainByKey(env, session, localEphemeralPub);
  if (previousCounterChainVal.IsObject()) {
    Napi::Object previousCounterChain = previousCounterChainVal.As<Napi::Object>();
    Napi::Object chainKey = EnsureObject(previousCounterChain.Get("chainKey"), "chain.chainKey");
    if (env.IsExceptionPending()) {
      return false;
    }
    Napi::Value chainCounter = chainKey.Get("counter");
    if (chainCounter.IsNumber()) {
      ratchet.Set("previousCounter", chainCounter);
    }
    DeleteSessionChainByKey(env, session, localEphemeralPub);
  }

  ratchet.Set("ephemeralKeyPair", GenerateCurveKeyPairInternal(env));
  if (env.IsExceptionPending()) {
    return false;
  }
  if (!CalculateRatchetInternal(env, session, remoteKey, true)) {
    return false;
  }
  ratchet.Set("lastRemoteEphemeralKey", remoteKey);
  return true;
}

Napi::Buffer<uint8_t> EncryptAes256CbcRaw(const Napi::Env& env,
                                          const Napi::Buffer<uint8_t>& key,
                                          const Napi::Buffer<uint8_t>& data,
                                          const Napi::Buffer<uint8_t>& iv) {
  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createCipheriv = crypto.Get("createCipheriv").As<Napi::Function>();
  Napi::Object cipher = createCipheriv
                            .Call(crypto, {Napi::String::New(env, "aes-256-cbc"), key, iv})
                            .As<Napi::Object>();
  Napi::Value updated = cipher.Get("update").As<Napi::Function>().Call(cipher, {data});
  Napi::Value final = cipher.Get("final").As<Napi::Function>().Call(cipher, {});
  return BufferConcat(env, {updated, final});
}

Napi::Buffer<uint8_t> DecryptAes256CbcRaw(const Napi::Env& env,
                                          const Napi::Buffer<uint8_t>& key,
                                          const Napi::Buffer<uint8_t>& data,
                                          const Napi::Buffer<uint8_t>& iv) {
  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createDecipheriv = crypto.Get("createDecipheriv").As<Napi::Function>();
  Napi::Object decipher = createDecipheriv
                              .Call(crypto, {Napi::String::New(env, "aes-256-cbc"), key, iv})
                              .As<Napi::Object>();
  Napi::Value updated = decipher.Get("update").As<Napi::Function>().Call(decipher, {data});
  Napi::Value final = decipher.Get("final").As<Napi::Function>().Call(decipher, {});
  return BufferConcat(env, {updated, final});
}

Napi::Buffer<uint8_t> BuildWhisperMacInputRaw(const Napi::Env& env,
                                              const Napi::Buffer<uint8_t>& left,
                                              const Napi::Buffer<uint8_t>& right,
                                              uint8_t versionByte,
                                              const Napi::Buffer<uint8_t>& messageProto) {
  if (left.Length() != 33 || right.Length() != 33) {
    Napi::Error::New(env, "Identity keys must be 33-byte buffers").ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }
  Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, messageProto.Length() + 67);
  std::memcpy(out.Data(), left.Data(), 33);
  std::memcpy(out.Data() + 33, right.Data(), 33);
  out.Data()[66] = versionByte;
  std::memcpy(out.Data() + 67, messageProto.Data(), messageProto.Length());
  return out;
}

Napi::Buffer<uint8_t> AssembleWhisperFrameRaw(const Napi::Env& env,
                                              uint8_t versionByte,
                                              const Napi::Buffer<uint8_t>& messageProto,
                                              const Napi::Buffer<uint8_t>& mac,
                                              uint32_t macLength) {
  if (macLength > mac.Length()) {
    Napi::RangeError::New(env, "macLength out of bounds").ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }
  Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, messageProto.Length() + macLength + 1);
  out.Data()[0] = versionByte;
  std::memcpy(out.Data() + 1, messageProto.Data(), messageProto.Length());
  std::memcpy(out.Data() + 1 + messageProto.Length(), mac.Data(), macLength);
  return out;
}

bool TimingSafeEqualRaw(const Napi::Env& env,
                        const Napi::Buffer<uint8_t>& a,
                        const Napi::Buffer<uint8_t>& b) {
  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function fn = crypto.Get("timingSafeEqual").As<Napi::Function>();
  return fn.Call(crypto, {a, b}).ToBoolean().Value();
}

Napi::Buffer<uint8_t> SerializeWhisperMessageRaw(const Napi::Env& env,
                                                 const Napi::Buffer<uint8_t>& ephemeralKey,
                                                 uint32_t counter,
                                                 uint32_t previousCounter,
                                                 const Napi::Buffer<uint8_t>& ciphertext) {
  textsecure::WhisperMessage proto;
  proto.mutable_ephemeralkey()->assign(reinterpret_cast<const char*>(ephemeralKey.Data()),
                                       ephemeralKey.Length());
  proto.set_counter(counter);
  proto.set_previouscounter(previousCounter);
  proto.mutable_ciphertext()->assign(reinterpret_cast<const char*>(ciphertext.Data()),
                                     ciphertext.Length());
  const size_t byteSize = proto.ByteSizeLong();
  if (byteSize > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    Napi::RangeError::New(env, "Protobuf message too large").ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }
  Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, byteSize);
  if (byteSize > 0 &&
      !proto.SerializeToArray(out.Data(), static_cast<int>(byteSize))) {
    Napi::Error::New(env, "Failed to serialize WhisperMessage protobuf")
        .ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }
  return out;
}

bool ParseWhisperMessageRaw(const Napi::Env& env,
                            const Napi::Buffer<uint8_t>& messageProto,
                            textsecure::WhisperMessage* out) {
  if (messageProto.Length() > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    Napi::RangeError::New(env, "Protobuf message too large").ThrowAsJavaScriptException();
    return false;
  }
  if (!out->ParseFromArray(messageProto.Data(), static_cast<int>(messageProto.Length()))) {
    Napi::Error::New(env, "Invalid WhisperMessage protobuf").ThrowAsJavaScriptException();
    return false;
  }
  return true;
}

}  // namespace

Napi::Value CurveGetPublicFromPrivateKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "curveGetPublicFromPrivateKey(privateKey) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> privateKey = EnsurePrivateKey(info[0], "private key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  std::vector<uint8_t> unclampedKey(privateKey.Data(), privateKey.Data() + privateKey.Length());
  unclampedKey[0] |= 6;
  unclampedKey[31] |= 128;
  unclampedKey[31] &= static_cast<uint8_t>(~64);

  Napi::Object axlsign = RequireAxlSign(env);
  if (env.IsExceptionPending()) {
    SecureZeroVector(unclampedKey);
    return env.Null();
  }
  Napi::Function generateKeyPair = EnsureFunction(axlsign.Get("generateKeyPair"), "axlsign.generateKeyPair");
  if (env.IsExceptionPending()) {
    SecureZeroVector(unclampedKey);
    return env.Null();
  }

  Napi::Buffer<uint8_t> seed = Napi::Buffer<uint8_t>::Copy(env, unclampedKey.data(), unclampedKey.size());
  SecureZeroVector(unclampedKey);
  Napi::Object keyPair = EnsureObject(generateKeyPair.Call(axlsign, {seed}), "generated key pair");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> publicKey = EnsureBuffer(keyPair.Get("public"), "generated key pair.public");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return PrefixPublicKey(env, publicKey);
}

Napi::Value CurveGenerateKeyPair(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Object keyPair = GenerateCurveKeyPairInternal(env);
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return keyPair;
}

Napi::Value CurveCalculateAgreement(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "curveCalculateAgreement(publicKey, privateKey) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> normalizedPublicKey = NormalizePublicKey(info[0], "public key");
  Napi::Buffer<uint8_t> privateKey = EnsurePrivateKey(info[1], "private key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object axlsign = RequireAxlSign(env);
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Function sharedKey = EnsureFunction(axlsign.Get("sharedKey"), "axlsign.sharedKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value sharedSecretValue = sharedKey.Call(axlsign, {privateKey, normalizedPublicKey});
  Napi::Buffer<uint8_t> sharedSecret = EnsureBuffer(sharedSecretValue, "agreement secret");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return sharedSecret;
}

Napi::Value CurveCalculateSignature(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "curveCalculateSignature(privateKey, message) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> privateKey = EnsurePrivateKey(info[0], "private key");
  Napi::Buffer<uint8_t> message = EnsureBuffer(info[1], "message");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return CalculateSignatureInternal(env, privateKey, message);
}

Napi::Value CurveVerifySignature(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(env, "curveVerifySignature(publicKey, message, signature) requires 3 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> normalizedPublicKey = NormalizePublicKey(info[0], "public key");
  Napi::Buffer<uint8_t> message = EnsureBuffer(info[1], "message");
  Napi::Buffer<uint8_t> signature = EnsureBuffer(info[2], "signature");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (signature.Length() != 64) {
    Napi::Error::New(env, "Invalid signature").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object axlsign = RequireAxlSign(env);
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Function verify = EnsureFunction(axlsign.Get("verify"), "axlsign.verify");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return verify.Call(axlsign, {normalizedPublicKey, message, signature});
}

Napi::Value KeyhelperGenerateIdentityKeyPair(const Napi::CallbackInfo& info) {
  return CurveGenerateKeyPair(info);
}

Napi::Value KeyhelperGenerateSignedPreKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(
        env,
        "keyhelperGenerateSignedPreKey(identityKeyPair, signedKeyId) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object identityKeyPair = EnsureObject(info[0], "identityKeyPair");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Buffer<uint8_t> identityPrivateKey = EnsureBuffer(identityKeyPair.Get("privKey"), "identityKeyPair.privKey");
  Napi::Buffer<uint8_t> identityPublicKey = EnsureBuffer(identityKeyPair.Get("pubKey"), "identityKeyPair.pubKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (identityPrivateKey.Length() != 32 || identityPublicKey.Length() != 33 ||
      identityPublicKey.Data()[0] != kCurvePublicKeyPrefix) {
    Napi::TypeError::New(env, "Invalid argument for identityKeyPair").ThrowAsJavaScriptException();
    return env.Null();
  }

  uint32_t signedKeyId = 0;
  if (!ParseNonNegativeInteger(env, info[1], "signedKeyId", &signedKeyId)) {
    return env.Null();
  }

  Napi::Object keyPair = GenerateCurveKeyPairInternal(env);
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Buffer<uint8_t> signedPublicKey = EnsureBuffer(keyPair.Get("pubKey"), "keyPair.pubKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Buffer<uint8_t> signature = CalculateSignatureInternal(env, identityPrivateKey, signedPublicKey);
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object result = Napi::Object::New(env);
  result.Set("keyId", Napi::Number::New(env, signedKeyId));
  result.Set("keyPair", keyPair);
  result.Set("signature", signature);
  return result;
}

Napi::Value KeyhelperGeneratePreKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "keyhelperGeneratePreKey(keyId) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  uint32_t keyId = 0;
  if (!ParseNonNegativeInteger(env, info[0], "keyId", &keyId)) {
    return env.Null();
  }

  Napi::Object result = Napi::Object::New(env);
  result.Set("keyId", Napi::Number::New(env, keyId));
  result.Set("keyPair", GenerateCurveKeyPairInternal(env));
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return result;
}

Napi::Value SessionBuilderInitSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 8 || !info[0].IsBoolean() || !info[6].IsNumber()) {
    Napi::TypeError::New(
        env,
        "sessionBuilderInitSession(isInitiator, ourEphemeralKey, ourSignedKey, theirIdentityPubKey, theirEphemeralPubKey, theirSignedPubKey, registrationId, ourIdentityKey) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  const bool isInitiator = info[0].As<Napi::Boolean>().Value();
  Napi::Buffer<uint8_t> theirIdentityPubKey =
      EnsureBuffer(info[3], "theirIdentityPubKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  bool hasOurEphemeralKey = false;
  Napi::Object ourEphemeralKey;
  if (!info[1].IsUndefined() && !info[1].IsNull()) {
    hasOurEphemeralKey = true;
    ourEphemeralKey = EnsureObject(info[1], "ourEphemeralKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
  }

  bool hasOurSignedKey = false;
  Napi::Object ourSignedKey;
  if (!info[2].IsUndefined() && !info[2].IsNull()) {
    hasOurSignedKey = true;
    ourSignedKey = EnsureObject(info[2], "ourSignedKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
  }

  bool hasTheirEphemeralPubKey = false;
  Napi::Buffer<uint8_t> theirEphemeralPubKey;
  if (!info[4].IsUndefined() && !info[4].IsNull()) {
    hasTheirEphemeralPubKey = true;
    theirEphemeralPubKey = EnsureBuffer(info[4], "theirEphemeralPubKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
  }

  bool hasTheirSignedPubKey = false;
  Napi::Buffer<uint8_t> theirSignedPubKey;
  if (!info[5].IsUndefined() && !info[5].IsNull()) {
    hasTheirSignedPubKey = true;
    theirSignedPubKey = EnsureBuffer(info[5], "theirSignedPubKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
  }

  if (isInitiator) {
    if (hasOurSignedKey) {
      Napi::Error::New(env, "Invalid call to initSession").ThrowAsJavaScriptException();
      return env.Null();
    }
    if (!hasOurEphemeralKey) {
      Napi::Error::New(env, "Invalid call to initSession").ThrowAsJavaScriptException();
      return env.Null();
    }
    ourSignedKey = ourEphemeralKey;
    hasOurSignedKey = true;
  } else {
    if (hasTheirSignedPubKey) {
      Napi::Error::New(env, "Invalid call to initSession").ThrowAsJavaScriptException();
      return env.Null();
    }
    if (!hasTheirEphemeralPubKey) {
      Napi::Error::New(env, "Invalid call to initSession").ThrowAsJavaScriptException();
      return env.Null();
    }
    theirSignedPubKey = theirEphemeralPubKey;
    hasTheirSignedPubKey = true;
  }

  if (!hasOurSignedKey || !hasTheirSignedPubKey) {
    Napi::Error::New(env, "Invalid call to initSession").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object ourIdentityKey = EnsureObject(info[7], "ourIdentityKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> ourIdentityPrivKey =
      EnsurePrivateKey(ourIdentityKey.Get("privKey"), "ourIdentityKey.privKey");
  Napi::Buffer<uint8_t> ourSignedPrivKey =
      EnsurePrivateKey(ourSignedKey.Get("privKey"), "ourSignedKey.privKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> normalizedTheirSignedPubKey =
      NormalizePublicKey(theirSignedPubKey, "theirSignedPubKey");
  Napi::Buffer<uint8_t> normalizedTheirIdentityPubKey =
      NormalizePublicKey(theirIdentityPubKey, "theirIdentityPubKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> a1 =
      CalculateAgreementInternal(env, normalizedTheirSignedPubKey, ourIdentityPrivKey);
  Napi::Buffer<uint8_t> a2 =
      CalculateAgreementInternal(env, normalizedTheirIdentityPubKey, ourSignedPrivKey);
  Napi::Buffer<uint8_t> a3 =
      CalculateAgreementInternal(env, normalizedTheirSignedPubKey, ourSignedPrivKey);
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> a4;
  Napi::Buffer<uint8_t>* a4Ptr = nullptr;
  if (hasOurEphemeralKey && hasTheirEphemeralPubKey) {
    Napi::Buffer<uint8_t> ourEphemeralPrivKey =
        EnsurePrivateKey(ourEphemeralKey.Get("privKey"), "ourEphemeralKey.privKey");
    Napi::Buffer<uint8_t> normalizedTheirEphemeralPubKey =
        NormalizePublicKey(theirEphemeralPubKey, "theirEphemeralPubKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    a4 = CalculateAgreementInternal(env, normalizedTheirEphemeralPubKey, ourEphemeralPrivKey);
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    a4Ptr = &a4;
  }

  Napi::Buffer<uint8_t> sharedSecret =
      BuildSessionSharedSecretRawInternal(env, isInitiator, a1, a2, a3, a4Ptr);
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Buffer<uint8_t> zeroSalt =
      Napi::Buffer<uint8_t>::Copy(env, kZeroSaltBytes, sizeof(kZeroSaltBytes));
  std::vector<Napi::Buffer<uint8_t>> masterKey =
      DeriveSecretsInternal(env, sharedSecret, zeroSalt, kWhisperTextInfo, 3);
  ZeroBuffer(a1);
  ZeroBuffer(a2);
  ZeroBuffer(a3);
  if (a4Ptr != nullptr) {
    ZeroBuffer(a4);
  }
  ZeroBuffer(sharedSecret);
  ZeroBuffer(zeroSalt);
  if (env.IsExceptionPending() || masterKey.size() < 2) {
    return env.Null();
  }

  Napi::Object session = Napi::Object::New(env);
  session.Set("_chains", Napi::Object::New(env));
  session.Set("registrationId", info[6].As<Napi::Number>());

  Napi::Object currentRatchet = Napi::Object::New(env);
  currentRatchet.Set("rootKey", masterKey[0]);
  if (isInitiator) {
    currentRatchet.Set("ephemeralKeyPair", GenerateCurveKeyPairInternal(env));
  } else {
    currentRatchet.Set("ephemeralKeyPair", ourSignedKey);
  }
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  currentRatchet.Set("lastRemoteEphemeralKey", theirSignedPubKey);
  currentRatchet.Set("previousCounter", Napi::Number::New(env, 0));
  session.Set("currentRatchet", currentRatchet);

  Napi::Object indexInfo = Napi::Object::New(env);
  const double now = UnixTimeMsNow();
  indexInfo.Set("created", Napi::Number::New(env, now));
  indexInfo.Set("used", Napi::Number::New(env, now));
  indexInfo.Set("remoteIdentityKey", theirIdentityPubKey);
  if (isInitiator) {
    Napi::Buffer<uint8_t> baseKey = EnsureBuffer(ourEphemeralKey.Get("pubKey"), "ourEphemeralKey.pubKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    indexInfo.Set("baseKey", baseKey);
    indexInfo.Set("baseKeyType", Napi::Number::New(env, kBaseKeyTypeOurs));
  } else {
    indexInfo.Set("baseKey", theirEphemeralPubKey);
    indexInfo.Set("baseKeyType", Napi::Number::New(env, kBaseKeyTypeTheirs));
  }
  indexInfo.Set("closed", Napi::Number::New(env, -1));
  session.Set("indexInfo", indexInfo);

  if (isInitiator) {
    if (!CalculateSendingRatchetInternal(env, session, theirSignedPubKey)) {
      return env.Null();
    }
  }

  return session;
}

Napi::Value SessionBuilderCalculateSendingRatchet(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "sessionBuilderCalculateSendingRatchet(session, remoteKey) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object session = EnsureObject(info[0], "session");
  Napi::Buffer<uint8_t> remoteKey = EnsureBuffer(info[1], "remoteKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (!CalculateSendingRatchetInternal(env, session, remoteKey)) {
    return env.Null();
  }
  return env.Undefined();
}

Napi::Value SessionCipherCalculateRatchet(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[2].IsBoolean()) {
    Napi::TypeError::New(env, "sessionCipherCalculateRatchet(session, remoteKey, sending) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object session = EnsureObject(info[0], "session");
  Napi::Buffer<uint8_t> remoteKey = EnsureBuffer(info[1], "remoteKey");
  const bool sending = info[2].As<Napi::Boolean>().Value();
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (!CalculateRatchetInternal(env, session, remoteKey, sending)) {
    return env.Null();
  }
  return env.Undefined();
}

Napi::Value SessionCipherMaybeStepRatchet(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[2].IsNumber()) {
    Napi::TypeError::New(env, "sessionCipherMaybeStepRatchet(session, remoteKey, previousCounter) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object session = EnsureObject(info[0], "session");
  Napi::Buffer<uint8_t> remoteKey = EnsureBuffer(info[1], "remoteKey");
  const int64_t previousCounter = info[2].As<Napi::Number>().Int64Value();
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (!MaybeStepRatchetInternal(env, session, remoteKey, previousCounter)) {
    return env.Null();
  }
  return env.Undefined();
}

Napi::Value SessionCipherEncryptWhisperMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(
        env,
        "sessionCipherEncryptWhisperMessage(session, data, ourIdentityKey[, version]) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object session = EnsureObject(info[0], "session");
  Napi::Buffer<uint8_t> data = EnsureBuffer(info[1], "data");
  Napi::Buffer<uint8_t> ourIdentityKey = EnsureBuffer(info[2], "ourIdentityKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  uint32_t version = 3;
  if (info.Length() > 3 && info[3].IsNumber()) {
    version = info[3].As<Napi::Number>().Uint32Value();
  }
  if (version < 1 || version > 15) {
    Napi::RangeError::New(env, "version must be in range 1..15").ThrowAsJavaScriptException();
    return env.Null();
  }
  const uint8_t versionTuple = static_cast<uint8_t>(((version & 0x0fU) << 4) | (version & 0x0fU));

  Napi::Object ratchet = EnsureObject(session.Get("currentRatchet"), "session.currentRatchet");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Object ephemeralKeyPair =
      EnsureObject(ratchet.Get("ephemeralKeyPair"), "session.currentRatchet.ephemeralKeyPair");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Buffer<uint8_t> ephemeralPub =
      EnsureBuffer(ephemeralKeyPair.Get("pubKey"), "session.currentRatchet.ephemeralKeyPair.pubKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Value chainVal = GetSessionChainByKey(env, session, ephemeralPub);
  if (!chainVal.IsObject()) {
    Napi::Error::New(env, "No chain for current ephemeral key").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object chain = chainVal.As<Napi::Object>();
  Napi::Value chainTypeVal = chain.Get("chainType");
  if (!chainTypeVal.IsNumber()) {
    Napi::TypeError::New(env, "chain.chainType must be a number").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (chainTypeVal.As<Napi::Number>().Int32Value() == kChainTypeReceiving) {
    Napi::Error::New(env, "Tried to encrypt on a receiving chain").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object chainKey = EnsureObject(chain.Get("chainKey"), "chain.chainKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value counterVal = chainKey.Get("counter");
  if (!counterVal.IsNumber()) {
    Napi::TypeError::New(env, "chain.chainKey.counter must be a number").ThrowAsJavaScriptException();
    return env.Null();
  }
  const int64_t nextCounter = counterVal.As<Napi::Number>().Int64Value() + 1;
  if (!FillMessageKeysInternal(env, chain, nextCounter)) {
    return env.Null();
  }

  Napi::Value counterAfterVal = chainKey.Get("counter");
  if (!counterAfterVal.IsNumber()) {
    Napi::TypeError::New(env, "chain.chainKey.counter must be a number").ThrowAsJavaScriptException();
    return env.Null();
  }
  const int64_t counter = counterAfterVal.As<Napi::Number>().Int64Value();

  Napi::Object messageKeys = EnsureObject(chain.Get("messageKeys"), "chain.messageKeys");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  const std::string counterKey = std::to_string(counter);
  Napi::Value messageKeyVal = messageKeys.Get(counterKey);
  if (!messageKeyVal.IsBuffer() && !(messageKeyVal.IsTypedArray() &&
                                     messageKeyVal.As<Napi::TypedArray>().TypedArrayType() == napi_uint8_array)) {
    Napi::Error::New(env, "Key used already or never filled").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> messageKey = EnsureBuffer(messageKeyVal, "message key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> zeroSalt =
      Napi::Buffer<uint8_t>::Copy(env, kZeroSaltBytes, sizeof(kZeroSaltBytes));
  std::vector<Napi::Buffer<uint8_t>> keys =
      DeriveSecretsInternal(env, messageKey, zeroSalt, kWhisperMessageKeysInfo, 3);
  ZeroBuffer(messageKey);
  messageKeys.Delete(counterKey);
  if (env.IsExceptionPending() || keys.size() < 3) {
    return env.Null();
  }
  if (keys[2].Length() < 16) {
    Napi::Error::New(env, "Derived IV material too short").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> iv = Napi::Buffer<uint8_t>::Copy(env, keys[2].Data(), 16);
  Napi::Buffer<uint8_t> ciphertext = EncryptAes256CbcRaw(env, keys[0], data, iv);
  if (env.IsExceptionPending()) {
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    ZeroBuffer(iv);
    return env.Null();
  }

  Napi::Value previousCounterVal = ratchet.Get("previousCounter");
  if (!previousCounterVal.IsNumber()) {
    Napi::TypeError::New(env, "session.currentRatchet.previousCounter must be a number")
        .ThrowAsJavaScriptException();
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    ZeroBuffer(iv);
    return env.Null();
  }
  const uint32_t previousCounter = previousCounterVal.As<Napi::Number>().Uint32Value();
  Napi::Buffer<uint8_t> messageProto =
      SerializeWhisperMessageRaw(env, ephemeralPub, static_cast<uint32_t>(counter), previousCounter, ciphertext);
  if (env.IsExceptionPending()) {
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    ZeroBuffer(iv);
    return env.Null();
  }

  Napi::Object indexInfo = EnsureObject(session.Get("indexInfo"), "session.indexInfo");
  Napi::Buffer<uint8_t> remoteIdentityKey =
      EnsureBuffer(indexInfo.Get("remoteIdentityKey"), "session.indexInfo.remoteIdentityKey");
  if (env.IsExceptionPending()) {
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    ZeroBuffer(iv);
    return env.Null();
  }

  Napi::Buffer<uint8_t> macInput =
      BuildWhisperMacInputRaw(env, ourIdentityKey, remoteIdentityKey, versionTuple, messageProto);
  if (env.IsExceptionPending()) {
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    ZeroBuffer(iv);
    return env.Null();
  }
  Napi::Buffer<uint8_t> mac = CalculateMacRaw(env, keys[1], macInput);
  Napi::Buffer<uint8_t> frame = AssembleWhisperFrameRaw(env, versionTuple, messageProto, mac, 8);

  ZeroBuffer(keys[0]);
  ZeroBuffer(keys[1]);
  ZeroBuffer(keys[2]);
  ZeroBuffer(iv);
  ZeroBuffer(macInput);

  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return frame;
}

Napi::Value SessionCipherDecryptWhisperMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(
        env,
        "sessionCipherDecryptWhisperMessage(session, messageBuffer, ourIdentityKey[, version]) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object session = EnsureObject(info[0], "session");
  Napi::Buffer<uint8_t> messageBuffer = EnsureBuffer(info[1], "messageBuffer");
  Napi::Buffer<uint8_t> ourIdentityKey = EnsureBuffer(info[2], "ourIdentityKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (messageBuffer.Length() < 9) {
    Napi::Error::New(env, "Incompatible version number on WhisperMessage")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  uint32_t version = 3;
  if (info.Length() > 3 && info[3].IsNumber()) {
    version = info[3].As<Napi::Number>().Uint32Value();
  }
  const uint8_t versionByte = messageBuffer.Data()[0];
  const uint32_t versionMajor = static_cast<uint32_t>(versionByte >> 4);
  const uint32_t versionMinor = static_cast<uint32_t>(versionByte & 0x0fU);
  if (versionMinor > version || versionMajor < version) {
    Napi::Error::New(env, "Incompatible version number on WhisperMessage")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  const uint8_t versionTuple = static_cast<uint8_t>(((version & 0x0fU) << 4) | (version & 0x0fU));

  const size_t protoLength = messageBuffer.Length() - 9;
  Napi::Buffer<uint8_t> messageProto =
      Napi::Buffer<uint8_t>::Copy(env, messageBuffer.Data() + 1, protoLength);
  Napi::Buffer<uint8_t> incomingMac =
      Napi::Buffer<uint8_t>::Copy(env, messageBuffer.Data() + 1 + protoLength, 8);

  textsecure::WhisperMessage message;
  if (!ParseWhisperMessageRaw(env, messageProto, &message)) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> ephemeralKey = Napi::Buffer<uint8_t>::Copy(
      env, reinterpret_cast<const uint8_t*>(message.ephemeralkey().data()), message.ephemeralkey().size());
  if (!MaybeStepRatchetInternal(env, session, ephemeralKey, message.previouscounter())) {
    return env.Null();
  }

  Napi::Value chainVal = GetSessionChainByKey(env, session, ephemeralKey);
  if (!chainVal.IsObject()) {
    Napi::Error::New(env, "No matching sessions found for message").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object chain = chainVal.As<Napi::Object>();
  Napi::Value chainTypeVal = chain.Get("chainType");
  if (!chainTypeVal.IsNumber()) {
    Napi::TypeError::New(env, "chain.chainType must be a number").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (chainTypeVal.As<Napi::Number>().Int32Value() == kChainTypeSending) {
    Napi::Error::New(env, "Tried to decrypt on a sending chain").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!FillMessageKeysInternal(env, chain, message.counter())) {
    return env.Null();
  }

  Napi::Object messageKeys = EnsureObject(chain.Get("messageKeys"), "chain.messageKeys");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  const std::string counterKey = std::to_string(message.counter());
  Napi::Value messageKeyVal = messageKeys.Get(counterKey);
  if (!messageKeyVal.IsBuffer() && !(messageKeyVal.IsTypedArray() &&
                                     messageKeyVal.As<Napi::TypedArray>().TypedArrayType() == napi_uint8_array)) {
    Napi::Error::New(env, "Key used already or never filled").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> messageKey = EnsureBuffer(messageKeyVal, "message key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> zeroSalt =
      Napi::Buffer<uint8_t>::Copy(env, kZeroSaltBytes, sizeof(kZeroSaltBytes));
  std::vector<Napi::Buffer<uint8_t>> keys =
      DeriveSecretsInternal(env, messageKey, zeroSalt, kWhisperMessageKeysInfo, 3);
  ZeroBuffer(messageKey);
  messageKeys.Delete(counterKey);
  if (env.IsExceptionPending() || keys.size() < 3) {
    return env.Null();
  }

  Napi::Object indexInfo = EnsureObject(session.Get("indexInfo"), "session.indexInfo");
  Napi::Buffer<uint8_t> remoteIdentityKey =
      EnsureBuffer(indexInfo.Get("remoteIdentityKey"), "session.indexInfo.remoteIdentityKey");
  if (env.IsExceptionPending()) {
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    return env.Null();
  }
  Napi::Buffer<uint8_t> macInput =
      BuildWhisperMacInputRaw(env, remoteIdentityKey, ourIdentityKey, versionTuple, messageProto);
  if (env.IsExceptionPending()) {
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    return env.Null();
  }
  Napi::Buffer<uint8_t> calculatedMac = CalculateMacRaw(env, keys[1], macInput);
  Napi::Buffer<uint8_t> calculatedMac8 = Napi::Buffer<uint8_t>::Copy(env, calculatedMac.Data(), 8);
  if (!TimingSafeEqualRaw(env, incomingMac, calculatedMac8)) {
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    ZeroBuffer(macInput);
    ZeroBuffer(calculatedMac8);
    Napi::Error::New(env, "Bad MAC").ThrowAsJavaScriptException();
    return env.Null();
  }

  const std::string ciphertextStr = message.ciphertext();
  Napi::Buffer<uint8_t> ciphertext = Napi::Buffer<uint8_t>::Copy(
      env, reinterpret_cast<const uint8_t*>(ciphertextStr.data()), ciphertextStr.size());
  if (keys[2].Length() < 16) {
    ZeroBuffer(keys[0]);
    ZeroBuffer(keys[1]);
    ZeroBuffer(keys[2]);
    ZeroBuffer(macInput);
    ZeroBuffer(calculatedMac8);
    Napi::Error::New(env, "Derived IV material too short").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> iv = Napi::Buffer<uint8_t>::Copy(env, keys[2].Data(), 16);
  Napi::Buffer<uint8_t> plaintext = DecryptAes256CbcRaw(env, keys[0], ciphertext, iv);

  ZeroBuffer(keys[0]);
  ZeroBuffer(keys[1]);
  ZeroBuffer(keys[2]);
  ZeroBuffer(iv);
  ZeroBuffer(macInput);
  ZeroBuffer(calculatedMac8);

  if (env.IsExceptionPending()) {
    return env.Null();
  }

  session.Delete("pendingPreKey");
  return plaintext;
}

Napi::Value EncryptAes256Cbc(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(env, "encryptAes256Cbc(key, data, iv) requires 3 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> key = EnsureBuffer(info[0], "key");
  Napi::Buffer<uint8_t> data = EnsureBuffer(info[1], "data");
  Napi::Buffer<uint8_t> iv = EnsureBuffer(info[2], "iv");
  if (env.IsExceptionPending()) return env.Null();

  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createCipheriv = crypto.Get("createCipheriv").As<Napi::Function>();
  Napi::Object cipher = createCipheriv
                            .Call(crypto, {Napi::String::New(env, "aes-256-cbc"), key, iv})
                            .As<Napi::Object>();
  Napi::Value updated = cipher.Get("update").As<Napi::Function>().Call(cipher, {data});
  Napi::Value final = cipher.Get("final").As<Napi::Function>().Call(cipher, {});
  return BufferConcat(env, {updated, final});
}

Napi::Value DecryptAes256Cbc(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(env, "decryptAes256Cbc(key, data, iv) requires 3 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> key = EnsureBuffer(info[0], "key");
  Napi::Buffer<uint8_t> data = EnsureBuffer(info[1], "data");
  Napi::Buffer<uint8_t> iv = EnsureBuffer(info[2], "iv");
  if (env.IsExceptionPending()) return env.Null();

  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createDecipheriv = crypto.Get("createDecipheriv").As<Napi::Function>();
  Napi::Object decipher = createDecipheriv
                              .Call(crypto, {Napi::String::New(env, "aes-256-cbc"), key, iv})
                              .As<Napi::Object>();
  Napi::Value updated = decipher.Get("update").As<Napi::Function>().Call(decipher, {data});
  Napi::Value final = decipher.Get("final").As<Napi::Function>().Call(decipher, {});
  return BufferConcat(env, {updated, final});
}

Napi::Value CalculateMacSha256(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "calculateMacSha256(key, data) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> key = EnsureBuffer(info[0], "key");
  Napi::Buffer<uint8_t> data = EnsureBuffer(info[1], "data");
  if (env.IsExceptionPending()) return env.Null();
  return CalculateMacRaw(env, key, data);
}

Napi::Value HashSha512(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "hashSha512(data) requires 1 argument").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> data = EnsureBuffer(info[0], "data");
  if (env.IsExceptionPending()) return env.Null();
  return HashRaw(env, data);
}

Napi::Value TimingSafeEqual(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "timingSafeEqual(a, b) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> a = EnsureBuffer(info[0], "a");
  Napi::Buffer<uint8_t> b = EnsureBuffer(info[1], "b");
  if (env.IsExceptionPending()) return env.Null();

  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function fn = crypto.Get("timingSafeEqual").As<Napi::Function>();
  return fn.Call(crypto, {a, b});
}

Napi::Value DeriveSecrets(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(env, "deriveSecrets(input, salt, info[, chunks]) requires 3 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> input = EnsureBuffer(info[0], "input");
  Napi::Buffer<uint8_t> salt = EnsureBuffer(info[1], "salt");
  Napi::Buffer<uint8_t> infoBuf = EnsureBuffer(info[2], "info");
  if (env.IsExceptionPending()) return env.Null();

  if (salt.Length() != 32) {
    Napi::Error::New(env, "Got salt of incorrect length").ThrowAsJavaScriptException();
    return env.Null();
  }

  uint32_t chunks = 3;
  if (info.Length() >= 4 && info[3].IsNumber()) {
    chunks = info[3].As<Napi::Number>().Uint32Value();
  }
  if (chunks < 1 || chunks > 3) {
    Napi::RangeError::New(env, "chunks must be between 1 and 3").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createHmac = crypto.Get("createHmac").As<Napi::Function>();
  Napi::String sha256 = Napi::String::New(env, "sha256");
  Napi::Buffer<uint8_t> prk = CalculateMacRawWithCrypto(env, crypto, createHmac, sha256, salt, input);
  std::vector<uint8_t> infoArray(infoBuf.Length() + 1 + 32, 0);
  std::memcpy(infoArray.data() + 32, infoBuf.Data(), infoBuf.Length());
  infoArray[infoArray.size() - 1] = 1;

  Napi::Array out = Napi::Array::New(env, chunks);
  Napi::Buffer<uint8_t> t1 = CalculateMacRawWithCrypto(
      env, crypto, createHmac, sha256, prk,
      Napi::Buffer<uint8_t>::Copy(env, infoArray.data() + 32, infoArray.size() - 32));
  out.Set(0u, t1);

  if (chunks > 1) {
    std::memcpy(infoArray.data(), t1.Data(), 32);
    infoArray[infoArray.size() - 1] = 2;
    Napi::Buffer<uint8_t> t2 = CalculateMacRawWithCrypto(
        env, crypto, createHmac, sha256, prk,
        Napi::Buffer<uint8_t>::Copy(env, infoArray.data(), infoArray.size()));
    out.Set(1u, t2);
    if (chunks > 2) {
      std::memcpy(infoArray.data(), t2.Data(), 32);
      infoArray[infoArray.size() - 1] = 3;
      Napi::Buffer<uint8_t> t3 = CalculateMacRawWithCrypto(
          env, crypto, createHmac, sha256, prk,
          Napi::Buffer<uint8_t>::Copy(env, infoArray.data(), infoArray.size()));
      out.Set(2u, t3);
    }
  }

  SecureZeroVector(infoArray);
  return out;
}

namespace {
constexpr uint32_t kWhisperFieldEphemeralKey =
    textsecure::WhisperMessage::kEphemeralKeyFieldNumber;
constexpr uint32_t kWhisperFieldCounter = textsecure::WhisperMessage::kCounterFieldNumber;
constexpr uint32_t kWhisperFieldPreviousCounter =
    textsecure::WhisperMessage::kPreviousCounterFieldNumber;
constexpr uint32_t kWhisperFieldCiphertext =
    textsecure::WhisperMessage::kCiphertextFieldNumber;

constexpr uint32_t kPreKeyFieldPreKeyId =
    textsecure::PreKeyWhisperMessage::kPreKeyIdFieldNumber;
constexpr uint32_t kPreKeyFieldBaseKey =
    textsecure::PreKeyWhisperMessage::kBaseKeyFieldNumber;
constexpr uint32_t kPreKeyFieldIdentityKey =
    textsecure::PreKeyWhisperMessage::kIdentityKeyFieldNumber;
constexpr uint32_t kPreKeyFieldMessage =
    textsecure::PreKeyWhisperMessage::kMessageFieldNumber;
constexpr uint32_t kPreKeyFieldRegistrationId =
    textsecure::PreKeyWhisperMessage::kRegistrationIdFieldNumber;
constexpr uint32_t kPreKeyFieldSignedPreKeyId =
    textsecure::PreKeyWhisperMessage::kSignedPreKeyIdFieldNumber;

static_assert(kWhisperFieldEphemeralKey == 1, "Unexpected WhisperMessage.ephemeralKey field id");
static_assert(kWhisperFieldCounter == 2, "Unexpected WhisperMessage.counter field id");
static_assert(kWhisperFieldPreviousCounter == 3,
              "Unexpected WhisperMessage.previousCounter field id");
static_assert(kWhisperFieldCiphertext == 4, "Unexpected WhisperMessage.ciphertext field id");
static_assert(kPreKeyFieldPreKeyId == 1, "Unexpected PreKeyWhisperMessage.preKeyId field id");
static_assert(kPreKeyFieldBaseKey == 2, "Unexpected PreKeyWhisperMessage.baseKey field id");
static_assert(kPreKeyFieldIdentityKey == 3, "Unexpected PreKeyWhisperMessage.identityKey field id");
static_assert(kPreKeyFieldMessage == 4, "Unexpected PreKeyWhisperMessage.message field id");
static_assert(kPreKeyFieldRegistrationId == 5,
              "Unexpected PreKeyWhisperMessage.registrationId field id");
static_assert(kPreKeyFieldSignedPreKeyId == 6,
              "Unexpected PreKeyWhisperMessage.signedPreKeyId field id");

uint32_t EncodedChunk(const uint8_t* hash, std::size_t offset) {
  const uint64_t value = (static_cast<uint64_t>(hash[offset]) << 32) |
                         (static_cast<uint64_t>(hash[offset + 1]) << 24) |
                         (static_cast<uint64_t>(hash[offset + 2]) << 16) |
                         (static_cast<uint64_t>(hash[offset + 3]) << 8) |
                         (static_cast<uint64_t>(hash[offset + 4]));
  return static_cast<uint32_t>(value % 100000ULL);
}

std::string DisplayFingerprint(const Napi::Env& env,
                               const std::string& identifier,
                               const Napi::Buffer<uint8_t>& key,
                               uint32_t iterations) {
  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createHash = crypto.Get("createHash").As<Napi::Function>();
  Napi::String sha512 = Napi::String::New(env, "sha512");

  std::vector<uint8_t> prefix(2);
  prefix[0] = 0;
  prefix[1] = 0;
  std::vector<uint8_t> seed;
  seed.reserve(prefix.size() + key.Length() + identifier.size());
  seed.insert(seed.end(), prefix.begin(), prefix.end());
  seed.insert(seed.end(), key.Data(), key.Data() + key.Length());
  seed.insert(seed.end(), identifier.begin(), identifier.end());

  std::vector<uint8_t> combined;
  combined.reserve(seed.size() + key.Length());
  combined.insert(combined.end(), seed.begin(), seed.end());
  combined.insert(combined.end(), key.Data(), key.Data() + key.Length());

  std::vector<uint8_t> result;
  for (uint32_t i = 0; i < iterations; i++) {
    Napi::Buffer<uint8_t> hashInput = Napi::Buffer<uint8_t>::Copy(env, combined.data(), combined.size());
    Napi::Buffer<uint8_t> hashOutput = HashRawWithCrypto(env, crypto, createHash, sha512, hashInput);
    result.assign(hashOutput.Data(), hashOutput.Data() + hashOutput.Length());
    combined.assign(result.begin(), result.end());
    combined.insert(combined.end(), key.Data(), key.Data() + key.Length());
  }

  std::string out;
  out.reserve(30);
  for (std::size_t i = 0; i < 30; i += 5) {
    uint32_t chunk = EncodedChunk(result.data(), i);
    std::string s = std::to_string(chunk);
    while (s.size() < 5) {
      s = "0" + s;
    }
    out += s;
  }

  SecureZeroVector(prefix);
  SecureZeroVector(seed);
  SecureZeroVector(combined);
  SecureZeroVector(result);
  return out;
}

}  // namespace

Napi::Value NumericFingerprint(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 5 || !info[0].IsString() || !info[2].IsString() || !info[4].IsNumber()) {
    Napi::TypeError::New(
        env,
        "numericFingerprint(localId, localKey, remoteId, remoteKey, iterations) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> localKey = EnsureBuffer(info[1], "localKey");
  Napi::Buffer<uint8_t> remoteKey = EnsureBuffer(info[3], "remoteKey");
  if (env.IsExceptionPending()) return env.Null();

  uint32_t iterations = info[4].As<Napi::Number>().Uint32Value();
  if (iterations < 1) {
    Napi::RangeError::New(env, "iterations must be a positive integer").ThrowAsJavaScriptException();
    return env.Null();
  }

  const std::string localId = info[0].As<Napi::String>().Utf8Value();
  const std::string remoteId = info[2].As<Napi::String>().Utf8Value();
  const std::string left = DisplayFingerprint(env, localId, localKey, iterations);
  const std::string right = DisplayFingerprint(env, remoteId, remoteKey, iterations);
  const std::string result = left < right ? left + right : right + left;
  return Napi::String::New(env, result);
}

Napi::Value BuildSessionSharedSecret(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4 || !info[0].IsBoolean()) {
    Napi::TypeError::New(
        env,
        "buildSessionSharedSecret(isInitiator, a1, a2, a3[, a4]) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> a1 = EnsureBuffer(info[1], "a1");
  Napi::Buffer<uint8_t> a2 = EnsureBuffer(info[2], "a2");
  Napi::Buffer<uint8_t> a3 = EnsureBuffer(info[3], "a3");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (a1.Length() != 32 || a2.Length() != 32 || a3.Length() != 32) {
    Napi::Error::New(env, "a1, a2 and a3 must be 32-byte buffers").ThrowAsJavaScriptException();
    return env.Null();
  }

  bool hasA4 = false;
  Napi::Buffer<uint8_t> a4;
  if (info.Length() > 4 && !info[4].IsUndefined() && !info[4].IsNull()) {
    a4 = EnsureBuffer(info[4], "a4");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    if (a4.Length() != 32) {
      Napi::Error::New(env, "a4 must be a 32-byte buffer").ThrowAsJavaScriptException();
      return env.Null();
    }
    hasA4 = true;
  }

  const bool isInitiator = info[0].As<Napi::Boolean>().Value();
  const size_t totalLength = hasA4 ? 160 : 128;
  Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, totalLength);
  std::memset(out.Data(), 0, out.Length());
  std::memset(out.Data(), 0xff, 32);

  if (isInitiator) {
    std::memcpy(out.Data() + 32, a1.Data(), 32);
    std::memcpy(out.Data() + 64, a2.Data(), 32);
  } else {
    std::memcpy(out.Data() + 64, a1.Data(), 32);
    std::memcpy(out.Data() + 32, a2.Data(), 32);
  }
  std::memcpy(out.Data() + 96, a3.Data(), 32);
  if (hasA4) {
    std::memcpy(out.Data() + 128, a4.Data(), 32);
  }
  return out;
}

Napi::Value FillMessageKeys(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[1].IsNumber()) {
    Napi::TypeError::New(env, "fillMessageKeys(chain, counter) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object chain = EnsureObject(info[0], "chain");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (!chain.Get("chainKey").IsObject()) {
    Napi::TypeError::New(env, "chain.chainKey must be an object").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object chainKey = chain.Get("chainKey").As<Napi::Object>();
  Napi::Value currentCounterVal = chainKey.Get("counter");
  if (!currentCounterVal.IsNumber()) {
    Napi::TypeError::New(env, "chain.chainKey.counter must be a number")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  int64_t currentCounter = currentCounterVal.As<Napi::Number>().Int64Value();
  const int64_t targetCounter = info[1].As<Napi::Number>().Int64Value();
  if (currentCounter >= targetCounter) {
    return env.Undefined();
  }
  if (targetCounter - currentCounter > 2000) {
    Napi::Error::New(env, "Over 2000 messages into the future!").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Value currentKeyVal = chainKey.Get("key");
  if (currentKeyVal.IsUndefined()) {
    Napi::Error::New(env, "Chain closed").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> currentKey = EnsureBuffer(currentKeyVal, "chain.chainKey.key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object messageKeys;
  if (chain.Get("messageKeys").IsObject()) {
    messageKeys = chain.Get("messageKeys").As<Napi::Object>();
  } else {
    messageKeys = Napi::Object::New(env);
    chain.Set("messageKeys", messageKeys);
  }

  constexpr uint8_t oneByte[1] = {1};
  constexpr uint8_t twoByte[1] = {2};
  Napi::Buffer<uint8_t> one = Napi::Buffer<uint8_t>::Copy(env, oneByte, 1);
  Napi::Buffer<uint8_t> two = Napi::Buffer<uint8_t>::Copy(env, twoByte, 1);
  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createHmac = crypto.Get("createHmac").As<Napi::Function>();
  Napi::String sha256 = Napi::String::New(env, "sha256");

  while (currentCounter < targetCounter) {
    Napi::Buffer<uint8_t> messageKey =
        CalculateMacRawWithCrypto(env, crypto, createHmac, sha256, currentKey, one);
    Napi::Buffer<uint8_t> nextKey =
        CalculateMacRawWithCrypto(env, crypto, createHmac, sha256, currentKey, two);
    ++currentCounter;
    messageKeys.Set(std::to_string(currentCounter), messageKey);
    currentKey = nextKey;
  }

  chainKey.Set("counter", Napi::Number::New(env, static_cast<double>(currentCounter)));
  chainKey.Set("key", currentKey);
  return env.Undefined();
}

Napi::Value EncodeTupleByte(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
    Napi::TypeError::New(env, "encodeTupleByte(number1, number2) requires 2 numbers")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  const int32_t n1 = info[0].As<Napi::Number>().Int32Value();
  const int32_t n2 = info[1].As<Napi::Number>().Int32Value();
  if (n1 < 0 || n1 > 15 || n2 < 0 || n2 > 15) {
    Napi::TypeError::New(env, "Numbers must be 4 bits or less").ThrowAsJavaScriptException();
    return env.Null();
  }
  return Napi::Number::New(env, (n1 << 4) | n2);
}

Napi::Value DecodeTupleByte(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "decodeTupleByte(byte) requires 1 number")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  const uint32_t value = info[0].As<Napi::Number>().Uint32Value() & 0xffU;
  Napi::Array out = Napi::Array::New(env, 2);
  out.Set(uint32_t{0}, Napi::Number::New(env, value >> 4));
  out.Set(uint32_t{1}, Napi::Number::New(env, value & 0x0fU));
  return out;
}

Napi::Value BuildWhisperMacInput(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4 || !info[2].IsNumber()) {
    Napi::TypeError::New(
        env,
        "buildWhisperMacInput(leftIdentityKey, rightIdentityKey, versionByte, messageProto)")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> left = EnsureBuffer(info[0], "leftIdentityKey");
  Napi::Buffer<uint8_t> right = EnsureBuffer(info[1], "rightIdentityKey");
  Napi::Buffer<uint8_t> proto = EnsureBuffer(info[3], "messageProto");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (left.Length() != 33 || right.Length() != 33) {
    Napi::Error::New(env, "Identity keys must be 33-byte buffers").ThrowAsJavaScriptException();
    return env.Null();
  }
  const uint32_t versionByte = info[2].As<Napi::Number>().Uint32Value() & 0xffU;
  Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, proto.Length() + 67);
  std::memcpy(out.Data(), left.Data(), 33);
  std::memcpy(out.Data() + 33, right.Data(), 33);
  out.Data()[66] = static_cast<uint8_t>(versionByte);
  std::memcpy(out.Data() + 67, proto.Data(), proto.Length());
  return out;
}

Napi::Value AssembleWhisperFrame(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsNumber()) {
    Napi::TypeError::New(
        env,
        "assembleWhisperFrame(versionByte, messageProto, mac[, macLength]) requires 3 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> messageProto = EnsureBuffer(info[1], "messageProto");
  Napi::Buffer<uint8_t> mac = EnsureBuffer(info[2], "mac");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  uint32_t macLength = 8;
  if (info.Length() > 3 && info[3].IsNumber()) {
    macLength = info[3].As<Napi::Number>().Uint32Value();
  }
  if (macLength > mac.Length()) {
    Napi::RangeError::New(env, "macLength out of bounds").ThrowAsJavaScriptException();
    return env.Null();
  }
  const uint32_t versionByte = info[0].As<Napi::Number>().Uint32Value() & 0xffU;
  Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, messageProto.Length() + macLength + 1);
  out.Data()[0] = static_cast<uint8_t>(versionByte);
  std::memcpy(out.Data() + 1, messageProto.Data(), messageProto.Length());
  std::memcpy(out.Data() + 1 + messageProto.Length(), mac.Data(), macLength);
  return out;
}

namespace {

bool HasValue(const Napi::Object& object, const char* key) {
  if (!object.Has(key)) {
    return false;
  }
  const Napi::Value value = object.Get(key);
  return !value.IsUndefined() && !value.IsNull();
}

void SetProtoBytes(std::string* target, const Napi::Buffer<uint8_t>& value) {
  target->assign(reinterpret_cast<const char*>(value.Data()), value.Length());
}

Napi::Buffer<uint8_t> CopyProtoBytesToBuffer(const Napi::Env& env, const std::string& value) {
  if (value.empty()) {
    return Napi::Buffer<uint8_t>::New(env, 0);
  }
  return Napi::Buffer<uint8_t>::Copy(
      env, reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

bool ParseTupleVersion(const Napi::Env& env, const Napi::Value& value, uint32_t* out) {
  if (!value.IsNumber()) {
    Napi::TypeError::New(env, "version must be a number").ThrowAsJavaScriptException();
    return false;
  }
  const uint32_t version = value.As<Napi::Number>().Uint32Value();
  if (version < 1 || version > 15) {
    Napi::RangeError::New(env, "version must be in range 1..15").ThrowAsJavaScriptException();
    return false;
  }
  *out = version;
  return true;
}

bool PopulatePreKeyWhisperProto(const Napi::Env& env,
                                const Napi::Object& message,
                                textsecure::PreKeyWhisperMessage* proto) {
  if (HasValue(message, "preKeyId")) {
    Napi::Value preKeyIdValue = message.Get("preKeyId");
    if (!preKeyIdValue.IsNumber()) {
      Napi::TypeError::New(env, "message.preKeyId must be a number").ThrowAsJavaScriptException();
      return false;
    }
    proto->set_prekeyid(preKeyIdValue.As<Napi::Number>().Uint32Value());
  }

  if (HasValue(message, "baseKey")) {
    Napi::Buffer<uint8_t> baseKey = EnsureBuffer(message.Get("baseKey"), "message.baseKey");
    if (env.IsExceptionPending()) {
      return false;
    }
    SetProtoBytes(proto->mutable_basekey(), baseKey);
  }

  if (HasValue(message, "identityKey")) {
    Napi::Buffer<uint8_t> identityKey =
        EnsureBuffer(message.Get("identityKey"), "message.identityKey");
    if (env.IsExceptionPending()) {
      return false;
    }
    SetProtoBytes(proto->mutable_identitykey(), identityKey);
  }

  if (HasValue(message, "message")) {
    Napi::Buffer<uint8_t> innerMessage = EnsureBuffer(message.Get("message"), "message.message");
    if (env.IsExceptionPending()) {
      return false;
    }
    SetProtoBytes(proto->mutable_message(), innerMessage);
  }

  if (HasValue(message, "registrationId")) {
    Napi::Value registrationIdValue = message.Get("registrationId");
    if (!registrationIdValue.IsNumber()) {
      Napi::TypeError::New(env, "message.registrationId must be a number")
          .ThrowAsJavaScriptException();
      return false;
    }
    proto->set_registrationid(registrationIdValue.As<Napi::Number>().Uint32Value());
  }

  if (HasValue(message, "signedPreKeyId")) {
    Napi::Value signedPreKeyIdValue = message.Get("signedPreKeyId");
    if (!signedPreKeyIdValue.IsNumber()) {
      Napi::TypeError::New(env, "message.signedPreKeyId must be a number")
          .ThrowAsJavaScriptException();
      return false;
    }
    proto->set_signedprekeyid(signedPreKeyIdValue.As<Napi::Number>().Uint32Value());
  }

  return true;
}

Napi::Object PreKeyWhisperProtoToObject(const Napi::Env& env,
                                        const textsecure::PreKeyWhisperMessage& proto) {
  Napi::Object message = Napi::Object::New(env);
  message.Set("registrationId", Napi::Number::New(env, proto.registrationid()));
  message.Set("preKeyId", Napi::Number::New(env, proto.prekeyid()));
  message.Set("signedPreKeyId", Napi::Number::New(env, proto.signedprekeyid()));
  message.Set("baseKey", CopyProtoBytesToBuffer(env, proto.basekey()));
  message.Set("identityKey", CopyProtoBytesToBuffer(env, proto.identitykey()));
  message.Set("message", CopyProtoBytesToBuffer(env, proto.message()));
  return message;
}

template <typename ProtoMessage>
bool SerializeProtoMessage(const Napi::Env& env,
                           const ProtoMessage& message,
                           const char* errorMessage,
                           Napi::Buffer<uint8_t>* out) {
  const size_t byteSize = message.ByteSizeLong();
  if (byteSize > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    Napi::RangeError::New(env, "Protobuf message too large").ThrowAsJavaScriptException();
    return false;
  }

  *out = Napi::Buffer<uint8_t>::New(env, byteSize);
  if (byteSize == 0) {
    return true;
  }
  if (!message.SerializeToArray(out->Data(), static_cast<int>(byteSize))) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return false;
  }
  return true;
}

template <typename ProtoMessage>
bool ParseProtoMessage(const Napi::Env& env,
                       const Napi::Buffer<uint8_t>& data,
                       const char* errorMessage,
                       ProtoMessage* out) {
  if (data.Length() > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    Napi::RangeError::New(env, "Protobuf message too large").ThrowAsJavaScriptException();
    return false;
  }
  if (!out->ParseFromArray(data.Data(), static_cast<int>(data.Length()))) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return false;
  }
  return true;
}

}  // namespace

Napi::Value ProtobufEncodeWhisperMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "protobufEncodeWhisperMessage(message) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object message = EnsureObject(info[0], "message");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  textsecure::WhisperMessage proto;

  if (HasValue(message, "ephemeralKey")) {
    Napi::Buffer<uint8_t> ephemeralKey = EnsureBuffer(message.Get("ephemeralKey"), "message.ephemeralKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    SetProtoBytes(proto.mutable_ephemeralkey(), ephemeralKey);
  }

  if (HasValue(message, "counter")) {
    Napi::Value counterValue = message.Get("counter");
    if (!counterValue.IsNumber()) {
      Napi::TypeError::New(env, "message.counter must be a number").ThrowAsJavaScriptException();
      return env.Null();
    }
    proto.set_counter(counterValue.As<Napi::Number>().Uint32Value());
  }

  if (HasValue(message, "previousCounter")) {
    Napi::Value previousCounterValue = message.Get("previousCounter");
    if (!previousCounterValue.IsNumber()) {
      Napi::TypeError::New(env, "message.previousCounter must be a number")
          .ThrowAsJavaScriptException();
      return env.Null();
    }
    proto.set_previouscounter(previousCounterValue.As<Napi::Number>().Uint32Value());
  }

  if (HasValue(message, "ciphertext")) {
    Napi::Buffer<uint8_t> ciphertext = EnsureBuffer(message.Get("ciphertext"), "message.ciphertext");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    SetProtoBytes(proto.mutable_ciphertext(), ciphertext);
  }

  Napi::Buffer<uint8_t> out;
  if (!SerializeProtoMessage(env, proto, "Failed to serialize WhisperMessage protobuf", &out)) {
    return env.Null();
  }
  return out;
}

Napi::Value ProtobufDecodeWhisperMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "protobufDecodeWhisperMessage(data) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> data = EnsureBuffer(info[0], "data");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  textsecure::WhisperMessage proto;
  if (!ParseProtoMessage(env, data, "Invalid WhisperMessage protobuf", &proto)) {
    return env.Null();
  }

  Napi::Object message = Napi::Object::New(env);
  message.Set("ephemeralKey", CopyProtoBytesToBuffer(env, proto.ephemeralkey()));
  message.Set("counter", Napi::Number::New(env, proto.counter()));
  message.Set("previousCounter", Napi::Number::New(env, proto.previouscounter()));
  message.Set("ciphertext", CopyProtoBytesToBuffer(env, proto.ciphertext()));

  return message;
}

Napi::Value ProtobufEncodePreKeyWhisperMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "protobufEncodePreKeyWhisperMessage(message) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object message = EnsureObject(info[0], "message");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  textsecure::PreKeyWhisperMessage proto;
  if (!PopulatePreKeyWhisperProto(env, message, &proto)) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> out;
  if (!SerializeProtoMessage(env, proto, "Failed to serialize PreKeyWhisperMessage protobuf", &out)) {
    return env.Null();
  }
  return out;
}

Napi::Value ProtobufDecodePreKeyWhisperMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "protobufDecodePreKeyWhisperMessage(data) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> data = EnsureBuffer(info[0], "data");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  textsecure::PreKeyWhisperMessage proto;
  if (!ParseProtoMessage(env, data, "Invalid PreKeyWhisperMessage protobuf", &proto)) {
    return env.Null();
  }

  return PreKeyWhisperProtoToObject(env, proto);
}

Napi::Value SessionCipherEncodePreKeyWhisperMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env,
                         "sessionCipherEncodePreKeyWhisperMessage(message[, version]) requires 1 "
                         "argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object message = EnsureObject(info[0], "message");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  uint32_t version = 3;
  if (info.Length() > 1) {
    if (!ParseTupleVersion(env, info[1], &version)) {
      return env.Null();
    }
  }

  textsecure::PreKeyWhisperMessage proto;
  if (!PopulatePreKeyWhisperProto(env, message, &proto)) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> protoBytes;
  if (!SerializeProtoMessage(
          env, proto, "Failed to serialize PreKeyWhisperMessage protobuf", &protoBytes)) {
    return env.Null();
  }

  Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, protoBytes.Length() + 1);
  out.Data()[0] =
      static_cast<uint8_t>(((version & 0x0fU) << 4) | (version & 0x0fU));
  if (protoBytes.Length() > 0) {
    std::memcpy(out.Data() + 1, protoBytes.Data(), protoBytes.Length());
  }
  return out;
}

Napi::Value SessionCipherDecodePreKeyWhisperMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env,
                         "sessionCipherDecodePreKeyWhisperMessage(data[, version]) requires 1 "
                         "argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> data = EnsureBuffer(info[0], "data");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (data.Length() < 1) {
    Napi::Error::New(env, "Incompatible version number on PreKeyWhisperMessage")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  uint32_t version = 3;
  if (info.Length() > 1) {
    if (!ParseTupleVersion(env, info[1], &version)) {
      return env.Null();
    }
  }

  const uint8_t versionByte = data.Data()[0];
  const uint32_t versionMajor = static_cast<uint32_t>(versionByte >> 4);
  const uint32_t versionMinor = static_cast<uint32_t>(versionByte & 0x0fU);
  if (versionMinor > version || versionMajor < version) {
    Napi::Error::New(env, "Incompatible version number on PreKeyWhisperMessage")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  textsecure::PreKeyWhisperMessage proto;
  const size_t payloadLength = data.Length() - 1;
  if (payloadLength > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    Napi::RangeError::New(env, "Protobuf message too large").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!proto.ParseFromArray(data.Data() + 1, static_cast<int>(payloadLength))) {
    Napi::Error::New(env, "Invalid PreKeyWhisperMessage protobuf").ThrowAsJavaScriptException();
    return env.Null();
  }

  return PreKeyWhisperProtoToObject(env, proto);
}

}  // namespace libsignal_native
