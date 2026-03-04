#include "libsignal_native.h"
#include "proto/WhisperTextProtocol.pb.h"

#include <uv.h>

#include <algorithm>
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

template <typename ProtoMessage>
bool SerializeProtoMessage(const Napi::Env& env,
                           const ProtoMessage& message,
                           const char* errorMessage,
                           Napi::Buffer<uint8_t>* out) {
  const size_t byteSize = message.ByteSizeLong();
  if (byteSize > static_cast<size_t>(std::numeric_limits<int>::max())) {
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
  if (data.Length() > static_cast<size_t>(std::numeric_limits<int>::max())) {
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

  if (HasValue(message, "preKeyId")) {
    Napi::Value preKeyIdValue = message.Get("preKeyId");
    if (!preKeyIdValue.IsNumber()) {
      Napi::TypeError::New(env, "message.preKeyId must be a number").ThrowAsJavaScriptException();
      return env.Null();
    }
    proto.set_prekeyid(preKeyIdValue.As<Napi::Number>().Uint32Value());
  }

  if (HasValue(message, "baseKey")) {
    Napi::Buffer<uint8_t> baseKey = EnsureBuffer(message.Get("baseKey"), "message.baseKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    SetProtoBytes(proto.mutable_basekey(), baseKey);
  }

  if (HasValue(message, "identityKey")) {
    Napi::Buffer<uint8_t> identityKey =
        EnsureBuffer(message.Get("identityKey"), "message.identityKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    SetProtoBytes(proto.mutable_identitykey(), identityKey);
  }

  if (HasValue(message, "message")) {
    Napi::Buffer<uint8_t> innerMessage = EnsureBuffer(message.Get("message"), "message.message");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    SetProtoBytes(proto.mutable_message(), innerMessage);
  }

  if (HasValue(message, "registrationId")) {
    Napi::Value registrationIdValue = message.Get("registrationId");
    if (!registrationIdValue.IsNumber()) {
      Napi::TypeError::New(env, "message.registrationId must be a number")
          .ThrowAsJavaScriptException();
      return env.Null();
    }
    proto.set_registrationid(registrationIdValue.As<Napi::Number>().Uint32Value());
  }

  if (HasValue(message, "signedPreKeyId")) {
    Napi::Value signedPreKeyIdValue = message.Get("signedPreKeyId");
    if (!signedPreKeyIdValue.IsNumber()) {
      Napi::TypeError::New(env, "message.signedPreKeyId must be a number")
          .ThrowAsJavaScriptException();
      return env.Null();
    }
    proto.set_signedprekeyid(signedPreKeyIdValue.As<Napi::Number>().Uint32Value());
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

  Napi::Object message = Napi::Object::New(env);
  message.Set("registrationId", Napi::Number::New(env, proto.registrationid()));
  message.Set("preKeyId", Napi::Number::New(env, proto.prekeyid()));
  message.Set("signedPreKeyId", Napi::Number::New(env, proto.signedprekeyid()));
  message.Set("baseKey", CopyProtoBytesToBuffer(env, proto.basekey()));
  message.Set("identityKey", CopyProtoBytesToBuffer(env, proto.identitykey()));
  message.Set("message", CopyProtoBytesToBuffer(env, proto.message()));

  return message;
}

}  // namespace libsignal_native
