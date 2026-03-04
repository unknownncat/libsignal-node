#include "libsignal_native.h"

#include <cstring>
#include <limits>

namespace libsignal_native {

Napi::Object RequireModule(const Napi::Env& env, const char* name) {
  Napi::Object global = env.Global();
  Napi::Function require = global.Get("require").As<Napi::Function>();
  return require.Call(global, {Napi::String::New(env, name)}).As<Napi::Object>();
}

Napi::Object EnsureObject(const Napi::Value& value, const char* name) {
  Napi::Env env = value.Env();
  if (!value.IsObject()) {
    Napi::TypeError::New(env, std::string(name) + " must be an object").ThrowAsJavaScriptException();
    return Napi::Object();
  }
  return value.As<Napi::Object>();
}

Napi::Buffer<uint8_t> EnsureBuffer(const Napi::Value& value, const char* name) {
  Napi::Env env = value.Env();
  if (!value.IsBuffer()) {
    if (value.IsTypedArray()) {
      Napi::TypedArray typed = value.As<Napi::TypedArray>();
      if (typed.TypedArrayType() == napi_uint8_array) {
        Napi::Uint8Array input = value.As<Napi::Uint8Array>();
        return Napi::Buffer<uint8_t>::Copy(env, input.Data(), input.ByteLength());
      }
    }
    Napi::TypeError::New(env, std::string(name) + " must be a Uint8Array")
        .ThrowAsJavaScriptException();
    return Napi::Buffer<uint8_t>();
  }
  return value.As<Napi::Buffer<uint8_t>>();
}

Napi::Function EnsureFunction(const Napi::Value& value, const char* name) {
  Napi::Env env = value.Env();
  if (!value.IsFunction()) {
    Napi::TypeError::New(env, std::string(name) + " must be a function").ThrowAsJavaScriptException();
    return Napi::Function();
  }
  return value.As<Napi::Function>();
}

Napi::Buffer<uint8_t> BufferConcat(const Napi::Env& env, std::initializer_list<Napi::Value> values) {
  Napi::Object bufferCtor = env.Global().Get("Buffer").As<Napi::Object>();
  Napi::Function concat = bufferCtor.Get("concat").As<Napi::Function>();
  Napi::Array arr = Napi::Array::New(env, static_cast<uint32_t>(values.size()));
  uint32_t idx = 0;
  for (const Napi::Value& v : values) {
    arr.Set(idx++, v);
  }
  return concat.Call(bufferCtor, {arr}).As<Napi::Buffer<uint8_t>>();
}

std::string BufferToBase64(const Napi::Buffer<uint8_t>& buffer) {
  Napi::Env env = buffer.Env();
  Napi::Object asObject = buffer.As<Napi::Object>();
  Napi::Function toStringFn = asObject.Get("toString").As<Napi::Function>();
  return toStringFn.Call(asObject, {Napi::String::New(env, "base64")})
      .As<Napi::String>()
      .Utf8Value();
}

std::vector<uint8_t> CopyBufferToVector(const Napi::Buffer<uint8_t>& buffer) {
  return std::vector<uint8_t>(buffer.Data(), buffer.Data() + buffer.Length());
}

void SecureZeroMemory(void* ptr, size_t len) {
  volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
  while (len > 0) {
    *p++ = 0;
    --len;
  }
}

void SecureZeroVector(std::vector<uint8_t>& data) {
  if (!data.empty()) {
    SecureZeroMemory(data.data(), data.size());
    data.clear();
  }
}

Napi::Buffer<uint8_t> CalculateMacRawWithCrypto(const Napi::Env& env,
                                                const Napi::Object& crypto,
                                                const Napi::Function& createHmac,
                                                const Napi::String& algorithm,
                                                const Napi::Buffer<uint8_t>& key,
                                                const Napi::Buffer<uint8_t>& data) {
  Napi::Object hmac = createHmac.Call(crypto, {algorithm, key}).As<Napi::Object>();
  hmac.Get("update").As<Napi::Function>().Call(hmac, {data});
  return hmac.Get("digest").As<Napi::Function>().Call(hmac, {}).As<Napi::Buffer<uint8_t>>();
}

Napi::Buffer<uint8_t> CalculateMacRaw(const Napi::Env& env,
                                      const Napi::Buffer<uint8_t>& key,
                                      const Napi::Buffer<uint8_t>& data) {
  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createHmac = crypto.Get("createHmac").As<Napi::Function>();
  return CalculateMacRawWithCrypto(
      env, crypto, createHmac, Napi::String::New(env, "sha256"), key, data);
}

Napi::Buffer<uint8_t> HashRawWithCrypto(const Napi::Env& env,
                                        const Napi::Object& crypto,
                                        const Napi::Function& createHash,
                                        const Napi::String& algorithm,
                                        const Napi::Buffer<uint8_t>& data) {
  Napi::Object hash = createHash.Call(crypto, {algorithm}).As<Napi::Object>();
  hash.Get("update").As<Napi::Function>().Call(hash, {data});
  return hash.Get("digest").As<Napi::Function>().Call(hash, {}).As<Napi::Buffer<uint8_t>>();
}

Napi::Buffer<uint8_t> HashRaw(const Napi::Env& env, const Napi::Buffer<uint8_t>& data) {
  Napi::Object crypto = RequireModule(env, "crypto");
  Napi::Function createHash = crypto.Get("createHash").As<Napi::Function>();
  return HashRawWithCrypto(env, crypto, createHash, Napi::String::New(env, "sha512"), data);
}

Napi::Object GetIndexInfo(const Napi::Object& session) {
  Napi::Value indexInfoVal = session.Get("indexInfo");
  if (!indexInfoVal.IsObject()) {
    return Napi::Object();
  }
  return indexInfoVal.As<Napi::Object>();
}

bool IsClosedSession(const Napi::Object& session) {
  Napi::Object indexInfo = GetIndexInfo(session);
  if (indexInfo.IsEmpty()) {
    return true;
  }
  Napi::Value closedVal = indexInfo.Get("closed");
  if (!closedVal.IsNumber()) {
    return true;
  }
  return closedVal.As<Napi::Number>().Int64Value() != -1;
}

double SessionUsedAt(const Napi::Object& session) {
  Napi::Object indexInfo = GetIndexInfo(session);
  if (indexInfo.IsEmpty()) {
    return 0;
  }
  Napi::Value usedVal = indexInfo.Get("used");
  if (!usedVal.IsNumber()) {
    return 0;
  }
  return usedVal.As<Napi::Number>().DoubleValue();
}

double SessionClosedAt(const Napi::Object& session) {
  Napi::Object indexInfo = GetIndexInfo(session);
  if (indexInfo.IsEmpty()) {
    return std::numeric_limits<double>::infinity();
  }
  Napi::Value closedVal = indexInfo.Get("closed");
  if (!closedVal.IsNumber()) {
    return std::numeric_limits<double>::infinity();
  }
  return closedVal.As<Napi::Number>().DoubleValue();
}

Napi::Value FindOpenSessionValue(const Napi::Env& env, const Napi::Object& sessions) {
  Napi::Array keys = sessions.GetPropertyNames();
  const uint32_t length = keys.Length();
  for (uint32_t i = 0; i < length; ++i) {
    Napi::Value key = keys.Get(i);
    Napi::Value sessionVal = sessions.Get(key);
    if (!sessionVal.IsObject()) {
      continue;
    }
    Napi::Object session = sessionVal.As<Napi::Object>();
    if (!IsClosedSession(session)) {
      return session;
    }
  }
  return env.Undefined();
}

}  // namespace libsignal_native
