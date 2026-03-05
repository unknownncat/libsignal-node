#include "libsignal_native.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace libsignal_native {

namespace {

struct QueueTailState {
  uint64_t token = 0;
  std::unique_ptr<Napi::ObjectReference> tailRef;
};

struct QueueCleanupData {
  std::string bucket;
  uint64_t token = 0;
};

struct AwaitableInvokerData {
  Napi::FunctionReference awaitableRef;

  explicit AwaitableInvokerData(const Napi::Function& awaitable)
      : awaitableRef(Napi::Persistent(awaitable)) {}
};

std::unordered_map<std::string, QueueTailState> g_queueTailByBucket;
uint64_t g_nextQueueToken = 0;

Napi::Value ReturnUndefined(const Napi::CallbackInfo& info) {
  return info.Env().Undefined();
}

Napi::Value InvokeAwaitableNoArgs(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* data = static_cast<AwaitableInvokerData*>(info.Data());
  if (data == nullptr) {
    Napi::Error::New(env, "Invalid queue state").ThrowAsJavaScriptException();
    return env.Null();
  }
  try {
    Napi::Value out = data->awaitableRef.Value().Call(env.Global(), {});
    delete data;
    return out;
  } catch (...) {
    delete data;
    throw;
  }
}

Napi::Value CleanupQueueBucketIfTail(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* data = static_cast<QueueCleanupData*>(info.Data());
  if (data == nullptr) {
    return env.Undefined();
  }
  auto it = g_queueTailByBucket.find(data->bucket);
  if (it != g_queueTailByBucket.end() && it->second.token == data->token) {
    g_queueTailByBucket.erase(it);
  }
  delete data;
  return env.Undefined();
}

Napi::Buffer<uint8_t> Base64ToBuffer(const Napi::Env& env, const std::string& value) {
  Napi::Object bufferCtor = env.Global().Get("Buffer").As<Napi::Object>();
  Napi::Function from = bufferCtor.Get("from").As<Napi::Function>();
  return from
      .Call(bufferCtor, {Napi::String::New(env, value), Napi::String::New(env, "base64")})
      .As<Napi::Buffer<uint8_t>>();
}

Napi::Object SerializeMessageKeys(const Napi::Env& env, const Napi::Object& messageKeys) {
  Napi::Object out = Napi::Object::New(env);
  Napi::Array keys = messageKeys.GetPropertyNames();
  for (uint32_t i = 0; i < keys.Length(); ++i) {
    Napi::Value key = keys.Get(i);
    Napi::Value value = messageKeys.Get(key);
    Napi::Buffer<uint8_t> bytes = EnsureBuffer(value, "chain.messageKeys.*");
    if (env.IsExceptionPending()) {
      return Napi::Object();
    }
    out.Set(key, Napi::String::New(env, BufferToBase64(bytes)));
  }
  return out;
}

Napi::Object DeserializeMessageKeys(const Napi::Env& env, const Napi::Object& messageKeys) {
  Napi::Object out = Napi::Object::New(env);
  Napi::Array keys = messageKeys.GetPropertyNames();
  for (uint32_t i = 0; i < keys.Length(); ++i) {
    Napi::Value key = keys.Get(i);
    Napi::Value value = messageKeys.Get(key);
    if (!value.IsString()) {
      Napi::TypeError::New(env, "chain.messageKeys.* must be a base64 string")
          .ThrowAsJavaScriptException();
      return Napi::Object();
    }
    out.Set(key, Base64ToBuffer(env, value.As<Napi::String>().Utf8Value()));
  }
  return out;
}

Napi::Object SerializeChains(const Napi::Env& env, const Napi::Object& chains) {
  Napi::Object out = Napi::Object::New(env);
  Napi::Array keys = chains.GetPropertyNames();
  for (uint32_t i = 0; i < keys.Length(); ++i) {
    Napi::Value key = keys.Get(i);
    Napi::Object chain = EnsureObject(chains.Get(key), "chain");
    if (env.IsExceptionPending()) {
      return Napi::Object();
    }

    Napi::Object chainKey = EnsureObject(chain.Get("chainKey"), "chain.chainKey");
    if (env.IsExceptionPending()) {
      return Napi::Object();
    }
    Napi::Object chainOut = Napi::Object::New(env);
    Napi::Object chainKeyOut = Napi::Object::New(env);
    chainKeyOut.Set("counter", chainKey.Get("counter"));
    if (!chainKey.Get("key").IsUndefined() && !chainKey.Get("key").IsNull()) {
      Napi::Buffer<uint8_t> chainKeyBytes = EnsureBuffer(chainKey.Get("key"), "chain.chainKey.key");
      if (env.IsExceptionPending()) {
        return Napi::Object();
      }
      chainKeyOut.Set("key", Napi::String::New(env, BufferToBase64(chainKeyBytes)));
    }
    chainOut.Set("chainKey", chainKeyOut);
    chainOut.Set("chainType", chain.Get("chainType"));
    Napi::Object messageKeys =
        chain.Get("messageKeys").IsObject() ? chain.Get("messageKeys").As<Napi::Object>()
                                            : Napi::Object::New(env);
    chainOut.Set("messageKeys", SerializeMessageKeys(env, messageKeys));
    if (env.IsExceptionPending()) {
      return Napi::Object();
    }
    out.Set(key, chainOut);
  }
  return out;
}

Napi::Object DeserializeChains(const Napi::Env& env, const Napi::Object& chainsData) {
  Napi::Object out = Napi::Object::New(env);
  Napi::Array keys = chainsData.GetPropertyNames();
  for (uint32_t i = 0; i < keys.Length(); ++i) {
    Napi::Value key = keys.Get(i);
    Napi::Object chainData = EnsureObject(chainsData.Get(key), "chain data");
    if (env.IsExceptionPending()) {
      return Napi::Object();
    }

    Napi::Object chain = Napi::Object::New(env);
    Napi::Object chainKeyData = EnsureObject(chainData.Get("chainKey"), "chainData.chainKey");
    if (env.IsExceptionPending()) {
      return Napi::Object();
    }
    Napi::Object chainKey = Napi::Object::New(env);
    chainKey.Set("counter", chainKeyData.Get("counter"));
    if (!chainKeyData.Get("key").IsUndefined() && !chainKeyData.Get("key").IsNull()) {
      if (!chainKeyData.Get("key").IsString()) {
        Napi::TypeError::New(env, "chainData.chainKey.key must be a base64 string")
            .ThrowAsJavaScriptException();
        return Napi::Object();
      }
      chainKey.Set("key", Base64ToBuffer(env, chainKeyData.Get("key").As<Napi::String>().Utf8Value()));
    }
    chain.Set("chainKey", chainKey);
    chain.Set("chainType", chainData.Get("chainType"));
    Napi::Object messageKeysData = chainData.Get("messageKeys").IsObject()
                                       ? chainData.Get("messageKeys").As<Napi::Object>()
                                       : Napi::Object::New(env);
    chain.Set("messageKeys", DeserializeMessageKeys(env, messageKeysData));
    if (env.IsExceptionPending()) {
      return Napi::Object();
    }
    out.Set(key, chain);
  }
  return out;
}

}  // namespace

Napi::Value QueueJobByBucket(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString()) {
    Napi::TypeError::New(env, "queueJobByBucket(bucket, awaitable) requires bucket string")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Function awaitable = EnsureFunction(info[1], "awaitable");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  const std::string bucket = info[0].As<Napi::String>().Utf8Value();
  Napi::Object promiseCtor = env.Global().Get("Promise").As<Napi::Object>();
  Napi::Function promiseResolve = promiseCtor.Get("resolve").As<Napi::Function>();

  Napi::Value previousTail = env.Undefined();
  auto previousIt = g_queueTailByBucket.find(bucket);
  if (previousIt != g_queueTailByBucket.end() && previousIt->second.tailRef) {
    previousTail = previousIt->second.tailRef->Value();
  }

  Napi::Object previousPromise = promiseResolve.Call(promiseCtor, {previousTail}).As<Napi::Object>();
  auto* invokerData = new AwaitableInvokerData(awaitable);
  Napi::Function invoker =
      Napi::Function::New(env, InvokeAwaitableNoArgs, "invokeAwaitableNoArgs", invokerData);
  Napi::Function previousThen = previousPromise.Get("then").As<Napi::Function>();
  Napi::Object runPromise = previousThen.Call(previousPromise, {invoker, invoker}).As<Napi::Object>();

  Napi::Function swallow = Napi::Function::New(env, ReturnUndefined);
  Napi::Function runThen = runPromise.Get("then").As<Napi::Function>();
  Napi::Object tailPromise = runThen.Call(runPromise, {swallow, swallow}).As<Napi::Object>();

  const uint64_t token = ++g_nextQueueToken;
  QueueTailState state;
  state.token = token;
  state.tailRef = std::make_unique<Napi::ObjectReference>(Napi::Persistent(tailPromise));
  g_queueTailByBucket[bucket] = std::move(state);

  auto* cleanupData = new QueueCleanupData{bucket, token};
  Napi::Function cleanupFn = Napi::Function::New(
      env, CleanupQueueBucketIfTail, "cleanupQueueBucketIfTail", cleanupData);
  Napi::Function finallyFn = tailPromise.Get("finally").As<Napi::Function>();
  finallyFn.Call(tailPromise, {cleanupFn});

  return runPromise;
}

namespace {

Napi::Value ResolvePromiseValue(const Napi::Env& env, const Napi::Value& value) {
  Napi::Object promiseCtor = env.Global().Get("Promise").As<Napi::Object>();
  Napi::Function promiseResolve = promiseCtor.Get("resolve").As<Napi::Function>();
  return promiseResolve.Call(promiseCtor, {value});
}

Napi::Value CallStorageMethodResolved(const Napi::Env& env,
                                      const Napi::Object& storage,
                                      const char* methodName,
                                      std::initializer_list<Napi::Value> args) {
  Napi::Function method = EnsureFunction(storage.Get(methodName), methodName);
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value result = method.Call(storage, args);
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return ResolvePromiseValue(env, result);
}

bool IsTruthy(const Napi::Value& value) {
  if (value.IsUndefined() || value.IsNull()) {
    return false;
  }
  return value.ToBoolean().Value();
}

void ConsoleError(const Napi::Env& env, std::initializer_list<Napi::Value> args) {
  Napi::Value consoleVal = env.Global().Get("console");
  if (!consoleVal.IsObject()) {
    return;
  }
  Napi::Object console = consoleVal.As<Napi::Object>();
  Napi::Value errorVal = console.Get("error");
  if (!errorVal.IsFunction()) {
    return;
  }
  errorVal.As<Napi::Function>().Call(console, args);
}

Napi::Value CallAddonMethod(const Napi::Env& env,
                            const Napi::Object& addon,
                            const char* methodName,
                            std::initializer_list<Napi::Value> args) {
  Napi::Function method = EnsureFunction(addon.Get(methodName), methodName);
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return method.Call(addon, args);
}

Napi::Object ChainPromiseThen(const Napi::Env& env,
                              const Napi::Object& promise,
                              const Napi::Function& onFulfilled) {
  Napi::Function thenFn = EnsureFunction(promise.Get("then"), "promise.then");
  if (env.IsExceptionPending()) {
    return Napi::Object();
  }
  return thenFn.Call(promise, {onFulfilled}).As<Napi::Object>();
}

struct SessionBuilderOutgoingState {
  std::unique_ptr<Napi::ObjectReference> storageRef;
  std::unique_ptr<Napi::ObjectReference> addonRef;
  std::unique_ptr<Napi::ObjectReference> deviceRef;
  std::unique_ptr<Napi::FunctionReference> sessionRecordCtorRef;
  std::unique_ptr<Napi::ObjectReference> baseKeyRef;
  std::unique_ptr<Napi::ObjectReference> sessionRef;
  std::string fullyQualifiedAddress;
  std::string identifier;

  SessionBuilderOutgoingState(const Napi::Object& storage,
                              const Napi::Object& addon,
                              const Napi::Object& device,
                              const Napi::Function& sessionRecordCtor,
                              std::string address,
                              std::string id)
      : storageRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(storage))),
        addonRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(addon))),
        deviceRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(device))),
        sessionRecordCtorRef(
            std::make_unique<Napi::FunctionReference>(Napi::Persistent(sessionRecordCtor))),
        fullyQualifiedAddress(std::move(address)),
        identifier(std::move(id)) {}
};

struct SessionBuilderIncomingState {
  std::unique_ptr<Napi::ObjectReference> storageRef;
  std::unique_ptr<Napi::ObjectReference> addonRef;
  std::unique_ptr<Napi::ObjectReference> recordRef;
  std::unique_ptr<Napi::ObjectReference> messageRef;
  std::unique_ptr<Napi::ObjectReference> preKeyPairRef;
  std::unique_ptr<Napi::ObjectReference> signedPreKeyPairRef;
  std::string identifier;

  SessionBuilderIncomingState(const Napi::Object& storage,
                              const Napi::Object& addon,
                              const Napi::Object& record,
                              const Napi::Object& message,
                              std::string id)
      : storageRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(storage))),
        addonRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(addon))),
        recordRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(record))),
        messageRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(message))),
        identifier(std::move(id)) {}
};

struct SessionCipherDecryptWithSessionsState {
  std::unique_ptr<Napi::ObjectReference> storageRef;
  std::unique_ptr<Napi::ObjectReference> addonRef;
  std::unique_ptr<Napi::ObjectReference> sessionsRef;
  std::unique_ptr<Napi::ObjectReference> messageBufferRef;
  uint32_t version = 3;

  SessionCipherDecryptWithSessionsState(const Napi::Object& storage,
                                        const Napi::Object& addon,
                                        const Napi::Array& sessions,
                                        const Napi::Buffer<uint8_t>& messageBuffer,
                                        uint32_t messageVersion)
      : storageRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(storage))),
        addonRef(std::make_unique<Napi::ObjectReference>(Napi::Persistent(addon))),
        sessionsRef(std::make_unique<Napi::ObjectReference>(
            Napi::Persistent(sessions.As<Napi::Object>()))),
        messageBufferRef(std::make_unique<Napi::ObjectReference>(
            Napi::Persistent(messageBuffer.As<Napi::Object>()))),
        version(messageVersion) {}
};

Napi::Value CleanupSessionBuilderOutgoingState(const Napi::CallbackInfo& info) {
  auto* state = static_cast<SessionBuilderOutgoingState*>(info.Data());
  delete state;
  return info.Env().Undefined();
}

Napi::Value CleanupSessionBuilderIncomingState(const Napi::CallbackInfo& info) {
  auto* state = static_cast<SessionBuilderIncomingState*>(info.Data());
  delete state;
  return info.Env().Undefined();
}

Napi::Value CleanupSessionCipherDecryptWithSessionsState(const Napi::CallbackInfo& info) {
  auto* state = static_cast<SessionCipherDecryptWithSessionsState*>(info.Data());
  delete state;
  return info.Env().Undefined();
}

Napi::Value SessionBuilderInitOutgoingAfterTrusted(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* state = static_cast<SessionBuilderOutgoingState*>(info.Data());
  if (state == nullptr) {
    Napi::Error::New(env, "Invalid outgoing init state").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (info.Length() < 1 || !info[0].ToBoolean().Value()) {
    Napi::Error::New(env, "UNTRUSTED_IDENTITY").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object addon = state->addonRef->Value();
  Napi::Object device = state->deviceRef->Value();
  Napi::Object signedPreKey = EnsureObject(device.Get("signedPreKey"), "device.signedPreKey");
  Napi::Buffer<uint8_t> identityKey = EnsureBuffer(device.Get("identityKey"), "device.identityKey");
  Napi::Buffer<uint8_t> signedPreKeyPublicKey =
      EnsureBuffer(signedPreKey.Get("publicKey"), "device.signedPreKey.publicKey");
  Napi::Buffer<uint8_t> signedPreKeySignature =
      EnsureBuffer(signedPreKey.Get("signature"), "device.signedPreKey.signature");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  CallAddonMethod(
      env, addon, "curveVerifySignature",
      {identityKey, signedPreKeyPublicKey, signedPreKeySignature});
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Value baseKeyValue = CallAddonMethod(env, addon, "curveGenerateKeyPair", {});
  Napi::Object baseKey = EnsureObject(baseKeyValue, "baseKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  state->baseKeyRef = std::make_unique<Napi::ObjectReference>(Napi::Persistent(baseKey));

  return CallStorageMethodResolved(env, state->storageRef->Value(), "getOurIdentity", {});
}

Napi::Value SessionBuilderInitOutgoingAfterIdentity(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* state = static_cast<SessionBuilderOutgoingState*>(info.Data());
  if (state == nullptr) {
    Napi::Error::New(env, "Invalid outgoing init state").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object ourIdentityKey = EnsureObject(info[0], "ourIdentityKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object addon = state->addonRef->Value();
  Napi::Object device = state->deviceRef->Value();
  Napi::Object signedPreKey = EnsureObject(device.Get("signedPreKey"), "device.signedPreKey");
  Napi::Object baseKey = state->baseKeyRef->Value();
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Value preKeyValue = device.Get("preKey");
  Napi::Value theirEphemeralPubKey = env.Undefined();
  if (!preKeyValue.IsUndefined() && !preKeyValue.IsNull()) {
    Napi::Object preKey = EnsureObject(preKeyValue, "device.preKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    theirEphemeralPubKey = EnsureBuffer(preKey.Get("publicKey"), "device.preKey.publicKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
  }

  Napi::Buffer<uint8_t> theirIdentityPubKey =
      EnsureBuffer(device.Get("identityKey"), "device.identityKey");
  Napi::Buffer<uint8_t> theirSignedPubKey =
      EnsureBuffer(signedPreKey.Get("publicKey"), "device.signedPreKey.publicKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Value sessionValue = CallAddonMethod(
      env, addon, "sessionBuilderInitSession",
      {Napi::Boolean::New(env, true), baseKey, env.Undefined(), theirIdentityPubKey,
       theirEphemeralPubKey, theirSignedPubKey, device.Get("registrationId"), ourIdentityKey});
  Napi::Object session = EnsureObject(sessionValue, "session");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object pendingPreKey = Napi::Object::New(env);
  pendingPreKey.Set("signedKeyId", signedPreKey.Get("keyId"));
  pendingPreKey.Set("baseKey", baseKey.Get("pubKey"));
  if (!preKeyValue.IsUndefined() && !preKeyValue.IsNull()) {
    Napi::Object preKey = EnsureObject(preKeyValue, "device.preKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    pendingPreKey.Set("preKeyId", preKey.Get("keyId"));
  }
  session.Set("pendingPreKey", pendingPreKey);
  state->sessionRef = std::make_unique<Napi::ObjectReference>(Napi::Persistent(session));

  return CallStorageMethodResolved(
      env, state->storageRef->Value(), "loadSession",
      {Napi::String::New(env, state->fullyQualifiedAddress)});
}

Napi::Value SessionBuilderInitOutgoingAfterLoadRecord(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* state = static_cast<SessionBuilderOutgoingState*>(info.Data());
  if (state == nullptr) {
    Napi::Error::New(env, "Invalid outgoing init state").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object record;
  if (info.Length() > 0 && info[0].IsObject()) {
    record = info[0].As<Napi::Object>();
  } else {
    record = state->sessionRecordCtorRef->Value().New({});
  }

  Napi::Function getOpenSession = EnsureFunction(record.Get("getOpenSession"), "record.getOpenSession");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value openSession = getOpenSession.Call(record, {});
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (openSession.IsObject()) {
    Napi::Function closeSession = EnsureFunction(record.Get("closeSession"), "record.closeSession");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    closeSession.Call(record, {openSession});
    if (env.IsExceptionPending()) {
      return env.Null();
    }
  }

  Napi::Function setSession = EnsureFunction(record.Get("setSession"), "record.setSession");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  setSession.Call(record, {state->sessionRef->Value()});
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  return CallStorageMethodResolved(
      env, state->storageRef->Value(), "storeSession",
      {Napi::String::New(env, state->fullyQualifiedAddress), record});
}

Napi::Value SessionBuilderInitIncomingAfterTrusted(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* state = static_cast<SessionBuilderIncomingState*>(info.Data());
  if (state == nullptr) {
    Napi::Error::New(env, "Invalid incoming init state").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (info.Length() < 1 || !info[0].ToBoolean().Value()) {
    Napi::Error::New(env, "UNTRUSTED_IDENTITY").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object record = state->recordRef->Value();
  Napi::Object message = state->messageRef->Value();
  Napi::Buffer<uint8_t> baseKey = EnsureBuffer(message.Get("baseKey"), "message.baseKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Function getSession = EnsureFunction(record.Get("getSession"), "record.getSession");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value existingSession = getSession.Call(record, {baseKey});
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (existingSession.IsObject()) {
    return env.Undefined();
  }

  return CallStorageMethodResolved(
      env, state->storageRef->Value(), "loadPreKey", {message.Get("preKeyId")});
}

Napi::Value SessionBuilderInitIncomingAfterPreKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* state = static_cast<SessionBuilderIncomingState*>(info.Data());
  if (state == nullptr) {
    Napi::Error::New(env, "Invalid incoming init state").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object message = state->messageRef->Value();
  Napi::Value preKeyId = message.Get("preKeyId");
  if (IsTruthy(preKeyId) && (info.Length() < 1 || !info[0].IsObject())) {
    Napi::Error::New(env, "INVALID_PREKEY_ID").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (info.Length() > 0 && info[0].IsObject()) {
    state->preKeyPairRef =
        std::make_unique<Napi::ObjectReference>(Napi::Persistent(info[0].As<Napi::Object>()));
  } else {
    state->preKeyPairRef.reset();
  }

  return CallStorageMethodResolved(
      env, state->storageRef->Value(), "loadSignedPreKey", {message.Get("signedPreKeyId")});
}

Napi::Value SessionBuilderInitIncomingAfterSignedPreKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* state = static_cast<SessionBuilderIncomingState*>(info.Data());
  if (state == nullptr) {
    Napi::Error::New(env, "Invalid incoming init state").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (info.Length() < 1 || !info[0].IsObject()) {
    Napi::Error::New(env, "MISSING_SIGNED_PREKEY").ThrowAsJavaScriptException();
    return env.Null();
  }
  state->signedPreKeyPairRef =
      std::make_unique<Napi::ObjectReference>(Napi::Persistent(info[0].As<Napi::Object>()));
  return CallStorageMethodResolved(env, state->storageRef->Value(), "getOurIdentity", {});
}

Napi::Value SessionBuilderInitIncomingAfterIdentity(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* state = static_cast<SessionBuilderIncomingState*>(info.Data());
  if (state == nullptr) {
    Napi::Error::New(env, "Invalid incoming init state").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object ourIdentity = EnsureObject(info[0], "ourIdentityKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Object addon = state->addonRef->Value();
  Napi::Object record = state->recordRef->Value();
  Napi::Object message = state->messageRef->Value();

  Napi::Value preKeyPair = env.Undefined();
  if (state->preKeyPairRef) {
    preKeyPair = state->preKeyPairRef->Value();
  }
  Napi::Object signedPreKeyPair = state->signedPreKeyPairRef->Value();
  Napi::Buffer<uint8_t> identityKey = EnsureBuffer(message.Get("identityKey"), "message.identityKey");
  Napi::Buffer<uint8_t> baseKey = EnsureBuffer(message.Get("baseKey"), "message.baseKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Value sessionValue = CallAddonMethod(
      env, addon, "sessionBuilderInitSession",
      {Napi::Boolean::New(env, false), preKeyPair, signedPreKeyPair, identityKey, baseKey,
       env.Undefined(), message.Get("registrationId"), ourIdentity});
  Napi::Object session = EnsureObject(sessionValue, "session");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Function getOpenSession = EnsureFunction(record.Get("getOpenSession"), "record.getOpenSession");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value existingOpenSession = getOpenSession.Call(record, {});
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (existingOpenSession.IsObject()) {
    Napi::Function closeSession = EnsureFunction(record.Get("closeSession"), "record.closeSession");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    closeSession.Call(record, {existingOpenSession});
    if (env.IsExceptionPending()) {
      return env.Null();
    }
  }

  Napi::Function setSession = EnsureFunction(record.Get("setSession"), "record.setSession");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  setSession.Call(record, {session});
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  return message.Get("preKeyId");
}

Napi::Value SessionCipherDecryptWithSessionsAfterIdentity(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* state = static_cast<SessionCipherDecryptWithSessionsState*>(info.Data());
  if (state == nullptr) {
    Napi::Error::New(env, "Invalid decrypt state").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object ourIdentity = EnsureObject(info[0], "ourIdentityKey");
  Napi::Buffer<uint8_t> ourIdentityPubKey =
      EnsureBuffer(ourIdentity.Get("pubKey"), "ourIdentityKey.pubKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object addon = state->addonRef->Value();
  Napi::Array sessions = state->sessionsRef->Value().As<Napi::Array>();
  Napi::Buffer<uint8_t> messageBuffer = state->messageBufferRef->Value().As<Napi::Buffer<uint8_t>>();
  std::vector<std::string> errors;
  errors.reserve(sessions.Length());
  for (uint32_t i = 0; i < sessions.Length(); ++i) {
    Napi::Value sessionValue = sessions.Get(i);
    if (!sessionValue.IsObject()) {
      continue;
    }
    Napi::Object session = sessionValue.As<Napi::Object>();
    Napi::Value plaintext = CallAddonMethod(
        env, addon, "sessionCipherDecryptWhisperMessage",
        {session, messageBuffer, ourIdentityPubKey, Napi::Number::New(env, state->version)});
    if (env.IsExceptionPending()) {
      Napi::Error error = env.GetAndClearPendingException();
      std::string message = "Unknown error";
      Napi::Value messageValue = error.Value().Get("message");
      if (messageValue.IsString()) {
        message = messageValue.As<Napi::String>().Utf8Value();
      }
      Napi::Value stackValue = error.Value().Get("stack");
      if (stackValue.IsString()) {
        message += " ";
        message += stackValue.As<Napi::String>().Utf8Value();
      }
      errors.push_back(std::move(message));
      continue;
    }

    Napi::Value indexInfoValue = session.Get("indexInfo");
    if (indexInfoValue.IsObject()) {
      Napi::Object indexInfo = indexInfoValue.As<Napi::Object>();
      const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
      indexInfo.Set("used", Napi::Number::New(env, static_cast<double>(nowMs)));
    }

    Napi::Object result = Napi::Object::New(env);
    result.Set("session", session);
    result.Set("plaintext", plaintext);
    return result;
  }

  ConsoleError(env, {Napi::String::New(env, "Failed to decrypt message with any known session...")});
  for (const std::string& error : errors) {
    ConsoleError(env, {Napi::String::New(env, "Session error:" + error)});
  }
  Napi::Error::New(env, "No matching sessions found for message").ThrowAsJavaScriptException();
  return env.Null();
}

}  // namespace

Napi::Value AdapterIsTrustedIdentity(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(
        env,
        "adapterIsTrustedIdentity(storage, identifier, identityKey[, direction]) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object storage = EnsureObject(info[0], "storage");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (!info[1].IsString()) {
    Napi::TypeError::New(env, "identifier must be a string").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> identityKey = EnsureBuffer(info[2], "identityKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (info.Length() > 3) {
    return CallStorageMethodResolved(env, storage, "isTrustedIdentity",
                                     {info[1], identityKey, info[3]});
  }
  return CallStorageMethodResolved(env, storage, "isTrustedIdentity", {info[1], identityKey});
}

Napi::Value AdapterLoadSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[1].IsString()) {
    Napi::TypeError::New(env, "adapterLoadSession(storage, id) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object storage = EnsureObject(info[0], "storage");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return CallStorageMethodResolved(env, storage, "loadSession", {info[1]});
}

Napi::Value AdapterStoreSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[1].IsString()) {
    Napi::TypeError::New(env, "adapterStoreSession(storage, id, session) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object storage = EnsureObject(info[0], "storage");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return CallStorageMethodResolved(env, storage, "storeSession", {info[1], info[2]});
}

Napi::Value AdapterLoadPreKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "adapterLoadPreKey(storage, id) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object storage = EnsureObject(info[0], "storage");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return CallStorageMethodResolved(env, storage, "loadPreKey", {info[1]});
}

Napi::Value AdapterRemovePreKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "adapterRemovePreKey(storage, id) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object storage = EnsureObject(info[0], "storage");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return CallStorageMethodResolved(env, storage, "removePreKey", {info[1]});
}

Napi::Value AdapterLoadSignedPreKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "adapterLoadSignedPreKey(storage, id) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object storage = EnsureObject(info[0], "storage");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return CallStorageMethodResolved(env, storage, "loadSignedPreKey", {info[1]});
}

Napi::Value AdapterGetOurRegistrationId(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "adapterGetOurRegistrationId(storage) requires storage")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object storage = EnsureObject(info[0], "storage");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return CallStorageMethodResolved(env, storage, "getOurRegistrationId", {});
}

Napi::Value AdapterGetOurIdentity(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "adapterGetOurIdentity(storage) requires storage")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object storage = EnsureObject(info[0], "storage");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return CallStorageMethodResolved(env, storage, "getOurIdentity", {});
}

Napi::Value SessionBuilderInitOutgoing(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 5 || !info[1].IsString() || !info[2].IsString()) {
    Napi::TypeError::New(
        env,
        "sessionBuilderInitOutgoing(storage, fullyQualifiedAddress, identifier, device, "
        "sessionRecordCtor) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object storage = EnsureObject(info[0], "storage");
  Napi::Object device = EnsureObject(info[3], "device");
  Napi::Function sessionRecordCtor = EnsureFunction(info[4], "sessionRecordCtor");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object addon =
      info.This().IsObject() ? info.This().As<Napi::Object>() : Napi::Object::New(env);
  auto* state =
      new SessionBuilderOutgoingState(storage, addon, device, sessionRecordCtor,
                                      info[1].As<Napi::String>().Utf8Value(),
                                      info[2].As<Napi::String>().Utf8Value());

  Napi::Buffer<uint8_t> identityKey = EnsureBuffer(device.Get("identityKey"), "device.identityKey");
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Value trustedPromiseValue = CallStorageMethodResolved(
      env, storage, "isTrustedIdentity",
      {Napi::String::New(env, state->identifier), identityKey});
  if (env.IsExceptionPending() || !trustedPromiseValue.IsObject()) {
    delete state;
    return env.Null();
  }

  Napi::Object chain = trustedPromiseValue.As<Napi::Object>();
  Napi::Function stepTrusted = Napi::Function::New(
      env, SessionBuilderInitOutgoingAfterTrusted, "sessionBuilderInitOutgoingAfterTrusted",
      state);
  chain = ChainPromiseThen(env, chain, stepTrusted);
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Function stepIdentity = Napi::Function::New(
      env, SessionBuilderInitOutgoingAfterIdentity, "sessionBuilderInitOutgoingAfterIdentity",
      state);
  chain = ChainPromiseThen(env, chain, stepIdentity);
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Function stepLoadRecord = Napi::Function::New(
      env, SessionBuilderInitOutgoingAfterLoadRecord,
      "sessionBuilderInitOutgoingAfterLoadRecord", state);
  chain = ChainPromiseThen(env, chain, stepLoadRecord);
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Function cleanup =
      Napi::Function::New(env, CleanupSessionBuilderOutgoingState,
                          "cleanupSessionBuilderOutgoingState", state);
  Napi::Function thenFn = EnsureFunction(chain.Get("then"), "promise.then");
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }
  thenFn.Call(chain, {cleanup, cleanup});
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }
  return chain;
}

Napi::Value SessionBuilderInitIncoming(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4 || !info[1].IsString()) {
    Napi::TypeError::New(
        env,
        "sessionBuilderInitIncoming(storage, identifier, record, message) requires valid "
        "arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object storage = EnsureObject(info[0], "storage");
  Napi::Object record = EnsureObject(info[2], "record");
  Napi::Object message = EnsureObject(info[3], "message");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object addon =
      info.This().IsObject() ? info.This().As<Napi::Object>() : Napi::Object::New(env);
  auto* state = new SessionBuilderIncomingState(
      storage, addon, record, message, info[1].As<Napi::String>().Utf8Value());

  Napi::Buffer<uint8_t> identityKey = EnsureBuffer(message.Get("identityKey"), "message.identityKey");
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Value trustedPromiseValue = CallStorageMethodResolved(
      env, storage, "isTrustedIdentity",
      {Napi::String::New(env, state->identifier), identityKey});
  if (env.IsExceptionPending() || !trustedPromiseValue.IsObject()) {
    delete state;
    return env.Null();
  }

  Napi::Object chain = trustedPromiseValue.As<Napi::Object>();
  Napi::Function stepTrusted = Napi::Function::New(
      env, SessionBuilderInitIncomingAfterTrusted, "sessionBuilderInitIncomingAfterTrusted",
      state);
  chain = ChainPromiseThen(env, chain, stepTrusted);
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Function stepPreKey = Napi::Function::New(
      env, SessionBuilderInitIncomingAfterPreKey, "sessionBuilderInitIncomingAfterPreKey",
      state);
  chain = ChainPromiseThen(env, chain, stepPreKey);
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Function stepSignedPreKey =
      Napi::Function::New(env, SessionBuilderInitIncomingAfterSignedPreKey,
                          "sessionBuilderInitIncomingAfterSignedPreKey", state);
  chain = ChainPromiseThen(env, chain, stepSignedPreKey);
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Function stepIdentity = Napi::Function::New(
      env, SessionBuilderInitIncomingAfterIdentity, "sessionBuilderInitIncomingAfterIdentity",
      state);
  chain = ChainPromiseThen(env, chain, stepIdentity);
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Function cleanup =
      Napi::Function::New(env, CleanupSessionBuilderIncomingState,
                          "cleanupSessionBuilderIncomingState", state);
  Napi::Function thenFn = EnsureFunction(chain.Get("then"), "promise.then");
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }
  thenFn.Call(chain, {cleanup, cleanup});
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }
  return chain;
}

Napi::Value SessionCipherDecryptWithSessions(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[2].IsArray()) {
    Napi::TypeError::New(
        env,
        "sessionCipherDecryptWithSessions(storage, messageBuffer, sessions[, version]) requires "
        "valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object storage = EnsureObject(info[0], "storage");
  Napi::Buffer<uint8_t> messageBuffer = EnsureBuffer(info[1], "messageBuffer");
  Napi::Array sessions = info[2].As<Napi::Array>();
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (sessions.Length() == 0) {
    Napi::Error::New(env, "No sessions available").ThrowAsJavaScriptException();
    return env.Null();
  }

  uint32_t version = 3;
  if (info.Length() > 3 && !info[3].IsUndefined() && !info[3].IsNull()) {
    if (!info[3].IsNumber()) {
      Napi::TypeError::New(env, "version must be a number").ThrowAsJavaScriptException();
      return env.Null();
    }
    version = info[3].As<Napi::Number>().Uint32Value();
    if (version < 1 || version > 15) {
      Napi::RangeError::New(env, "version must be in range 1..15")
          .ThrowAsJavaScriptException();
      return env.Null();
    }
  }

  Napi::Object addon =
      info.This().IsObject() ? info.This().As<Napi::Object>() : Napi::Object::New(env);
  auto* state = new SessionCipherDecryptWithSessionsState(
      storage, addon, sessions, messageBuffer, version);

  Napi::Value identityPromise =
      CallStorageMethodResolved(env, storage, "getOurIdentity", {});
  if (env.IsExceptionPending() || !identityPromise.IsObject()) {
    delete state;
    return env.Null();
  }

  Napi::Object chain = identityPromise.As<Napi::Object>();
  Napi::Function stepIdentity = Napi::Function::New(
      env, SessionCipherDecryptWithSessionsAfterIdentity,
      "sessionCipherDecryptWithSessionsAfterIdentity", state);
  chain = ChainPromiseThen(env, chain, stepIdentity);
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }

  Napi::Function cleanup = Napi::Function::New(
      env, CleanupSessionCipherDecryptWithSessionsState,
      "cleanupSessionCipherDecryptWithSessionsState", state);
  Napi::Function thenFn = EnsureFunction(chain.Get("then"), "promise.then");
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }
  thenFn.Call(chain, {cleanup, cleanup});
  if (env.IsExceptionPending()) {
    delete state;
    return env.Null();
  }
  return chain;
}

Napi::Value SessionRecordMigrate(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionRecordMigrate(data[, targetVersion]) requires data")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object data = EnsureObject(info[0], "data");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  std::string targetVersion = "v1";
  if (info.Length() > 1) {
    if (!info[1].IsString()) {
      Napi::TypeError::New(env, "targetVersion must be a string").ThrowAsJavaScriptException();
      return env.Null();
    }
    targetVersion = info[1].As<Napi::String>().Utf8Value();
  }
  if (targetVersion != "v1") {
    Napi::Error::New(env, "Unsupported SessionRecord target version")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  const Napi::Value versionVal = data.Get("version");
  bool run = versionVal.IsUndefined();
  if (!run) {
    if (!versionVal.IsString()) {
      Napi::Error::New(env, "Error migrating SessionRecord").ThrowAsJavaScriptException();
      return env.Null();
    }
    run = versionVal.As<Napi::String>().Utf8Value() == targetVersion;
  }
  if (!run) {
    Napi::Error::New(env, "Error migrating SessionRecord").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!versionVal.IsUndefined()) {
    return env.Undefined();
  }

  Napi::Object sessions =
      data.Get("_sessions").IsObject() ? data.Get("_sessions").As<Napi::Object>()
                                       : Napi::Object::New(env);
  const Napi::Value registrationId = data.Get("registrationId");
  Napi::Array keys = sessions.GetPropertyNames();
  if (IsTruthy(registrationId)) {
    for (uint32_t i = 0; i < keys.Length(); ++i) {
      Napi::Value key = keys.Get(i);
      Napi::Value sessionVal = sessions.Get(key);
      if (!sessionVal.IsObject()) {
        continue;
      }
      Napi::Object session = sessionVal.As<Napi::Object>();
      Napi::Value sessionRegistrationId = session.Get("registrationId");
      if (sessionRegistrationId.IsUndefined() || sessionRegistrationId.IsNull()) {
        session.Set("registrationId", registrationId);
      }
    }
    return env.Undefined();
  }

  for (uint32_t i = 0; i < keys.Length(); ++i) {
    Napi::Value key = keys.Get(i);
    Napi::Value sessionVal = sessions.Get(key);
    if (!sessionVal.IsObject()) {
      continue;
    }
    Napi::Object session = sessionVal.As<Napi::Object>();
    Napi::Value indexInfoVal = session.Get("indexInfo");
    if (!indexInfoVal.IsObject()) {
      continue;
    }
    Napi::Object indexInfo = indexInfoVal.As<Napi::Object>();
    Napi::Value closedVal = indexInfo.Get("closed");
    if (!closedVal.IsNumber()) {
      continue;
    }
    if (closedVal.As<Napi::Number>().Int64Value() == -1) {
      ConsoleError(env,
                   {Napi::String::New(env, "V1 session storage migration error: registrationId"),
                    registrationId, Napi::String::New(env, "for open session version"),
                    versionVal});
    }
  }
  return env.Undefined();
}

Napi::Value SessionEntryAddChain(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    Napi::TypeError::New(env, "sessionEntryAddChain(chains, key, value) requires 3 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object chains = EnsureObject(info[0], "chains");
  Napi::Buffer<uint8_t> key = EnsureBuffer(info[1], "key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  const std::string id = BufferToBase64(key);
  if (chains.Has(id)) {
    Napi::Error::New(env, "Overwrite attempt").ThrowAsJavaScriptException();
    return env.Null();
  }
  chains.Set(id, info[2]);
  return env.Undefined();
}

Napi::Value SessionEntryGetChain(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "sessionEntryGetChain(chains, key) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object chains = EnsureObject(info[0], "chains");
  Napi::Buffer<uint8_t> key = EnsureBuffer(info[1], "key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return chains.Get(BufferToBase64(key));
}

Napi::Value SessionEntryDeleteChain(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "sessionEntryDeleteChain(chains, key) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object chains = EnsureObject(info[0], "chains");
  Napi::Buffer<uint8_t> key = EnsureBuffer(info[1], "key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  const std::string id = BufferToBase64(key);
  if (!chains.Has(id)) {
    Napi::Error::New(env, "Not Found").ThrowAsJavaScriptException();
    return env.Null();
  }
  chains.Delete(id);
  return env.Undefined();
}

Napi::Value SessionEntrySerialize(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionEntrySerialize(entry) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object entry = EnsureObject(info[0], "entry");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object out = Napi::Object::New(env);
  if (!entry.Get("registrationId").IsUndefined()) {
    out.Set("registrationId", entry.Get("registrationId"));
  }

  Napi::Object currentRatchet = EnsureObject(entry.Get("currentRatchet"), "entry.currentRatchet");
  Napi::Object indexInfo = EnsureObject(entry.Get("indexInfo"), "entry.indexInfo");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object currentRatchetOut = Napi::Object::New(env);
  Napi::Object ephemeral = EnsureObject(currentRatchet.Get("ephemeralKeyPair"), "entry.currentRatchet.ephemeralKeyPair");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Buffer<uint8_t> ephemeralPub = EnsureBuffer(ephemeral.Get("pubKey"), "entry.currentRatchet.ephemeralKeyPair.pubKey");
  Napi::Buffer<uint8_t> ephemeralPriv = EnsureBuffer(ephemeral.Get("privKey"), "entry.currentRatchet.ephemeralKeyPair.privKey");
  Napi::Buffer<uint8_t> lastRemote = EnsureBuffer(currentRatchet.Get("lastRemoteEphemeralKey"), "entry.currentRatchet.lastRemoteEphemeralKey");
  Napi::Buffer<uint8_t> rootKey = EnsureBuffer(currentRatchet.Get("rootKey"), "entry.currentRatchet.rootKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Object ephemeralOut = Napi::Object::New(env);
  ephemeralOut.Set("pubKey", Napi::String::New(env, BufferToBase64(ephemeralPub)));
  ephemeralOut.Set("privKey", Napi::String::New(env, BufferToBase64(ephemeralPriv)));
  currentRatchetOut.Set("ephemeralKeyPair", ephemeralOut);
  currentRatchetOut.Set("lastRemoteEphemeralKey", Napi::String::New(env, BufferToBase64(lastRemote)));
  currentRatchetOut.Set("previousCounter", currentRatchet.Get("previousCounter"));
  currentRatchetOut.Set("rootKey", Napi::String::New(env, BufferToBase64(rootKey)));
  out.Set("currentRatchet", currentRatchetOut);

  Napi::Object indexInfoOut = Napi::Object::New(env);
  Napi::Buffer<uint8_t> baseKey = EnsureBuffer(indexInfo.Get("baseKey"), "entry.indexInfo.baseKey");
  Napi::Buffer<uint8_t> remoteIdentityKey = EnsureBuffer(indexInfo.Get("remoteIdentityKey"), "entry.indexInfo.remoteIdentityKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  indexInfoOut.Set("baseKey", Napi::String::New(env, BufferToBase64(baseKey)));
  indexInfoOut.Set("baseKeyType", indexInfo.Get("baseKeyType"));
  indexInfoOut.Set("closed", indexInfo.Get("closed"));
  indexInfoOut.Set("used", indexInfo.Get("used"));
  indexInfoOut.Set("created", indexInfo.Get("created"));
  indexInfoOut.Set("remoteIdentityKey", Napi::String::New(env, BufferToBase64(remoteIdentityKey)));
  out.Set("indexInfo", indexInfoOut);

  Napi::Object chains =
      entry.Get("_chains").IsObject() ? entry.Get("_chains").As<Napi::Object>() : Napi::Object::New(env);
  out.Set("_chains", SerializeChains(env, chains));
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Value pendingPreKeyVal = entry.Get("pendingPreKey");
  if (pendingPreKeyVal.IsObject()) {
    Napi::Object pendingPreKey = pendingPreKeyVal.As<Napi::Object>();
    Napi::Object pendingOut = Napi::Object::New(env);
    pendingOut.Set("signedKeyId", pendingPreKey.Get("signedKeyId"));
    if (!pendingPreKey.Get("preKeyId").IsUndefined()) {
      pendingOut.Set("preKeyId", pendingPreKey.Get("preKeyId"));
    }
    Napi::Buffer<uint8_t> pendingBaseKey = EnsureBuffer(pendingPreKey.Get("baseKey"), "entry.pendingPreKey.baseKey");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    pendingOut.Set("baseKey", Napi::String::New(env, BufferToBase64(pendingBaseKey)));
    out.Set("pendingPreKey", pendingOut);
  }

  return out;
}

Napi::Value SessionEntryDeserialize(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionEntryDeserialize(data) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object data = EnsureObject(info[0], "data");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object entry = Napi::Object::New(env);
  if (!data.Get("registrationId").IsUndefined()) {
    entry.Set("registrationId", data.Get("registrationId"));
  }

  Napi::Object currentRatchetData =
      EnsureObject(data.Get("currentRatchet"), "data.currentRatchet");
  Napi::Object indexInfoData = EnsureObject(data.Get("indexInfo"), "data.indexInfo");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object currentRatchet = Napi::Object::New(env);
  Napi::Object ephemeralData =
      EnsureObject(currentRatchetData.Get("ephemeralKeyPair"), "data.currentRatchet.ephemeralKeyPair");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  if (!ephemeralData.Get("pubKey").IsString() || !ephemeralData.Get("privKey").IsString() ||
      !currentRatchetData.Get("lastRemoteEphemeralKey").IsString() ||
      !currentRatchetData.Get("rootKey").IsString()) {
    Napi::TypeError::New(env, "Invalid serialized session currentRatchet")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object ephemeral = Napi::Object::New(env);
  ephemeral.Set("pubKey", Base64ToBuffer(env, ephemeralData.Get("pubKey").As<Napi::String>().Utf8Value()));
  ephemeral.Set("privKey", Base64ToBuffer(env, ephemeralData.Get("privKey").As<Napi::String>().Utf8Value()));
  currentRatchet.Set("ephemeralKeyPair", ephemeral);
  currentRatchet.Set(
      "lastRemoteEphemeralKey",
      Base64ToBuffer(env, currentRatchetData.Get("lastRemoteEphemeralKey").As<Napi::String>().Utf8Value()));
  currentRatchet.Set("previousCounter", currentRatchetData.Get("previousCounter"));
  currentRatchet.Set("rootKey", Base64ToBuffer(env, currentRatchetData.Get("rootKey").As<Napi::String>().Utf8Value()));
  entry.Set("currentRatchet", currentRatchet);

  if (!indexInfoData.Get("baseKey").IsString() || !indexInfoData.Get("remoteIdentityKey").IsString()) {
    Napi::TypeError::New(env, "Invalid serialized session indexInfo")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object indexInfo = Napi::Object::New(env);
  indexInfo.Set("baseKey", Base64ToBuffer(env, indexInfoData.Get("baseKey").As<Napi::String>().Utf8Value()));
  indexInfo.Set("baseKeyType", indexInfoData.Get("baseKeyType"));
  indexInfo.Set("closed", indexInfoData.Get("closed"));
  indexInfo.Set("used", indexInfoData.Get("used"));
  indexInfo.Set("created", indexInfoData.Get("created"));
  indexInfo.Set(
      "remoteIdentityKey",
      Base64ToBuffer(env, indexInfoData.Get("remoteIdentityKey").As<Napi::String>().Utf8Value()));
  entry.Set("indexInfo", indexInfo);

  Napi::Object chainsData =
      data.Get("_chains").IsObject() ? data.Get("_chains").As<Napi::Object>() : Napi::Object::New(env);
  entry.Set("_chains", DeserializeChains(env, chainsData));
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Value pendingPreKeyVal = data.Get("pendingPreKey");
  if (pendingPreKeyVal.IsObject()) {
    Napi::Object pendingPreKeyData = pendingPreKeyVal.As<Napi::Object>();
    if (!pendingPreKeyData.Get("baseKey").IsString()) {
      Napi::TypeError::New(env, "Invalid serialized pendingPreKey")
          .ThrowAsJavaScriptException();
      return env.Null();
    }
    Napi::Object pendingPreKey = Napi::Object::New(env);
    pendingPreKey.Set("signedKeyId", pendingPreKeyData.Get("signedKeyId"));
    if (!pendingPreKeyData.Get("preKeyId").IsUndefined()) {
      pendingPreKey.Set("preKeyId", pendingPreKeyData.Get("preKeyId"));
    }
    pendingPreKey.Set("baseKey", Base64ToBuffer(env, pendingPreKeyData.Get("baseKey").As<Napi::String>().Utf8Value()));
    entry.Set("pendingPreKey", pendingPreKey);
  }

  return entry;
}

Napi::Value SessionRecordGetSessionByBaseKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[2].IsNumber()) {
    Napi::TypeError::New(
        env,
        "sessionRecordGetSessionByBaseKey(sessions, key, ourBaseKeyType) requires 3 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object sessions = EnsureObject(info[0], "sessions");
  Napi::Buffer<uint8_t> key = EnsureBuffer(info[1], "key");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  const int32_t ourBaseKeyType = info[2].As<Napi::Number>().Int32Value();
  Napi::Value sessionVal = sessions.Get(BufferToBase64(key));
  if (sessionVal.IsUndefined() || sessionVal.IsNull()) {
    return env.Undefined();
  }
  if (!sessionVal.IsObject()) {
    return env.Undefined();
  }

  Napi::Object session = sessionVal.As<Napi::Object>();
  Napi::Object indexInfo = GetIndexInfo(session);
  if (!indexInfo.IsEmpty()) {
    Napi::Value baseKeyTypeVal = indexInfo.Get("baseKeyType");
    if (baseKeyTypeVal.IsNumber() &&
        baseKeyTypeVal.As<Napi::Number>().Int32Value() == ourBaseKeyType) {
      Napi::Error::New(env, "Tried to lookup a session using our basekey")
          .ThrowAsJavaScriptException();
      return env.Null();
    }
  }

  return session;
}

Napi::Value SessionRecordGetOpenSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionRecordGetOpenSession(sessions) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object sessions = EnsureObject(info[0], "sessions");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return FindOpenSessionValue(env, sessions);
}

Napi::Value SessionRecordHaveOpenSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionRecordHaveOpenSession(sessions) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object sessions = EnsureObject(info[0], "sessions");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value openSessionVal = FindOpenSessionValue(env, sessions);
  if (!openSessionVal.IsObject()) {
    return Napi::Boolean::New(env, false);
  }
  Napi::Object openSession = openSessionVal.As<Napi::Object>();
  return Napi::Boolean::New(env, openSession.Get("registrationId").IsNumber());
}

Napi::Value SessionRecordGetSessionsSorted(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionRecordGetSessionsSorted(sessions) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object sessions = EnsureObject(info[0], "sessions");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Array keys = sessions.GetPropertyNames();
  std::vector<Napi::Object> values;
  values.reserve(keys.Length());
  for (uint32_t i = 0; i < keys.Length(); ++i) {
    Napi::Value value = sessions.Get(keys.Get(i));
    if (value.IsObject()) {
      values.emplace_back(value.As<Napi::Object>());
    }
  }

  std::sort(values.begin(), values.end(), [](const Napi::Object& a, const Napi::Object& b) {
    const double aUsed = SessionUsedAt(a);
    const double bUsed = SessionUsedAt(b);
    if (aUsed == bUsed) {
      return false;
    }
    return aUsed > bUsed;
  });

  Napi::Array out = Napi::Array::New(env, values.size());
  for (uint32_t i = 0; i < values.size(); ++i) {
    out.Set(i, values[i]);
  }
  return out;
}

Napi::Value SessionRecordRemoveOldSessions(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[1].IsNumber()) {
    Napi::TypeError::New(
        env,
        "sessionRecordRemoveOldSessions(sessions, maxClosedSessions) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object sessions = EnsureObject(info[0], "sessions");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  const int32_t maxClosedSessions = info[1].As<Napi::Number>().Int32Value();
  if (maxClosedSessions < 0) {
    Napi::RangeError::New(env, "maxClosedSessions must be >= 0").ThrowAsJavaScriptException();
    return env.Null();
  }

  while (sessions.GetPropertyNames().Length() > static_cast<uint32_t>(maxClosedSessions)) {
    Napi::Array keys = sessions.GetPropertyNames();
    bool found = false;
    double oldestClosed = 0;
    Napi::Value oldestKey = env.Undefined();

    for (uint32_t i = 0; i < keys.Length(); ++i) {
      Napi::Value key = keys.Get(i);
      Napi::Value sessionVal = sessions.Get(key);
      if (!sessionVal.IsObject()) {
        continue;
      }
      Napi::Object session = sessionVal.As<Napi::Object>();
      if (!IsClosedSession(session)) {
        continue;
      }
      const double closedAt = SessionClosedAt(session);
      if (!found || closedAt < oldestClosed) {
        found = true;
        oldestClosed = closedAt;
        oldestKey = key;
      }
    }

    if (!found || oldestKey.IsUndefined()) {
      Napi::Error::New(env, "Corrupt sessions object").ThrowAsJavaScriptException();
      return env.Null();
    }
    sessions.Delete(oldestKey);
  }

  return env.Undefined();
}

Napi::Value SessionRecordDeleteAllSessions(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionRecordDeleteAllSessions(sessions) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object sessions = EnsureObject(info[0], "sessions");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Array keys = sessions.GetPropertyNames();
  for (uint32_t i = 0; i < keys.Length(); ++i) {
    sessions.Delete(keys.Get(i));
  }
  return env.Undefined();
}

Napi::Value SessionRecordSetSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "sessionRecordSetSession(sessions, session) requires 2 arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object sessions = EnsureObject(info[0], "sessions");
  Napi::Object session = EnsureObject(info[1], "session");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  Napi::Object indexInfo = EnsureObject(session.Get("indexInfo"), "session.indexInfo");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Buffer<uint8_t> baseKey = EnsureBuffer(indexInfo.Get("baseKey"), "session.indexInfo.baseKey");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  sessions.Set(BufferToBase64(baseKey), session);
  return env.Undefined();
}

Napi::Value SessionRecordCloseSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionRecordCloseSession(session) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object session = EnsureObject(info[0], "session");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Object indexInfo = EnsureObject(session.Get("indexInfo"), "session.indexInfo");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value closedVal = indexInfo.Get("closed");
  if (!closedVal.IsNumber()) {
    Napi::TypeError::New(env, "session.indexInfo.closed must be a number")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  if (closedVal.As<Napi::Number>().Int64Value() != -1) {
    return Napi::Boolean::New(env, false);
  }
  const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  indexInfo.Set("closed", Napi::Number::New(env, static_cast<double>(nowMs)));
  return Napi::Boolean::New(env, true);
}

Napi::Value SessionRecordOpenSession(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionRecordOpenSession(session) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object session = EnsureObject(info[0], "session");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Object indexInfo = EnsureObject(session.Get("indexInfo"), "session.indexInfo");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  Napi::Value closedVal = indexInfo.Get("closed");
  if (!closedVal.IsNumber()) {
    Napi::TypeError::New(env, "session.indexInfo.closed must be a number")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  if (closedVal.As<Napi::Number>().Int64Value() == -1) {
    return Napi::Boolean::New(env, false);
  }
  indexInfo.Set("closed", Napi::Number::New(env, -1));
  return Napi::Boolean::New(env, true);
}

Napi::Value SessionRecordIsClosed(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::TypeError::New(env, "sessionRecordIsClosed(session) requires 1 argument")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object session = EnsureObject(info[0], "session");
  if (env.IsExceptionPending()) {
    return env.Null();
  }
  return Napi::Boolean::New(env, IsClosedSession(session));
}

}  // namespace libsignal_native
