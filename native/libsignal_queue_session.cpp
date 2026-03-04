#include "libsignal_native.h"

#include <algorithm>
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

}  // namespace libsignal_native
