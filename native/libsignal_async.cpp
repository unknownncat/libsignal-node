#include "libsignal_native.h"

#include <cstring>
#include <utility>
#include <vector>

namespace libsignal_native {

namespace {

class BuildSessionSharedSecretWorker final : public Napi::AsyncWorker {
 public:
  BuildSessionSharedSecretWorker(const Napi::Env& env,
                                 bool isInitiator,
                                 std::vector<uint8_t> a1,
                                 std::vector<uint8_t> a2,
                                 std::vector<uint8_t> a3,
                                 std::vector<uint8_t> a4,
                                 bool hasA4)
      : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        isInitiator_(isInitiator),
        a1_(std::move(a1)),
        a2_(std::move(a2)),
        a3_(std::move(a3)),
        a4_(std::move(a4)),
        hasA4_(hasA4) {}

  ~BuildSessionSharedSecretWorker() override {
    SecureZeroVector(a1_);
    SecureZeroVector(a2_);
    SecureZeroVector(a3_);
    SecureZeroVector(a4_);
    SecureZeroVector(out_);
  }

  Napi::Promise GetPromise() const { return deferred_.Promise(); }

  void Execute() override {
    if (a1_.size() != 32 || a2_.size() != 32 || a3_.size() != 32) {
      SetError("a1, a2 and a3 must be 32-byte buffers");
      return;
    }
    if (hasA4_ && a4_.size() != 32) {
      SetError("a4 must be a 32-byte buffer");
      return;
    }

    const size_t totalLength = hasA4_ ? 160 : 128;
    out_.assign(totalLength, 0);
    std::memset(out_.data(), 0xff, 32);

    if (isInitiator_) {
      std::memcpy(out_.data() + 32, a1_.data(), 32);
      std::memcpy(out_.data() + 64, a2_.data(), 32);
    } else {
      std::memcpy(out_.data() + 64, a1_.data(), 32);
      std::memcpy(out_.data() + 32, a2_.data(), 32);
    }
    std::memcpy(out_.data() + 96, a3_.data(), 32);
    if (hasA4_) {
      std::memcpy(out_.data() + 128, a4_.data(), 32);
    }
  }

  void OnOK() override {
    deferred_.Resolve(Napi::Buffer<uint8_t>::Copy(Env(), out_.data(), out_.size()));
  }

  void OnError(const Napi::Error& error) override { deferred_.Reject(error.Value()); }

 private:
  Napi::Promise::Deferred deferred_;
  bool isInitiator_ = false;
  std::vector<uint8_t> a1_;
  std::vector<uint8_t> a2_;
  std::vector<uint8_t> a3_;
  std::vector<uint8_t> a4_;
  bool hasA4_ = false;
  std::vector<uint8_t> out_;
};

class BuildWhisperMacInputWorker final : public Napi::AsyncWorker {
 public:
  BuildWhisperMacInputWorker(const Napi::Env& env,
                             std::vector<uint8_t> leftIdentityKey,
                             std::vector<uint8_t> rightIdentityKey,
                             uint8_t versionByte,
                             std::vector<uint8_t> messageProto)
      : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        leftIdentityKey_(std::move(leftIdentityKey)),
        rightIdentityKey_(std::move(rightIdentityKey)),
        versionByte_(versionByte),
        messageProto_(std::move(messageProto)) {}

  ~BuildWhisperMacInputWorker() override {
    SecureZeroVector(leftIdentityKey_);
    SecureZeroVector(rightIdentityKey_);
    SecureZeroVector(messageProto_);
    SecureZeroVector(out_);
  }

  Napi::Promise GetPromise() const { return deferred_.Promise(); }

  void Execute() override {
    if (leftIdentityKey_.size() != 33 || rightIdentityKey_.size() != 33) {
      SetError("Identity keys must be 33-byte buffers");
      return;
    }
    out_.assign(messageProto_.size() + 67, 0);
    std::memcpy(out_.data(), leftIdentityKey_.data(), 33);
    std::memcpy(out_.data() + 33, rightIdentityKey_.data(), 33);
    out_[66] = versionByte_;
    std::memcpy(out_.data() + 67, messageProto_.data(), messageProto_.size());
  }

  void OnOK() override {
    deferred_.Resolve(Napi::Buffer<uint8_t>::Copy(Env(), out_.data(), out_.size()));
  }

  void OnError(const Napi::Error& error) override { deferred_.Reject(error.Value()); }

 private:
  Napi::Promise::Deferred deferred_;
  std::vector<uint8_t> leftIdentityKey_;
  std::vector<uint8_t> rightIdentityKey_;
  uint8_t versionByte_ = 0;
  std::vector<uint8_t> messageProto_;
  std::vector<uint8_t> out_;
};

class AssembleWhisperFrameWorker final : public Napi::AsyncWorker {
 public:
  AssembleWhisperFrameWorker(const Napi::Env& env,
                             uint8_t versionByte,
                             std::vector<uint8_t> messageProto,
                             std::vector<uint8_t> mac,
                             uint32_t macLength)
      : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        versionByte_(versionByte),
        messageProto_(std::move(messageProto)),
        mac_(std::move(mac)),
        macLength_(macLength) {}

  ~AssembleWhisperFrameWorker() override {
    SecureZeroVector(messageProto_);
    SecureZeroVector(mac_);
    SecureZeroVector(out_);
  }

  Napi::Promise GetPromise() const { return deferred_.Promise(); }

  void Execute() override {
    if (macLength_ > mac_.size()) {
      SetError("macLength out of bounds");
      return;
    }
    out_.assign(messageProto_.size() + macLength_ + 1, 0);
    out_[0] = versionByte_;
    std::memcpy(out_.data() + 1, messageProto_.data(), messageProto_.size());
    std::memcpy(out_.data() + 1 + messageProto_.size(), mac_.data(), macLength_);
  }

  void OnOK() override {
    deferred_.Resolve(Napi::Buffer<uint8_t>::Copy(Env(), out_.data(), out_.size()));
  }

  void OnError(const Napi::Error& error) override { deferred_.Reject(error.Value()); }

 private:
  Napi::Promise::Deferred deferred_;
  uint8_t versionByte_ = 0;
  std::vector<uint8_t> messageProto_;
  std::vector<uint8_t> mac_;
  uint32_t macLength_ = 8;
  std::vector<uint8_t> out_;
};

}  // namespace

Napi::Value BuildSessionSharedSecretAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4 || !info[0].IsBoolean()) {
    Napi::TypeError::New(
        env,
        "buildSessionSharedSecretAsync(isInitiator, a1, a2, a3[, a4]) requires valid arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> a1 = EnsureBuffer(info[1], "a1");
  Napi::Buffer<uint8_t> a2 = EnsureBuffer(info[2], "a2");
  Napi::Buffer<uint8_t> a3 = EnsureBuffer(info[3], "a3");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  bool hasA4 = false;
  std::vector<uint8_t> a4v;
  if (info.Length() > 4 && !info[4].IsUndefined() && !info[4].IsNull()) {
    Napi::Buffer<uint8_t> a4 = EnsureBuffer(info[4], "a4");
    if (env.IsExceptionPending()) {
      return env.Null();
    }
    hasA4 = true;
    a4v = CopyBufferToVector(a4);
  }

  auto* worker = new BuildSessionSharedSecretWorker(
      env, info[0].As<Napi::Boolean>().Value(), CopyBufferToVector(a1), CopyBufferToVector(a2),
      CopyBufferToVector(a3), std::move(a4v), hasA4);
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value BuildWhisperMacInputAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4 || !info[2].IsNumber()) {
    Napi::TypeError::New(
        env,
        "buildWhisperMacInputAsync(leftIdentityKey, rightIdentityKey, versionByte, messageProto)")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> left = EnsureBuffer(info[0], "leftIdentityKey");
  Napi::Buffer<uint8_t> right = EnsureBuffer(info[1], "rightIdentityKey");
  Napi::Buffer<uint8_t> proto = EnsureBuffer(info[3], "messageProto");
  if (env.IsExceptionPending()) {
    return env.Null();
  }

  auto* worker = new BuildWhisperMacInputWorker(
      env, CopyBufferToVector(left), CopyBufferToVector(right),
      static_cast<uint8_t>(info[2].As<Napi::Number>().Uint32Value() & 0xffU),
      CopyBufferToVector(proto));
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value AssembleWhisperFrameAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsNumber()) {
    Napi::TypeError::New(
        env,
        "assembleWhisperFrameAsync(versionByte, messageProto, mac[, macLength]) requires 3 arguments")
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

  auto* worker = new AssembleWhisperFrameWorker(
      env, static_cast<uint8_t>(info[0].As<Napi::Number>().Uint32Value() & 0xffU),
      CopyBufferToVector(messageProto), CopyBufferToVector(mac), macLength);
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

}  // namespace libsignal_native
