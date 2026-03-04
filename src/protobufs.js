import native from './native.js';

export const WhisperMessage = {
  create(properties = {}) {
    return { ...properties };
  },
  encode(message) {
    return {
      finish() {
        return native.protobufEncodeWhisperMessage(message);
      },
    };
  },
  decode(data) {
    return native.protobufDecodeWhisperMessage(data);
  },
};

export const PreKeyWhisperMessage = {
  create(properties = {}) {
    return { ...properties };
  },
  encode(message) {
    return {
      finish() {
        return native.protobufEncodePreKeyWhisperMessage(message);
      },
    };
  },
  decode(data) {
    return native.protobufDecodePreKeyWhisperMessage(data);
  },
};