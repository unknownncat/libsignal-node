import native from './native.js';

export default class ProtocolAddress {
  static from(encodedAddress) {
    const parsed = native.parseProtocolAddress(encodedAddress);
    return new this(parsed.id, parsed.deviceId);
  }

  constructor(id, deviceId) {
    if (typeof id !== 'string') {
      throw new TypeError('id required for addr');
    }
    if (id.indexOf('.') !== -1) {
      throw new TypeError('encoded addr detected');
    }
    this.id = id;
    if (!Number.isInteger(deviceId) || deviceId < 0) {
      throw new TypeError('number required for deviceId');
    }
    this.deviceId = deviceId;
  }

  toString() {
    return `${this.id}.${this.deviceId}`;
  }

  is(other) {
    if (!(other instanceof ProtocolAddress)) {
      return false;
    }
    return other.id === this.id && other.deviceId === this.deviceId;
  }
}