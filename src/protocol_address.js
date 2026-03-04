// vim: ts=4:sw=4:expandtab

const { default: native } = require('./native');


class ProtocolAddress {

    static from(encodedAddress) {
        if (native && typeof native.parseProtocolAddress === 'function') {
            const parsed = native.parseProtocolAddress(encodedAddress);
            return new this(parsed.id, parsed.deviceId);
        }
        if (typeof encodedAddress !== 'string') {
            throw new Error('Invalid address encoding');
        }
        const sep = encodedAddress.lastIndexOf('.');
        if (sep <= 0 || sep === encodedAddress.length - 1) {
            throw new Error('Invalid address encoding');
        }
        const id = encodedAddress.slice(0, sep);
        const devicePart = encodedAddress.slice(sep + 1);
        if (!/^\d+$/.test(devicePart)) {
            throw new Error('Invalid address encoding');
        }
        const deviceId = Number(devicePart);
        if (!Number.isSafeInteger(deviceId)) {
            throw new Error('Invalid address encoding');
        }
        return new this(id, deviceId);
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

module.exports = ProtocolAddress;
