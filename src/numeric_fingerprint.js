const crypto = require('./crypto.js');
const { default: native } = require('./native');

const VERSION = 0;

function asBuffer(value, name) {
    if (Buffer.isBuffer(value)) {
        return value;
    }
    if (typeof value === 'string') {
        return Buffer.from(value);
    }
    if (value instanceof ArrayBuffer) {
        return Buffer.from(value);
    }
    if (ArrayBuffer.isView(value)) {
        return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    throw new TypeError(`Invalid ${name}`);
}

function shortToBuffer(number) {
    const out = Buffer.alloc(2);
    out.writeUInt16LE(number & 0xffff, 0);
    return out;
}

function getEncodedChunk(hash, offset) {
    let chunk = (hash[offset] * Math.pow(2, 32) +
        hash[offset + 1] * Math.pow(2, 24) +
        hash[offset + 2] * Math.pow(2, 16) +
        hash[offset + 3] * Math.pow(2, 8) +
        hash[offset + 4]) % 100000;
    let s = chunk.toString();
    while (s.length < 5) {
        s = `0${s}`;
    }
    return s;
}

function iterateHash(data, key, count) {
    let combined = Buffer.concat([data, key]);
    let result = combined;
    for (let i = 0; i < count; i++) {
        result = crypto.hash(combined);
        combined = Buffer.concat([result, key]);
    }
    return result;
}

function getDisplayStringFor(identifier, key, iterations) {
    const bytes = Buffer.concat([
        shortToBuffer(VERSION),
        key,
        Buffer.from(identifier)
    ]);
    const output = iterateHash(bytes, key, iterations);
    return getEncodedChunk(output, 0) +
        getEncodedChunk(output, 5) +
        getEncodedChunk(output, 10) +
        getEncodedChunk(output, 15) +
        getEncodedChunk(output, 20) +
        getEncodedChunk(output, 25);
}

exports.FingerprintGenerator = function (iterations) {
    if (!Number.isInteger(iterations) || iterations < 1) {
        throw new TypeError('iterations must be a positive integer');
    }
    this.iterations = iterations;
};

exports.FingerprintGenerator.prototype = {
    createFor: function (localIdentifier, localIdentityKey,
        remoteIdentifier, remoteIdentityKey) {
        if (typeof localIdentifier !== 'string' ||
            typeof remoteIdentifier !== 'string') {
            throw new Error('Invalid arguments');
        }
        const localKey = asBuffer(localIdentityKey, 'localIdentityKey');
        const remoteKey = asBuffer(remoteIdentityKey, 'remoteIdentityKey');
        if (native && typeof native.numericFingerprint === 'function') {
            return Promise.resolve(
                native.numericFingerprint(
                    localIdentifier,
                    localKey,
                    remoteIdentifier,
                    remoteKey,
                    this.iterations
                )
            );
        }
        return Promise.resolve([
            getDisplayStringFor(localIdentifier, localKey, this.iterations),
            getDisplayStringFor(remoteIdentifier, remoteKey, this.iterations)
        ]).then(function (fingerprints) {
            return fingerprints.sort().join('');
        });
    }
};
