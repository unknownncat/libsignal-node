
'use strict';

const { axlsign } = require('@unknownncat/curve25519-node');
const nodeCrypto = require('crypto');

const KEY_BUNDLE_TYPE = Buffer.from([5]);

const prefixKeyInPublicKey = function (pubKey) {
  return Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);
};

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (pubKey === undefined) {
        throw new Error("Undefined public key");
    }
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1);
    } else {
        console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
        return pubKey;
    }
}

function unclampEd25519PrivateKey(clampedSk) {
    const unclampedSk = new Uint8Array(clampedSk);

    // Fix the first byte
    unclampedSk[0] |= 6; // Ensure last 3 bits match expected `110` pattern

    // Fix the last byte
    unclampedSk[31] |= 128; // Restore the highest bit
    unclampedSk[31] &= ~64; // Clear the second-highest bit

    return unclampedSk;
}

exports.getPublicFromPrivateKey = function(privKey) {
    const unclampedPK = unclampEd25519PrivateKey(privKey);
    const keyPair = axlsign.generateKeyPair(unclampedPK);
    return prefixKeyInPublicKey(Buffer.from(keyPair.public));
};

exports.generateKeyPair = function() {
    const keyPair = axlsign.generateKeyPair(nodeCrypto.randomBytes(32));
    return {
        privKey: Buffer.from(keyPair.private),
        pubKey: prefixKeyInPublicKey(Buffer.from(keyPair.public)),
    };
};

exports.calculateAgreement = function(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }

    const secret = axlsign.sharedKey(privKey, pubKey);
    return Buffer.from(secret);
};

exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    return Buffer.from(axlsign.sign(privKey, message));
};

exports.verifySignature = function(pubKey, msg, sig) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    return axlsign.verify(pubKey, msg, sig);
};
