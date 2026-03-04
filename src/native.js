'use strict';

let nativeAddon = null;

try {
    nativeAddon = require('../build/Release/libsignal_native.node');
} catch (_) {
    nativeAddon = null;
}

module.exports = nativeAddon;

