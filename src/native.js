import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
if (typeof global.require !== 'function') {
  global.require = require;
}
const nativeAddon = require('../build/Release/libsignal_native.node');

export default nativeAddon;
