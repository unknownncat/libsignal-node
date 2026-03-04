export function assertUint8Array(value, name = 'value') {
  if (!(value instanceof Uint8Array)) {
    const constructorName =
      value && value.constructor && value.constructor.name ? value.constructor.name : typeof value;
    throw new TypeError(`Expected Uint8Array for ${name}, got ${constructorName}`);
  }
  return value;
}

export function asUint8Array(value, name = 'value') {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError(`Invalid ${name}`);
}

export function asBuffer(value, name = 'value') {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  const bytes = assertUint8Array(value, name);
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export function toBase64(value, name = 'value') {
  const bytes = asBuffer(value, name);
  return bytes.toString('base64');
}
