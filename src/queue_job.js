import native from './native.js';

export default function queueJob(bucket, awaitable) {
  if (typeof bucket !== 'string') {
    throw new TypeError('bucket must be a string');
  }
  return native.queueJobByBucket(bucket, awaitable);
}