import { types as utilTypes } from 'node:util';
import { MvxError } from './errors.js';

export function assertOptionsObject(value, label) {
  if (!value || typeof value !== 'object'
    || utilTypes.isProxy(value) || Array.isArray(value)) {
    throw new MvxError(`${label} options must be a plain non-proxy object`, { code: 'INVALID_ARGUMENT' });
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new MvxError(`${label} options must be a plain non-proxy object`, { code: 'INVALID_ARGUMENT' });
  }
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!Object.hasOwn(descriptor, 'value')) {
      throw new MvxError(`${label} options may not contain accessor property: ${key}`, { code: 'INVALID_ARGUMENT' });
    }
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new MvxError(`${label} options may not contain symbol properties`, { code: 'INVALID_ARGUMENT' });
  }
  return value;
}
