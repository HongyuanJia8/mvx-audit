import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

export const FINDING_FINGERPRINT_PROFILE = 'mvx-finding-v1';
export const EVIDENCE_FINGERPRINT_PROFILE = 'mvx-evidence-v1';
export const FINGERPRINT_LIMITS = Object.freeze({
  maxDepth: 512,
  maxNodes: 5_000_000,
  maxCanonicalBytes: 12_000_000
});

function fail(message) {
  throw new TypeError(`Fingerprint input ${message}`);
}

function write(hash, context, value) {
  context.bytes += Buffer.byteLength(value);
  if (context.bytes > FINGERPRINT_LIMITS.maxCanonicalBytes) fail('exceeds the canonical byte limit');
  hash.update(value);
}

function enter(context, value) {
  if (utilTypes.isProxy(value)) fail('contains a proxy');
  if (context.ancestors.has(value)) fail('must not contain cycles');
  context.ancestors.add(value);
}

function count(context, depth) {
  if (depth > FINGERPRINT_LIMITS.maxDepth) fail('exceeds the nesting depth limit');
  context.nodes += 1;
  if (context.nodes > FINGERPRINT_LIMITS.maxNodes) fail('exceeds the node limit');
}

function isArrayIndex(key, length) {
  const index = Number(key);
  return Number.isSafeInteger(index) && index >= 0 && index < length && String(index) === key;
}

function updateCanonical(hash, context, value, depth = 0) {
  count(context, depth);
  if (value === null) return write(hash, context, 'null');
  if (typeof value === 'string' || typeof value === 'boolean') return write(hash, context, JSON.stringify(value));
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('contains a non-finite number');
    return write(hash, context, JSON.stringify(value));
  }
  if (['undefined', 'bigint', 'function', 'symbol'].includes(typeof value)) fail(`contains unsupported ${typeof value}`);
  if (!value || typeof value !== 'object') fail('contains an unsupported value');

  enter(context, value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) fail('contains a non-plain array');
      if (Object.getOwnPropertySymbols(value).length > 0) fail('contains a symbol-keyed array property');
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set)) fail('contains an array accessor');
      const extra = Object.getOwnPropertyNames(value)
        .find((key) => key !== 'length' && !isArrayIndex(key, value.length));
      if (extra !== undefined) fail('contains an extra array property');
      write(hash, context, '[');
      for (let index = 0; index < value.length; index += 1) {
        if (index > 0) write(hash, context, ',');
        const descriptor = descriptors[index];
        if (!descriptor || descriptor.value === undefined) updateCanonical(hash, context, null, depth + 1);
        else updateCanonical(hash, context, descriptor.value, depth + 1);
      }
      return write(hash, context, ']');
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail('contains a non-plain object');
    if (Object.getOwnPropertySymbols(value).length > 0) fail('contains a symbol-keyed object property');
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set)) fail('contains an object accessor');
    const keys = Object.keys(value).filter((key) => descriptors[key].value !== undefined)
      .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
    write(hash, context, '{');
    keys.forEach((key, index) => {
      const descriptor = descriptors[key];
      if (index > 0) write(hash, context, ',');
      write(hash, context, JSON.stringify(key));
      write(hash, context, ':');
      updateCanonical(hash, context, descriptor.value, depth + 1);
    });
    return write(hash, context, '}');
  } finally {
    context.ancestors.delete(value);
  }
}

function digest(profile, value) {
  const hash = createHash('sha256').update(profile).update('\0');
  updateCanonical(hash, { ancestors: new WeakSet(), bytes: 0, nodes: 0 }, value);
  return hash.digest('hex');
}

export function findingKey(finding) {
  if (!finding || typeof finding !== 'object' || utilTypes.isProxy(finding)) {
    throw new TypeError('Finding must be a non-proxy object');
  }
  const prototype = Object.getPrototypeOf(finding);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Finding must be a plain object');
  const descriptors = Object.getOwnPropertyDescriptors(finding);
  for (const name of ['fingerprint', 'id']) {
    if (descriptors[name]?.get || descriptors[name]?.set) throw new TypeError(`Finding ${name} must be a data property`);
  }
  const key = descriptors.fingerprint?.value ?? descriptors.id?.value;
  if (typeof key !== 'string' || key.length === 0) throw new TypeError('Finding requires a non-empty fingerprint or rule ID');
  return key;
}

export function findingFingerprint(finding) {
  return digest(FINDING_FINGERPRINT_PROFILE, { fingerprint: findingKey(finding) });
}

export function evidenceFingerprint(finding, evidence) {
  if (evidence === undefined) throw new TypeError('Evidence fingerprint requires a defined JSON value');
  return digest(EVIDENCE_FINGERPRINT_PROFILE, {
    fingerprint: findingKey(finding),
    evidence
  });
}
