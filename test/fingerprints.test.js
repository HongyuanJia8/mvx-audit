import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EVIDENCE_FINGERPRINT_PROFILE, FINDING_FINGERPRINT_PROFILE, FINGERPRINT_LIMITS,
  evidenceFingerprint, findingFingerprint, findingKey
} from '../src/fingerprints.js';
import { createFinding } from '../src/model.js';

const RULE = {
  id: 'MVX999', title: 'Fingerprint fixture', severity: 'high', confidence: 'high',
  category: 'test', description: 'Synthetic finding.', remediation: 'Review it.', references: []
};

test('finding creation assigns a stable default key while retaining explicit scoped keys', () => {
  const defaultFinding = createFinding(RULE, { file: 'worker.js', line: 1 });
  const scopedFinding = createFinding(RULE, { field: 'permissions' }, { fingerprint: 'MVX999:scope' });
  assert.equal(defaultFinding.fingerprint, 'MVX999');
  assert.equal(scopedFinding.fingerprint, 'MVX999:scope');
  assert.equal(findingKey({ id: 'LEGACY001' }), 'LEGACY001');
  assert.throws(() => findingKey({}), /non-empty fingerprint/);
  assert.equal(FINDING_FINGERPRINT_PROFILE, 'mvx-finding-v1');
  assert.equal(EVIDENCE_FINGERPRINT_PROFILE, 'mvx-evidence-v1');
  assert.equal(FINGERPRINT_LIMITS.maxDepth, 512);
});

test('finding and evidence fingerprints are canonical, deterministic, and domain separated', () => {
  const finding = createFinding(RULE, { file: 'worker.js', line: 1 });
  const reordered = { line: 1, details: { second: 2, first: 1 }, file: 'worker.js' };
  const canonical = { details: { first: 1, second: 2 }, file: 'worker.js', line: 1 };
  const findingDigest = findingFingerprint(finding);
  const evidenceDigest = evidenceFingerprint(finding, canonical);
  assert.match(findingDigest, /^[a-f0-9]{64}$/);
  assert.match(evidenceDigest, /^[a-f0-9]{64}$/);
  assert.notEqual(findingDigest, evidenceDigest);
  assert.equal(evidenceFingerprint(finding, reordered), evidenceDigest);
  assert.notEqual(evidenceFingerprint(finding, { ...canonical, line: 2 }), evidenceDigest);
  assert.notEqual(evidenceFingerprint({ ...finding, fingerprint: 'MVX999:other' }, canonical), evidenceDigest);

  const vectorFinding = { fingerprint: 'MVX102:cookies' };
  assert.equal(findingFingerprint(vectorFinding), '15af11ff59e5cd84b0b221d0c01c52bcc55f0b73804e2f766dcf53827e1c1eb3');
  assert.equal(evidenceFingerprint(vectorFinding, {
    details: { allowed: true, count: 1 }, file: 'worker.js', line: 2
  }), '3345df6c9467b08da1e4b3f1ef1c06ea2ff15c3fa058f41ac678ce899b5490c9');
});

test('canonical fingerprints reject ambiguous objects and bound recursion', () => {
  const finding = { id: 'MVX999' };
  const sparse = Array(1);
  assert.equal(evidenceFingerprint(finding, sparse), evidenceFingerprint(finding, [null]));
  assert.notEqual(evidenceFingerprint(finding, sparse), evidenceFingerprint(finding, []));
  assert.equal(evidenceFingerprint(finding, [undefined]), evidenceFingerprint(finding, [null]));
  assert.equal(evidenceFingerprint(finding, { omitted: undefined }), evidenceFingerprint(finding, {}));
  assert.equal(evidenceFingerprint(finding, { '\u{1F600}': 1, '\uE000': 2, text: '\uD800' }),
    evidenceFingerprint(finding, { text: '\uD800', '\uE000': 2, '\u{1F600}': 1 }));
  assert.equal(evidenceFingerprint(finding, { value: -0 }), evidenceFingerprint(finding, { value: 0 }));
  assert.throws(() => evidenceFingerprint(finding, undefined), /requires a defined JSON value/);

  let getterReads = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'value', { enumerable: true, get() { getterReads += 1; return getterReads; } });
  assert.throws(() => evidenceFingerprint(finding, accessor), /object accessor/);
  assert.equal(getterReads, 0);

  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => evidenceFingerprint(finding, cyclic), /must not contain cycles/);
  for (const value of [1n, () => {}, Symbol('value'), new Date(0), new Map(), { value: Number.NaN }]) {
    assert.throws(() => evidenceFingerprint(finding, value), /Fingerprint input/);
  }
  const decorated = [];
  decorated.extra = true;
  assert.throws(() => evidenceFingerprint(finding, decorated), /extra array property/);
  const symbolKeyed = { [Symbol('key')]: true };
  assert.throws(() => evidenceFingerprint(finding, symbolKeyed), /symbol-keyed object property/);
  const proxied = new Proxy({}, { getPrototypeOf() { throw new Error('must not inspect proxy'); } });
  assert.throws(() => evidenceFingerprint(finding, proxied), /contains a proxy/);
  assert.throws(() => findingKey(new Proxy({ id: 'MVX999' }, {})), /non-proxy object/);
  const getterFinding = {};
  Object.defineProperty(getterFinding, 'id', { get() { throw new Error('must not read getter'); } });
  assert.throws(() => findingKey(getterFinding), /data property/);

  let deep = {};
  for (let index = 0; index <= FINGERPRINT_LIMITS.maxDepth; index += 1) deep = { nested: deep };
  assert.throws(() => evidenceFingerprint(finding, deep), /nesting depth limit/);
  assert.throws(() => evidenceFingerprint(finding, {
    value: 'x'.repeat(FINGERPRINT_LIMITS.maxCanonicalBytes)
  }), /canonical byte limit/);
});
