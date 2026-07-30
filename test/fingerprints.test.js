import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EVIDENCE_FINGERPRINT_PROFILE, FINDING_FINGERPRINT_PROFILE,
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
});
