import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { compareExtensions } from '../src/compare.js';
import { writeExtension } from '../support/helpers.js';

const ROOT = path.resolve('corpus/fixtures');

test('remote code comparison distinguishes CSP change from source behavior', async () => {
  const result = await compareExtensions(path.join(ROOT, 'remote-code/mv2'), path.join(ROOT, 'remote-code/mv3'));
  assert.ok(result.delta.resolvedFindings.some((finding) => finding.id === 'MVX107'));
  assert.ok(result.before.findings.some((finding) => finding.id === 'MVX201'));
  assert.ok(result.after.findings.some((finding) => finding.id === 'MVX201'));
  assert.equal(result.delta.riskScore, -25);
});

test('request control migration reports removed and introduced mechanisms', async () => {
  const result = await compareExtensions(path.join(ROOT, 'request-tampering/mv2'), path.join(ROOT, 'request-tampering/mv3'));
  assert.ok(result.delta.resolvedFindings.some((finding) => finding.id === 'MVX110'));
  assert.ok(result.delta.introducedFindings.some((finding) => finding.id === 'MVX113'));
  assert.deepEqual(result.delta.permissionsAdded, ['declarativeNetRequest']);
  assert.deepEqual(result.delta.hostsAdded, []);
  assert.deepEqual(result.delta.hostsRemoved, []);
});

test('comparison reports evidence movement even when the rule persists', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-compare-evidence-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const before = await writeExtension(path.join(temp, 'before'), { manifest_version: 2, name: 'Before', version: '1.0.0' }, {
    'a.js': 'eval(firstPayload);\n'
  });
  const after = await writeExtension(path.join(temp, 'after'), { manifest_version: 3, name: 'After', version: '1.0.0' }, {
    'different.js': 'eval(secondPayload);\neval(thirdPayload);\n'
  });
  const result = await compareExtensions(before, after);
  assert.equal(result.delta.resolvedFindings.length, 0);
  assert.equal(result.delta.introducedFindings.length, 0);
  assert.equal(result.delta.evidenceAdded[0].evidence.file, 'different.js');
  assert.equal(result.delta.evidenceRemoved[0].evidence.file, 'a.js');
  assert.equal(result.delta.evidenceCount.delta, 1);
  assert.notEqual(result.before.analysis.sha256, result.after.analysis.sha256);
});
