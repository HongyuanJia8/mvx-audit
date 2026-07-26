import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { compareExtensions } from '../src/compare.js';

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

