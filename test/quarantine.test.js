import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fetchSample, planSample } from '../src/quarantine.js';

const ID = 'abcdefghijklmnopabcdefghijklmnop';
const REF = '1'.repeat(40);
const PAYLOAD = Buffer.from('CRX fixture bytes');
const SHA256 = createHash('sha256').update(PAYLOAD).digest('hex');
const GIT_BLOB = createHash('sha1').update(`blob ${PAYLOAD.length}\0`).update(PAYLOAD).digest('hex');
const sources = [{ id: 'gherardo-crx', ref: REF }];
const record = {
  extensionId: ID,
  artifacts: [{
    provider: 'gherardo-crx',
    path: `AutomatedExtensions/${ID}.crx`,
    size: PAYLOAD.length,
    gitBlobSha: GIT_BLOB,
    reportedSha256: SHA256
  }]
};

function response(bytes = PAYLOAD) {
  return new Response(bytes, { status: 200, headers: { 'content-length': String(bytes.length) } });
}

test('sample plan exposes pinned artifact metadata without downloading', () => {
  const plan = planSample(record, sources);
  assert.equal(plan.artifacts[0].downloadable, true);
  assert.match(plan.artifacts[0].url, new RegExp(REF));
  assert.equal(plan.artifacts[0].reportedSha256, SHA256);
});

test('sample fetch requires acknowledgement and verifies both hashes', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-quarantine-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await assert.rejects(() => fetchSample({ record, sources, quarantineDir: root, fetcher: async () => response() }),
    (error) => error.code === 'RISK_ACK_REQUIRED');
  const first = await fetchSample({ record, sources, quarantineDir: root, acknowledgeRisk: true, fetcher: async () => response() });
  assert.equal(first.cached, false);
  assert.deepEqual(await readFile(first.path), PAYLOAD);
  const second = await fetchSample({ record, sources, quarantineDir: root, acknowledgeRisk: true, fetcher: async () => { throw new Error('should not fetch'); } });
  assert.equal(second.cached, true);
});

test('sample fetch removes partial data after checksum mismatch', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-quarantine-bad-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const tampered = Buffer.from('tampered bytes!!');
  await assert.rejects(() => fetchSample({
    record,
    sources,
    quarantineDir: root,
    acknowledgeRisk: true,
    fetcher: async () => response(tampered)
  }), (error) => ['SAMPLE_CHECKSUM', 'SAMPLE_LIMIT'].includes(error.code));
});

test('sample fetch rejects symlink quarantine roots and untrusted redirects', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-quarantine-link-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const linked = path.join(temp, 'linked');
  await symlink(path.join(temp, 'real'), linked);
  await assert.rejects(() => fetchSample({ record, sources, quarantineDir: linked, acknowledgeRisk: true, fetcher: async () => response() }),
    (error) => error.code === 'UNSAFE_QUARANTINE');
  const root = path.join(temp, 'safe');
  const redirect = new Response(null, { status: 302, headers: { location: 'https://evil.example/sample.crx' } });
  await assert.rejects(() => fetchSample({ record, sources, quarantineDir: root, acknowledgeRisk: true, fetcher: async () => redirect }),
    (error) => error.code === 'UNSAFE_DOWNLOAD');
});
