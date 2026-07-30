import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runStaticBenchmark, staticBenchmarkToText } from '../src/benchmark.js';
import { makeCrx, makeSignedCrx3 } from '../support/archive-fixture.js';

const ID = 'abcdefghijklmnopabcdefghijklmnop';
const HASH = 'a'.repeat(64);

test('static benchmark measures review triggers without claiming malware accuracy', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const extensionRoot = path.join(root, ID);
  await mkdir(extensionRoot);
  await writeFile(path.join(extensionRoot, `${HASH}.crx`), 'fixture');
  const rulePack = path.join(root, 'benchmark-rules.json');
  await writeFile(rulePack, `${JSON.stringify({
    schemaVersion: 1,
    namespace: 'benchmark.test',
    name: 'Benchmark indicators',
    version: '1.0.0',
    rules: [{
      id: 'BENCHMARK_IOC', title: 'Benchmark indicator', severity: 'high', confidence: 'high',
      category: 'campaign-ioc', description: 'Synthetic benchmark indicator.', remediation: 'Review it.',
      references: [], indicators: [{ type: 'path', value: 'worker.js' }]
    }]
  })}\n`, 'utf8');
  let observedRulePacks;
  let observedUnpackOptions;
  let observedDestination;
  const report = await runStaticBenchmark({
    quarantineDir: root,
    records: [{ extensionId: ID, labels: ['behavior-confirmed-malicious'] }],
    label: 'behavior-confirmed-malicious',
    acknowledgeRisk: true,
    rulePacks: [rulePack],
    requireValidSignature: true,
    unpacker: async (_input, destination, options) => {
      observedDestination = destination;
      observedUnpackOptions = options;
      return { destination, files: 2 };
    },
    auditor: async (_destination, options) => {
      observedRulePacks = options._preparedRulePacks.provenance;
      return {
        target: { manifestVersion: 3, version: '1.0' },
        summary: { counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } },
        scan: { filesVisited: 2 },
        findings: [{ id: 'MVX999', severity: 'high' }]
      };
    }
  });
  assert.equal(report.summary.reviewTriggerRate, 1);
  assert.equal(report.ruleCounts.MVX999, 1);
  assert.equal(report.rulePacks[0].namespace, 'benchmark.test');
  assert.deepEqual(observedRulePacks, report.rulePacks);
  assert.deepEqual(observedUnpackOptions, {
    requireValidSignature: true,
    expectedArchiveSha256: HASH,
    expectedExtensionId: ID
  });
  await assert.rejects(() => lstat(path.dirname(observedDestination)), (error) => error.code === 'ENOENT');
  assert.match(report.caveats[0], /not malware-classification accuracy/);
  assert.match(staticBenchmarkToText({ ...report, rulePacks: undefined }), /Rule packs: 0/);
});

test('static benchmark ignores an untrusted existing extraction and audits fresh signed bytes', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-cache-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const signed = makeSignedCrx3([
    {
      name: 'manifest.json',
      content: '{"manifest_version":3,"name":"Fresh archive","version":"1.0.0"}'
    },
    { name: 'worker.js', content: 'eval(payload);\n' }
  ]);
  const hash = createHash('sha256').update(signed.bytes).digest('hex');
  const destination = path.join(root, signed.extensionId, 'unpacked', hash);
  await mkdir(destination, { recursive: true });
  await writeFile(path.join(destination, 'manifest.json'), '{"manifest_version":3,"name":"Untrusted benign cache","version":"1.0.0"}');
  await writeFile(path.join(root, signed.extensionId, `${hash}.crx`), signed.bytes);
  const report = await runStaticBenchmark({
    quarantineDir: root,
    acknowledgeRisk: true,
    requireValidSignature: true
  });
  assert.equal(report.summary.failures, 0);
  assert.equal(report.results[0].cachedExtraction, false);
  assert.equal(report.results[0].authenticity.status, 'verified');
  assert.deepEqual(report.results[0].triggeringRules, ['MVX201']);
  assert.match(await readFile(path.join(destination, 'manifest.json'), 'utf8'), /Untrusted benign cache/);
});

test('strict benchmark rejects an invalid CRX even when a persistent extraction exists', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-strict-cache-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bytes = makeCrx([{
    name: 'manifest.json', content: '{"manifest_version":3}'
  }]);
  const hash = createHash('sha256').update(bytes).digest('hex');
  const destination = path.join(root, ID, 'unpacked', hash);
  await mkdir(destination, { recursive: true });
  await writeFile(path.join(destination, 'manifest.json'), '{"manifest_version":3}');
  await writeFile(path.join(root, ID, `${hash}.crx`), bytes);
  const report = await runStaticBenchmark({
    quarantineDir: root,
    acknowledgeRisk: true,
    requireValidSignature: true
  });
  assert.equal(report.summary.analyzed, 0);
  assert.equal(report.summary.failures, 1);
  assert.equal(report.failures[0].code, 'ARCHIVE_IDENTITY_UNVERIFIABLE');
});

test('benchmark counts invalid CRX authenticity as an MVX004 review trigger', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-authenticity-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, ID));
  const bytes = makeCrx([{
    name: 'manifest.json',
    content: '{"manifest_version":3,"name":"Benchmark authenticity","version":"1.0.0"}'
  }]);
  const hash = createHash('sha256').update(bytes).digest('hex');
  await writeFile(path.join(root, ID, `${hash}.crx`), bytes);
  const report = await runStaticBenchmark({ quarantineDir: root, acknowledgeRisk: true });
  assert.equal(report.summary.analyzed, 1);
  assert.equal(report.results[0].authenticity.status, 'invalid');
  assert.equal(report.results[0].reviewTriggered, true);
  assert.deepEqual(report.results[0].triggeringRules, ['MVX004']);
  assert.equal(report.results[0].severityCounts.high, 1);
});

test('benchmark rejects archive hash and verified extension-ID mismatches before audit', async (t) => {
  const signed = makeSignedCrx3([{
    name: 'manifest.json',
    content: '{"manifest_version":3,"name":"Identity mismatch","version":"1.0.0"}'
  }]);

  const wrongHashRoot = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-wrong-hash-'));
  t.after(() => rm(wrongHashRoot, { recursive: true, force: true }));
  await mkdir(path.join(wrongHashRoot, signed.extensionId));
  await writeFile(path.join(wrongHashRoot, signed.extensionId, `${HASH}.crx`), signed.bytes);
  const wrongHash = await runStaticBenchmark({
    quarantineDir: wrongHashRoot,
    acknowledgeRisk: true,
    requireValidSignature: true
  });
  assert.equal(wrongHash.failures[0].code, 'ARCHIVE_IDENTITY_MISMATCH');
  await assert.rejects(
    () => lstat(path.join(wrongHashRoot, signed.extensionId, 'unpacked', HASH)),
    (error) => error.code === 'ENOENT'
  );

  const actualHash = createHash('sha256').update(signed.bytes).digest('hex');
  const wrongIdRoot = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-wrong-id-'));
  t.after(() => rm(wrongIdRoot, { recursive: true, force: true }));
  await mkdir(path.join(wrongIdRoot, ID));
  await writeFile(path.join(wrongIdRoot, ID, `${actualHash}.crx`), signed.bytes);
  const wrongId = await runStaticBenchmark({
    quarantineDir: wrongIdRoot,
    acknowledgeRisk: true,
    requireValidSignature: true
  });
  assert.equal(wrongId.failures[0].code, 'ARCHIVE_IDENTITY_MISMATCH');
  await assert.rejects(
    () => lstat(path.join(wrongIdRoot, ID, 'unpacked', actualHash)),
    (error) => error.code === 'ENOENT'
  );
});

test('static benchmark requires explicit risk acknowledgement and validates threshold', async () => {
  await assert.rejects(() => runStaticBenchmark(), (error) => error.code === 'RISK_ACK_REQUIRED');
  await assert.rejects(() => runStaticBenchmark({ acknowledgeRisk: true, threshold: 'urgent' }),
    (error) => error.code === 'INVALID_ARGUMENT');
});

test('static benchmark isolates individual analyzer failures', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-failure-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, ID));
  await writeFile(path.join(root, ID, `${HASH}.crx`), 'fixture');
  const report = await runStaticBenchmark({
    quarantineDir: root, acknowledgeRisk: true,
    unpacker: async () => { throw Object.assign(new Error('bad archive'), { code: 'INVALID_CRX' }); }
  });
  assert.equal(report.summary.failures, 1);
  assert.equal(report.failures[0].code, 'INVALID_CRX');
  assert.equal(report.summary.reviewTriggerRate, null);
});

test('benchmark reports cleanup failure without hiding the original failure or temporary path', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-cleanup-failure-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, ID));
  await writeFile(path.join(root, ID, `${HASH}.crx`), 'fixture');
  let workspace;
  const report = await runStaticBenchmark({
    quarantineDir: root,
    acknowledgeRisk: true,
    unpacker: async (_input, destination) => {
      workspace = path.dirname(destination);
      return { files: 1 };
    },
    auditor: async (destination) => {
      throw Object.assign(new Error(`${destination} original failure`), { code: 'AUDIT_FAILED' });
    },
    remover: async (target) => {
      throw Object.assign(new Error(`${target} cleanup failure`), { code: 'EACCES' });
    }
  });
  t.after(() => rm(workspace, { recursive: true, force: true }));
  assert.equal(report.summary.failures, 1);
  assert.equal(report.failures[0].code, 'TEMP_CLEANUP_FAILED');
  assert.equal(report.failures[0].originalCode, 'AUDIT_FAILED');
  assert.match(report.failures[0].message, /cleanup failed after AUDIT_FAILED/);
  assert.match(report.failures[0].message, /<temporary extraction> cleanup failure/);
  assert.doesNotMatch(report.failures[0].message, /mvx-benchmark-/);
});

test('static benchmark rejects missing and symlink quarantine roots', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-link-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const linked = path.join(root, 'linked');
  await symlink(path.join(root, 'missing'), linked);
  await assert.rejects(() => runStaticBenchmark({ quarantineDir: linked, acknowledgeRisk: true }),
    (error) => error.code === 'UNSAFE_QUARANTINE');
  await assert.rejects(() => runStaticBenchmark({ quarantineDir: path.join(root, 'absent'), acknowledgeRisk: true }),
    (error) => error.code === 'QUARANTINE_NOT_FOUND');
});
