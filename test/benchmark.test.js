import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runStaticBenchmark, staticBenchmarkToText } from '../src/benchmark.js';

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
  const report = await runStaticBenchmark({
    quarantineDir: root,
    records: [{ extensionId: ID, labels: ['behavior-confirmed-malicious'] }],
    label: 'behavior-confirmed-malicious',
    acknowledgeRisk: true,
    rulePacks: [rulePack],
    unpacker: async (_input, destination) => ({ destination, files: 2 }),
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
  assert.match(report.caveats[0], /not malware-classification accuracy/);
  assert.match(staticBenchmarkToText({ ...report, rulePacks: undefined }), /Rule packs: 0/);
});

test('static benchmark safely reuses an existing extraction', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-cache-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = path.join(root, ID, 'unpacked', HASH);
  await mkdir(destination, { recursive: true });
  await writeFile(path.join(root, ID, `${HASH}.crx`), 'fixture');
  const report = await runStaticBenchmark({
    quarantineDir: root, acknowledgeRisk: true,
    unpacker: async () => { throw Object.assign(new Error('exists'), { code: 'OUTPUT_EXISTS' }); },
    auditor: async () => ({
      target: { manifestVersion: 3, version: '1.0' }, scan: { filesVisited: 4 },
      summary: { counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }, findings: []
    })
  });
  assert.equal(report.summary.failures, 0);
  assert.equal(report.results[0].cachedExtraction, true);
  assert.equal(report.results[0].files, 4);
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
