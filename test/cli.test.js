import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runCli } from '../src/cli.js';
import { makeCrx } from '../support/archive-fixture.js';
import { captureStreams } from '../support/helpers.js';

const ROOT = path.resolve('corpus/fixtures');

test('CLI audit emits JSON and honors severity threshold', async () => {
  const capture = captureStreams();
  const code = await runCli(['audit', path.join(ROOT, 'cookie-access/mv3'), '--format', 'json', '--fail-on', 'high'], capture.streams);
  const result = JSON.parse(capture.output().stdout);
  assert.equal(code, 1);
  assert.equal(result.target.manifestVersion, 3);
  assert.equal(result.package.profile, 'mvx-package-v1');
  assert.equal(result.analysis.packageSha256, result.package.sha256);
  assert.equal(capture.output().stderr, '');

  const strict = captureStreams();
  assert.equal(await runCli([
    'audit', path.join(ROOT, 'cookie-access/mv3'), '--require-valid-signature'
  ], strict.streams), 2);
  assert.match(strict.output().stderr, /INVALID_ARGUMENT.*packed CRX\/ZIP/);
});

test('CLI packed audit requires acknowledgement and preserves fail-on semantics', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-cli-packed-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const input = path.join(temp, 'sample.crx');
  await writeFile(input, makeCrx([
    { name: 'manifest.json', content: '{"manifest_version":3,"name":"Packed CLI","version":"1.0.0"}' },
    { name: 'worker.js', content: 'eval(payload);\n' }
  ]));

  const refused = captureStreams();
  assert.equal(await runCli(['audit', input, '--format', 'json'], refused.streams), 2);
  assert.match(refused.output().stderr, /RISK_ACK_REQUIRED/);

  const accepted = captureStreams();
  assert.equal(await runCli([
    'audit', input, '--acknowledge-risk', '--format', 'json', '--fail-on', 'critical'
  ], accepted.streams), 1);
  const result = JSON.parse(accepted.output().stdout);
  assert.equal(result.target.root, input);
  assert.equal(result.artifact.format, 'crx');
  assert.match(result.artifact.sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.analysis.packageSha256, result.package.sha256);
  assert.ok(result.findings.some((finding) => finding.id === 'MVX201'));
  assert.ok(result.findings.some((finding) => finding.id === 'MVX004'));

  const strict = captureStreams();
  assert.equal(await runCli([
    'audit', input, '--acknowledge-risk', '--require-valid-signature'
  ], strict.streams), 2);
  assert.match(strict.output().stderr, /CRX_SIGNATURE_REQUIRED.*invalid-signed-header/);

  const directoryNamedZip = path.join(temp, 'unpacked.zip');
  await mkdir(directoryNamedZip);
  await writeFile(path.join(directoryNamedZip, 'manifest.json'), '{"manifest_version":3,"name":"Directory","version":"1.0.0"}\n', 'utf8');
  const directoryAudit = captureStreams();
  assert.equal(await runCli(['audit', directoryNamedZip, '--format', 'json'], directoryAudit.streams), 0);
  assert.equal(JSON.parse(directoryAudit.output().stdout).target.inputType, undefined);

  const broken = path.join(temp, 'broken.crx');
  await writeFile(broken, makeCrx([
    { name: 'manifest.json', content: '{broken' }
  ]));
  const failed = captureStreams();
  assert.equal(await runCli(['audit', broken, '--acknowledge-risk'], failed.streams), 2);
  assert.match(failed.output().stderr, /INVALID_MANIFEST.*<temporary extraction>\/extension\/manifest\.json/);
  assert.doesNotMatch(failed.output().stderr, /mvx-packed-audit-/);
});

test('CLI returns usage error for an unknown command', async () => {
  const capture = captureStreams();
  const code = await runCli(['unknown'], capture.streams);
  assert.equal(code, 2);
  assert.match(capture.output().stderr, /INVALID_ARGUMENT/);
});

test('CLI validates the complete corpus', async () => {
  const capture = captureStreams();
  const code = await runCli(['corpus', 'validate'], capture.streams);
  assert.equal(code, 0);
  assert.match(capture.output().stdout, /17 scenarios/);
});

test('CLI help documents stable exit codes', async () => {
  const capture = captureStreams();
  const code = await runCli(['--help'], capture.streams);
  assert.equal(code, 0);
  assert.match(capture.output().stdout, /Exit codes:/);
  assert.match(capture.output().stdout, /file\.crx\|file\.zip/);
  assert.match(capture.output().stdout, /--acknowledge-risk/);
  assert.match(capture.output().stdout, /rules validate/);
  assert.match(capture.output().stdout, /--rule-pack/);
  assert.match(capture.output().stdout, /--require-valid-signature/);
});

test('CLI emits valid SARIF and version output', async () => {
  const versionCapture = captureStreams();
  assert.equal(await runCli(['--version'], versionCapture.streams), 0);
  assert.match(versionCapture.output().stdout, /^3\.0\.0/);

  const sarifCapture = captureStreams();
  assert.equal(await runCli(['audit', path.join(ROOT, 'cookie-access/mv3'), '--format', 'sarif'], sarifCapture.streams), 0);
  assert.equal(JSON.parse(sarifCapture.output().stdout).version, '2.1.0');
});

test('CLI reports malformed catalog as validation failure', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-cli-catalog-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const catalogPath = path.join(temp, 'catalog.json');
  await writeFile(catalogPath, 'null\n', 'utf8');
  const capture = captureStreams();
  const code = await runCli(['corpus', 'validate', '--catalog', catalogPath], capture.streams);
  assert.equal(code, 1);
  assert.match(capture.output().stdout, /catalog must be a JSON object/);
});

test('CLI treats malformed nested catalog values as validation failures, not crashes', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-cli-nested-catalog-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const catalogPath = path.join(temp, 'catalog.json');
  await writeFile(catalogPath, '{"schemaVersion":1,"scenarios":[null]}\n', 'utf8');
  const capture = captureStreams();
  const code = await runCli(['corpus', 'validate', '--catalog', catalogPath], capture.streams);
  assert.equal(code, 1);
  assert.match(capture.output().stdout, /must be a JSON object/);
  assert.equal(capture.output().stderr, '');
});

test('CLI returns input error when a supported source exceeds the hard limit', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-cli-limit-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeFile(path.join(temp, 'manifest.json'), '{"manifest_version":3,"name":"Large","version":"1.0.0"}\n', 'utf8');
  await writeFile(path.join(temp, 'large.js'), `eval(payload);\n${'x'.repeat(10_000_000)}`, 'utf8');
  const capture = captureStreams();
  const code = await runCli(['audit', temp], capture.streams);
  assert.equal(code, 2);
  assert.match(capture.output().stderr, /SCAN_LIMIT.*large\.js/);
});

test('CLI reports and validates the real-world intelligence snapshot', async () => {
  const stats = captureStreams();
  assert.equal(await runCli(['intel', 'stats'], stats.streams), 0);
  assert.match(stats.output().stdout, /Unique extension IDs: 5122/);
  const validation = captureStreams();
  assert.equal(await runCli(['intel', 'validate', '--format', 'json'], validation.streams), 0);
  assert.equal(JSON.parse(validation.output().stdout).valid, true);
});

test('CLI looks up threat intelligence by extension ID', async () => {
  const capture = captureStreams();
  const code = await runCli(['intel', 'lookup', 'acmnokigkgihogfbeooklgemindnbine', '--format', 'json'], capture.streams);
  const records = JSON.parse(capture.output().stdout);
  assert.equal(code, 0);
  assert.equal(records[0].extensionId, 'acmnokigkgihogfbeooklgemindnbine');
  assert.ok(records[0].provenance.length > 0);
});

test('CLI refuses CRX extraction without explicit risk acknowledgement', async () => {
  const capture = captureStreams();
  assert.equal(await runCli(['sample', 'unpack', 'missing.crx'], capture.streams), 2);
  assert.match(capture.output().stderr, /RISK_ACK_REQUIRED/);
});

test('CLI evaluates recorded lab events without running extension code', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-cli-lab-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const eventsPath = path.join(temp, 'events.jsonl');
  await writeFile(eventsPath, [
    JSON.stringify({ schemaVersion: 1, timestamp: '2026-01-02T03:04:05.000Z', type: 'lab.completed', data: {} }),
    ''
  ].join('\n'), 'utf8');
  const capture = captureStreams();
  const code = await runCli([
    'lab', 'evaluate', 'lab/scenarios/credential-exfiltration.json', eventsPath, '--format', 'json'
  ], capture.streams);
  const report = JSON.parse(capture.output().stdout);
  assert.equal(code, 0);
  assert.equal(report.verdict, 'no_trigger_observed');
  assert.equal(report.summary.completed, true);
});

test('CLI creates a bounded real-sample batch plan without downloading', async () => {
  const capture = captureStreams();
  const code = await runCli(['sample', 'plan-many', '--limit', '3', '--max-total-bytes', '1000000', '--format', 'json'], capture.streams);
  const plan = JSON.parse(capture.output().stdout);
  assert.equal(code, 0);
  assert.ok(plan.selected > 0 && plan.selected <= 3);
  assert.ok(plan.totalBytes <= 1_000_000);
  assert.equal(plan.selections[0].labels.includes('behavior-confirmed-malicious'), true);
});
