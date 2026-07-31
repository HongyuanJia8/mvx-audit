import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  access, chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile
} from 'node:fs/promises';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { runCli } from '../src/cli.js';
import {
  LAB_EVALUATION_PROFILE, LAB_EVIDENCE_PROFILE, LAB_EXECUTION_PROFILE,
  LAB_VERIFICATION_PROFILE, evaluateLabFiles, evaluateLabRun, labReportToText,
  labVerificationToText, parseLabEvents, verifyLabReport
} from '../src/lab.js';
import { prepareLabInputSnapshot, removeLabInputSnapshot } from '../src/lab-snapshot.js';
import { VERSION } from '../src/version.js';
import { captureStreams, writeExtension } from '../support/helpers.js';

const IMAGE_ID = `sha256:${'1'.repeat(64)}`;
const AT = '2026-07-30T12:00:00.000Z';
const DONE = '2026-07-30T12:00:01.000Z';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

async function evidenceFixture(t) {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-lab-provenance-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3,
    name: 'Lab provenance fixture',
    version: '1.0.0'
  }, { 'worker.js': 'chrome.runtime.onInstalled.addListener(() => {});\n' });
  const scenarioDocument = {
    schemaVersion: 1,
    id: 'provenance-test',
    targetUrl: 'https://accounts.example.test/login',
    canaries: { sessionCookie: 'mvx-session-provenance-123456' },
    durationMs: 1_000
  };
  const scenarioSource = `${JSON.stringify(scenarioDocument, null, 2)}\n`;
  const scenario = path.join(temp, 'scenario.json');
  await writeFile(scenario, scenarioSource);
  const audit = await auditExtension(extension);
  const seccompSha256 = sha256(await readFile(path.resolve('lab/seccomp-chromium.json')));
  const events = [
    {
      schemaVersion: 1,
      timestamp: AT,
      type: 'lab.started',
      data: {
        profile: LAB_EXECUTION_PROFILE,
        browser: 'Chromium 140.0.0.0',
        imageId: IMAGE_ID,
        imageReference: 'mvx-lab:test',
        network: 'none',
        durationMs: 1_000,
        packageSha256: audit.package.sha256,
        analysisSha256: audit.analysis.sha256,
        scenarioSha256: sha256(scenarioSource),
        seccompSha256,
        toolVersion: VERSION
      }
    },
    { schemaVersion: 1, timestamp: DONE, type: 'lab.completed', data: { extensionTargetsObserved: 1 } }
  ];
  const eventsSource = `${events.map((event) => JSON.stringify(event)).join('\n')}\n`;
  const eventsPath = path.join(temp, 'events.jsonl');
  await writeFile(eventsPath, eventsSource);
  const report = await evaluateLabFiles(scenario, eventsPath);
  const reportPath = path.join(temp, 'report.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  return {
    temp, extension, scenario, scenarioSource, events, eventsPath, eventsSource, report, reportPath, audit
  };
}

test('file evaluation binds exact scenario, event, execution, and deterministic result identities', async (t) => {
  const fixture = await evidenceFixture(t);
  assert.equal(JSON.parse(await readFile(path.resolve('package.json'), 'utf8')).version, VERSION);
  const { report } = fixture;
  assert.equal(report.evidenceProvenance.profile, LAB_EVIDENCE_PROFILE);
  assert.equal(report.evidenceProvenance.scenario.sha256, sha256(fixture.scenarioSource));
  assert.equal(report.evidenceProvenance.events.sha256, sha256(fixture.eventsSource));
  assert.equal(report.evidenceProvenance.events.records, 2);
  assert.equal(report.evidenceProvenance.evaluation.profile, LAB_EVALUATION_PROFILE);
  assert.match(report.evidenceProvenance.evaluation.sha256, /^[a-f0-9]{64}$/);
  assert.equal(report.execution.profile, LAB_EXECUTION_PROFILE);
  assert.equal(report.execution.extension.packageSha256, fixture.audit.package.sha256);
  assert.equal(report.execution.container.imageId, IMAGE_ID);
  assert.match(labReportToText(report), new RegExp(`Events SHA-256: ${sha256(fixture.eventsSource)}`));

  const copiedScenario = path.join(fixture.temp, 'copied-scenario.json');
  const copiedEvents = path.join(fixture.temp, 'copied-events.jsonl');
  await writeFile(copiedScenario, fixture.scenarioSource);
  await writeFile(copiedEvents, fixture.eventsSource);
  assert.deepEqual(await evaluateLabFiles(copiedScenario, copiedEvents), report);
});

test('lab report verification recomputes all local identities and exposes image trust explicitly', async (t) => {
  const fixture = await evidenceFixture(t);
  const verified = await verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    { expectedImageId: IMAGE_ID }
  );
  assert.equal(verified.profile, LAB_VERIFICATION_PROFILE);
  assert.equal(verified.valid, true);
  assert.equal(verified.checks.expectedImageIdentity, true);
  assert.equal(verified.caveat, null);
  assert.equal(verified.report.sha256, sha256(await readFile(fixture.reportPath)));
  assert.match(labVerificationToText(verified), /Expected image checked: yes/);

  const recordedOnly = await verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath
  );
  assert.equal(recordedOnly.checks.expectedImageIdentity, null);
  assert.match(recordedOnly.caveat, /not compared with an independently supplied/);

  const cli = captureStreams();
  assert.equal(await runCli([
    'lab', 'verify', fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    '--expected-image-id', IMAGE_ID, '--format', 'json'
  ], cli.streams), 0);
  assert.equal(JSON.parse(cli.output().stdout).valid, true);
});

test('lab verification binds every independently supplied identity', async (t) => {
  const fixture = await evidenceFixture(t);
  const reportSha256 = sha256(await readFile(fixture.reportPath));
  const seccompSha256 = sha256(await readFile(path.resolve('lab/seccomp-chromium.json')));
  const expected = {
    expectedReportSha256: reportSha256,
    expectedPackageSha256: fixture.audit.package.sha256,
    expectedAnalysisSha256: fixture.audit.analysis.sha256,
    expectedScenarioSha256: sha256(fixture.scenarioSource),
    expectedEventsSha256: sha256(fixture.eventsSource),
    expectedEvaluationSha256: fixture.report.evidenceProvenance.evaluation.sha256,
    expectedSeccompSha256: seccompSha256,
    expectedImageId: IMAGE_ID
  };
  const verified = await verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath, expected
  );
  assert.deepEqual(verified.checks.independent, {
    reportSha256: true,
    packageSha256: true,
    analysisSha256: true,
    scenarioSha256: true,
    eventsSha256: true,
    evaluationSha256: true,
    seccompSha256: true,
    imageId: true
  });
  assert.equal(verified.checks.privateExtensionSnapshot, true);
  assert.equal(verified.caveat, null);
  assert.deepEqual(verified.caveats, []);
  assert.deepEqual(verified.identities, {
    packageSha256: fixture.audit.package.sha256,
    analysisSha256: fixture.audit.analysis.sha256,
    scenarioSha256: sha256(fixture.scenarioSource),
    eventsSha256: sha256(fixture.eventsSource),
    evaluationSha256: fixture.report.evidenceProvenance.evaluation.sha256,
    seccompSha256,
    imageId: IMAGE_ID
  });
  assert.match(labVerificationToText(verified), /Independent identities checked: 8\/8/);

  const cli = captureStreams();
  assert.equal(await runCli([
    'lab', 'verify', fixture.reportPath, fixture.extension, fixture.scenario,
    fixture.eventsPath,
    '--expected-report-sha256', reportSha256,
    '--expected-package-sha256', fixture.audit.package.sha256,
    '--expected-analysis-sha256', fixture.audit.analysis.sha256,
    '--expected-scenario-sha256', sha256(fixture.scenarioSource),
    '--expected-events-sha256', sha256(fixture.eventsSource),
    '--expected-evaluation-sha256', fixture.report.evidenceProvenance.evaluation.sha256,
    '--expected-seccomp-sha256', seccompSha256,
    '--expected-image-id', IMAGE_ID,
    '--format', 'json'
  ], cli.streams), 0);
  assert.equal(Object.values(JSON.parse(cli.output().stdout).checks.independent)
    .every((value) => value === true), true);
});

test('lab verification rejects each mismatched independent identity before trust is claimed', async (t) => {
  const fixture = await evidenceFixture(t);
  const wrongDigest = '0'.repeat(64);
  const mismatches = [
    ['expectedReportSha256', wrongDigest],
    ['expectedPackageSha256', wrongDigest],
    ['expectedAnalysisSha256', wrongDigest],
    ['expectedScenarioSha256', wrongDigest],
    ['expectedEventsSha256', wrongDigest],
    ['expectedEvaluationSha256', wrongDigest],
    ['expectedSeccompSha256', wrongDigest],
    ['expectedImageId', `sha256:${'2'.repeat(64)}`]
  ];
  for (const [key, value] of mismatches) {
    await assert.rejects(() => verifyLabReport(
      fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
      { [key]: value }
    ), (error) => error.code === 'LAB_IDENTITY_MISMATCH', key);
  }
});

test('lab verification snapshots options and cleans a private extension copy', async (t) => {
  const fixture = await evidenceFixture(t);
  const temporaryDirectory = path.join(fixture.temp, 'verification-temporary');
  await mkdir(temporaryDirectory);
  const options = {
    expectedPackageSha256: fixture.audit.package.sha256,
    temporaryDirectory
  };
  const pending = verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath, options
  );
  options.expectedPackageSha256 = '0'.repeat(64);
  options.temporaryDirectory = fixture.extension;
  const verified = await pending;
  assert.equal(verified.checks.privateExtensionSnapshot, true);
  assert.deepEqual(await readdir(temporaryDirectory), []);

  const insideExtension = path.join(fixture.extension, 'temporary');
  await mkdir(insideExtension);
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    { temporaryDirectory: insideExtension }
  ), (error) => error.code === 'UNSAFE_LAB_INPUT');
  const temporaryLink = path.join(fixture.temp, 'temporary-link');
  await symlink(temporaryDirectory, temporaryLink);
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    { temporaryDirectory: temporaryLink }
  ), (error) => error.code === 'UNSAFE_LAB_INPUT');

  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    {
      seccompProfile: path.join(fixture.temp, 'missing-seccomp.json'),
      temporaryDirectory
    }
  ), (error) => error.code === 'LAB_INPUT_NOT_FOUND');
  assert.deepEqual(await readdir(temporaryDirectory), []);
});

test('verification rejects semantic, raw-byte, extension, image, and isolation identity drift', async (t) => {
  const fixture = await evidenceFixture(t);
  await writeFile(fixture.eventsPath, `${fixture.eventsSource}\n`);
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath
  ), (error) => error.code === 'LAB_REPORT_MISMATCH');
  await writeFile(fixture.eventsPath, fixture.eventsSource);

  const changedReport = { ...fixture.report, verdict: 'suspicious_activity' };
  await writeFile(fixture.reportPath, `${JSON.stringify(changedReport, null, 2)}\n`);
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath
  ), (error) => error.code === 'LAB_REPORT_MISMATCH');
  await writeFile(fixture.reportPath, `${JSON.stringify(fixture.report, null, 2)}\n`);

  const otherExtension = await writeExtension(path.join(fixture.temp, 'other-extension'), {
    manifest_version: 3, name: 'Other extension', version: '1.0.0'
  }, { 'other.js': 'void 0;\n' });
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, otherExtension, fixture.scenario, fixture.eventsPath
  ), (error) => error.code === 'LAB_IDENTITY_MISMATCH');
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    { expectedImageId: `sha256:${'2'.repeat(64)}` }
  ), (error) => error.code === 'LAB_IDENTITY_MISMATCH');

  const otherSeccomp = path.join(fixture.temp, 'seccomp.json');
  await writeFile(otherSeccomp, '{}\n');
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    { seccompProfile: otherSeccomp }
  ), (error) => error.code === 'LAB_IDENTITY_MISMATCH');
});

test('strict evidence inputs reject duplicate keys, invalid UTF-8, symlinks, and ambiguous streams', async (t) => {
  const fixture = await evidenceFixture(t);
  const invalidScenario = path.join(fixture.temp, 'duplicate-scenario.json');
  await writeFile(invalidScenario, `{"schemaVersion":1,"schemaVersion":1,"id":"x","targetUrl":"https://example.test","canaries":{"token":"1234567890123456"}}`);
  await assert.rejects(() => evaluateLabFiles(invalidScenario, fixture.eventsPath),
    (error) => error.code === 'INVALID_LAB_SCENARIO' && /duplicate JSON field/.test(error.message));

  const duplicateEvent = path.join(fixture.temp, 'duplicate-event.jsonl');
  await writeFile(duplicateEvent, `{"schemaVersion":1,"timestamp":"${AT}","type":"lab.completed","type":"lab.error","data":{}}\n`);
  await assert.rejects(() => evaluateLabFiles(fixture.scenario, duplicateEvent),
    (error) => error.code === 'INVALID_LAB_EVENTS' && /duplicate JSON field/.test(error.message));

  const invalidUtf8 = path.join(fixture.temp, 'invalid-utf8.jsonl');
  await writeFile(invalidUtf8, Buffer.from([0xff, 0xfe]));
  await assert.rejects(() => evaluateLabFiles(fixture.scenario, invalidUtf8),
    (error) => error.code === 'INVALID_LAB_EVENTS');

  const scenarioLink = path.join(fixture.temp, 'scenario-link.json');
  const eventsLink = path.join(fixture.temp, 'events-link.jsonl');
  const reportLink = path.join(fixture.temp, 'report-link.json');
  await symlink(fixture.scenario, scenarioLink);
  await symlink(fixture.eventsPath, eventsLink);
  await symlink(fixture.reportPath, reportLink);
  await assert.rejects(() => evaluateLabFiles(scenarioLink, fixture.eventsPath),
    (error) => error.code === 'UNSAFE_LAB_INPUT');
  await assert.rejects(() => evaluateLabFiles(fixture.scenario, eventsLink),
    (error) => error.code === 'UNSAFE_LAB_INPUT');
  await assert.rejects(() => verifyLabReport(
    reportLink, fixture.extension, fixture.scenario, fixture.eventsPath
  ), (error) => error.code === 'UNSAFE_LAB_REPORT');
  const duplicateReport = path.join(fixture.temp, 'duplicate-report.json');
  await writeFile(duplicateReport, '{"schemaVersion":1,"schemaVersion":1}\n');
  await assert.rejects(() => verifyLabReport(
    duplicateReport, fixture.extension, fixture.scenario, fixture.eventsPath
  ), (error) => error.code === 'INVALID_LAB_REPORT' && /duplicate JSON field/.test(error.message));

  const completed = { schemaVersion: 1, timestamp: AT, type: 'lab.completed', data: {} };
  const started = { schemaVersion: 1, timestamp: DONE, type: 'lab.started', data: {} };
  assert.throws(() => evaluateLabRun({
    schemaVersion: 1, id: 'ordering', targetUrl: 'https://example.test/',
    canaries: { tokenValue: '1234567890123456' }
  }, [completed, started]), (error) => error.code === 'INVALID_LAB_EVENTS');
  assert.throws(() => parseLabEvents(`${JSON.stringify(completed)}\n${JSON.stringify(completed)}\n`),
    (error) => error.code === 'INVALID_LAB_EVENTS');
  const hidden = { ...completed };
  Object.defineProperty(hidden, 'hidden', { value: 'ambiguous' });
  assert.throws(() => evaluateLabRun({
    schemaVersion: 1, id: 'hidden', targetUrl: 'https://example.test/',
    canaries: { tokenValue: '1234567890123456' }
  }, [hidden]), (error) => error.code === 'INVALID_LAB_EVENTS');

  const prototypeEvents = [];
  Object.setPrototypeOf(prototypeEvents, {
    forEach(callback) { callback(completed, 0); }
  });
  assert.throws(() => evaluateLabRun({
    schemaVersion: 1, id: 'prototype-array', targetUrl: 'https://example.test/',
    canaries: { tokenValue: '1234567890123456' }
  }, prototypeEvents), (error) => error.code === 'INVALID_LAB_EVENTS');

  const accessorEvents = [completed];
  Object.defineProperty(accessorEvents, '0', { enumerable: true, get: () => completed });
  assert.throws(() => evaluateLabRun({
    schemaVersion: 1, id: 'accessor-array', targetUrl: 'https://example.test/',
    canaries: { tokenValue: '1234567890123456' }
  }, accessorEvents), (error) => error.code === 'INVALID_LAB_EVENTS');

  const nestedArray = [];
  Object.setPrototypeOf(nestedArray, null);
  assert.throws(() => evaluateLabRun({
    schemaVersion: 1, id: 'nested-array', targetUrl: 'https://example.test/',
    canaries: { tokenValue: '1234567890123456' }
  }, [{ ...completed, data: { nestedArray } }]), (error) => error.code === 'INVALID_LAB_EVENTS');

  const nonCanonicalScenario = path.join(fixture.temp, 'noncanonical-scenario.json');
  await writeFile(nonCanonicalScenario, JSON.stringify({
    schemaVersion: 1, id: 'noncanonical', targetUrl: 'https://EXAMPLE.test',
    canaries: { tokenValue: '1234567890123456' }
  }));
  await assert.rejects(() => evaluateLabFiles(nonCanonicalScenario, fixture.eventsPath),
    (error) => error.code === 'INVALID_LAB_SCENARIO');
});

test('offline evaluation remains available but verification requires live execution provenance', async (t) => {
  const fixture = await evidenceFixture(t);
  const events = path.join(fixture.temp, 'external-events.jsonl');
  await writeFile(events, `${JSON.stringify({
    schemaVersion: 1, timestamp: AT, type: 'lab.completed', data: {}
  })}\n`);
  const report = await evaluateLabFiles(fixture.scenario, events);
  assert.equal(report.execution, undefined);
  const reportPath = path.join(fixture.temp, 'external-report.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  await assert.rejects(() => verifyLabReport(
    reportPath, fixture.extension, fixture.scenario, events
  ), (error) => error.code === 'LAB_PROVENANCE_MISSING');
});

test('lab input snapshots isolate mounted bytes from later source mutations and clean safely', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-lab-snapshot-test-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'Snapshot', version: '1.0.0'
  }, { 'worker.js': 'const original = true;\n' });
  const scenario = path.join(temp, 'scenario.json');
  const scenarioBytes = Buffer.from('{"schemaVersion":1,"id":"snapshot","targetUrl":"https://example.test/","canaries":{"tokenValue":"1234567890123456"}}\n');
  await writeFile(scenario, scenarioBytes);
  const temporaryDirectory = path.join(temp, 'temporary');
  await writeExtension(temporaryDirectory, { manifest_version: 3, name: 'Temp holder', version: '1.0.0' });
  await rm(path.join(temporaryDirectory, 'manifest.json'));
  const snapshot = await prepareLabInputSnapshot(extension, scenario, { temporaryDirectory });
  assert.equal(Object.isFrozen(snapshot), true);
  assert.deepEqual(await readFile(snapshot.scenario), scenarioBytes);
  const snapshotWorker = await readFile(path.join(snapshot.extension, 'worker.js'), 'utf8');
  if (process.platform !== 'win32') {
    assert.equal((await lstat(snapshot.workspace)).mode & 0o777, 0o700);
    assert.equal((await lstat(snapshot.extension)).mode & 0o777, 0o755);
    assert.equal((await lstat(path.join(snapshot.extension, 'worker.js'))).mode & 0o777, 0o444);
    assert.equal((await lstat(snapshot.scenario)).mode & 0o777, 0o444);
  }
  await writeFile(path.join(extension, 'worker.js'), 'const changed = true;\n');
  await writeFile(scenario, '{}\n');
  assert.equal(await readFile(path.join(snapshot.extension, 'worker.js'), 'utf8'), snapshotWorker);
  assert.deepEqual(await readFile(snapshot.scenario), scenarioBytes);
  assert.notEqual((await auditExtension(extension)).package.sha256, snapshot.package.sha256);
  const workspace = snapshot.workspace;
  await removeLabInputSnapshot(snapshot);
  await assert.rejects(() => access(workspace));
  await assert.rejects(() => removeLabInputSnapshot(snapshot),
    (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => removeLabInputSnapshot({ workspace }),
    (error) => error.code === 'INVALID_ARGUMENT');

  const extensionLink = path.join(temp, 'extension-link');
  const scenarioLink = path.join(temp, 'scenario-link.json');
  await symlink(extension, extensionLink);
  await symlink(scenario, scenarioLink);
  await assert.rejects(() => prepareLabInputSnapshot(extensionLink, scenario, { temporaryDirectory }),
    (error) => error.code === 'UNSAFE_LAB_INPUT');
  await assert.rejects(() => prepareLabInputSnapshot(extension, scenarioLink, { temporaryDirectory }),
    (error) => error.code === 'UNSAFE_LAB_INPUT');

  await writeFile(scenario, scenarioBytes);
  const temporaryLink = path.join(temp, 'temporary-link');
  await symlink(temporaryDirectory, temporaryLink);
  await assert.rejects(() => prepareLabInputSnapshot(
    extension, scenario, { temporaryDirectory: temporaryLink }
  ), (error) => error.code === 'UNSAFE_LAB_INPUT');
  const insideExtension = path.join(extension, 'temporary');
  await mkdir(insideExtension);
  await assert.rejects(() => prepareLabInputSnapshot(
    extension, scenario, { temporaryDirectory: insideExtension }
  ), (error) => error.code === 'UNSAFE_LAB_INPUT');
});

test('image identity CLI option is scoped to lab verify and malformed verifier options fail closed', async (t) => {
  const fixture = await evidenceFixture(t);
  const ignored = captureStreams();
  assert.equal(await runCli([
    'audit', fixture.extension, '--expected-image-id', IMAGE_ID
  ], ignored.streams), 2);
  assert.match(ignored.output().stderr, /--expected-image-id applies only to lab verify/);
  const evaluate = captureStreams();
  assert.equal(await runCli([
    'lab', 'evaluate', fixture.scenario, fixture.eventsPath, '--expected-image-id', IMAGE_ID
  ], evaluate.streams), 2);
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath, null
  ), (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    { expectedImageId: 'sha256:not-a-digest' }
  ), (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    { expectedScenarioSha256: 'A'.repeat(64) }
  ), (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    { unexpected: true }
  ), (error) => error.code === 'INVALID_ARGUMENT');
  const accessorOptions = {};
  Object.defineProperty(accessorOptions, 'expectedReportSha256', {
    enumerable: true,
    get: () => '0'.repeat(64)
  });
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    accessorOptions
  ), (error) => error.code === 'INVALID_ARGUMENT');
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, fixture.extension, fixture.scenario, fixture.eventsPath,
    proxy
  ), (error) => error.code === 'INVALID_ARGUMENT');
  const scoped = captureStreams();
  assert.equal(await runCli([
    'lab', 'evaluate', fixture.scenario, fixture.eventsPath,
    '--expected-events-sha256', sha256(fixture.eventsSource)
  ], scoped.streams), 2);
  assert.match(scoped.output().stderr, /Lab evidence identity options apply only to lab verify/);
  await assert.rejects(() => evaluateLabFiles(null, fixture.eventsPath),
    (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => verifyLabReport(
    fixture.reportPath, Symbol('extension'), fixture.scenario, fixture.eventsPath
  ), (error) => error.code === 'INVALID_ARGUMENT');
});

test('host wrapper runs immutable snapshots by image ID and emits a verifiable retained bundle', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-lab-wrapper-test-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'Wrapper fixture', version: '1.0.0'
  }, { 'worker.js': 'void 0;\n' });
  const scenario = path.join(temp, 'scenario.json');
  await writeFile(scenario, JSON.stringify({
    schemaVersion: 1,
    id: 'wrapper-test',
    targetUrl: 'https://example.test/',
    canaries: { tokenValue: '1234567890123456' },
    durationMs: 1_000
  }, null, 2) + '\n');
  const fakeBin = path.join(temp, 'bin');
  await writeExtension(fakeBin, { manifest_version: 3, name: 'Fake bin holder', version: '1.0.0' });
  await rm(path.join(fakeBin, 'manifest.json'));
  const docker = path.join(fakeBin, 'docker');
  const dockerLog = path.join(temp, 'docker-log.jsonl');
  await writeFile(docker, `#!/usr/bin/env node
const { appendFileSync, writeFileSync } = require('node:fs');
const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_DOCKER_LOG, JSON.stringify(args) + '\\n');
if (args[0] === 'image') {
  process.stdout.write('${IMAGE_ID}\\n');
} else {
  const cidIndex = args.indexOf('--cidfile');
  if (cidIndex !== -1) writeFileSync(args[cidIndex + 1], '${'2'.repeat(64)}\\n');
  const environment = {};
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== '--env') continue;
    const pair = args[++index];
    const boundary = pair.indexOf('=');
    environment[pair.slice(0, boundary)] = pair.slice(boundary + 1);
  }
  const data = {
    profile: environment.MVX_LAB_PROFILE,
    browser: 'Chromium fake-wrapper-test',
    imageId: environment.MVX_LAB_IMAGE_ID,
    imageReference: environment.MVX_LAB_IMAGE_REFERENCE,
    network: 'none',
    durationMs: 1000,
    packageSha256: environment.MVX_LAB_PACKAGE_SHA256,
    analysisSha256: environment.MVX_LAB_ANALYSIS_SHA256,
    scenarioSha256: environment.MVX_LAB_SCENARIO_SHA256,
    seccompSha256: environment.MVX_LAB_SECCOMP_SHA256,
    toolVersion: environment.MVX_LAB_TOOL_VERSION
  };
  process.stdout.write(JSON.stringify({ schemaVersion: 1, timestamp: '${AT}', type: 'lab.started', data }) + '\\n');
  process.stdout.write(JSON.stringify({ schemaVersion: 1, timestamp: '${DONE}', type: 'lab.completed', data: { extensionTargetsObserved: 1 } }) + '\\n');
}
`);
  await chmod(docker, 0o700);
  const output = path.join(temp, 'output');
  const execution = await run(process.execPath, [
    path.resolve('scripts/run-lab.mjs'),
    '--extension', extension,
    '--scenario', scenario,
    '--output', output,
    '--image', 'mvx-lab:test',
    '--acknowledge-risk'
  ], {
    cwd: path.resolve('.'),
    env: { ...process.env, PATH: `${fakeBin}${path.delimiter}${process.env.PATH}`, FAKE_DOCKER_LOG: dockerLog }
  });
  assert.equal(execution.code, 0, execution.stderr);
  assert.match(execution.stdout, /Lab verdict: no_trigger_observed; contained: yes/);
  const reportPath = path.join(output, 'report.json');
  const retainedScenario = path.join(output, 'scenario.json');
  const events = path.join(output, 'events.jsonl');
  const report = JSON.parse(await readFile(reportPath, 'utf8'));
  assert.equal(report.execution.container.imageId, IMAGE_ID);
  assert.equal((await verifyLabReport(
    reportPath, extension, retainedScenario, events, { expectedImageId: IMAGE_ID }
  )).valid, true);

  const invocations = (await readFile(dockerLog, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(invocations.length, 2);
  const dockerRun = invocations[1];
  assert.deepEqual(dockerRun.slice(-2), [IMAGE_ID, '--acknowledge-risk']);
  const cidFile = dockerRun[dockerRun.indexOf('--cidfile') + 1];
  assert.match(cidFile, /container\.cid$/);
  await assert.rejects(() => access(cidFile));
  const securityOption = dockerRun[dockerRun.findIndex((value) => value.startsWith('seccomp='))];
  const seccompSnapshot = securityOption.slice('seccomp='.length);
  assert.notEqual(seccompSnapshot, path.resolve('lab/seccomp-chromium.json'));
  await assert.rejects(() => access(seccompSnapshot));
  const mounts = dockerRun.filter((value) => value.startsWith('type=bind,src='));
  assert.equal(mounts.some((value) => value.includes(`src=${extension},`)), false);
  assert.equal(mounts.some((value) => value.includes(`src=${retainedScenario},`)), false);
  assert.ok(mounts.every((value) => value.endsWith(',readonly')));
});

test('host wrapper force-removes a container after event output overflow', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-lab-wrapper-overflow-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'Overflow fixture', version: '1.0.0'
  });
  const scenario = path.join(temp, 'scenario.json');
  await writeFile(scenario, JSON.stringify({
    schemaVersion: 1, id: 'overflow-test', targetUrl: 'https://example.test/',
    canaries: { tokenValue: '1234567890123456' }, durationMs: 1_000
  }) + '\n');
  const fakeBin = path.join(temp, 'bin');
  await writeExtension(fakeBin, { manifest_version: 3, name: 'Fake bin holder', version: '1.0.0' });
  await rm(path.join(fakeBin, 'manifest.json'));
  const docker = path.join(fakeBin, 'docker');
  const dockerLog = path.join(temp, 'docker-log.jsonl');
  const containerId = '3'.repeat(64);
  await writeFile(docker, `#!/usr/bin/env node
const { appendFileSync, chmodSync, writeFileSync } = require('node:fs');
const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_DOCKER_LOG, JSON.stringify(args) + '\\n');
if (args[0] === 'image') {
  process.stdout.write('${IMAGE_ID}\\n');
} else if (args[0] === 'rm') {
  process.exit(args[1] === '--force' && args[2] === '${containerId}'
    ? Number(process.env.FAKE_RM_EXIT || 0) : 9);
} else {
  const cidIndex = args.indexOf('--cidfile');
  writeFileSync(args[cidIndex + 1], '${containerId}\\n');
  if (process.env.FAKE_CID_UNREADABLE) chmodSync(args[cidIndex + 1], 0o000);
  process.on('SIGTERM', () => {});
  process.stdout.on('error', () => {});
  process.stdout.write(Buffer.alloc(20_000_001, 0x78));
  setInterval(() => {}, 1_000);
}
`);
  await chmod(docker, 0o700);
  const output = path.join(temp, 'output');
  const execution = await run(process.execPath, [
    path.resolve('scripts/run-lab.mjs'),
    '--extension', extension, '--scenario', scenario, '--output', output,
    '--image', 'mvx-lab:test', '--acknowledge-risk'
  ], {
    cwd: path.resolve('.'),
    env: { ...process.env, PATH: `${fakeBin}${path.delimiter}${process.env.PATH}`, FAKE_DOCKER_LOG: dockerLog }
  });
  assert.equal(execution.code, 1);
  assert.match(execution.stderr, /Lab event stream exceeds 20000000 bytes/);
  const invocations = (await readFile(dockerLog, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(invocations.length, 3);
  assert.deepEqual(invocations[2], ['rm', '--force', containerId]);
  const cidFile = invocations[1][invocations[1].indexOf('--cidfile') + 1];
  await assert.rejects(() => access(cidFile));

  const failedOutput = path.join(temp, 'failed-cleanup-output');
  const failedCleanup = await run(process.execPath, [
    path.resolve('scripts/run-lab.mjs'),
    '--extension', extension, '--scenario', scenario, '--output', failedOutput,
    '--image', 'mvx-lab:test', '--acknowledge-risk'
  ], {
    cwd: path.resolve('.'),
    env: {
      ...process.env,
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH}`,
      FAKE_DOCKER_LOG: dockerLog,
      FAKE_RM_EXIT: '9'
    }
  });
  assert.equal(failedCleanup.code, 1);
  assert.match(failedCleanup.stderr, /Lab container cleanup failed after LAB_LIMIT; private snapshot retained at/);
  const allInvocations = (await readFile(dockerLog, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(allInvocations.length, 6);
  assert.deepEqual(allInvocations[5], ['rm', '--force', containerId]);
  const retainedCidFile = allInvocations[4][allInvocations[4].indexOf('--cidfile') + 1];
  const retainedSnapshot = path.dirname(retainedCidFile);
  await access(retainedSnapshot);
  assert.match(failedCleanup.stderr, new RegExp(retainedSnapshot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  await rm(retainedSnapshot, { recursive: true, force: true });

  const unreadableOutput = path.join(temp, 'unreadable-cid-output');
  const unreadableCid = await run(process.execPath, [
    path.resolve('scripts/run-lab.mjs'),
    '--extension', extension, '--scenario', scenario, '--output', unreadableOutput,
    '--image', 'mvx-lab:test', '--acknowledge-risk'
  ], {
    cwd: path.resolve('.'),
    env: {
      ...process.env,
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH}`,
      FAKE_DOCKER_LOG: dockerLog,
      FAKE_CID_UNREADABLE: '1'
    }
  });
  assert.equal(unreadableCid.code, 1);
  assert.match(unreadableCid.stderr, /Lab container cleanup failed after LAB_LIMIT; private snapshot retained at/);
  const finalInvocations = (await readFile(dockerLog, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(finalInvocations.length, 8);
  assert.equal(finalInvocations[7][0], 'run');
  const unreadableCidFile = finalInvocations[7][finalInvocations[7].indexOf('--cidfile') + 1];
  const unreadableSnapshot = path.dirname(unreadableCidFile);
  await access(unreadableSnapshot);
  assert.match(unreadableCid.stderr, new RegExp(unreadableSnapshot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  await rm(unreadableSnapshot, { recursive: true, force: true });
});
