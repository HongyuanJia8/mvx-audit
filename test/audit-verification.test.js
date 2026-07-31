import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import {
  AUDIT_VERIFICATION_PROFILE, auditVerificationToText,
  verifyAuditReport
} from '../src/audit-verification.js';
import { runCli } from '../src/cli.js';
import { auditExtensionArchive } from '../src/packed-audit.js';
import { makeSignedCrx3, makeZip } from '../support/archive-fixture.js';
import { captureStreams, writeExtension } from '../support/helpers.js';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

const DISPOSITION_AT = '2026-07-30T12:00:00.000Z';

test('audit verification reproduces a path-independent directory report and external identities', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-audit-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const first = await writeExtension(path.join(root, 'first'), {
    manifest_version: 3,
    name: 'Verification fixture',
    version: '1.0.0',
    permissions: ['cookies'],
    host_permissions: ['https://example.invalid/*']
  }, { 'worker.js': 'eval(payload);\n' });
  const second = path.join(root, 'relocated');
  await cp(first, second, { recursive: true });
  const audit = await auditExtension(first);
  const reportBytes = Buffer.from(`${JSON.stringify(audit, null, 2)}\n`);
  const reportPath = path.join(root, 'report.json');
  await writeFile(reportPath, reportBytes);

  const verification = await verifyAuditReport(reportPath, second, {
    expectedReportSha256: sha256(reportBytes),
    expectedPackageSha256: audit.package.sha256,
    expectedAnalysisSha256: audit.analysis.sha256
  });
  assert.equal(verification.profile, AUDIT_VERIFICATION_PROFILE);
  assert.equal(verification.valid, true);
  assert.equal(verification.inputType, 'directory');
  assert.equal(verification.checks.independent.reportSha256, true);
  assert.equal(verification.checks.independent.packageSha256, true);
  assert.equal(verification.checks.locationMetadataMatchesInput, false);
  assert.equal(verification.caveats.length, 1);
  assert.match(auditVerificationToText(verification), /Audit report valid: yes/);
  assert.equal(
    (await verifyAuditReport(reportPath, first)).checks.locationMetadataMatchesInput,
    true
  );

  await writeFile(path.join(second, 'worker.js'), 'eval(changed);\n');
  await assert.rejects(
    () => verifyAuditReport(reportPath, second),
    (error) => error.code === 'AUDIT_REPORT_MISMATCH'
  );
  await assert.rejects(
    () => verifyAuditReport(reportPath, first, {
      expectedReportSha256: '0'.repeat(64)
    }),
    (error) => error.code === 'AUDIT_IDENTITY_MISMATCH'
  );
  await assert.rejects(
    () => verifyAuditReport(reportPath, second, {
      expectedPackageSha256: audit.package.sha256
    }),
    (error) => error.code === 'AUDIT_IDENTITY_MISMATCH'
  );
});

test('audit verification binds packed bytes, signature identity, and CLI acknowledgement', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-packed-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const temporaryDirectory = path.join(root, 'temporary');
  await mkdir(temporaryDirectory);
  const signed = makeSignedCrx3([
    {
      name: 'manifest.json',
      content: '{"manifest_version":3,"name":"Packed verification","version":"2.0.0"}'
    },
    { name: 'worker.js', content: 'eval(payload);\n' }
  ]);
  const first = path.join(root, 'first.crx');
  const relocated = path.join(root, 'relocated.bin');
  await writeFile(first, signed.bytes);
  await writeFile(relocated, signed.bytes);
  const archiveSha256 = sha256(signed.bytes);
  const audit = await auditExtensionArchive(first, {
    temporaryDirectory,
    requireValidSignature: true,
    expectedArchiveSha256: archiveSha256,
    expectedExtensionId: signed.extensionId
  });
  const reportBytes = Buffer.from(`${JSON.stringify(audit, null, 2)}\n`);
  const reportPath = path.join(root, 'packed-report.json');
  await writeFile(reportPath, reportBytes);

  const verification = await verifyAuditReport(reportPath, relocated, {
    temporaryDirectory,
    requireValidSignature: true,
    expectedArchiveSha256: archiveSha256,
    expectedExtensionId: signed.extensionId
  });
  assert.equal(verification.inputType, 'archive');
  assert.equal(verification.identities.artifactSha256, archiveSha256);
  assert.equal(verification.identities.extensionId, signed.extensionId);
  assert.equal(verification.checks.independent.validSignature, true);
  assert.deepEqual(await readdir(temporaryDirectory), []);

  const defaultAudit = await auditExtensionArchive(first, { temporaryDirectory });
  const defaultReport = path.join(root, 'default-packed-report.json');
  await writeFile(defaultReport, `${JSON.stringify(defaultAudit, null, 2)}\n`);
  assert.equal((await verifyAuditReport(defaultReport, relocated, {
    temporaryDirectory,
    requireValidSignature: true,
    expectedArchiveSha256: archiveSha256,
    expectedExtensionId: signed.extensionId
  })).valid, true);

  const zipPath = path.join(root, 'unsigned.zip');
  await writeFile(zipPath, makeZip([
    {
      name: 'manifest.json',
      content: '{"manifest_version":3,"name":"Unsigned verification","version":"1.0.0"}'
    }
  ]));
  const zipAudit = await auditExtensionArchive(zipPath, { temporaryDirectory });
  const zipReport = path.join(root, 'zip-report.json');
  await writeFile(zipReport, `${JSON.stringify(zipAudit)}\n`);
  for (const independent of [
    { requireValidSignature: true },
    { expectedExtensionId: signed.extensionId }
  ]) {
    await assert.rejects(
      () => verifyAuditReport(zipReport, zipPath, { temporaryDirectory, ...independent }),
      (error) => error.code === 'AUDIT_IDENTITY_UNVERIFIABLE'
    );
  }

  const refused = captureStreams();
  assert.equal(await runCli([
    'audit', 'verify', reportPath, relocated, '--format', 'json'
  ], refused.streams), 2);
  assert.match(refused.output().stderr, /RISK_ACK_REQUIRED/);

  const accepted = captureStreams();
  assert.equal(await runCli([
    'audit', 'verify', reportPath, relocated, '--acknowledge-risk',
    '--require-valid-signature',
    '--expected-archive-sha256', archiveSha256,
    '--expected-extension-id', signed.extensionId,
    '--format', 'json'
  ], accepted.streams), 0);
  assert.equal(JSON.parse(accepted.output().stdout).valid, true);
  assert.equal(accepted.output().stderr, '');

  for (const argv of [
    ['audit', 'verify', reportPath, relocated, '--acknowledge-risk', '--format', 'sarif'],
    ['audit', 'verify', reportPath, relocated, '--acknowledge-risk', '--fail-on', 'high'],
    ['audit', 'verify', reportPath, relocated, '--acknowledge-risk',
      '--disposition-at', DISPOSITION_AT],
    ['compare', first, relocated, '--expected-report-sha256', archiveSha256]
  ]) {
    const rejected = captureStreams();
    assert.equal(await runCli(argv, rejected.streams), 2);
    assert.match(rejected.output().stderr, /INVALID_ARGUMENT/);
  }
});

test('audit verification rejects ambiguous reports and hostile options before analysis', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-invalid-report-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(root, 'extension'), {
    manifest_version: 3, name: 'Invalid report fixture', version: '1.0.0'
  });
  const report = await auditExtension(extension);
  const reportPath = path.join(root, 'report.json');
  await writeFile(reportPath, `${JSON.stringify(report).replace(
    '"schemaVersion":1',
    '"schemaVersion":1,"schemaVersion":1'
  )}\n`);
  await assert.rejects(
    () => verifyAuditReport(reportPath, extension),
    (error) => error.code === 'INVALID_AUDIT_REPORT' && /duplicate/.test(error.message)
  );

  const realReport = path.join(root, 'real-report.json');
  await writeFile(realReport, `${JSON.stringify(report)}\n`);
  const linkedReport = path.join(root, 'linked-report.json');
  await symlink(realReport, linkedReport);
  await assert.rejects(
    () => verifyAuditReport(linkedReport, extension),
    (error) => error.code === 'UNSAFE_AUDIT_REPORT'
  );
  for (const options of [null, [], new Date(), new Proxy({}, {})]) {
    await assert.rejects(
      () => verifyAuditReport(realReport, extension, options),
      (error) => error.code === 'INVALID_ARGUMENT'
    );
  }
  const accessor = {};
  Object.defineProperty(accessor, 'expectedReportSha256', {
    get() {
      throw new Error('must not execute');
    }
  });
  await assert.rejects(
    () => verifyAuditReport(realReport, extension, accessor),
    (error) => error.code === 'INVALID_ARGUMENT' && /accessor/.test(error.message)
  );
  const sparsePaths = new Array(1);
  const extraPaths = [];
  extraPaths.extra = 'ignored.json';
  for (const rulePacks of [sparsePaths, extraPaths]) {
    await assert.rejects(
      () => verifyAuditReport(realReport, extension, { rulePacks }),
      (error) => error.code === 'INVALID_ARGUMENT'
    );
  }
  const accessorPaths = ['ignored.json'];
  Object.defineProperty(accessorPaths, '0', {
    get() {
      throw new Error('must not execute');
    }
  });
  const symbolPaths = [];
  symbolPaths[Symbol('ignored')] = 'ignored.json';
  const customPrototypePaths = [];
  Object.setPrototypeOf(customPrototypePaths, null);
  const invalidOptionSets = [
    { zUnknown: true, aUnknown: true },
    { expectedPackageSha256: 'A'.repeat(64) },
    { expectedExtensionId: 'z'.repeat(32) },
    { requireValidSignature: 'yes' },
    { temporaryDirectory: '' },
    { reportLimits: { unknown: 1 } },
    { reportLimits: { maxReportBytes: 0 } },
    { rulePacks: null },
    { rulePacks: new Proxy([], {}) },
    { rulePacks: accessorPaths },
    { rulePacks: symbolPaths },
    { rulePacks: customPrototypePaths },
    { rulePacks: [''] }
  ];
  for (const invalidOptions of invalidOptionSets) {
    await assert.rejects(
      () => verifyAuditReport(realReport, extension, invalidOptions),
      (error) => error.code === 'INVALID_ARGUMENT'
    );
  }
  for (const [reportInput, extensionInput] of [
    ['', extension],
    [realReport, ''],
    [null, extension]
  ]) {
    await assert.rejects(
      () => verifyAuditReport(reportInput, extensionInput),
      (error) => error.code === 'INVALID_ARGUMENT'
    );
  }
  await assert.rejects(
    () => verifyAuditReport(realReport, extension, { archiveLimits: {} }),
    (error) => error.code === 'INVALID_ARGUMENT'
  );

  const malformed = path.join(root, 'malformed.json');
  await writeFile(malformed, '{');
  const wrongSchema = path.join(root, 'wrong-schema.json');
  await writeFile(wrongSchema, '{}');
  const deep = path.join(root, 'deep.json');
  await writeFile(deep, `${'['.repeat(130)}0${']'.repeat(130)}`);
  const invalidArtifact = path.join(root, 'invalid-artifact.json');
  await writeFile(invalidArtifact, JSON.stringify({ ...report, artifact: { path: '' } }));
  for (const [input, code] of [
    [malformed, 'INVALID_AUDIT_REPORT'],
    [wrongSchema, 'INVALID_AUDIT_REPORT'],
    [deep, 'AUDIT_REPORT_LIMIT'],
    [invalidArtifact, 'INVALID_AUDIT_REPORT']
  ]) {
    await assert.rejects(
      () => verifyAuditReport(input, extension),
      (error) => error.code === code
    );
  }
});

test('audit verification replays exact rule-pack and disposition-policy provenance', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-review-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const first = await writeExtension(path.join(root, 'first'), {
    manifest_version: 3, name: 'Review replay', version: '1.0.0'
  }, {
    'worker.js': "fetch('https://telemetry.campaign.example.invalid/collect');\n"
  });
  const relocated = path.join(root, 'relocated');
  await cp(first, relocated, { recursive: true });
  const rulePack = path.join(root, 'rule-pack.json');
  await writeFile(rulePack, await readFile(path.resolve('examples/campaign-rule-pack.json')));
  const baseline = await auditExtension(first, { rulePacks: [rulePack] });
  const fingerprint = 'RP:example.campaign:NETWORK_MARKER';
  assert.ok(baseline.findings.some((finding) => finding.fingerprint === fingerprint));
  const policy = {
    schemaVersion: 1,
    policyId: 'verification.review',
    name: 'Verification review',
    version: '2026.07.30',
    entries: [{
      fingerprint,
      packageSha256: baseline.package.sha256,
      analysisSha256: baseline.analysis.sha256,
      artifactSha256: null,
      disposition: 'accepted-risk',
      owner: 'security-team@example.invalid',
      justification: 'Reviewed against the exact package for audit verification.',
      expiresAt: '2026-08-30T12:00:00.000Z',
      ticketUrl: 'https://example.invalid/reviews/verification'
    }]
  };
  const policyPath = path.join(root, 'policy.json');
  await writeFile(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
  const audit = await auditExtension(first, {
    rulePacks: [rulePack],
    dispositionPolicies: [policyPath],
    dispositionAt: DISPOSITION_AT
  });
  assert.equal(
    audit.findings.find((finding) => finding.fingerprint === fingerprint).disposition.status,
    'active'
  );
  const reportPath = path.join(root, 'report.json');
  await writeFile(reportPath, `${JSON.stringify(audit, null, 2)}\n`);

  const verification = await verifyAuditReport(reportPath, relocated, {
    rulePacks: [rulePack],
    dispositionPolicies: [policyPath]
  });
  assert.equal(verification.checks.rulePackProvenance, true);
  assert.equal(verification.checks.dispositionProvenance, true);
  await assert.rejects(
    () => verifyAuditReport(reportPath, relocated, { rulePacks: [rulePack] }),
    (error) => error.code === 'AUDIT_REPORT_MISMATCH'
  );

  const changedPack = JSON.parse(await readFile(rulePack, 'utf8'));
  changedPack.version = '2026.07.30-revised';
  await writeFile(rulePack, `${JSON.stringify(changedPack, null, 2)}\n`);
  await assert.rejects(
    () => verifyAuditReport(reportPath, relocated, {
      rulePacks: [rulePack],
      dispositionPolicies: [policyPath]
    }),
    (error) => error.code === 'AUDIT_REPORT_MISMATCH'
  );
});

test('audit verification rejects report tampering, unsafe paths, limits, and prototype traps', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-tamper-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(root, 'extension'), {
    manifest_version: 3,
    name: 'Tamper matrix',
    version: '1.0.0',
    permissions: ['cookies']
  }, { 'worker.js': 'eval(payload);\n' });
  const audit = await auditExtension(extension);
  const reportPath = path.join(root, 'report.json');
  await writeFile(reportPath, `${JSON.stringify(audit, null, 2)}\n`);
  const mutations = [
    ['tool version', (report) => { report.tool.version = '0.0.0-tampered'; }],
    ['summary', (report) => { report.summary.total += 1; }],
    ['package provenance', (report) => { report.package.bytes += 1; }],
    ['analysis provenance', (report) => { report.analysis.sha256 = '0'.repeat(64); }],
    ['rule-pack provenance', (report) => {
      report.rulePacks.push({
        schemaVersion: 1,
        namespace: 'tampered.pack',
        name: 'Tampered',
        version: '1',
        bytes: 1,
        sha256: '0'.repeat(64),
        rules: 1,
        indicators: 1
      });
    }],
    ['finding', (report) => { report.findings[0].title = 'Tampered title'; }]
  ];
  for (const [label, mutate] of mutations) {
    const tampered = structuredClone(audit);
    mutate(tampered);
    const tamperedPath = path.join(root, `${label.replaceAll(' ', '-')}.json`);
    await writeFile(tamperedPath, `${JSON.stringify(tampered)}\n`);
    await assert.rejects(
      () => verifyAuditReport(tamperedPath, extension),
      (error) => error.code === 'AUDIT_REPORT_MISMATCH',
      label
    );
  }

  const unsafe = structuredClone(audit);
  unsafe.target.root += '\u202e';
  const unsafePath = path.join(root, 'unsafe-path.json');
  await writeFile(unsafePath, `${JSON.stringify(unsafe)}\n`);
  await assert.rejects(
    () => verifyAuditReport(unsafePath, extension),
    (error) => error.code === 'INVALID_AUDIT_REPORT' && /unsafe display/.test(error.message)
  );
  const invalidUtf8 = path.join(root, 'invalid-utf8.json');
  await writeFile(invalidUtf8, Buffer.from([0xff]));
  await assert.rejects(
    () => verifyAuditReport(invalidUtf8, extension),
    (error) => error.code === 'INVALID_AUDIT_REPORT'
  );
  await assert.rejects(
    () => verifyAuditReport(reportPath, extension, {
      reportLimits: { maxReportBytes: 1 }
    }),
    (error) => error.code === 'AUDIT_REPORT_LIMIT'
  );
  for (const reportLimits of [new Proxy({}, {}), { get maxReportBytes() {
    throw new Error('must not execute');
  } }]) {
    await assert.rejects(
      () => verifyAuditReport(reportPath, extension, { reportLimits }),
      (error) => error.code === 'INVALID_ARGUMENT'
    );
  }

  let prototypeTrapExecuted = false;
  Object.defineProperty(Object.prototype, '_preparedRulePacks', {
    configurable: true,
    get() {
      prototypeTrapExecuted = true;
      throw new Error('must not execute');
    }
  });
  try {
    assert.equal((await verifyAuditReport(reportPath, extension)).valid, true);
  } finally {
    delete Object.prototype._preparedRulePacks;
  }
  assert.equal(prototypeTrapExecuted, false);
});
