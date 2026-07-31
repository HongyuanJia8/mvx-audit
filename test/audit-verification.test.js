import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cp, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { auditExtension } from '../src/analyzer.js';
import {
  AUDIT_VERIFICATION_PROFILE, auditVerificationToText,
  verifyAuditReport
} from '../src/audit-verification.js';
import { runCli } from '../src/cli.js';
import { auditExtensionArchive } from '../src/packed-audit.js';
import {
  assertPrivateWorkspace, createPrivateWorkspace, removePrivateWorkspace,
  resolvePrivateWorkspaceParent
} from '../src/private-workspace.js';
import { makeSignedCrx3, makeZip } from '../support/archive-fixture.js';
import { captureStreams, writeExtension } from '../support/helpers.js';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

const DISPOSITION_AT = '2026-07-30T12:00:00.000Z';
const execFileAsync = promisify(execFile);

test('audit verification reproduces a path-independent directory report and external identities', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-audit-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const temporaryDirectory = path.join(root, 'temporary');
  await mkdir(temporaryDirectory);
  const first = await writeExtension(path.join(root, 'first'), {
    manifest_version: 3,
    name: 'Verification fixture',
    version: '1.0.0',
    permissions: ['cookies'],
    host_permissions: ['https://example.invalid/*']
  }, { 'worker.js': 'eval(payload);\n' });
  const second = path.join(root, 'relocated');
  await cp(first, second, { recursive: true });
  await symlink('worker.js', path.join(first, 'worker-link.js'));
  await symlink('worker.js', path.join(second, 'worker-link.js'));
  const audit = await auditExtension(first);
  const reportBytes = Buffer.from(`${JSON.stringify(audit, null, 2)}\n`);
  const reportPath = path.join(root, 'report.json');
  await writeFile(reportPath, reportBytes);

  const verification = await verifyAuditReport(reportPath, second, {
    expectedReportSha256: sha256(reportBytes),
    expectedPackageSha256: audit.package.sha256,
    expectedAnalysisSha256: audit.analysis.sha256,
    temporaryDirectory
  });
  assert.equal(verification.profile, AUDIT_VERIFICATION_PROFILE);
  assert.equal(verification.valid, true);
  assert.equal(verification.inputType, 'directory');
  assert.equal(verification.checks.independent.reportSha256, true);
  assert.equal(verification.checks.independent.packageSha256, true);
  assert.equal(verification.checks.recordedSignatureRequirement, null);
  assert.equal(verification.checks.locationMetadataMatchesInput, false);
  assert.equal(verification.caveats.length, 1);
  assert.deepEqual(await readdir(temporaryDirectory), []);
  await assert.rejects(
    () => verifyAuditReport(reportPath, first, {
      temporaryDirectory,
      limits: { maxFiles: 1 }
    }),
    (error) => error.code === 'SCAN_LIMIT'
  );
  assert.deepEqual(await readdir(temporaryDirectory), []);
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
  assert.equal(verification.checks.recordedSignatureRequirement, true);
  assert.deepEqual(await readdir(temporaryDirectory), []);

  const defaultAudit = await auditExtensionArchive(first, { temporaryDirectory });
  assert.equal(defaultAudit.artifact.identityPolicy.requireValidSignature, false);
  const defaultReport = path.join(root, 'default-packed-report.json');
  await writeFile(defaultReport, `${JSON.stringify(defaultAudit, null, 2)}\n`);
  assert.equal((await verifyAuditReport(defaultReport, relocated, {
    temporaryDirectory,
    requireValidSignature: true,
    expectedArchiveSha256: archiveSha256,
    expectedExtensionId: signed.extensionId
  })).valid, true);
  const legacyAudit = structuredClone(defaultAudit);
  delete legacyAudit.artifact.identityPolicy.requireValidSignature;
  const legacyReport = path.join(root, 'legacy-packed-report.json');
  await writeFile(legacyReport, `${JSON.stringify(legacyAudit)}\n`);
  const legacyVerification = await verifyAuditReport(legacyReport, relocated, {
    temporaryDirectory
  });
  assert.equal(legacyVerification.checks.recordedSignatureRequirement, null);
  assert.match(legacyVerification.caveats.at(-1), /legacy packed report/);
  const strictOnlyAudit = await auditExtensionArchive(first, {
    temporaryDirectory,
    requireValidSignature: true
  });
  assert.equal(strictOnlyAudit.artifact.identityPolicy.requireValidSignature, true);
  assert.notDeepEqual(strictOnlyAudit.artifact.identityPolicy, defaultAudit.artifact.identityPolicy);
  const strictOnlyReport = path.join(root, 'strict-only-report.json');
  await writeFile(strictOnlyReport, `${JSON.stringify(strictOnlyAudit)}\n`);
  assert.equal((await verifyAuditReport(strictOnlyReport, relocated, {
    temporaryDirectory
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
  const wrongZip = path.join(root, 'wrong.zip');
  await writeFile(wrongZip, makeZip([{ name: 'manifest.json', content: '{' }]));
  await assert.rejects(
    () => verifyAuditReport(zipReport, wrongZip, {
      temporaryDirectory,
      expectedArchiveSha256: zipAudit.artifact.sha256
    }),
    (error) => error.code === 'AUDIT_IDENTITY_MISMATCH'
  );
  const otherZip = path.join(root, 'other.zip');
  await writeFile(otherZip, makeZip([{
    name: 'manifest.json',
    content: '{"manifest_version":3,"name":"Other archive","version":"1.0.0"}'
  }]));
  const otherZipSha256 = sha256(await readFile(otherZip));
  const pinnedZipAudit = await auditExtensionArchive(zipPath, {
    temporaryDirectory,
    expectedArchiveSha256: zipAudit.artifact.sha256
  });
  const pinnedZipReport = path.join(root, 'pinned-zip-report.json');
  await writeFile(pinnedZipReport, `${JSON.stringify(pinnedZipAudit)}\n`);
  await assert.rejects(
    () => verifyAuditReport(pinnedZipReport, otherZip, {
      temporaryDirectory,
      expectedArchiveSha256: otherZipSha256
    }),
    (error) => error.code === 'ARCHIVE_IDENTITY_MISMATCH'
  );
  const invalidSigned = makeSignedCrx3([
    { name: 'manifest.json', content: '{' }
  ], { tamperProofIndex: 0 });
  const invalidSignedPath = path.join(root, 'invalid-signed.crx');
  await writeFile(invalidSignedPath, invalidSigned.bytes);
  await assert.rejects(
    () => verifyAuditReport(defaultReport, invalidSignedPath, {
      temporaryDirectory,
      requireValidSignature: true
    }),
    (error) => error.code === 'AUDIT_IDENTITY_UNVERIFIABLE'
  );
  assert.deepEqual(await readdir(temporaryDirectory), []);

  const invalidAudit = await auditExtensionArchive(invalidSignedPath, {
    temporaryDirectory
  }).catch((error) => {
    assert.equal(error.code, 'INVALID_MANIFEST');
    return null;
  });
  assert.equal(invalidAudit, null);
  const tamperedIdentity = makeSignedCrx3([
    {
      name: 'manifest.json',
      content: '{"manifest_version":3,"name":"Forged identity","version":"1.0.0"}'
    }
  ], { tamperProofIndex: 0 });
  const tamperedIdentityPath = path.join(root, 'tampered-identity.crx');
  await writeFile(tamperedIdentityPath, tamperedIdentity.bytes);
  const tamperedAudit = await auditExtensionArchive(tamperedIdentityPath, {
    temporaryDirectory
  });
  const tamperedReport = path.join(root, 'tampered-identity-report.json');
  await writeFile(tamperedReport, `${JSON.stringify(tamperedAudit)}\n`);
  const tamperedVerification = await verifyAuditReport(
    tamperedReport,
    tamperedIdentityPath,
    { temporaryDirectory }
  );
  assert.equal(tamperedVerification.identities.authenticityStatus, 'invalid');
  assert.equal(tamperedVerification.identities.extensionId, null);
  assert.equal(tamperedVerification.identities.developerKeySha256, null);
  assert.doesNotMatch(auditVerificationToText(tamperedVerification), /Verified extension ID/);
  assert.match(auditVerificationToText(tamperedVerification), /CRX authenticity: invalid/);

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
  for (const unrelated of [
    ['--catalog', 'catalog.json'],
    ['--artifact', '0'],
    ['--quarantine', 'samples'],
    ['--destination', 'output'],
    ['--limit', '1'],
    ['--max-bytes', '1'],
    ['--max-total-bytes', '1'],
    ['--label', 'fixture'],
    ['--threshold', 'high']
  ]) {
    const rejected = captureStreams();
    assert.equal(await runCli([
      'audit', 'verify', reportPath, relocated, '--acknowledge-risk', ...unrelated
    ], rejected.streams), 2);
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
  const duplicateSource = `${JSON.stringify(report).replace(
    '"schemaVersion":1',
    '"schemaVersion":1,"schemaVersion":1'
  )}\n`;
  await writeFile(reportPath, duplicateSource);
  await assert.rejects(
    () => verifyAuditReport(reportPath, extension),
    (error) => error.code === 'INVALID_AUDIT_REPORT' && /duplicate/.test(error.message)
  );
  const injectionReport = path.join(root, 'injection-report.json');
  const injectionKey = '\u001b[2J';
  await writeFile(
    injectionReport,
    `{"\\u001b[2J":1,"\\u001b[2J":2,${JSON.stringify(report).slice(1)}`
  );
  await assert.rejects(
    () => verifyAuditReport(injectionReport, extension),
    (error) => error.code === 'INVALID_AUDIT_REPORT'
      && !error.message.includes(injectionKey)
      && error.message.length < 100
  );
  const injectionCli = captureStreams();
  assert.equal(await runCli([
    'audit', 'verify', injectionReport, extension, '--acknowledge-risk'
  ], injectionCli.streams), 2);
  assert.doesNotMatch(injectionCli.output().stderr, /\u001b/);
  assert.ok(injectionCli.output().stderr.length < 200);
  const malformedEscape = path.join(root, 'malformed-escape.json');
  await writeFile(malformedEscape, Buffer.from('{"field":"\u001b"}'));
  const malformedEscapeCli = captureStreams();
  assert.equal(await runCli([
    'audit', 'verify', malformedEscape, extension, '--acknowledge-risk'
  ], malformedEscapeCli.streams), 2);
  assert.doesNotMatch(malformedEscapeCli.output().stderr, /\u001b/);
  assert.match(malformedEscapeCli.output().stderr, /Audit report is not valid JSON/);

  const arrayReport = path.join(root, 'array-report.json');
  await writeFile(arrayReport, '[]');
  const originalArrayMap = Object.getOwnPropertyDescriptor(Array.prototype, 'map');
  let arrayPrototypeTrapExecuted = false;
  Object.defineProperty(Array.prototype, 'map', {
    configurable: true,
    get() {
      arrayPrototypeTrapExecuted = true;
      throw new Error('must not execute');
    }
  });
  try {
    await assert.rejects(
      () => verifyAuditReport(arrayReport, extension),
      (error) => error.code === 'INVALID_AUDIT_REPORT'
    );
  } finally {
    Object.defineProperty(Array.prototype, 'map', originalArrayMap);
  }
  assert.equal(arrayPrototypeTrapExecuted, false);

  const primitivePackage = structuredClone(report);
  primitivePackage.package = 1;
  const primitivePackageReport = path.join(root, 'primitive-package.json');
  await writeFile(primitivePackageReport, `${JSON.stringify(primitivePackage)}\n`);
  let boxedPrototypeTrapExecuted = false;
  Object.defineProperty(Number.prototype, 'sha256', {
    configurable: true,
    get() {
      boxedPrototypeTrapExecuted = true;
      throw new Error('must not execute');
    }
  });
  try {
    await assert.rejects(
      () => verifyAuditReport(primitivePackageReport, extension),
      (error) => error.code === 'INVALID_AUDIT_REPORT'
    );
  } finally {
    delete Number.prototype.sha256;
  }
  assert.equal(boxedPrototypeTrapExecuted, false);

  for (const [label, mutate] of [
    ['invalid-signature-policy', (value) => {
      value.artifact = {
        path: '/tmp/archive.crx',
        identityPolicy: { requireValidSignature: 'yes' }
      };
    }],
    ['invalid-archive-policy', (value) => {
      value.artifact = {
        path: '/tmp/archive.crx',
        identityPolicy: { expectedArchiveSha256: 1 }
      };
    }],
    ['invalid-disposition-time', (value) => {
      value.dispositionEvaluation = { evaluatedAt: 1 };
    }]
  ]) {
    const malformedNested = structuredClone(report);
    mutate(malformedNested);
    const malformedNestedPath = path.join(root, `${label}.json`);
    await writeFile(malformedNestedPath, `${JSON.stringify(malformedNested)}\n`);
    await assert.rejects(
      () => verifyAuditReport(malformedNestedPath, extension),
      (error) => error.code === 'INVALID_AUDIT_REPORT'
    );
  }

  const realReport = path.join(root, 'real-report.json');
  await writeFile(realReport, `${JSON.stringify(report)}\n`);
  assert.equal((await verifyAuditReport(
    realReport,
    path.join(extension, 'manifest.json'),
    { temporaryDirectory: root }
  )).valid, true);
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
  const revokedOptions = Proxy.revocable({}, {});
  revokedOptions.revoke();
  await assert.rejects(
    () => verifyAuditReport(realReport, extension, revokedOptions.proxy),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
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
  const revokedPaths = Proxy.revocable([], {});
  revokedPaths.revoke();
  const invalidOptionSets = [
    { zUnknown: true, aUnknown: true },
    { expectedPackageSha256: 'A'.repeat(64) },
    { expectedExtensionId: 'z'.repeat(32) },
    { requireValidSignature: 'yes' },
    { temporaryDirectory: '' },
    { reportLimits: { unknown: 1 } },
    { reportLimits: { maxReportBytes: 0 } },
    { reportLimits: { maxReportValues: 0 } },
    { rulePacks: null },
    { rulePacks: new Proxy([], {}) },
    { rulePacks: revokedPaths.proxy },
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
  const missingInput = path.join(root, 'missing-extension');
  const wrongFile = path.join(root, 'not-manifest.json');
  await writeFile(wrongFile, '{}');
  const linkedInput = path.join(root, 'linked-extension');
  await symlink(extension, linkedInput);
  for (const [input, code] of [
    [missingInput, 'INPUT_NOT_FOUND'],
    [wrongFile, 'INVALID_INPUT'],
    [linkedInput, 'UNSAFE_INPUT']
  ]) {
    await assert.rejects(
      () => verifyAuditReport(realReport, input),
      (error) => error.code === code
    );
  }
  for (const [temporaryDirectory, code] of [
    [path.join(root, 'missing-temporary'), 'TEMP_NOT_FOUND'],
    [realReport, 'UNSAFE_TEMP'],
    [linkedInput, 'UNSAFE_TEMP']
  ]) {
    await assert.rejects(
      () => verifyAuditReport(realReport, extension, { temporaryDirectory }),
      (error) => error.code === code
    );
  }
  const invalidExtension = await writeExtension(path.join(root, 'invalid-extension'), {
    manifest_version: 3, name: 'Invalid snapshot', version: '1.0.0'
  });
  await writeFile(path.join(invalidExtension, 'manifest.json'), '{');
  const snapshotParent = path.join(root, 'snapshot-parent');
  await mkdir(snapshotParent);
  await assert.rejects(
    () => verifyAuditReport(realReport, invalidExtension, {
      temporaryDirectory: snapshotParent
    }),
    (error) => error.code === 'INVALID_MANIFEST'
      && !error.message.includes('mvx-audit-input-')
  );
  assert.deepEqual(await readdir(snapshotParent), []);

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

  const hugeDepth = path.join(root, 'huge-depth.json');
  await writeFile(hugeDepth, `${'['.repeat(1_500_000)}0${']'.repeat(1_500_000)}`);
  const moduleUrl = pathToFileURL(path.resolve('src/audit-verification.js')).href;
  const childScript = `
    import { verifyAuditReport } from ${JSON.stringify(moduleUrl)};
    try {
      await verifyAuditReport(${JSON.stringify(hugeDepth)}, ${JSON.stringify(extension)});
      process.stdout.write('unexpected-success');
    } catch (error) {
      process.stdout.write(String(error.code));
    }
  `;
  const child = await execFileAsync(process.execPath, [
    '--max-old-space-size=32',
    '--input-type=module',
    '--eval',
    childScript
  ], { timeout: 10_000, maxBuffer: 1_024 });
  assert.equal(child.stdout, 'AUDIT_REPORT_LIMIT');

  const shallow = path.join(root, 'shallow-wide.json');
  const shallowMembers = Array.from(
    { length: 260_000 },
    (_, index) => `"key${index}":0`
  ).join(',');
  await writeFile(shallow, `{${shallowMembers}}`);
  const shallowChildScript = `
    import { verifyAuditReport } from ${JSON.stringify(moduleUrl)};
    try {
      await verifyAuditReport(${JSON.stringify(shallow)}, ${JSON.stringify(extension)});
      process.stdout.write('unexpected-success');
    } catch (error) {
      process.stdout.write(String(error.code));
    }
  `;
  const shallowChild = await execFileAsync(process.execPath, [
    '--max-old-space-size=32',
    '--input-type=module',
    '--eval',
    shallowChildScript
  ], { timeout: 10_000, maxBuffer: 1_024 });
  assert.equal(shallowChild.stdout, 'AUDIT_REPORT_LIMIT');
});

test('directory snapshot cannot be redirected by a root symlink race', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-root-race-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = await writeExtension(path.join(root, 'input'), {
    manifest_version: 3, name: 'Original root', version: '1.0.0'
  });
  const outside = await writeExtension(path.join(root, 'outside'), {
    manifest_version: 3, name: 'Outside root', version: '1.0.0'
  });
  const outsideAudit = await auditExtension(outside);
  const reportPath = path.join(root, 'outside-report.json');
  await writeFile(reportPath, `${JSON.stringify(outsideAudit)}\n`);
  const parked = path.join(root, 'parked-input');
  let racing = true;
  const race = (async () => {
    while (racing) {
      let moved = false;
      try {
        await rename(input, parked);
        moved = true;
        await symlink(outside, input);
        await new Promise((resolve) => setImmediate(resolve));
        await rm(input, { force: true });
      } catch {
        await rm(input, { force: true }).catch(() => {});
      }
      if (moved) await rename(parked, input);
      await new Promise((resolve) => setImmediate(resolve));
    }
  })();
  try {
    const typedRaceError = (error) => [
      'AUDIT_REPORT_MISMATCH',
      'AUDIT_SNAPSHOT_FAILED',
      'INPUT_NOT_FOUND',
      'UNSAFE_INPUT'
    ].includes(error.code);
    for (let attempt = 0; attempt < 8; attempt += 1) {
      await assert.rejects(
        () => verifyAuditReport(reportPath, input),
        typedRaceError
      );
      await assert.rejects(
        () => verifyAuditReport(reportPath, path.join(input, 'manifest.json')),
        typedRaceError
      );
    }
  } finally {
    racing = false;
    await race;
  }
});

test('directory snapshot rejects a temporary parent inside the extension', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-contained-temp-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(root, 'extension'), {
    manifest_version: 3, name: 'Contained temporary parent', version: '1.0.0'
  });
  const audit = await auditExtension(extension);
  const reportPath = path.join(root, 'report.json');
  await writeFile(reportPath, `${JSON.stringify(audit)}\n`);
  const containedTemporary = path.join(extension, 'temporary');
  await mkdir(containedTemporary);
  await assert.rejects(
    () => verifyAuditReport(reportPath, extension, {
      temporaryDirectory: containedTemporary
    }),
    (error) => error.code === 'UNSAFE_TEMP'
  );
  assert.deepEqual(await readdir(containedTemporary), []);
});

test('private workspace creation rejects a redirected validated parent', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-workspace-race-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const parent = path.join(root, 'parent');
  const parked = path.join(root, 'parked-parent');
  const redirected = path.join(root, 'redirected');
  await Promise.all([mkdir(parent), mkdir(redirected)]);
  const validated = await resolvePrivateWorkspaceParent(parent, {
    missingMessage: 'missing',
    unsafeMessage: 'unsafe',
    changedMessage: 'changed'
  });
  await rename(parent, parked);
  await symlink(redirected, parent);
  await assert.rejects(
    () => createPrivateWorkspace(validated, 'workspace-', {
      changedMessage: 'changed',
      cleanupMessage: 'cleanup failed'
    }),
    (error) => error.code === 'UNSAFE_TEMP'
  );
  assert.deepEqual(await readdir(redirected), []);
});

test('private workspace handoffs reject a replaced workspace path', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-workspace-handoff-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const validated = await resolvePrivateWorkspaceParent(root, {
    missingMessage: 'missing',
    unsafeMessage: 'unsafe',
    changedMessage: 'changed'
  });
  const workspace = await createPrivateWorkspace(validated, 'workspace-', {
    changedMessage: 'changed',
    cleanupMessage: 'cleanup failed'
  });
  const parked = `${workspace.path}.parked`;
  await rename(workspace.path, parked);
  await mkdir(workspace.path);
  await assert.rejects(
    () => assertPrivateWorkspace(workspace, { changedMessage: 'changed' }),
    (error) => error.code === 'UNSAFE_TEMP'
  );
  await assert.rejects(
    () => removePrivateWorkspace(workspace, {
      changedMessage: 'changed',
      cleanupMessage: 'cleanup failed'
    }),
    (error) => error.code === 'UNSAFE_TEMP'
  );
  assert.deepEqual(await readdir(workspace.path), []);
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

  let artifactTrapExecuted = false;
  Object.defineProperty(Object.prototype, 'artifact', {
    configurable: true,
    get() {
      artifactTrapExecuted = true;
      throw new Error('must not execute');
    }
  });
  try {
    assert.equal((await verifyAuditReport(reportPath, extension)).inputType, 'directory');
  } finally {
    delete Object.prototype.artifact;
  }
  assert.equal(artifactTrapExecuted, false);

  const missingOperands = captureStreams();
  assert.equal(await runCli([
    'audit', 'verify', '--acknowledge-risk', '--format', 'json'
  ], missingOperands.streams), 2);
  assert.match(missingOperands.output().stderr, /audit verify requires report/);
});
