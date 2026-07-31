import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  COMPARISON_VERIFICATION_PROFILE,
  comparisonVerificationToText,
  verifyComparisonReport
} from '../src/comparison-verification.js';
import { compareExtensionArchives, compareExtensions } from '../src/compare.js';
import { runCli } from '../src/cli.js';
import { makeSignedCrx3, makeZip } from '../support/archive-fixture.js';
import { captureStreams, writeExtension } from '../support/helpers.js';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

const DISPOSITION_AT = '2026-07-30T12:00:00.000Z';

async function directoryFixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-comparison-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const temporaryDirectory = path.join(root, 'temporary');
  await mkdir(temporaryDirectory);
  const before = await writeExtension(path.join(root, 'before'), {
    manifest_version: 2,
    name: 'Comparison verification',
    version: '1.0.0',
    permissions: ['cookies']
  }, {
    'worker.js': 'eval(beforePayload);\n'
  });
  const after = await writeExtension(path.join(root, 'after'), {
    manifest_version: 3,
    name: 'Comparison verification',
    version: '2.0.0',
    permissions: ['cookies'],
    host_permissions: ['https://example.invalid/*']
  }, {
    'worker.js': 'eval(afterPayload);\n',
    'new.js': 'const release = 2;\n'
  });
  return { root, temporaryDirectory, before, after };
}

async function packedFixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-packed-comparison-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const temporaryDirectory = path.join(root, 'temporary');
  await mkdir(temporaryDirectory);
  const beforeSigned = makeSignedCrx3([
    {
      name: 'manifest.json',
      content: '{"manifest_version":3,"name":"Signed comparison","version":"1.0.0"}'
    },
    { name: 'worker.js', content: 'eval(beforePayload);\n' }
  ]);
  const afterSigned = makeSignedCrx3([
    {
      name: 'manifest.json',
      content: '{"manifest_version":3,"name":"Signed comparison","version":"2.0.0"}'
    },
    { name: 'worker.js', content: 'eval(afterPayload);\n' },
    { name: 'added.js', content: 'const added = true;\n' }
  ]);
  const before = path.join(root, 'before.crx');
  const after = path.join(root, 'after.crx');
  await writeFile(before, beforeSigned.bytes);
  await writeFile(after, afterSigned.bytes);
  return {
    root,
    temporaryDirectory,
    before,
    after,
    beforeSigned,
    afterSigned,
    beforeSha256: sha256(beforeSigned.bytes),
    afterSha256: sha256(afterSigned.bytes)
  };
}

test('comparison verification reproduces directory reports and independent identities', async (t) => {
  const fixture = await directoryFixture(t);
  const comparison = await compareExtensions(fixture.before, fixture.after);
  const reportBytes = Buffer.from(`${JSON.stringify(comparison, null, 2)}\n`);
  const reportPath = path.join(fixture.root, 'comparison.json');
  await writeFile(reportPath, reportBytes);
  const relocatedBefore = path.join(fixture.root, 'relocated-before');
  const relocatedAfter = path.join(fixture.root, 'relocated-after');
  await cp(fixture.before, relocatedBefore, { recursive: true });
  await cp(fixture.after, relocatedAfter, { recursive: true });

  const verification = await verifyComparisonReport(
    reportPath,
    relocatedBefore,
    relocatedAfter,
    {
      expectedReportSha256: sha256(reportBytes),
      expectedBeforePackageSha256: comparison.before.package.sha256,
      expectedAfterPackageSha256: comparison.after.package.sha256,
      expectedBeforeAnalysisSha256: comparison.before.analysis.sha256,
      expectedAfterAnalysisSha256: comparison.after.analysis.sha256,
      temporaryDirectory: fixture.temporaryDirectory
    }
  );
  assert.equal(verification.profile, COMPARISON_VERIFICATION_PROFILE);
  assert.equal(verification.valid, true);
  assert.equal(verification.inputType, 'directory');
  assert.deepEqual(verification.checks.locationMetadataMatchesInput, {
    before: false,
    after: false
  });
  assert.equal(verification.checks.independent.before.packageSha256, true);
  assert.equal(verification.checks.independent.after.analysisSha256, true);
  assert.equal(verification.identities.before.packageSha256, comparison.before.package.sha256);
  assert.equal(verification.identities.after.packageSha256, comparison.after.package.sha256);
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);
  assert.match(comparisonVerificationToText(verification), /Comparison report valid: yes/);

  const refused = captureStreams();
  assert.equal(await runCli([
    'compare', 'verify', reportPath, relocatedBefore, relocatedAfter
  ], refused.streams), 2);
  assert.match(refused.output().stderr, /RISK_ACK_REQUIRED/);
  const cli = captureStreams();
  assert.equal(await runCli([
    'compare', 'verify', reportPath, relocatedBefore, relocatedAfter,
    '--acknowledge-risk', '--format', 'json',
    '--expected-report-sha256', sha256(reportBytes),
    '--before-package-sha256', comparison.before.package.sha256,
    '--after-package-sha256', comparison.after.package.sha256
  ], cli.streams), 0);
  assert.equal(JSON.parse(cli.output().stdout).profile, COMPARISON_VERIFICATION_PROFILE);

  await writeFile(path.join(relocatedAfter, 'worker.js'), 'eval(tampered);\n');
  await assert.rejects(
    () => verifyComparisonReport(reportPath, relocatedBefore, relocatedAfter, {
      temporaryDirectory: fixture.temporaryDirectory
    }),
    (error) => error.code === 'COMPARISON_REPORT_MISMATCH'
  );
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);
});

test('comparison verification replays rule packs and rejects delta tampering', async (t) => {
  const fixture = await directoryFixture(t);
  const rulePack = path.join(fixture.root, 'rules.json');
  const pack = {
    schemaVersion: 1,
    namespace: 'comparison.verify',
    name: 'Comparison verification indicators',
    version: '1.0.0',
    rules: [{
      id: 'PAYLOAD',
      title: 'Synthetic comparison payload',
      severity: 'high',
      confidence: 'high',
      category: 'campaign-ioc',
      description: 'A synthetic payload marker matched.',
      remediation: 'Review the matching source.',
      references: [],
      indicators: [{ type: 'text', value: 'afterPayload', scope: 'source' }]
    }]
  };
  await writeFile(rulePack, `${JSON.stringify(pack)}\n`);
  const comparison = await compareExtensions(fixture.before, fixture.after, {
    rulePacks: [rulePack]
  });
  const reportPath = path.join(fixture.root, 'rules-comparison.json');
  await writeFile(reportPath, `${JSON.stringify(comparison)}\n`);
  assert.equal((await verifyComparisonReport(
    reportPath,
    fixture.before,
    fixture.after,
    {
      rulePacks: [rulePack],
      temporaryDirectory: fixture.temporaryDirectory
    }
  )).valid, true);

  pack.rules[0].indicators[0].value = 'differentPayload';
  await writeFile(rulePack, `${JSON.stringify(pack)}\n`);
  await assert.rejects(
    () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
      rulePacks: [rulePack],
      temporaryDirectory: fixture.temporaryDirectory
    }),
    (error) => error.code === 'COMPARISON_REPORT_MISMATCH'
  );

  const tampered = structuredClone(comparison);
  tampered.delta.riskScore += 1;
  const tamperedPath = path.join(fixture.root, 'tampered-comparison.json');
  await writeFile(tamperedPath, `${JSON.stringify(tampered)}\n`);
  await writeFile(rulePack, `${JSON.stringify({
    ...pack,
    rules: [{
      ...pack.rules[0],
      indicators: [{ type: 'text', value: 'afterPayload', scope: 'source' }]
    }]
  })}\n`);
  await assert.rejects(
    () => verifyComparisonReport(tamperedPath, fixture.before, fixture.after, {
      rulePacks: [rulePack],
      temporaryDirectory: fixture.temporaryDirectory
    }),
    (error) => error.code === 'COMPARISON_REPORT_MISMATCH'
  );
});

test('comparison verification replays one exact disposition evaluation', async (t) => {
  const fixture = await directoryFixture(t);
  const baseline = await compareExtensions(fixture.before, fixture.after);
  const entry = (audit) => {
    const finding = audit.findings.find((candidate) => candidate.id === 'MVX201');
    return {
      fingerprint: finding.fingerprint,
      packageSha256: audit.package.sha256,
      analysisSha256: audit.analysis.sha256,
      artifactSha256: null,
      disposition: 'accepted-risk',
      owner: 'researcher@example.invalid',
      justification: 'Synthetic exact-input comparison verification review.',
      expiresAt: '2027-07-30T00:00:00.000Z'
    };
  };
  const policyPath = path.join(fixture.root, 'policy.json');
  const policy = {
    schemaVersion: 1,
    policyId: 'comparison-verification.review',
    name: 'Comparison verification review',
    version: '2026.07.30',
    entries: [entry(baseline.before), entry(baseline.after)]
  };
  await writeFile(policyPath, `${JSON.stringify(policy)}\n`);
  const comparison = await compareExtensions(fixture.before, fixture.after, {
    dispositionPolicies: [policyPath],
    dispositionAt: DISPOSITION_AT
  });
  assert.equal(comparison.before.dispositionEvaluation.evaluatedAt, DISPOSITION_AT);
  assert.equal(comparison.after.dispositionEvaluation.evaluatedAt, DISPOSITION_AT);
  const reportPath = path.join(fixture.root, 'reviewed-comparison.json');
  await writeFile(reportPath, `${JSON.stringify(comparison)}\n`);
  assert.equal((await verifyComparisonReport(
    reportPath,
    fixture.before,
    fixture.after,
    {
      dispositionPolicies: [policyPath],
      temporaryDirectory: fixture.temporaryDirectory
    }
  )).valid, true);

  policy.entries[0].justification = 'Changed review metadata must not transfer.';
  await writeFile(policyPath, `${JSON.stringify(policy)}\n`);
  await assert.rejects(
    () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
      dispositionPolicies: [policyPath],
      temporaryDirectory: fixture.temporaryDirectory
    }),
    (error) => error.code === 'COMPARISON_REPORT_MISMATCH'
  );

  const divergent = structuredClone(comparison);
  divergent.after.dispositionEvaluation.evaluatedAt = '2026-07-30T12:00:01.000Z';
  const divergentPath = path.join(fixture.root, 'divergent-time.json');
  await writeFile(divergentPath, `${JSON.stringify(divergent)}\n`);
  await assert.rejects(
    () => verifyComparisonReport(divergentPath, fixture.before, fixture.after, {
      dispositionPolicies: [policyPath]
    }),
    (error) => error.code === 'INVALID_COMPARISON_REPORT'
  );
});

test('comparison verification binds packed bytes, signatures, continuity, and package delta', async (t) => {
  const fixture = await packedFixture(t);
  assert.equal(fixture.beforeSigned.extensionId, fixture.afterSigned.extensionId);
  const comparison = await compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: fixture.temporaryDirectory,
    requireSameExtensionId: true,
    expectedBeforeArchiveSha256: fixture.beforeSha256,
    expectedAfterArchiveSha256: fixture.afterSha256,
    expectedExtensionId: fixture.beforeSigned.extensionId
  });
  const reportBytes = Buffer.from(`${JSON.stringify(comparison, null, 2)}\n`);
  const reportPath = path.join(fixture.root, 'packed-comparison.json');
  await writeFile(reportPath, reportBytes);
  const relocatedBefore = path.join(fixture.root, 'relocated-before.bin');
  const relocatedAfter = path.join(fixture.root, 'relocated-after.bin');
  await writeFile(relocatedBefore, fixture.beforeSigned.bytes);
  await writeFile(relocatedAfter, fixture.afterSigned.bytes);

  const verification = await verifyComparisonReport(
    reportPath,
    relocatedBefore,
    relocatedAfter,
    {
      expectedReportSha256: sha256(reportBytes),
      expectedBeforeArchiveSha256: fixture.beforeSha256,
      expectedAfterArchiveSha256: fixture.afterSha256,
      expectedBeforePackageSha256: comparison.before.package.sha256,
      expectedAfterPackageSha256: comparison.after.package.sha256,
      expectedExtensionId: fixture.beforeSigned.extensionId,
      requireValidSignature: true,
      temporaryDirectory: fixture.temporaryDirectory
    }
  );
  assert.equal(verification.inputType, 'archive');
  assert.equal(verification.checks.packageDelta, true);
  assert.equal(verification.checks.archiveContinuity, true);
  assert.equal(verification.checks.recordedSignatureRequirement, true);
  assert.equal(verification.identities.before.artifactSha256, fixture.beforeSha256);
  assert.equal(verification.identities.after.artifactSha256, fixture.afterSha256);
  assert.equal(verification.identities.before.extensionId, fixture.beforeSigned.extensionId);
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);
  assert.match(comparisonVerificationToText(verification), /Before archive SHA-256:/);
  assert.match(comparisonVerificationToText(verification), /verified developer key SHA-256:/i);
  const cli = captureStreams();
  assert.equal(await runCli([
    'compare', 'verify', reportPath, relocatedBefore, relocatedAfter,
    '--acknowledge-risk', '--format', 'json', '--require-valid-signature',
    '--expected-report-sha256', sha256(reportBytes),
    '--before-archive-sha256', fixture.beforeSha256,
    '--after-archive-sha256', fixture.afterSha256,
    '--expected-extension-id', fixture.beforeSigned.extensionId
  ], cli.streams), 0);
  assert.equal(JSON.parse(cli.output().stdout).inputType, 'archive');

  const legacy = structuredClone(comparison);
  delete legacy.before.artifact.identityPolicy.requireValidSignature;
  delete legacy.after.artifact.identityPolicy.requireValidSignature;
  const legacyPath = path.join(fixture.root, 'legacy-packed-comparison.json');
  await writeFile(legacyPath, `${JSON.stringify(legacy)}\n`);
  const legacyVerification = await verifyComparisonReport(
    legacyPath,
    relocatedBefore,
    relocatedAfter,
    { temporaryDirectory: fixture.temporaryDirectory }
  );
  assert.equal(legacyVerification.checks.recordedSignatureRequirement, null);
  assert.match(legacyVerification.caveats.at(-1), /legacy packed side/);
  const inconsistentStrict = structuredClone(comparison);
  inconsistentStrict.before.artifact.identityPolicy.requireValidSignature = false;
  inconsistentStrict.after.artifact.identityPolicy.requireValidSignature = false;
  const inconsistentStrictPath = path.join(fixture.root, 'inconsistent-strict.json');
  await writeFile(inconsistentStrictPath, `${JSON.stringify(inconsistentStrict)}\n`);
  await assert.rejects(
    () => verifyComparisonReport(
      inconsistentStrictPath,
      relocatedBefore,
      relocatedAfter,
      { temporaryDirectory: fixture.temporaryDirectory }
    ),
    (error) => error.code === 'INVALID_COMPARISON_REPORT'
  );

  await assert.rejects(
    () => verifyComparisonReport(reportPath, relocatedBefore, relocatedAfter, {
      expectedAfterArchiveSha256: '0'.repeat(64),
      temporaryDirectory: fixture.temporaryDirectory
    }),
    (error) => error.code === 'COMPARISON_IDENTITY_MISMATCH'
  );
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);

  const tampered = structuredClone(comparison);
  tampered.packageDelta.summary.files.added += 1;
  const tamperedPath = path.join(fixture.root, 'tampered-packed.json');
  await writeFile(tamperedPath, `${JSON.stringify(tampered)}\n`);
  await assert.rejects(
    () => verifyComparisonReport(tamperedPath, relocatedBefore, relocatedAfter, {
      temporaryDirectory: fixture.temporaryDirectory
    }),
    (error) => error.code === 'COMPARISON_REPORT_MISMATCH'
  );
});

test('comparison verification rejects hostile reports and options with typed errors', async (t) => {
  const fixture = await directoryFixture(t);
  const comparison = await compareExtensions(fixture.before, fixture.after);
  const reportPath = path.join(fixture.root, 'comparison.json');
  await writeFile(reportPath, `${JSON.stringify(comparison)}\n`);

  const cases = [
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        expectedBeforePackageSha256: '0'.repeat(63)
      }),
      'INVALID_ARGUMENT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        expectedBeforeArchiveSha256: '0'.repeat(64)
      }),
      'INVALID_ARGUMENT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        reportLimits: { maxReportBytes: 10 }
      }),
      'COMPARISON_REPORT_LIMIT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        unknown: true
      }),
      'INVALID_ARGUMENT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        expectedExtensionId: 'a'.repeat(31)
      }),
      'INVALID_ARGUMENT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        requireValidSignature: 'yes'
      }),
      'INVALID_ARGUMENT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        temporaryDirectory: ''
      }),
      'INVALID_ARGUMENT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        reportLimits: { unknown: 1 }
      }),
      'INVALID_ARGUMENT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        reportLimits: { maxReportValues: 0 }
      }),
      'INVALID_ARGUMENT'
    ],
    [
      () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
        expectedReportSha256: '0'.repeat(64)
      }),
      'COMPARISON_IDENTITY_MISMATCH'
    ]
  ];
  for (const [operation, code] of cases) {
    await assert.rejects(operation, (error) => error.code === code);
  }

  const proxy = new Proxy({}, {});
  await assert.rejects(
    () => verifyComparisonReport(reportPath, fixture.before, fixture.after, proxy),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
  await assert.rejects(
    () => verifyComparisonReport('', fixture.before, fixture.after),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
  const revocable = Proxy.revocable([], {});
  revocable.revoke();
  await assert.rejects(
    () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
      rulePacks: revocable.proxy
    }),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
  const sparse = [];
  sparse.length = 1;
  await assert.rejects(
    () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
      rulePacks: sparse
    }),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
  const accessor = [];
  Object.defineProperty(accessor, '0', {
    configurable: true,
    enumerable: true,
    get() {
      throw new Error('must not run');
    }
  });
  accessor.length = 1;
  await assert.rejects(
    () => verifyComparisonReport(reportPath, fixture.before, fixture.after, {
      dispositionPolicies: accessor
    }),
    (error) => error.code === 'INVALID_ARGUMENT'
  );

  const duplicatePath = path.join(fixture.root, 'duplicate.json');
  await writeFile(duplicatePath, '{"schemaVersion":1,"schemaVersion":1}\n');
  await assert.rejects(
    () => verifyComparisonReport(duplicatePath, fixture.before, fixture.after),
    (error) => error.code === 'INVALID_COMPARISON_REPORT'
  );
  const linkedReport = path.join(fixture.root, 'linked.json');
  await symlink(reportPath, linkedReport);
  await assert.rejects(
    () => verifyComparisonReport(linkedReport, fixture.before, fixture.after),
    (error) => error.code === 'UNSAFE_COMPARISON_REPORT'
  );
  const malformedAudit = structuredClone(comparison);
  malformedAudit.before.target = null;
  const malformedAuditPath = path.join(fixture.root, 'malformed-audit.json');
  await writeFile(malformedAuditPath, `${JSON.stringify(malformedAudit)}\n`);
  await assert.rejects(
    () => verifyComparisonReport(malformedAuditPath, fixture.before, fixture.after),
    (error) => error.code === 'INVALID_COMPARISON_REPORT'
  );
  const packedFields = structuredClone(comparison);
  packedFields.archiveContinuity = {};
  const packedFieldsPath = path.join(fixture.root, 'directory-packed-fields.json');
  await writeFile(packedFieldsPath, `${JSON.stringify(packedFields)}\n`);
  await assert.rejects(
    () => verifyComparisonReport(packedFieldsPath, fixture.before, fixture.after),
    (error) => error.code === 'INVALID_COMPARISON_REPORT'
  );

  const unsignedBefore = path.join(fixture.root, 'before.zip');
  const unsignedAfter = path.join(fixture.root, 'after.zip');
  await writeFile(unsignedBefore, makeZip([{
    name: 'manifest.json',
    content: '{"manifest_version":3,"name":"Unsigned before","version":"1.0.0"}'
  }]));
  await writeFile(unsignedAfter, makeZip([{
    name: 'manifest.json',
    content: '{"manifest_version":3,"name":"Unsigned after","version":"2.0.0"}'
  }]));
  const packed = await compareExtensionArchives(unsignedBefore, unsignedAfter, {
    temporaryDirectory: fixture.temporaryDirectory
  });
  const packedPath = path.join(fixture.root, 'unsigned-comparison.json');
  await writeFile(packedPath, `${JSON.stringify(packed)}\n`);
  await assert.rejects(
    () => verifyComparisonReport(packedPath, unsignedBefore, unsignedAfter, {
      requireValidSignature: true,
      temporaryDirectory: fixture.temporaryDirectory
    }),
    (error) => error.code === 'COMPARISON_IDENTITY_UNVERIFIABLE'
  );
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);
  assert.match(sha256(await readFile(reportPath)), /^[a-f0-9]{64}$/);
});
