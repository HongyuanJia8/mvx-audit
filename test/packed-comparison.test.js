import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runCli } from '../src/cli.js';
import {
  ARCHIVE_CONTINUITY_PROFILE, PACKAGE_DELTA_PROFILE, compareExtensionArchives
} from '../src/compare.js';
import { comparisonToMarkdown } from '../src/reporters.js';
import { makeSignedCrx3, makeZip } from '../support/archive-fixture.js';
import { captureStreams } from '../support/helpers.js';

const AT = '2026-07-30T12:00:00.000Z';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function comparisonFixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-packed-comparison-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const temporaryDirectory = path.join(root, 'temporary');
  await mkdir(temporaryDirectory);
  const beforeSigned = makeSignedCrx3([
    {
      name: 'manifest.json',
      content: '{"manifest_version":3,"name":"Versioned fixture","version":"1.0.0","background":{"service_worker":"worker.js"}}'
    },
    { name: 'worker.js', content: 'eval(beforePayload);\n' },
    { name: 'stable.txt', content: 'unchanged\n' },
    { name: 'removed.js', content: 'const removed = true;\n' },
    { name: 'flip', content: 'file before directory\n' }
  ]);
  const afterSigned = makeSignedCrx3([
    {
      name: 'manifest.json',
      content: '{"manifest_version":3,"name":"Versioned fixture","version":"2.0.0","background":{"service_worker":"worker.js"}}'
    },
    { name: 'worker.js', content: 'eval(afterPayload);\n' },
    { name: 'stable.txt', content: 'unchanged\n' },
    { name: 'added.js', content: 'const added = true;\n' },
    { name: 'flip/', content: '' },
    { name: 'flip/nested.js', content: 'const nested = true;\n' }
  ]);
  const before = path.join(root, 'before.crx');
  const after = path.join(root, 'after.crx');
  await writeFile(before, beforeSigned.bytes);
  await writeFile(after, afterSigned.bytes);
  return {
    root, temporaryDirectory, before, after, beforeSigned, afterSigned,
    beforeSha256: sha256(beforeSigned.bytes),
    afterSha256: sha256(afterSigned.bytes)
  };
}

test('packed comparison binds archive identity and reports deterministic package entry changes', async (t) => {
  const fixture = await comparisonFixture(t);
  assert.equal(fixture.beforeSigned.extensionId, fixture.afterSigned.extensionId);
  const result = await compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: fixture.temporaryDirectory,
    requireValidSignature: true,
    requireSameExtensionId: true,
    expectedExtensionId: fixture.beforeSigned.extensionId,
    expectedBeforeArchiveSha256: fixture.beforeSha256,
    expectedAfterArchiveSha256: fixture.afterSha256
  });

  assert.equal(result.before.artifact.sha256, fixture.beforeSha256);
  assert.equal(result.after.artifact.sha256, fixture.afterSha256);
  assert.equal(result.before.artifact.identityPolicy.archiveSha256Match, true);
  assert.equal(result.after.artifact.identityPolicy.archiveSha256Match, true);
  assert.deepEqual(result.archiveContinuity, {
    profile: ARCHIVE_CONTINUITY_PROFILE,
    required: true,
    status: 'verified-same',
    sameExtensionId: true,
    sameDeveloperKey: true,
    sameArchiveBytes: false,
    samePackage: false,
    before: {
      format: 'crx',
      crxVersion: 3,
      archiveSha256: fixture.beforeSha256,
      authenticityStatus: 'verified',
      extensionId: fixture.beforeSigned.extensionId,
      developerKeySha256: result.before.artifact.authenticity.developerKeySha256
    },
    after: {
      format: 'crx',
      crxVersion: 3,
      archiveSha256: fixture.afterSha256,
      authenticityStatus: 'verified',
      extensionId: fixture.afterSigned.extensionId,
      developerKeySha256: result.after.artifact.authenticity.developerKeySha256
    }
  });
  assert.equal(result.packageDelta.profile, PACKAGE_DELTA_PROFILE);
  assert.deepEqual(result.packageDelta.summary.entries, {
    before: 5, after: 6, added: 2, removed: 1, modified: 3, unchanged: 1
  });
  assert.deepEqual(result.packageDelta.added.map((entry) => entry.path), ['added.js', 'flip/nested.js']);
  assert.deepEqual(result.packageDelta.removed.map((entry) => entry.path), ['removed.js']);
  assert.deepEqual(result.packageDelta.modified.map((entry) => [entry.path, entry.change]), [
    ['flip', 'type'],
    ['manifest.json', 'content'],
    ['worker.js', 'content']
  ]);
  assert.equal(result.delta.resolvedFindings.length, 0);
  assert.equal(result.delta.introducedFindings.length, 0);
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);
  assert.equal(JSON.stringify(result).includes('mvx-packed-audit-'), false);

  const markdown = comparisonToMarkdown(result);
  assert.match(markdown, /## Archive identity continuity/);
  assert.match(markdown, /VERIFIED-SAME/);
  assert.match(markdown, /\| Extension version \| 1\.0\.0 \| 2\.0\.0 \|/);
  assert.match(markdown, /## Package entry changes/);
  assert.match(markdown, /flip — type/);
  assert.match(markdown, new RegExp(fixture.beforeSha256));
  assert.match(
    markdown,
    new RegExp(result.before.artifact.authenticity.developerKeySha256)
  );

  const cli = captureStreams();
  assert.equal(await runCli([
    'compare', 'packed', fixture.before, fixture.after,
    '--acknowledge-risk', '--require-valid-signature', '--require-same-extension-id',
    '--expected-extension-id', fixture.beforeSigned.extensionId,
    '--before-archive-sha256', fixture.beforeSha256,
    '--after-archive-sha256', fixture.afterSha256,
    '--format', 'json'
  ], cli.streams), 0);
  assert.equal(JSON.parse(cli.output().stdout).archiveContinuity.status, 'verified-same');

  const identical = await compareExtensionArchives(fixture.before, fixture.before, {
    temporaryDirectory: fixture.temporaryDirectory,
    requireSameExtensionId: true
  });
  assert.equal(identical.archiveContinuity.status, 'verified-same');
  assert.equal(identical.archiveContinuity.sameArchiveBytes, true);
  assert.equal(identical.archiveContinuity.samePackage, true);
  assert.equal(identical.after.artifact.identityPolicy.expectedExtensionId, null);
  assert.equal(identical.after.artifact.identityPolicy.matched, null);
  assert.deepEqual(identical.packageDelta.summary.entries, {
    before: 5, after: 5, added: 0, removed: 0, modified: 0, unchanged: 5
  });
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);
});

test('packed comparison distinguishes verified identity changes from unverifiable archives', async (t) => {
  const fixture = await comparisonFixture(t);
  const other = makeSignedCrx3([
    { name: 'manifest.json', content: '{"manifest_version":3,"name":"Other signer","version":"1.0.0"}' }
  ], { algorithms: ['publisher-rsa'] });
  const otherPath = path.join(fixture.root, 'other.crx');
  await writeFile(otherPath, other.bytes);
  assert.notEqual(other.extensionId, fixture.beforeSigned.extensionId);

  const changed = await compareExtensionArchives(fixture.before, otherPath, {
    temporaryDirectory: fixture.temporaryDirectory
  });
  assert.equal(changed.archiveContinuity.status, 'verified-different');
  assert.equal(changed.archiveContinuity.sameExtensionId, false);
  assert.equal(changed.archiveContinuity.sameDeveloperKey, false);
  await assert.rejects(() => compareExtensionArchives(fixture.before, otherPath, {
    temporaryDirectory: fixture.temporaryDirectory,
    requireSameExtensionId: true
  }), (error) => error.code === 'ARCHIVE_IDENTITY_MISMATCH');

  const mismatchedInvalidManifest = makeSignedCrx3([
    { name: 'manifest.json', content: 'not JSON' }
  ], { algorithms: ['publisher-rsa'] });
  const mismatchedInvalidManifestPath = path.join(fixture.root, 'other-invalid-manifest.crx');
  await writeFile(mismatchedInvalidManifestPath, mismatchedInvalidManifest.bytes);
  await assert.rejects(() => compareExtensionArchives(
    fixture.before,
    mismatchedInvalidManifestPath,
    {
      temporaryDirectory: fixture.temporaryDirectory,
      requireSameExtensionId: true
    }
  ), (error) => error.code === 'ARCHIVE_IDENTITY_MISMATCH');

  const zipPath = path.join(fixture.root, 'unsigned.zip');
  await writeFile(zipPath, makeZip([
    { name: 'manifest.json', content: '{"manifest_version":3,"name":"Unsigned","version":"1.0.0"}' }
  ]));
  const unverifiable = await compareExtensionArchives(fixture.before, zipPath, {
    temporaryDirectory: fixture.temporaryDirectory
  });
  assert.equal(unverifiable.archiveContinuity.status, 'unverifiable');
  assert.equal(unverifiable.archiveContinuity.sameExtensionId, null);
  assert.equal(unverifiable.archiveContinuity.sameDeveloperKey, null);
  await assert.rejects(() => compareExtensionArchives(fixture.before, zipPath, {
    temporaryDirectory: fixture.temporaryDirectory,
    requireSameExtensionId: true
  }), (error) => error.code === 'ARCHIVE_IDENTITY_UNVERIFIABLE');
  await assert.rejects(() => compareExtensionArchives(fixture.before, zipPath, {
    temporaryDirectory: fixture.temporaryDirectory,
    requireValidSignature: true
  }), (error) => error.code === 'CRX_SIGNATURE_REQUIRED');
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);
});

test('packed comparison reuses one policy evaluation time and exact artifact identities', async (t) => {
  const fixture = await comparisonFixture(t);
  const baseline = await compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: fixture.temporaryDirectory
  });
  const beforeFinding = baseline.before.findings.find((finding) => finding.id === 'MVX201');
  const afterFinding = baseline.after.findings.find((finding) => finding.id === 'MVX201');
  assert.ok(beforeFinding);
  assert.ok(afterFinding);
  const policy = path.join(fixture.root, 'policy.json');
  const entry = (audit, finding) => ({
    fingerprint: finding.fingerprint,
    packageSha256: audit.package.sha256,
    analysisSha256: audit.analysis.sha256,
    artifactSha256: audit.artifact.sha256,
    disposition: 'accepted-risk',
    owner: 'researcher@example.invalid',
    justification: 'Synthetic exact-version review metadata for packed comparison testing.',
    expiresAt: '2027-07-30T00:00:00.000Z'
  });
  await writeFile(policy, `${JSON.stringify({
    schemaVersion: 1,
    policyId: 'comparison.review',
    name: 'Packed comparison review',
    version: '1.0.0',
    entries: [entry(baseline.before, beforeFinding), entry(baseline.after, afterFinding)]
  }, null, 2)}\n`);
  const reviewed = await compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: fixture.temporaryDirectory,
    dispositionPolicies: [policy],
    dispositionAt: AT
  });
  assert.equal(reviewed.before.dispositionEvaluation.evaluatedAt, AT);
  assert.equal(reviewed.after.dispositionEvaluation.evaluatedAt, AT);
  assert.equal(reviewed.before.findings.find((finding) => finding.id === 'MVX201').disposition.status, 'active');
  assert.equal(reviewed.after.findings.find((finding) => finding.id === 'MVX201').disposition.status, 'active');
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);
});

test('packed comparison cleans both sides on failure and rejects ambiguous API options', async (t) => {
  const fixture = await comparisonFixture(t);
  const broken = path.join(fixture.root, 'broken.crx');
  await writeFile(broken, 'not an archive');
  await assert.rejects(() => compareExtensionArchives(fixture.before, broken, {
    temporaryDirectory: fixture.temporaryDirectory
  }), (error) => error.code === 'INVALID_ARCHIVE');
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);

  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: fixture.temporaryDirectory,
    expectedBeforeArchiveSha256: '0'.repeat(64)
  }), (error) => error.code === 'ARCHIVE_IDENTITY_MISMATCH');
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);

  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: fixture.temporaryDirectory,
    expectedAfterArchiveSha256: '0'.repeat(64)
  }), (error) => error.code === 'ARCHIVE_IDENTITY_MISMATCH');
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);

  const linkedTemporary = path.join(fixture.root, 'linked-temporary');
  await symlink(fixture.temporaryDirectory, linkedTemporary);
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: linkedTemporary
  }), (error) => error.code === 'UNSAFE_TEMP');
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: linkedTemporary,
    expectedAfterArchiveSha256: 'not-a-digest'
  }), (error) => error.code === 'INVALID_ARGUMENT' && /expectedAfterArchiveSha256/.test(error.message));
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    temporaryDirectory: linkedTemporary,
    expectedExtensionId: 'not-an-extension-id'
  }), (error) => error.code === 'INVALID_ARGUMENT' && /expectedExtensionId/.test(error.message));

  for (const options of [null, [], new Date(), new Proxy({}, {})]) {
    await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, options),
      (error) => error.code === 'INVALID_ARGUMENT');
  }
  const accessor = {};
  Object.defineProperty(accessor, 'requireSameExtensionId', {
    get() { throw new Error('must not execute'); }
  });
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, accessor),
    (error) => error.code === 'INVALID_ARGUMENT' && /accessor/.test(error.message));
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    unknown: true
  }), (error) => error.code === 'INVALID_ARGUMENT' && /Unknown packed comparison option/.test(error.message));
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    requireSameExtensionId: 'yes'
  }), (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    archiveLimits: new Proxy({}, {})
  }), (error) => error.code === 'INVALID_ARGUMENT' && /archive limits/.test(error.message));
  const nestedAccessor = {};
  Object.defineProperty(nestedAccessor, 'maxFiles', {
    get() { throw new Error('must not execute'); }
  });
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    limits: nestedAccessor
  }), (error) => error.code === 'INVALID_ARGUMENT' && /accessor/.test(error.message));
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    rulePacks: new Proxy([], {})
  }), (error) => error.code === 'INVALID_ARGUMENT' && /non-proxy array/.test(error.message));
  const revokedRulePacks = Proxy.revocable([], {});
  revokedRulePacks.revoke();
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    rulePacks: revokedRulePacks.proxy
  }), (error) => error.code === 'INVALID_ARGUMENT' && /non-proxy array/.test(error.message));
  const sparseRulePacks = [];
  sparseRulePacks.length = 1;
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    rulePacks: sparseRulePacks
  }), (error) => error.code === 'INVALID_ARGUMENT' && /dense array/.test(error.message));

  const nonEnumerableArchiveLimits = {};
  Object.defineProperty(nonEnumerableArchiveLimits, 'maxArchiveBytes', {
    value: 1,
    enumerable: false
  });
  await assert.rejects(() => compareExtensionArchives(fixture.before, fixture.after, {
    archiveLimits: nonEnumerableArchiveLimits,
    temporaryDirectory: fixture.temporaryDirectory
  }), (error) => error.code === 'ARCHIVE_LIMIT');
  assert.deepEqual(await readdir(fixture.temporaryDirectory), []);

  const inheritedKeys = ['expectedBeforeArchiveSha256', '_preparedRulePacks'];
  const previousInherited = new Map(inheritedKeys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(Object.prototype, key)
  ]));
  let inheritedGetterCalls = 0;
  for (const key of inheritedKeys) {
    Object.defineProperty(Object.prototype, key, {
      configurable: true,
      get() {
        inheritedGetterCalls += 1;
        throw new Error('inherited getter must not execute');
      }
    });
  }
  try {
    const inheritedSafe = await compareExtensionArchives(fixture.before, fixture.after, {
      temporaryDirectory: fixture.temporaryDirectory
    });
    assert.equal(inheritedSafe.archiveContinuity.status, 'verified-same');
    assert.equal(inheritedGetterCalls, 0);
  } finally {
    for (const key of inheritedKeys) {
      const previous = previousInherited.get(key);
      if (previous) {
        Object.defineProperty(Object.prototype, key, previous);
      } else {
        delete Object.prototype[key];
      }
    }
  }

  await assert.rejects(() => compareExtensionArchives(Symbol('before'), fixture.after),
    (error) => error.code === 'INVALID_ARGUMENT' && /beforePath/.test(error.message));

  const missingRisk = captureStreams();
  assert.equal(await runCli([
    'compare', 'packed', fixture.before, fixture.after
  ], missingRisk.streams), 2);
  assert.match(missingRisk.output().stderr, /RISK_ACK_REQUIRED/);
  const wrongScope = captureStreams();
  assert.equal(await runCli([
    'compare', fixture.root, fixture.root, '--before-archive-sha256', fixture.beforeSha256
  ], wrongScope.streams), 2);
  assert.match(wrongScope.output().stderr, /Side-specific archive SHA-256 options/);
  const ambiguous = captureStreams();
  assert.equal(await runCli([
    'compare', 'packed', fixture.before, fixture.after, '--acknowledge-risk',
    '--expected-archive-sha256', fixture.beforeSha256
  ], ambiguous.streams), 2);
  assert.match(ambiguous.output().stderr, /requires --before-archive-sha256/);

  const duplicateIdentity = captureStreams();
  assert.equal(await runCli([
    'compare', 'packed', fixture.before, fixture.after, '--acknowledge-risk',
    '--before-archive-sha256', '0'.repeat(64),
    '--before-archive-sha256', fixture.beforeSha256
  ], duplicateIdentity.streams), 2);
  assert.match(duplicateIdentity.output().stderr, /Duplicate option: --before-archive-sha256/);

  const legacyPackedPath = captureStreams();
  assert.equal(await runCli([
    'compare', 'packed', fixture.root
  ], legacyPackedPath.streams), 2);
  assert.doesNotMatch(legacyPackedPath.output().stderr, /compare packed requires/);
});
