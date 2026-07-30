import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtensionArchive } from '../src/index.js';
import { auditToSarif, auditToText } from '../src/reporters.js';
import { makeCrx, makeSignedCrx3, makeZip } from '../support/archive-fixture.js';

async function fixture(t, format, entries, suppliedBytes) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-packed-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const temporaryDirectory = path.join(root, 'temporary');
  await mkdir(temporaryDirectory);
  const bytes = suppliedBytes ?? (format === 'crx' ? makeCrx(entries) : makeZip(entries));
  const input = path.join(root, `sample.${format}`);
  await writeFile(input, bytes);
  return { root, temporaryDirectory, input, bytes };
}

test('packed CRX audit binds exact archive provenance and removes its extraction', async (t) => {
  const manifest = JSON.stringify({ manifest_version: 3, name: 'Packed fixture', version: '1.0.0', background: { service_worker: 'worker.js' } });
  const worker = 'eval(payload);\n';
  const sample = await fixture(t, 'crx', [
    { name: 'manifest.json', content: manifest },
    { name: 'worker.js', content: worker, method: 8 }
  ]);
  const expectedSha256 = createHash('sha256').update(sample.bytes).digest('hex');
  const result = await auditExtensionArchive(sample.input, { temporaryDirectory: sample.temporaryDirectory });

  assert.equal(result.target.root, sample.input);
  assert.equal(result.target.inputType, 'archive');
  assert.deepEqual(result.artifact, {
    kind: 'extension-archive',
    path: sample.input,
    format: 'crx',
    crxVersion: 3,
    bytes: sample.bytes.length,
    sha256: expectedSha256,
    authenticity: {
      status: 'invalid',
      scheme: 'crx3',
      extensionId: null,
      developerKeySha256: null,
      proofs: [],
      error: 'invalid-signed-header'
    },
    identityPolicy: {
      profile: 'mvx-archive-identity-v1',
      expectedArchiveSha256: null,
      expectedExtensionId: null,
      archiveSha256Match: null,
      extensionIdMatch: null,
      matched: null
    },
    extraction: { entries: 2, files: 2, uncompressedBytes: Buffer.byteLength(manifest) + Buffer.byteLength(worker) }
  });
  assert.ok(result.findings.some((finding) => finding.id === 'MVX004'));
  assert.ok(result.findings.some((finding) => finding.id === 'MVX201'));
  assert.equal(result.analysis.packageSha256, result.package.sha256);
  assert.equal(result.package.fileCount, 2);
  assert.match(result.assumptions.at(-1), /removed without executing extension code/);
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);
  assert.doesNotMatch(JSON.stringify(result), /mvx-packed-audit-/);

  assert.match(auditToText(result), new RegExp(`Archive \\(CRX3\\) SHA-256: ${expectedSha256}`));
  assert.match(auditToText(result), /Authenticity: INVALID \(invalid-signed-header\)/);
  assert.deepEqual(auditToSarif(result).runs[0].properties.artifact, result.artifact);

  await assert.rejects(
    () => auditExtensionArchive(sample.input, {
      temporaryDirectory: sample.temporaryDirectory,
      requireValidSignature: true
    }),
    (error) => error.code === 'CRX_SIGNATURE_REQUIRED'
  );
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);
});

test('packed CRX audit reports verified developer-key integrity without claiming publisher trust', async (t) => {
  const entries = [{
    name: 'manifest.json',
    content: '{"manifest_version":3,"name":"Signed packed fixture","version":"1.0.0"}'
  }];
  const signed = makeSignedCrx3(entries, { algorithms: ['rsa', 'ecdsa'] });
  const sample = await fixture(t, 'crx', entries, signed.bytes);
  const expectedSha256 = createHash('sha256').update(signed.bytes).digest('hex');
  const result = await auditExtensionArchive(sample.input, {
    temporaryDirectory: sample.temporaryDirectory,
    requireValidSignature: true,
    expectedArchiveSha256: expectedSha256,
    expectedExtensionId: signed.extensionId
  });
  assert.equal(result.artifact.authenticity.status, 'verified');
  assert.equal(result.artifact.authenticity.extensionId, signed.extensionId);
  assert.equal(result.artifact.authenticity.proofs.length, 2);
  assert.deepEqual(result.artifact.identityPolicy, {
    profile: 'mvx-archive-identity-v1',
    expectedArchiveSha256: expectedSha256,
    expectedExtensionId: signed.extensionId,
    archiveSha256Match: true,
    extensionIdMatch: true,
    matched: true
  });
  assert.equal(result.findings.some((finding) => finding.id === 'MVX004'), false);
  assert.match(result.assumptions.join(' '), /does not prove publisher identity/);
  assert.match(auditToText(result), new RegExp(`Authenticity: VERIFIED \\(${signed.extensionId}, 2 proof\\(s\\)\\)`));
  assert.match(auditToText(result), /Identity policy: MATCHED \(archive SHA-256, extension ID\)/);
  assert.deepEqual(auditToSarif(result).runs[0].properties.artifact.identityPolicy, result.artifact.identityPolicy);
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);
});

test('packed ZIP audit and archive failures always clean private temporary state', async (t) => {
  const sample = await fixture(t, 'zip', [
    { name: 'manifest.json', content: '{"manifest_version":3,"name":"ZIP fixture","version":"1.0.0"}' },
    { name: 'worker.js', content: 'console.log("safe");' }
  ]);
  const result = await auditExtensionArchive(sample.input, { temporaryDirectory: sample.temporaryDirectory });
  assert.equal(result.artifact.format, 'zip');
  assert.equal(result.artifact.crxVersion, null);
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);

  await assert.rejects(
    () => auditExtensionArchive(sample.input, {
      temporaryDirectory: sample.temporaryDirectory,
      archiveLimits: { maxArchiveBytes: sample.bytes.length - 1 }
    }),
    (error) => error.code === 'ARCHIVE_LIMIT'
  );
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);

  await assert.rejects(
    () => auditExtensionArchive(sample.input, {
      temporaryDirectory: sample.temporaryDirectory,
      limits: { maxFileBytes: 10 }
    }),
    (error) => error.code === 'SCAN_LIMIT'
  );
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);

  await writeFile(sample.input, 'not an archive', 'utf8');
  await assert.rejects(
    () => auditExtensionArchive(sample.input, { temporaryDirectory: sample.temporaryDirectory }),
    (error) => error.code === 'INVALID_ARCHIVE'
  );
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);

  await writeFile(sample.input, makeZip([
    { name: 'manifest.json', content: '{broken' }
  ]));
  await assert.rejects(
    () => auditExtensionArchive(sample.input, { temporaryDirectory: sample.temporaryDirectory }),
    (error) => error.code === 'INVALID_MANIFEST'
      && !error.message.includes('mvx-packed-audit-')
      && error.message.includes('<temporary extraction>/extension/manifest.json')
      && error.cause === undefined
  );
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);
});

test('packed audit refuses a symlinked temporary parent', async (t) => {
  const sample = await fixture(t, 'zip', [
    { name: 'manifest.json', content: '{"manifest_version":3,"name":"ZIP fixture","version":"1.0.0"}' }
  ]);
  const linked = path.join(sample.root, 'linked-temporary');
  await symlink(sample.temporaryDirectory, linked);
  await assert.rejects(
    () => auditExtensionArchive(sample.input, { temporaryDirectory: linked }),
    (error) => error.code === 'UNSAFE_TEMP'
  );
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);

  await assert.rejects(
    () => auditExtensionArchive(sample.input, { temporaryDirectory: path.join(sample.root, 'missing') }),
    (error) => error.code === 'TEMP_NOT_FOUND'
  );
});

test('packed audits apply declarative rules and validate packs before creating temporary state', async (t) => {
  const sample = await fixture(t, 'zip', [
    { name: 'manifest.json', content: '{"manifest_version":3,"name":"Rule ZIP","version":"1.0.0"}' },
    { name: 'worker.js', content: "const endpoint = 'packed-ioc.example.invalid';\n" }
  ]);
  const rulePack = path.join(sample.root, 'rules.json');
  await writeFile(rulePack, `${JSON.stringify({
    schemaVersion: 1,
    namespace: 'packed.test',
    name: 'Packed test indicators',
    version: '1.0.0',
    rules: [{
      id: 'PACKED_IOC',
      title: 'Packed indicator',
      severity: 'high',
      confidence: 'high',
      category: 'campaign-ioc',
      description: 'A synthetic packed indicator matched.',
      remediation: 'Review the matching source.',
      references: [],
      indicators: [{ type: 'text', value: 'packed-ioc.example.invalid', scope: 'source' }]
    }]
  }, null, 2)}\n`, 'utf8');
  const result = await auditExtensionArchive(sample.input, {
    temporaryDirectory: sample.temporaryDirectory,
    rulePacks: [rulePack]
  });
  assert.ok(result.findings.some((finding) => finding.id === 'RP:packed.test:PACKED_IOC'));
  assert.equal(result.rulePacks[0].namespace, 'packed.test');
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);
  assert.equal(JSON.stringify(result.rulePacks).includes(rulePack), false);

  await writeFile(rulePack, '{broken', 'utf8');
  await assert.rejects(
    () => auditExtensionArchive(sample.input, {
      temporaryDirectory: sample.temporaryDirectory,
      rulePacks: [rulePack]
    }),
    (error) => error.code === 'INVALID_RULE_PACK'
  );
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);
});
