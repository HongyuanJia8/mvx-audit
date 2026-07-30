import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtensionArchive } from '../src/index.js';
import { auditToSarif, auditToText } from '../src/reporters.js';
import { makeCrx, makeZip } from '../support/archive-fixture.js';

async function fixture(t, format, entries) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-packed-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const temporaryDirectory = path.join(root, 'temporary');
  await mkdir(temporaryDirectory);
  const bytes = format === 'crx' ? makeCrx(entries) : makeZip(entries);
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
    extraction: { entries: 2, files: 2, uncompressedBytes: Buffer.byteLength(manifest) + Buffer.byteLength(worker) }
  });
  assert.ok(result.findings.some((finding) => finding.id === 'MVX201'));
  assert.match(result.assumptions.at(-1), /removed without executing extension code/);
  assert.deepEqual(await readdir(sample.temporaryDirectory), []);
  assert.doesNotMatch(JSON.stringify(result), /mvx-packed-audit-/);

  assert.match(auditToText(result), new RegExp(`Archive \\(CRX3\\) SHA-256: ${expectedSha256}`));
  assert.deepEqual(auditToSarif(result).runs[0].properties.artifact, result.artifact);
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
