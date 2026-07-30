import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { unpackCrx, unpackExtensionArchive } from '../src/archive.js';
import { makeCrx, makeZip } from '../support/archive-fixture.js';

async function withCrx(t, entries) {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-crx-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const input = path.join(temp, 'sample.crx');
  const destination = path.join(temp, 'unpacked');
  await writeFile(input, makeCrx(entries));
  return { temp, input, destination };
}

async function withZip(t, entries) {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-zip-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const input = path.join(temp, 'sample.zip');
  const destination = path.join(temp, 'unpacked');
  await writeFile(input, makeZip(entries));
  return { temp, input, destination };
}

test('CRX3 unpacker extracts stored and deflated files for static audit', async (t) => {
  const manifest = JSON.stringify({ manifest_version: 3, name: 'Realistic archive', version: '1.0.0', background: { service_worker: 'worker.js' } });
  const fixture = await withCrx(t, [
    { name: 'manifest.json', content: manifest },
    { name: 'worker.js', content: 'eval(payload);\n', method: 8 },
    { name: 'assets/', content: '' },
    { name: 'assets/readme.txt', content: 'data' }
  ]);
  const result = await unpackCrx(fixture.input, fixture.destination);
  const archiveBytes = await readFile(fixture.input);
  assert.equal(result.crxVersion, 3);
  assert.equal(result.archiveBytes, archiveBytes.length);
  assert.equal(result.archiveSha256, createHash('sha256').update(archiveBytes).digest('hex'));
  assert.equal(result.files, 3);
  assert.equal(await readFile(path.join(fixture.destination, 'assets/readme.txt'), 'utf8'), 'data');
  assert.ok((await auditExtension(fixture.destination)).findings.some((finding) => finding.id === 'MVX201'));
});

test('bounded extension archive unpacker supports ZIP without weakening CRX-only API', async (t) => {
  const fixture = await withZip(t, [
    { name: 'manifest.json', content: '{"manifest_version":3,"name":"ZIP","version":"1.0.0"}' },
    { name: 'worker.js', content: 'console.log("loaded");', method: 8 },
    { name: 'assets/', content: '', method: 8 }
  ]);
  await assert.rejects(() => unpackCrx(fixture.input, fixture.destination), (error) => error.code === 'INVALID_ARCHIVE');
  const result = await unpackExtensionArchive(fixture.input, fixture.destination);
  assert.equal(result.archiveFormat, 'zip');
  assert.equal(result.crxVersion, null);
  assert.equal(result.files, 2);
  assert.equal(result.entries, 3);
  assert.match(await readFile(path.join(fixture.destination, 'manifest.json'), 'utf8'), /manifest_version/);
});

test('ZIP extension packages retain traversal and link protections', async (t) => {
  const traversal = await withZip(t, [{ name: '../manifest.json', content: '{}' }]);
  await assert.rejects(() => unpackExtensionArchive(traversal.input, traversal.destination), (error) => error.code === 'UNSAFE_ARCHIVE');
  const symlink = await withZip(t, [{ name: 'manifest.json', content: '{}', externalAttributes: 0o120777 << 16 }]);
  await assert.rejects(() => unpackExtensionArchive(symlink.input, symlink.destination), (error) => error.code === 'UNSAFE_ARCHIVE');
});

test('ZIP directory entries require empty data and a valid local header', async (t) => {
  const manifest = '{}';
  const corrupt = await withZip(t, [
    { name: 'manifest.json', content: manifest },
    { name: 'assets/', content: '' }
  ]);
  const corruptBytes = makeZip([
    { name: 'manifest.json', content: manifest },
    { name: 'assets/', content: '' }
  ]);
  const directoryLocalOffset = 30 + Buffer.byteLength('manifest.json') + Buffer.byteLength(manifest);
  corruptBytes.writeUInt32LE(0, directoryLocalOffset);
  await writeFile(corrupt.input, corruptBytes);
  await assert.rejects(
    () => unpackExtensionArchive(corrupt.input, corrupt.destination),
    (error) => error.code === 'INVALID_ARCHIVE' && /local header/.test(error.message)
  );

  const payload = await withZip(t, [
    { name: 'manifest.json', content: manifest },
    { name: 'assets/', content: 'hidden data' }
  ]);
  await assert.rejects(
    () => unpackExtensionArchive(payload.input, payload.destination),
    (error) => error.code === 'INVALID_ARCHIVE' && /Directory entry carries data/.test(error.message)
  );
});

test('CRX unpacker rejects traversal and symbolic-link entries', async (t) => {
  const traversal = await withCrx(t, [{ name: '../manifest.json', content: '{}' }]);
  await assert.rejects(() => unpackCrx(traversal.input, traversal.destination), (error) => error.code === 'UNSAFE_ARCHIVE');
  const symlink = await withCrx(t, [{ name: 'manifest.json', content: '{}', externalAttributes: 0o120777 << 16 }]);
  await assert.rejects(() => unpackCrx(symlink.input, symlink.destination), (error) => error.code === 'UNSAFE_ARCHIVE');
});

test('CRX unpacker rejects CRC corruption and suspicious compression ratios', async (t) => {
  const corrupt = await withCrx(t, [{ name: 'manifest.json', content: '{}', crc: 1 }]);
  await assert.rejects(() => unpackCrx(corrupt.input, corrupt.destination), (error) => error.code === 'INVALID_ARCHIVE');
  const bomb = await withCrx(t, [{ name: 'manifest.json', content: 'a'.repeat(10_000), method: 8 }]);
  await assert.rejects(
    () => unpackCrx(bomb.input, bomb.destination, { limits: { maxCompressionRatio: 10, maxHighlyCompressedEntryBytes: 1_000 } }),
    (error) => error.code === 'ARCHIVE_LIMIT'
  );
});

test('CRX unpacker permits bounded highly-compressible assets', async (t) => {
  const fixture = await withCrx(t, [
    { name: 'manifest.json', content: '{"manifest_version":3}', method: 8 },
    { name: 'images/sparse.png', content: Buffer.alloc(3_000_000), method: 8 }
  ]);
  const result = await unpackCrx(fixture.input, fixture.destination);
  assert.equal(result.uncompressedBytes, 3_000_022);
});

test('CRX unpacker refuses existing destinations and malformed inputs', async (t) => {
  const fixture = await withCrx(t, [{ name: 'manifest.json', content: '{}' }]);
  await writeFile(path.join(fixture.temp, 'not-crx'), 'not a CRX');
  await assert.rejects(() => unpackCrx(path.join(fixture.temp, 'not-crx'), fixture.destination), (error) => error.code === 'INVALID_ARCHIVE');
  await writeFile(fixture.destination, 'occupied');
  await assert.rejects(() => unpackCrx(fixture.input, fixture.destination), (error) => error.code === 'OUTPUT_EXISTS');
});

test('archive limits are strict, canonical, and enforced during bounded input reads', async (t) => {
  const fixture = await withCrx(t, [{ name: 'manifest.json', content: '{}' }]);
  const archiveBytes = (await readFile(fixture.input)).length;
  await assert.rejects(
    () => unpackCrx(fixture.input, fixture.destination, { limits: { maxArchiveBytes: archiveBytes - 1 } }),
    (error) => error.code === 'ARCHIVE_LIMIT'
  );
  await assert.rejects(
    () => unpackCrx(fixture.input, fixture.destination, { limits: { maxArchiveBytes: String(archiveBytes) } }),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
  await assert.rejects(
    () => unpackCrx(fixture.input, fixture.destination, { limits: { ignoredLimit: 1 } }),
    (error) => error.code === 'INVALID_ARGUMENT' && /Unknown archive limit/.test(error.message)
  );
});
