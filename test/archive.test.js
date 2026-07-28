import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { deflateRawSync } from 'node:zlib';
import { auditExtension } from '../src/analyzer.js';
import { crc32, unpackCrx, unpackExtensionArchive } from '../src/archive.js';

function makeCrx(entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const content = Buffer.from(entry.content ?? '');
    const method = entry.method ?? 0;
    const compressed = method === 8 ? deflateRawSync(content) : content;
    const crc = entry.crc ?? crc32(content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034B50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x800, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(name.length, 26);
    localParts.push(local, name, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014B50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE((entry.externalAttributes ?? (entry.name.endsWith('/') ? 0o040755 << 16 : 0o100644 << 16)) >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, name);
    localOffset += local.length + name.length + compressed.length;
  }
  const localData = Buffer.concat(localParts);
  const centralData = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054B50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralData.length, 12);
  eocd.writeUInt32LE(localData.length, 16);
  const crx = Buffer.alloc(12);
  crx.write('Cr24', 0, 'ascii');
  crx.writeUInt32LE(3, 4);
  crx.writeUInt32LE(0, 8);
  return Buffer.concat([crx, localData, centralData, eocd]);
}

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
  await writeFile(input, makeCrx(entries).subarray(12));
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
  assert.equal(result.crxVersion, 3);
  assert.equal(result.files, 3);
  assert.equal(await readFile(path.join(fixture.destination, 'assets/readme.txt'), 'utf8'), 'data');
  assert.ok((await auditExtension(fixture.destination)).findings.some((finding) => finding.id === 'MVX201'));
});

test('bounded extension archive unpacker supports ZIP without weakening CRX-only API', async (t) => {
  const fixture = await withZip(t, [
    { name: 'manifest.json', content: '{"manifest_version":3,"name":"ZIP","version":"1.0.0"}' },
    { name: 'worker.js', content: 'console.log("loaded");', method: 8 }
  ]);
  await assert.rejects(() => unpackCrx(fixture.input, fixture.destination), (error) => error.code === 'INVALID_ARCHIVE');
  const result = await unpackExtensionArchive(fixture.input, fixture.destination);
  assert.equal(result.archiveFormat, 'zip');
  assert.equal(result.crxVersion, null);
  assert.equal(result.files, 2);
  assert.match(await readFile(path.join(fixture.destination, 'manifest.json'), 'utf8'), /manifest_version/);
});

test('ZIP extension packages retain traversal and link protections', async (t) => {
  const traversal = await withZip(t, [{ name: '../manifest.json', content: '{}' }]);
  await assert.rejects(() => unpackExtensionArchive(traversal.input, traversal.destination), (error) => error.code === 'UNSAFE_ARCHIVE');
  const symlink = await withZip(t, [{ name: 'manifest.json', content: '{}', externalAttributes: 0o120777 << 16 }]);
  await assert.rejects(() => unpackExtensionArchive(symlink.input, symlink.destination), (error) => error.code === 'UNSAFE_ARCHIVE');
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
