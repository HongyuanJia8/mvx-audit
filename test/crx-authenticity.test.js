import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { unpackCrx, unpackExtensionArchive } from '../src/archive.js';
import {
  makeCrx, makeSignedCrx2, makeSignedCrx3, makeZip
} from '../support/archive-fixture.js';

const ENTRIES = [{
  name: 'manifest.json',
  content: '{"manifest_version":3,"name":"Signed fixture","version":"1.0.0"}'
}];

function varint(input) {
  let value = BigInt(input);
  const bytes = [];
  do {
    let byte = Number(value & 0x7fn);
    value >>= 7n;
    if (value !== 0n) byte |= 0x80;
    bytes.push(byte);
  } while (value !== 0n);
  return Buffer.from(bytes);
}

async function unpackFixture(t, bytes, options = {}, extension = 'crx') {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-authenticity-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = path.join(root, `sample.${extension}`);
  const destination = path.join(root, 'unpacked');
  await writeFile(input, bytes);
  const result = await unpackExtensionArchive(input, destination, options);
  return { root, input, destination, result };
}

test('CRX2 verifies its legacy RSA/SHA-1 proof and derives the Chromium extension ID', async (t) => {
  const fixture = makeSignedCrx2(ENTRIES);
  const { result } = await unpackFixture(t, fixture.bytes, { requireValidSignature: true });
  assert.equal(result.authenticity.status, 'verified');
  assert.equal(result.authenticity.scheme, 'crx2-rsa-sha1');
  assert.equal(result.authenticity.extensionId, fixture.extensionId);
  const expectedId = createHash('sha256').update(fixture.publicKey).digest()
    .subarray(0, 16).toString('hex').replace(/[0-9a-f]/g, (digit) => {
      return String.fromCharCode(97 + Number.parseInt(digit, 16));
    });
  assert.equal(result.authenticity.extensionId, expectedId);
  assert.equal(result.authenticity.proofs.length, 1);
  assert.deepEqual(result.authenticity.proofs[0], {
    algorithm: 'rsa-sha1',
    publicKeySha256: createHash('sha256').update(fixture.publicKey).digest('hex'),
    derivedExtensionId: fixture.extensionId,
    developerKey: true,
    verified: true
  });
});

test('CRX3 verifies every RSA/ECDSA proof and identifies only the declared developer key', async (t) => {
  const fixture = makeSignedCrx3(ENTRIES, { algorithms: ['rsa', 'publisher-rsa', 'ecdsa'] });
  const { result } = await unpackFixture(t, fixture.bytes, { requireValidSignature: true });
  const authenticity = result.authenticity;
  assert.equal(authenticity.status, 'verified');
  assert.equal(authenticity.scheme, 'crx3');
  assert.equal(authenticity.extensionId, fixture.extensionId);
  assert.equal(authenticity.proofs.length, 3);
  assert.ok(authenticity.proofs.every((proof) => proof.verified));
  assert.equal(authenticity.proofs.filter((proof) => proof.developerKey).length, 1);
  assert.deepEqual(authenticity.proofs.map((proof) => proof.algorithm), [
    'rsa-sha256', 'rsa-sha256', 'ecdsa-sha256'
  ]);
  assert.match(authenticity.developerKeySha256, /^[a-f0-9]{64}$/);

  const serialized = JSON.stringify(authenticity);
  for (const key of fixture.publicKeys) {
    assert.equal(serialized.includes(key.toString('base64')), false);
    assert.equal(serialized.includes(key.toString('hex')), false);
  }
});

test('invalid CRX signatures remain available for forensic extraction but strict mode rejects them first', async (t) => {
  const tampered = makeSignedCrx3(ENTRIES, { tamperProofIndex: 0 });
  const permissive = await unpackFixture(t, tampered.bytes);
  assert.equal(permissive.result.authenticity.status, 'invalid');
  assert.equal(permissive.result.authenticity.error, 'signature-verification-failed');
  assert.equal(permissive.result.authenticity.proofs[0].verified, false);

  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-authenticity-strict-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = path.join(root, 'tampered.crx');
  const destination = path.join(root, 'must-not-exist');
  await writeFile(input, tampered.bytes);
  await assert.rejects(
    () => unpackCrx(input, destination, { requireValidSignature: true }),
    (error) => error.code === 'CRX_SIGNATURE_REQUIRED' && /signature-verification-failed/.test(error.message)
  );
  await assert.rejects(() => lstat(destination), (error) => error.code === 'ENOENT');
});

test('CRX3 requires a verified proof matching its declared ID', async (t) => {
  const fixture = makeSignedCrx3(ENTRIES, { declaredId: Buffer.alloc(16, 0x5a) });
  const { result } = await unpackFixture(t, fixture.bytes);
  assert.equal(result.authenticity.status, 'invalid');
  assert.equal(result.authenticity.error, 'developer-key-proof-missing');
  assert.equal(result.authenticity.developerKeySha256, null);
  assert.ok(result.authenticity.proofs.every((proof) => proof.verified && !proof.developerKey));
});

test('CRX2 and CRX3 reject SPKI DER with trailing bytes that Node otherwise accepts', async (t) => {
  const fixtures = [
    makeSignedCrx2(ENTRIES, { trailingPublicKeyData: Buffer.from([0]) }),
    makeSignedCrx3(ENTRIES, { trailingPublicKeyData: Buffer.from([0]) })
  ];
  for (const [index, fixture] of fixtures.entries()) {
    const permissive = await unpackFixture(t, fixture.bytes);
    assert.equal(permissive.result.authenticity.status, 'invalid');
    assert.equal(permissive.result.authenticity.proofs[0].error, 'invalid-public-key-or-signature');
    await assert.rejects(
      () => unpackCrx(
        permissive.input,
        path.join(permissive.root, `strict-${index}`),
        { requireValidSignature: true }
      ),
      (error) => error.code === 'CRX_SIGNATURE_REQUIRED'
    );
  }
});

test('CRX3 rejects oversized protobuf field numbers inside unknown groups', async (t) => {
  const invalidNestedTag = (0x20000000n << 3n) | 0n;
  const unknownGroup = Buffer.concat([
    Buffer.from([(4 << 3) | 3]),
    varint(invalidNestedTag),
    Buffer.from([0, (4 << 3) | 4])
  ]);
  const fixture = makeSignedCrx3(ENTRIES, { extraHeaderData: unknownGroup });
  const permissive = await unpackFixture(t, fixture.bytes);
  assert.equal(permissive.result.authenticity.status, 'invalid');
  assert.equal(permissive.result.authenticity.error, 'invalid-signed-header');
  await assert.rejects(
    () => unpackCrx(permissive.input, path.join(permissive.root, 'strict-group'), {
      requireValidSignature: true
    }),
    (error) => error.code === 'CRX_SIGNATURE_REQUIRED'
  );
});

test('unsigned CRX3 and ZIP authenticity statuses are explicit', async (t) => {
  const unsigned = await unpackFixture(t, makeCrx(ENTRIES));
  assert.deepEqual(unsigned.result.authenticity, {
    status: 'invalid', scheme: 'crx3', extensionId: null,
    developerKeySha256: null, proofs: [], error: 'invalid-signed-header'
  });
  const zip = await unpackFixture(t, makeZip(ENTRIES), {}, 'zip');
  assert.deepEqual(zip.result.authenticity, {
    status: 'not-applicable', scheme: null, extensionId: null,
    developerKeySha256: null, proofs: [], error: null
  });
});

test('signature options and CRX3 header resources are bounded', async (t) => {
  const fixture = makeSignedCrx3(ENTRIES, { algorithms: ['rsa', 'ecdsa'] });
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-authenticity-limits-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = path.join(root, 'signed.crx');
  await writeFile(input, fixture.bytes);
  await assert.rejects(
    () => unpackCrx(input, path.join(root, 'bad-option'), { requireValidSignature: 'yes' }),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
  await assert.rejects(
    () => unpackCrx(input, path.join(root, 'header-limit'), { limits: { maxCrxHeaderBytes: 1 } }),
    (error) => error.code === 'CRX_SIGNATURE_LIMIT'
  );
  await assert.rejects(
    () => unpackCrx(input, path.join(root, 'proof-limit'), { limits: { maxCrxProofs: 1 } }),
    (error) => error.code === 'CRX_SIGNATURE_LIMIT'
  );
  await assert.rejects(
    () => unpackCrx(input, path.join(root, 'key-limit'), { limits: { maxCrxKeyBytes: 1 } }),
    (error) => error.code === 'CRX_SIGNATURE_LIMIT'
  );
  await assert.rejects(
    () => unpackCrx(input, path.join(root, 'signature-limit'), { limits: { maxCrxSignatureBytes: 1 } }),
    (error) => error.code === 'CRX_SIGNATURE_LIMIT'
  );
});

test('archive identity policy binds external SHA-256 and verified extension ID before extraction', async (t) => {
  const fixture = makeSignedCrx3(ENTRIES);
  const expectedSha256 = createHash('sha256').update(fixture.bytes).digest('hex');
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-identity-policy-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = path.join(root, 'signed.crx');
  await writeFile(input, fixture.bytes);

  const matched = await unpackCrx(input, path.join(root, 'matched'), {
    expectedArchiveSha256: expectedSha256,
    expectedExtensionId: fixture.extensionId
  });
  assert.deepEqual(matched.identityPolicy, {
    profile: 'mvx-archive-identity-v1',
    requireValidSignature: false,
    expectedArchiveSha256: expectedSha256,
    expectedExtensionId: fixture.extensionId,
    archiveSha256Match: true,
    extensionIdMatch: true,
    matched: true
  });

  const failures = [
    {
      destination: 'wrong-hash',
      options: { expectedArchiveSha256: '0'.repeat(64) },
      code: 'ARCHIVE_IDENTITY_MISMATCH'
    },
    {
      destination: 'wrong-id',
      options: {
        expectedExtensionId: `${fixture.extensionId[0] === 'a' ? 'b' : 'a'}${fixture.extensionId.slice(1)}`
      },
      code: 'ARCHIVE_IDENTITY_MISMATCH'
    }
  ];
  for (const failure of failures) {
    const destination = path.join(root, failure.destination);
    await assert.rejects(() => unpackCrx(input, destination, failure.options), (error) => {
      return error.code === failure.code;
    });
    await assert.rejects(() => lstat(destination), (error) => error.code === 'ENOENT');
  }
});

test('extension-ID policy fails closed for invalid CRX or unsigned ZIP identity', async (t) => {
  const expectedExtensionId = 'a'.repeat(32);
  const inputs = [
    { bytes: makeCrx(ENTRIES), extension: 'crx' },
    { bytes: makeZip(ENTRIES), extension: 'zip' }
  ];
  for (const [index, inputFixture] of inputs.entries()) {
    const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-unverifiable-identity-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    const input = path.join(root, `sample.${inputFixture.extension}`);
    const destination = path.join(root, `output-${index}`);
    await writeFile(input, inputFixture.bytes);
    await assert.rejects(
      () => unpackExtensionArchive(input, destination, { expectedExtensionId }),
      (error) => error.code === 'ARCHIVE_IDENTITY_UNVERIFIABLE'
    );
    await assert.rejects(() => lstat(destination), (error) => error.code === 'ENOENT');
  }
});

test('archive identity policy rejects non-canonical values and supports SHA-bound ZIP input', async (t) => {
  const zip = makeZip(ENTRIES);
  const expectedArchiveSha256 = createHash('sha256').update(zip).digest('hex');
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-zip-identity-policy-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = path.join(root, 'sample.zip');
  await writeFile(input, zip);
  const result = await unpackExtensionArchive(input, path.join(root, 'matched'), {
    expectedArchiveSha256
  });
  assert.equal(result.authenticity.status, 'not-applicable');
  assert.deepEqual(result.identityPolicy, {
    profile: 'mvx-archive-identity-v1',
    requireValidSignature: false,
    expectedArchiveSha256,
    expectedExtensionId: null,
    archiveSha256Match: true,
    extensionIdMatch: null,
    matched: true
  });

  const invalidOptions = [
    { expectedArchiveSha256: Buffer.from(expectedArchiveSha256) },
    { expectedArchiveSha256: expectedArchiveSha256.toUpperCase() },
    { expectedExtensionId: 123 },
    { expectedExtensionId: 'A'.repeat(32) }
  ];
  for (const [index, options] of invalidOptions.entries()) {
    await assert.rejects(
      () => unpackExtensionArchive(input, path.join(root, `invalid-${index}`), options),
      (error) => error.code === 'INVALID_ARGUMENT'
    );
  }
});
