import { constants, createHash, generateKeyPairSync, sign } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import { crc32 } from '../src/archive.js';

const CRX3_CONTEXT = Buffer.from('CRX3 SignedData\0', 'utf8');
let fixtureKeys;

function keys() {
  if (!fixtureKeys) {
    fixtureKeys = {
      rsa: generateKeyPairSync('rsa', { modulusLength: 2048 }),
      publisherRsa: generateKeyPairSync('rsa', { modulusLength: 2048 }),
      ecdsa: generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    };
  }
  return fixtureKeys;
}

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

function bytesField(field, value) {
  return Buffer.concat([varint((BigInt(field) << 3n) | 2n), varint(value.length), value]);
}

function publicDer(keyPair) {
  return keyPair.publicKey.export({ format: 'der', type: 'spki' });
}

function idBytes(publicKey) {
  return createHash('sha256').update(publicKey).digest().subarray(0, 16);
}

function extensionId(value) {
  return value.toString('hex').replace(/[0-9a-f]/g, (digit) => {
    return String.fromCharCode(97 + Number.parseInt(digit, 16));
  });
}

function makeZipBytes(entries) {
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
  return Buffer.concat([localData, centralData, eocd]);
}

export function makeCrx(entries) {
  const crx = Buffer.alloc(12);
  crx.write('Cr24', 0, 'ascii');
  crx.writeUInt32LE(3, 4);
  crx.writeUInt32LE(0, 8);
  return Buffer.concat([crx, makeZipBytes(entries)]);
}

export function makeZip(entries) {
  return makeZipBytes(entries);
}

export function makeSignedCrx2(entries, { tamperSignature = false } = {}) {
  const zip = makeZipBytes(entries);
  const keyPair = keys().rsa;
  const key = publicDer(keyPair);
  const signature = sign('sha1', zip, {
    key: keyPair.privateKey,
    padding: constants.RSA_PKCS1_PADDING
  });
  if (tamperSignature) signature[0] ^= 0x01;
  const header = Buffer.alloc(16);
  header.write('Cr24', 0, 'ascii');
  header.writeUInt32LE(2, 4);
  header.writeUInt32LE(key.length, 8);
  header.writeUInt32LE(signature.length, 12);
  const declaredId = idBytes(key);
  return {
    bytes: Buffer.concat([header, key, signature, zip]),
    extensionId: extensionId(declaredId),
    publicKey: key
  };
}

export function makeSignedCrx3(entries, {
  algorithms = ['rsa'],
  declaredId,
  tamperProofIndex = -1
} = {}) {
  const zip = makeZipBytes(entries);
  const available = keys();
  const proofInputs = algorithms.map((algorithm) => {
    if (algorithm === 'rsa') return { algorithm, keyPair: available.rsa };
    if (algorithm === 'publisher-rsa') return { algorithm: 'rsa', keyPair: available.publisherRsa };
    if (algorithm === 'ecdsa') return { algorithm, keyPair: available.ecdsa };
    throw new Error(`Unknown fixture proof algorithm: ${algorithm}`);
  });
  const developerKey = publicDer(available.rsa);
  const crxId = declaredId === undefined ? idBytes(developerKey) : Buffer.from(declaredId);
  const signedHeader = bytesField(1, crxId);
  const signedHeaderLength = Buffer.alloc(4);
  signedHeaderLength.writeUInt32LE(signedHeader.length);
  const signedBytes = Buffer.concat([CRX3_CONTEXT, signedHeaderLength, signedHeader, zip]);
  const proofs = proofInputs.map(({ algorithm, keyPair }, index) => {
    const key = publicDer(keyPair);
    const signature = sign('sha256', signedBytes, algorithm === 'rsa'
      ? { key: keyPair.privateKey, padding: constants.RSA_PKCS1_PADDING }
      : keyPair.privateKey);
    if (index === tamperProofIndex) signature[0] ^= 0x01;
    return { algorithm, key, message: Buffer.concat([bytesField(1, key), bytesField(2, signature)]) };
  });
  const headerBody = Buffer.concat([
    ...proofs.map((proof) => bytesField(proof.algorithm === 'rsa' ? 2 : 3, proof.message)),
    bytesField(10000, signedHeader)
  ]);
  const header = Buffer.alloc(12);
  header.write('Cr24', 0, 'ascii');
  header.writeUInt32LE(3, 4);
  header.writeUInt32LE(headerBody.length, 8);
  return {
    bytes: Buffer.concat([header, headerBody, zip]),
    extensionId: extensionId(crxId),
    publicKeys: proofs.map((proof) => proof.key)
  };
}
