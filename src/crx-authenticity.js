import {
  constants, createHash, createPublicKey, createVerify
} from 'node:crypto';
import { MvxError } from './errors.js';

const CRX3_CONTEXT = Buffer.from('CRX3 SignedData\0', 'utf8');
const ZIP_MARKERS = [Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.from([0x50, 0x4b, 0x06, 0x07])];

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function extensionIdFromHash(hash) {
  return hash.subarray(0, 16).toString('hex').replace(/[0-9a-f]/g, (digit) => {
    return String.fromCharCode(97 + Number.parseInt(digit, 16));
  });
}

function invalid(scheme, error, { extensionId = null, developerKeySha256 = null, proofs = [] } = {}) {
  return { status: 'invalid', scheme, extensionId, developerKeySha256, proofs, error };
}

function readVarint(buffer, state, label) {
  let value = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (state.offset >= buffer.length) throw new MvxError(`Truncated ${label} varint`, { code: 'INVALID_CRX_HEADER' });
    const byte = buffer[state.offset++];
    if (index === 9 && byte > 1) throw new MvxError(`Overflowing ${label} varint`, { code: 'INVALID_CRX_HEADER' });
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) return value;
  }
  throw new MvxError(`Overflowing ${label} varint`, { code: 'INVALID_CRX_HEADER' });
}

function requireBytes(buffer, state, length, label) {
  if (!Number.isSafeInteger(length) || length < 0 || state.offset + length > buffer.length) {
    throw new MvxError(`Truncated ${label}`, { code: 'INVALID_CRX_HEADER' });
  }
  const value = buffer.subarray(state.offset, state.offset + length);
  state.offset += length;
  return value;
}

function readLengthDelimited(buffer, state, label) {
  const length = readVarint(buffer, state, `${label} length`);
  if (length > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new MvxError(`${label} length is too large`, { code: 'INVALID_CRX_HEADER' });
  }
  return requireBytes(buffer, state, Number(length), label);
}

function skipField(buffer, state, field, wire, depth) {
  if (depth > 64) throw new MvxError('CRX3 protobuf nesting exceeds 64 levels', { code: 'INVALID_CRX_HEADER' });
  if (wire === 0) {
    readVarint(buffer, state, 'protobuf field');
    return;
  }
  if (wire === 1) {
    requireBytes(buffer, state, 8, 'protobuf fixed64 field');
    return;
  }
  if (wire === 2) {
    readLengthDelimited(buffer, state, 'protobuf field');
    return;
  }
  if (wire === 3) {
    while (state.offset < buffer.length) {
      const tag = readVarint(buffer, state, 'protobuf group tag');
      const nestedField = Number(tag >> 3n);
      const nestedWire = Number(tag & 7n);
      if (nestedField === 0) throw new MvxError('CRX3 protobuf field number is zero', { code: 'INVALID_CRX_HEADER' });
      if (nestedWire === 4) {
        if (nestedField !== field) throw new MvxError('CRX3 protobuf group terminator differs', { code: 'INVALID_CRX_HEADER' });
        return;
      }
      skipField(buffer, state, nestedField, nestedWire, depth + 1);
    }
    throw new MvxError('Truncated CRX3 protobuf group', { code: 'INVALID_CRX_HEADER' });
  }
  if (wire === 5) {
    requireBytes(buffer, state, 4, 'protobuf fixed32 field');
    return;
  }
  throw new MvxError(`Unsupported CRX3 protobuf wire type: ${wire}`, { code: 'INVALID_CRX_HEADER' });
}

function parseMessage(buffer, onField) {
  const state = { offset: 0 };
  while (state.offset < buffer.length) {
    const tag = readVarint(buffer, state, 'protobuf tag');
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (field === 0 || field > 0x1fffffff || wire === 4) {
      throw new MvxError('Invalid CRX3 protobuf tag', { code: 'INVALID_CRX_HEADER' });
    }
    if (!onField(field, wire, buffer, state)) skipField(buffer, state, field, wire, 0);
  }
}

function parseProof(buffer, limits) {
  let publicKey = Buffer.alloc(0);
  let signature = Buffer.alloc(0);
  parseMessage(buffer, (field, wire, source, state) => {
    if (wire !== 2) return false;
    if (field === 1) {
      publicKey = readLengthDelimited(source, state, 'CRX3 public key');
      return true;
    }
    if (field === 2) {
      signature = readLengthDelimited(source, state, 'CRX3 signature');
      return true;
    }
    return false;
  });
  if (publicKey.length === 0) throw new MvxError('CRX3 public key is empty', { code: 'INVALID_CRX_HEADER' });
  if (publicKey.length > limits.maxCrxKeyBytes) {
    throw new MvxError(`CRX3 public key exceeds ${limits.maxCrxKeyBytes} bytes`, { code: 'CRX_SIGNATURE_LIMIT' });
  }
  if (signature.length === 0) throw new MvxError('CRX3 signature is empty', { code: 'INVALID_CRX_HEADER' });
  if (signature.length > limits.maxCrxSignatureBytes) {
    throw new MvxError(`CRX3 signature exceeds ${limits.maxCrxSignatureBytes} bytes`, { code: 'CRX_SIGNATURE_LIMIT' });
  }
  return { publicKey, signature };
}

function parseSignedData(buffer) {
  let crxId = Buffer.alloc(0);
  parseMessage(buffer, (field, wire, source, state) => {
    if (field !== 1 || wire !== 2) return false;
    crxId = readLengthDelimited(source, state, 'CRX3 ID');
    return true;
  });
  if (crxId.length !== 16) throw new MvxError('CRX3 ID must contain exactly 16 bytes', { code: 'INVALID_CRX_HEADER' });
  return crxId;
}

function parseCrx3Header(buffer, limits) {
  const rsa = [];
  const ecdsa = [];
  let signedHeader = null;
  parseMessage(buffer, (field, wire, source, state) => {
    if (wire !== 2) return false;
    if (field === 2 || field === 3) {
      const proof = readLengthDelimited(source, state, 'CRX3 proof');
      (field === 2 ? rsa : ecdsa).push(parseProof(proof, limits));
      if (rsa.length + ecdsa.length > limits.maxCrxProofs) {
        throw new MvxError('CRX3 proof count exceeds the limit', { code: 'CRX_SIGNATURE_LIMIT' });
      }
      return true;
    }
    if (field === 10000) {
      signedHeader = readLengthDelimited(source, state, 'CRX3 signed header');
      return true;
    }
    return false;
  });
  if (!signedHeader) throw new MvxError('CRX3 signed header is missing', { code: 'INVALID_CRX_HEADER' });
  if (rsa.length + ecdsa.length === 0) throw new MvxError('CRX3 contains no signature proofs', { code: 'INVALID_CRX_HEADER' });
  return { rsa, ecdsa, signedHeader, crxId: parseSignedData(signedHeader) };
}

function publicKey(value, algorithm) {
  const key = createPublicKey({ key: value, format: 'der', type: 'spki' });
  if (algorithm.startsWith('rsa-') && key.asymmetricKeyType !== 'rsa') {
    throw new Error('RSA proof does not contain an RSA key');
  }
  if (algorithm === 'ecdsa-sha256' && key.asymmetricKeyType !== 'ec') {
    throw new Error('ECDSA proof does not contain an EC key');
  }
  return key;
}

function verifyProof({ publicKey: keyBytes, signature }, algorithm, chunks) {
  const keyHash = sha256(keyBytes);
  const proof = {
    algorithm,
    publicKeySha256: keyHash.toString('hex'),
    derivedExtensionId: extensionIdFromHash(keyHash),
    developerKey: false,
    verified: false
  };
  try {
    const key = publicKey(keyBytes, algorithm);
    const verifier = createVerify(algorithm === 'rsa-sha1' ? 'sha1' : 'sha256');
    for (const chunk of chunks) verifier.update(chunk);
    verifier.end();
    const keyOptions = algorithm.startsWith('rsa-')
      ? { key, padding: constants.RSA_PKCS1_PADDING }
      : key;
    proof.verified = verifier.verify(keyOptions, signature);
    if (!proof.verified) proof.error = 'signature-verification-failed';
  } catch {
    proof.error = 'invalid-public-key-or-signature';
  }
  return proof;
}

function verifyCrx2(buffer, zipOffset, limits) {
  const keyLength = buffer.readUInt32LE(8);
  const signatureLength = buffer.readUInt32LE(12);
  if (keyLength > limits.maxCrxKeyBytes || signatureLength > limits.maxCrxSignatureBytes) {
    throw new MvxError('CRX2 key or signature exceeds the configured limit', { code: 'CRX_SIGNATURE_LIMIT' });
  }
  if (keyLength === 0 || signatureLength === 0) {
    return invalid('crx2-rsa-sha1', 'key-or-signature-size-invalid');
  }
  const keyStart = 16;
  const signatureStart = keyStart + keyLength;
  const key = buffer.subarray(keyStart, signatureStart);
  const signature = buffer.subarray(signatureStart, signatureStart + signatureLength);
  const proof = verifyProof({ publicKey: key, signature }, 'rsa-sha1', [buffer.subarray(zipOffset)]);
  proof.developerKey = true;
  const extensionId = proof.derivedExtensionId;
  const developerKeySha256 = proof.publicKeySha256;
  if (!proof.verified) return invalid('crx2-rsa-sha1', proof.error, { extensionId, developerKeySha256, proofs: [proof] });
  return {
    status: 'verified',
    scheme: 'crx2-rsa-sha1',
    extensionId,
    developerKeySha256,
    proofs: [proof],
    error: null
  };
}

function verifyCrx3(buffer, zipOffset, limits) {
  const headerLength = buffer.readUInt32LE(8);
  if (headerLength > limits.maxCrxHeaderBytes) {
    throw new MvxError(`CRX3 header exceeds ${limits.maxCrxHeaderBytes} bytes`, { code: 'CRX_SIGNATURE_LIMIT' });
  }
  const header = buffer.subarray(12, zipOffset);
  if (ZIP_MARKERS.some((marker) => header.indexOf(marker) !== -1)) {
    return invalid('crx3', 'header-contains-zip-marker');
  }
  let parsed;
  try {
    parsed = parseCrx3Header(header, limits);
  } catch (error) {
    if (error.code === 'CRX_SIGNATURE_LIMIT') throw error;
    return invalid('crx3', 'invalid-signed-header');
  }
  const extensionId = extensionIdFromHash(parsed.crxId);
  const signedHeaderLength = Buffer.alloc(4);
  signedHeaderLength.writeUInt32LE(parsed.signedHeader.length);
  const chunks = [CRX3_CONTEXT, signedHeaderLength, parsed.signedHeader, buffer.subarray(zipOffset)];
  const proofs = [
    ...parsed.rsa.map((proof) => verifyProof(proof, 'rsa-sha256', chunks)),
    ...parsed.ecdsa.map((proof) => verifyProof(proof, 'ecdsa-sha256', chunks))
  ];
  for (const proof of proofs) proof.developerKey = proof.derivedExtensionId === extensionId;
  const developerProof = proofs.find((proof) => proof.developerKey);
  const developerKeySha256 = developerProof?.publicKeySha256 ?? null;
  if (proofs.some((proof) => !proof.verified)) {
    return invalid('crx3', 'signature-verification-failed', { extensionId, developerKeySha256, proofs });
  }
  if (!developerProof) return invalid('crx3', 'developer-key-proof-missing', { extensionId, proofs });
  return { status: 'verified', scheme: 'crx3', extensionId, developerKeySha256, proofs, error: null };
}

export function verifyCrxAuthenticity(buffer, layout, limits) {
  if (layout.format === 'zip') {
    return {
      status: 'not-applicable', scheme: null, extensionId: null,
      developerKeySha256: null, proofs: [], error: null
    };
  }
  if (layout.version === 2) return verifyCrx2(buffer, layout.zipOffset, limits);
  return verifyCrx3(buffer, layout.zipOffset, limits);
}
