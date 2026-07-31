import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, open, realpath, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { verifyCrxAuthenticity } from './crx-authenticity.js';
import { MvxError } from './errors.js';
import { readBoundedRegularFile } from './safe-file.js';

const DEFAULT_LIMITS = Object.freeze({
  maxArchiveBytes: 100_000_000,
  maxCrxHeaderBytes: 262_144,
  maxCrxProofs: 32,
  maxCrxKeyBytes: 65_536,
  maxCrxSignatureBytes: 65_536,
  maxEntries: 10_000,
  maxEntryBytes: 50_000_000,
  maxTotalBytes: 250_000_000,
  maxCompressionRatio: 200,
  maxHighlyCompressedEntryBytes: 5_000_000,
  maxPathDepth: 64
});
const CRC_TABLE = new Uint32Array(256);
const SHA256 = /^[a-f0-9]{64}$/;
const EXTENSION_ID = /^[a-p]{32}$/;
for (let index = 0; index < CRC_TABLE.length; index += 1) {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (0xEDB88320 ^ (value >>> 1)) : (value >>> 1);
  CRC_TABLE[index] = value >>> 0;
}

function normalizeLimits(options) {
  if (!options || Array.isArray(options) || typeof options !== 'object') {
    throw new MvxError('Archive limits must be an object', { code: 'INVALID_ARGUMENT' });
  }
  const supported = new Set(Object.keys(DEFAULT_LIMITS));
  const unknown = Object.keys(options).filter((key) => !supported.has(key)).sort();
  if (unknown.length > 0) throw new MvxError(`Unknown archive limit: ${unknown.join(', ')}`, { code: 'INVALID_ARGUMENT' });
  const limits = {};
  for (const [key, fallback] of Object.entries(DEFAULT_LIMITS)) {
    const value = Object.hasOwn(options, key) ? options[key] : fallback;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new MvxError(`${key} must be a positive safe integer`, { code: 'INVALID_ARGUMENT' });
    }
    limits[key] = value;
  }
  return limits;
}

function crc32(bytes) {
  let crc = 0xFFFFFFFF;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function requireRange(buffer, offset, length, label) {
  if (!Number.isSafeInteger(offset) || offset < 0 || length < 0 || offset + length > buffer.length) {
    throw new MvxError(`Truncated archive ${label}`, { code: 'INVALID_ARCHIVE' });
  }
}

function archiveZipOffset(buffer, allowZip) {
  requireRange(buffer, 0, 4, 'header');
  if (allowZip && buffer.readUInt32LE(0) === 0x04034B50) return { format: 'zip', version: null, offset: 0 };
  requireRange(buffer, 0, 12, 'CRX header');
  if (buffer.subarray(0, 4).toString('ascii') !== 'Cr24') throw new MvxError('Input is not a supported CRX or ZIP archive', { code: 'INVALID_ARCHIVE' });
  const version = buffer.readUInt32LE(4);
  let offset;
  if (version === 2) {
    requireRange(buffer, 0, 16, 'CRX2 header');
    offset = 16 + buffer.readUInt32LE(8) + buffer.readUInt32LE(12);
  } else if (version === 3) offset = 12 + buffer.readUInt32LE(8);
  else throw new MvxError(`Unsupported CRX version: ${version}`, { code: 'INVALID_ARCHIVE' });
  requireRange(buffer, offset, 4, 'ZIP payload');
  return { format: 'crx', version, offset };
}

function decodeName(bytes, utf8) {
  if (!utf8 && bytes.some((byte) => byte > 0x7F)) {
    throw new MvxError('Non-ASCII ZIP path is missing the UTF-8 flag', { code: 'INVALID_ARCHIVE' });
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    throw new MvxError('ZIP path is not valid UTF-8', { code: 'INVALID_ARCHIVE', cause: error });
  }
}

function safeRelativePath(name, limits) {
  if (!name || name.includes('\0') || name.includes('\\') || name.startsWith('/') || /^[a-z]:/i.test(name)) {
    throw new MvxError(`Unsafe archive path: ${JSON.stringify(name)}`, { code: 'UNSAFE_ARCHIVE' });
  }
  const directory = name.endsWith('/');
  const trimmed = directory ? name.slice(0, -1) : name;
  const segments = trimmed.split('/');
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new MvxError(`Unsafe archive path: ${JSON.stringify(name)}`, { code: 'UNSAFE_ARCHIVE' });
  }
  if (segments.length > limits.maxPathDepth) throw new MvxError('Archive path depth exceeds the limit', { code: 'ARCHIVE_LIMIT' });
  return { path: segments.join('/'), directory };
}

function locateEocd(buffer, zipOffset) {
  const minimum = Math.max(zipOffset, buffer.length - 65_557);
  for (let offset = buffer.length - 22; offset >= minimum; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054B50) return offset;
  }
  throw new MvxError('ZIP end-of-central-directory record was not found', { code: 'INVALID_ARCHIVE' });
}

function parseEntries(buffer, zipOffset, limits) {
  const eocd = locateEocd(buffer, zipOffset);
  requireRange(buffer, eocd, 22, 'end record');
  const disk = buffer.readUInt16LE(eocd + 4);
  const centralDisk = buffer.readUInt16LE(eocd + 6);
  const diskEntries = buffer.readUInt16LE(eocd + 8);
  const totalEntries = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  const centralOffset = buffer.readUInt32LE(eocd + 16);
  const commentLength = buffer.readUInt16LE(eocd + 20);
  if ([diskEntries, totalEntries].includes(0xFFFF) || [centralSize, centralOffset].includes(0xFFFFFFFF)) {
    throw new MvxError('Zip64 archives are not supported', { code: 'UNSAFE_ARCHIVE' });
  }
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== totalEntries) throw new MvxError('Multi-disk ZIP is not supported', { code: 'UNSAFE_ARCHIVE' });
  if (totalEntries > limits.maxEntries) throw new MvxError(`Archive exceeds ${limits.maxEntries} entries`, { code: 'ARCHIVE_LIMIT' });
  requireRange(buffer, eocd + 22, commentLength, 'comment');
  if (eocd + 22 + commentLength !== buffer.length) throw new MvxError('Trailing data follows the ZIP end record', { code: 'INVALID_ARCHIVE' });
  const centralStart = zipOffset + centralOffset;
  requireRange(buffer, centralStart, centralSize, 'central directory');
  if (centralStart + centralSize !== eocd) throw new MvxError('Central directory offsets are inconsistent', { code: 'INVALID_ARCHIVE' });

  const entries = [];
  const names = new Set();
  let cursor = centralStart;
  let totalBytes = 0;
  for (let index = 0; index < totalEntries; index += 1) {
    requireRange(buffer, cursor, 46, 'central entry');
    if (buffer.readUInt32LE(cursor) !== 0x02014B50) throw new MvxError('Invalid central directory entry', { code: 'INVALID_ARCHIVE' });
    const flags = buffer.readUInt16LE(cursor + 8);
    const method = buffer.readUInt16LE(cursor + 10);
    const expectedCrc = buffer.readUInt32LE(cursor + 16);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const uncompressedSize = buffer.readUInt32LE(cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const entryCommentLength = buffer.readUInt16LE(cursor + 32);
    const externalAttributes = buffer.readUInt32LE(cursor + 38);
    const localOffset = buffer.readUInt32LE(cursor + 42);
    requireRange(buffer, cursor + 46, nameLength + extraLength + entryCommentLength, 'central entry data');
    const rawName = buffer.subarray(cursor + 46, cursor + 46 + nameLength);
    const safe = safeRelativePath(decodeName(rawName, Boolean(flags & 0x800)), limits);
    if (names.has(safe.path)) throw new MvxError(`Duplicate archive path: ${safe.path}`, { code: 'UNSAFE_ARCHIVE' });
    names.add(safe.path);
    const unixType = (externalAttributes >>> 16) & 0o170000;
    if (unixType === 0o120000) throw new MvxError(`Symbolic link entry is forbidden: ${safe.path}`, { code: 'UNSAFE_ARCHIVE' });
    if (flags & 1) throw new MvxError(`Encrypted entry is forbidden: ${safe.path}`, { code: 'UNSAFE_ARCHIVE' });
    if (![0, 8].includes(method)) throw new MvxError(`Unsupported compression method ${method}: ${safe.path}`, { code: 'UNSAFE_ARCHIVE' });
    if (safe.directory && (uncompressedSize !== 0 || expectedCrc !== 0)) {
      throw new MvxError(`Directory entry carries data or a nonzero CRC: ${safe.path}`, { code: 'INVALID_ARCHIVE' });
    }
    if (uncompressedSize > limits.maxEntryBytes) throw new MvxError(`Archive entry exceeds ${limits.maxEntryBytes} bytes: ${safe.path}`, { code: 'ARCHIVE_LIMIT' });
    if (uncompressedSize > limits.maxHighlyCompressedEntryBytes
      && uncompressedSize / Math.max(1, compressedSize) > limits.maxCompressionRatio) {
      throw new MvxError(`Suspicious compression ratio: ${safe.path}`, { code: 'ARCHIVE_LIMIT' });
    }
    totalBytes += uncompressedSize;
    if (totalBytes > limits.maxTotalBytes) throw new MvxError(`Archive expands beyond ${limits.maxTotalBytes} bytes`, { code: 'ARCHIVE_LIMIT' });
    entries.push({ ...safe, flags, method, expectedCrc, compressedSize, uncompressedSize, localOffset, rawName });
    cursor += 46 + nameLength + extraLength + entryCommentLength;
  }
  if (cursor !== centralStart + centralSize) throw new MvxError('Central directory entry count is inconsistent', { code: 'INVALID_ARCHIVE' });
  return entries;
}

function entryData(buffer, zipOffset, entry) {
  const local = zipOffset + entry.localOffset;
  requireRange(buffer, local, 30, `local header for ${entry.path}`);
  if (buffer.readUInt32LE(local) !== 0x04034B50) throw new MvxError(`Invalid local header: ${entry.path}`, { code: 'INVALID_ARCHIVE' });
  const localFlags = buffer.readUInt16LE(local + 6);
  const localMethod = buffer.readUInt16LE(local + 8);
  const nameLength = buffer.readUInt16LE(local + 26);
  const extraLength = buffer.readUInt16LE(local + 28);
  requireRange(buffer, local + 30, nameLength + extraLength + entry.compressedSize, `data for ${entry.path}`);
  const localName = decodeName(buffer.subarray(local + 30, local + 30 + nameLength), Boolean(localFlags & 0x800));
  if (localName !== `${entry.path}${entry.directory ? '/' : ''}` || localMethod !== entry.method || (localFlags & 1)) {
    throw new MvxError(`Local and central entry metadata differ: ${entry.path}`, { code: 'INVALID_ARCHIVE' });
  }
  const start = local + 30 + nameLength + extraLength;
  const compressed = buffer.subarray(start, start + entry.compressedSize);
  let output;
  try {
    output = entry.method === 0 ? Buffer.from(compressed) : inflateRawSync(compressed, { maxOutputLength: entry.uncompressedSize + 1 });
  } catch (error) {
    throw new MvxError(`Cannot decompress archive entry: ${entry.path}`, { code: 'INVALID_ARCHIVE', cause: error });
  }
  if (output.length !== entry.uncompressedSize || crc32(output) !== entry.expectedCrc) {
    throw new MvxError(`Archive entry failed size or CRC verification: ${entry.path}`, { code: 'INVALID_ARCHIVE' });
  }
  return output;
}

async function safeParent(destination) {
  const absolute = path.resolve(destination);
  const parent = path.dirname(absolute);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const parentStat = await lstat(parent);
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) throw new MvxError('Archive destination parent is unsafe', { code: 'UNSAFE_ARCHIVE' });
  return { absolute, parent: await realpath(parent) };
}

async function unpackArchive(inputPath, destination, options, allowZip) {
  if (!destination) throw new MvxError('Archive extraction requires a destination directory', { code: 'INVALID_ARGUMENT' });
  const expectedExtensionIdIfVerified =
    Object.getOwnPropertyDescriptor(options, '_expectedExtensionIdIfVerified')?.value;
  const expectedDeveloperKeySha256IfVerified =
    Object.getOwnPropertyDescriptor(options, '_expectedDeveloperKeySha256IfVerified')?.value;
  if (options.requireValidSignature !== undefined && typeof options.requireValidSignature !== 'boolean') {
    throw new MvxError('requireValidSignature must be boolean', { code: 'INVALID_ARGUMENT' });
  }
  if (options.expectedArchiveSha256 !== undefined
    && (typeof options.expectedArchiveSha256 !== 'string' || !SHA256.test(options.expectedArchiveSha256))) {
    throw new MvxError('expectedArchiveSha256 must be a lowercase SHA-256 digest', { code: 'INVALID_ARGUMENT' });
  }
  if (options.expectedExtensionId !== undefined
    && (typeof options.expectedExtensionId !== 'string' || !EXTENSION_ID.test(options.expectedExtensionId))) {
    throw new MvxError('expectedExtensionId must be a lowercase Chromium extension ID', { code: 'INVALID_ARGUMENT' });
  }
  if (expectedExtensionIdIfVerified !== undefined
    && (typeof expectedExtensionIdIfVerified !== 'string' || !EXTENSION_ID.test(expectedExtensionIdIfVerified))) {
    throw new MvxError('_expectedExtensionIdIfVerified must be a lowercase Chromium extension ID', { code: 'INVALID_ARGUMENT' });
  }
  if (expectedDeveloperKeySha256IfVerified !== undefined
    && (typeof expectedDeveloperKeySha256IfVerified !== 'string'
      || !SHA256.test(expectedDeveloperKeySha256IfVerified))) {
    throw new MvxError(
      '_expectedDeveloperKeySha256IfVerified must be a lowercase SHA-256 digest',
      { code: 'INVALID_ARGUMENT' }
    );
  }
  if (options.expectedExtensionId !== undefined && expectedExtensionIdIfVerified !== undefined) {
    throw new MvxError('Extension ID expectations cannot be combined', { code: 'INVALID_ARGUMENT' });
  }
  const limits = normalizeLimits(options.limits ?? {});
  const input = path.resolve(inputPath);
  const inputStat = await lstat(input).catch((error) => {
    throw new MvxError(`Cannot read archive: ${input}`, { code: 'INPUT_NOT_FOUND', cause: error });
  });
  if (inputStat.isSymbolicLink() || !inputStat.isFile()) throw new MvxError('Archive input must be a regular non-symlink file', { code: 'UNSAFE_ARCHIVE' });
  const buffer = await readBoundedRegularFile(input, {
    maxBytes: limits.maxArchiveBytes,
    label: 'Archive',
    limitCode: 'ARCHIVE_LIMIT',
    missingCode: 'INPUT_NOT_FOUND',
    unsafeCode: 'UNSAFE_ARCHIVE'
  });
  const archiveSha256 = createHash('sha256').update(buffer).digest('hex');
  if (options.expectedArchiveSha256 && archiveSha256 !== options.expectedArchiveSha256) {
    throw new MvxError('Archive SHA-256 does not match its expected identity', { code: 'ARCHIVE_IDENTITY_MISMATCH' });
  }
  const { format, version, offset: zipOffset } = archiveZipOffset(buffer, allowZip);
  const authenticity = verifyCrxAuthenticity(buffer, { format, version, zipOffset }, limits);
  if (options.expectedExtensionId && authenticity.status !== 'verified') {
    throw new MvxError('Expected extension ID cannot be verified without a valid CRX signature', {
      code: 'ARCHIVE_IDENTITY_UNVERIFIABLE'
    });
  }
  const verifiedExtensionIdExpectation = options.expectedExtensionId ?? expectedExtensionIdIfVerified;
  if (verifiedExtensionIdExpectation && authenticity.status === 'verified'
    && authenticity.extensionId !== verifiedExtensionIdExpectation) {
    throw new MvxError('Verified CRX extension ID does not match its expected identity', { code: 'ARCHIVE_IDENTITY_MISMATCH' });
  }
  if (expectedDeveloperKeySha256IfVerified && authenticity.status === 'verified'
    && authenticity.developerKeySha256 !== expectedDeveloperKeySha256IfVerified) {
    throw new MvxError('Verified CRX developer key does not match its expected identity', {
      code: 'ARCHIVE_IDENTITY_MISMATCH'
    });
  }
  if (options.requireValidSignature && authenticity.status !== 'verified') {
    const reason = authenticity.error ?? authenticity.status;
    throw new MvxError(`A valid CRX signature is required: ${reason}`, { code: 'CRX_SIGNATURE_REQUIRED' });
  }
  const identityPolicy = {
    profile: 'mvx-archive-identity-v1',
    expectedArchiveSha256: options.expectedArchiveSha256 ?? null,
    expectedExtensionId: options.expectedExtensionId ?? null,
    archiveSha256Match: options.expectedArchiveSha256 ? true : null,
    extensionIdMatch: options.expectedExtensionId ? true : null,
    matched: options.expectedArchiveSha256 || options.expectedExtensionId ? true : null
  };
  const entries = parseEntries(buffer, zipOffset, limits);
  const { absolute, parent } = await safeParent(destination);
  try {
    await lstat(absolute);
    throw new MvxError(`Archive destination already exists: ${absolute}`, { code: 'OUTPUT_EXISTS' });
  } catch (error) {
    if (error instanceof MvxError) throw error;
    if (error.code !== 'ENOENT') throw error;
  }
  const temporary = path.join(parent, `.${path.basename(absolute)}.${randomUUID()}.partial`);
  await mkdir(temporary, { mode: 0o700 });
  try {
    let files = 0;
    let totalBytes = 0;
    for (const entry of entries) {
      const target = path.join(temporary, ...entry.path.split('/'));
      const output = entryData(buffer, zipOffset, entry);
      if (entry.directory) {
        await mkdir(target, { recursive: true, mode: 0o700 });
        continue;
      }
      await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      const handle = await open(target, 'wx', 0o600);
      try {
        await handle.writeFile(output);
        await handle.sync();
      } finally {
        await handle.close();
      }
      files += 1;
      totalBytes += output.length;
    }
    await rename(temporary, absolute);
    const destinationStat = await stat(absolute);
    if (!destinationStat.isDirectory()) throw new MvxError('Archive destination verification failed', { code: 'UNSAFE_ARCHIVE' });
    return {
      input,
      destination: absolute,
      archiveFormat: format,
      crxVersion: version,
      archiveBytes: buffer.length,
      archiveSha256,
      authenticity,
      identityPolicy,
      entries: entries.length,
      files,
      uncompressedBytes: totalBytes
    };
  } catch (error) {
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }
}

export async function unpackCrx(inputPath, destination, options = {}) {
  return unpackArchive(inputPath, destination, options, false);
}

export async function unpackExtensionArchive(inputPath, destination, options = {}) {
  return unpackArchive(inputPath, destination, options, true);
}

export { DEFAULT_LIMITS as ARCHIVE_LIMITS, crc32 };
