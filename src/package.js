import { createHash } from 'node:crypto';

export const PACKAGE_PROFILE = 'mvx-package-v1';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function startsWith(bytes, signature) {
  return bytes.length >= signature.length && signature.every((byte, index) => bytes[index] === byte);
}

export function executableFormat(bytes) {
  if (startsWith(bytes, [0x00, 0x61, 0x73, 0x6d])) return 'webassembly';
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (startsWith(bytes, [0x4d, 0x5a])) return 'windows-executable';
  const magic = bytes.length >= 4 ? bytes.readUInt32BE(0) : null;
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca].includes(magic)) return 'mach-o';
  return null;
}

export function packageInventory(entries) {
  const normalized = entries.map((entry) => ({ ...entry }))
    .sort((left, right) => compareText(left.path, right.path) || compareText(left.type, right.type));
  const files = normalized.filter((entry) => entry.type === 'file');
  const identity = { profile: PACKAGE_PROFILE, entries: normalized };
  return {
    ...identity,
    fileCount: files.length,
    totalBytes: files.reduce((total, entry) => total + entry.bytes, 0),
    sha256: sha256(JSON.stringify(identity))
  };
}
