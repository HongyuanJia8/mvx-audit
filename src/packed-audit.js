import { chmod, lstat, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { auditExtension } from './analyzer.js';
import { unpackExtensionArchive } from './archive.js';
import { MvxError } from './errors.js';

async function resolveTemporaryParent(input) {
  const absolute = path.resolve(input ?? os.tmpdir());
  let stat;
  try {
    stat = await lstat(absolute);
  } catch (error) {
    throw new MvxError(`Temporary directory does not exist: ${absolute}`, { code: 'TEMP_NOT_FOUND', cause: error });
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new MvxError('Temporary directory must be a real directory', { code: 'UNSAFE_TEMP' });
  }
  return realpath(absolute);
}

export async function auditExtensionArchive(inputPath, options = {}) {
  const temporaryParent = await resolveTemporaryParent(options.temporaryDirectory);
  const workspace = await mkdtemp(path.join(temporaryParent, 'mvx-packed-audit-'));
  try {
    await chmod(workspace, 0o700);
    const extracted = path.join(workspace, 'extension');
    const archive = await unpackExtensionArchive(inputPath, extracted, { limits: options.archiveLimits });
    const audit = await auditExtension(extracted, { limits: options.limits });
    return {
      ...audit,
      target: { ...audit.target, root: archive.input, inputType: 'archive' },
      artifact: {
        kind: 'extension-archive',
        path: archive.input,
        format: archive.archiveFormat,
        crxVersion: archive.crxVersion,
        bytes: archive.archiveBytes,
        sha256: archive.archiveSha256,
        extraction: {
          entries: archive.entries,
          files: archive.files,
          uncompressedBytes: archive.uncompressedBytes
        }
      },
      assumptions: [
        ...audit.assumptions,
        'The archive was defensively extracted into a private temporary directory, statically audited, and removed without executing extension code.'
      ]
    };
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
