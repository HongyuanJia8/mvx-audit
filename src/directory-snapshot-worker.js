import {
  lstat, mkdir, readdir, readlink, stat, symlink, writeFile
} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { MvxError } from './errors.js';
import { readBoundedRegularFile } from './safe-file.js';

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sameIdentity(actual, expected) {
  return actual.dev === expected.dev && actual.ino === expected.ino;
}

function fail(message, code) {
  throw new MvxError(message, { code });
}

async function snapshot(destinationRoot, expectedRoot, limits) {
  const state = { entries: 0, files: 0, bytes: 0 };

  async function visit(destination, expectedDirectory, depth) {
    const current = await stat('.', { bigint: true });
    if (!current.isDirectory() || !sameIdentity(current, expectedDirectory)) {
      fail('An extension directory changed while the private snapshot was created', 'UNSAFE_INPUT');
    }
    if (depth > limits.maxDepth) {
      fail(`Extension directory depth exceeds ${limits.maxDepth}`, 'SCAN_LIMIT');
    }
    await mkdir(destination, { mode: 0o700 });
    const entries = await readdir('.', { withFileTypes: true });
    entries.sort((left, right) => compareText(left.name, right.name));
    for (const entry of entries) {
      state.entries += 1;
      if (state.entries > limits.maxEntries) {
        fail(`Extension contains more than ${limits.maxEntries} entries`, 'SCAN_LIMIT');
      }
      const entryStat = await lstat(entry.name, { bigint: true });
      const destinationPath = path.join(destination, entry.name);
      if (entryStat.isSymbolicLink()) {
        const target = await readlink(entry.name, { encoding: 'buffer' });
        await symlink(target, destinationPath);
      } else if (entryStat.isDirectory()) {
        process.chdir(entry.name);
        const entered = await stat('.', { bigint: true });
        if (!sameIdentity(entered, entryStat)) {
          fail('An extension directory changed while the private snapshot was created', 'UNSAFE_INPUT');
        }
        await visit(destinationPath, entryStat, depth + 1);
        process.chdir('..');
        const returned = await stat('.', { bigint: true });
        if (!sameIdentity(returned, expectedDirectory)) {
          fail('An extension directory moved while the private snapshot was created', 'UNSAFE_INPUT');
        }
      } else if (entryStat.isFile()) {
        state.files += 1;
        if (state.files > limits.maxFiles) {
          fail(`Extension contains more than ${limits.maxFiles} files`, 'SCAN_LIMIT');
        }
        const bytes = await readBoundedRegularFile(entry.name, {
          maxBytes: limits.maxPackageFileBytes,
          label: 'Audit snapshot file',
          limitCode: 'SCAN_LIMIT',
          missingCode: 'INVALID_INPUT',
          unsafeCode: 'UNSAFE_INPUT'
        });
        state.bytes += bytes.length;
        if (state.bytes > limits.maxPackageBytes) {
          fail(`Package content exceeds ${limits.maxPackageBytes} bytes`, 'SCAN_LIMIT');
        }
        await writeFile(destinationPath, bytes, { flag: 'wx', mode: 0o400 });
      } else {
        fail(
          'Audit verification cannot snapshot special filesystem entries safely',
          'UNSAFE_INPUT'
        );
      }
    }
  }

  await visit(destinationRoot, expectedRoot, 0);
}

const [destinationRoot, expectedDev, expectedIno, serializedLimits] = process.argv.slice(2);
try {
  await snapshot(
    destinationRoot,
    { dev: BigInt(expectedDev), ino: BigInt(expectedIno) },
    JSON.parse(serializedLimits)
  );
  process.send?.({ ok: true });
} catch (error) {
  const code = typeof error?.code === 'string' ? error.code : 'AUDIT_SNAPSHOT_FAILED';
  const safeMessages = new Set([
    'SCAN_LIMIT',
    'UNSAFE_INPUT'
  ]);
  process.send?.({
    ok: false,
    code,
    message: safeMessages.has(code) && typeof error?.message === 'string'
      ? error.message
      : 'Private audit snapshot worker failed'
  });
  process.exitCode = 1;
}
