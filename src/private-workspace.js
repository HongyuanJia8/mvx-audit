import { chmod, lstat, mkdtemp, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { MvxError } from './errors.js';

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === ''
    || (relative !== '..'
      && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative));
}

function sharedWritableWithoutSticky(stat) {
  return (stat.mode & 0o022n) !== 0n && (stat.mode & 0o1000n) === 0n;
}

export async function resolvePrivateWorkspaceParent(input, {
  missingMessage,
  unsafeMessage,
  changedMessage,
  missingCode = 'TEMP_NOT_FOUND',
  unsafeCode = 'UNSAFE_TEMP'
}) {
  const absolute = path.resolve(input);
  let initial;
  try {
    initial = await lstat(absolute, { bigint: true });
  } catch (error) {
    throw new MvxError(missingMessage, { code: missingCode, cause: error });
  }
  if (initial.isSymbolicLink() || !initial.isDirectory()) {
    throw new MvxError(unsafeMessage, { code: unsafeCode });
  }
  let canonical;
  let resolved;
  try {
    canonical = await realpath(absolute);
    resolved = await lstat(canonical, { bigint: true });
  } catch (error) {
    throw new MvxError(changedMessage, { code: unsafeCode, cause: error });
  }
  if (!resolved.isDirectory()
    || !sameIdentity(initial, resolved)
    || sharedWritableWithoutSticky(resolved)) {
    throw new MvxError(changedMessage, { code: unsafeCode });
  }
  return Object.freeze({ path: canonical, stat: resolved });
}

export async function createPrivateWorkspace(parent, prefix, {
  changedMessage,
  cleanupMessage,
  forbiddenRoot,
  unsafeCode = 'UNSAFE_TEMP',
  cleanupCode = 'TEMP_CLEANUP_FAILED'
}) {
  let created;
  try {
    created = await mkdtemp(path.join(parent.path, prefix));
  } catch (error) {
    throw new MvxError(changedMessage, { code: unsafeCode, cause: error });
  }
  let canonical;
  try {
    canonical = await realpath(created);
    const [workspaceStat, currentParentStat] = await Promise.all([
      lstat(canonical, { bigint: true }),
      lstat(path.dirname(canonical), { bigint: true })
    ]);
    if (!workspaceStat.isDirectory()
      || !currentParentStat.isDirectory()
      || !sameIdentity(currentParentStat, parent.stat)
      || (forbiddenRoot !== undefined && isWithin(forbiddenRoot, canonical))) {
      throw new MvxError(changedMessage, { code: unsafeCode });
    }
    await chmod(canonical, 0o700);
    return Object.freeze({
      path: canonical,
      stat: workspaceStat,
      parent
    });
  } catch (error) {
    const failure = error instanceof MvxError
      ? error
      : new MvxError(changedMessage, { code: unsafeCode, cause: error });
    if (canonical === undefined) throw failure;
    try {
      await rm(canonical, { recursive: true, force: true });
    } catch (cleanupError) {
      throw new MvxError(cleanupMessage, {
        code: cleanupCode,
        cause: cleanupError
      });
    }
    throw failure;
  }
}

export async function assertPrivateWorkspace(workspace, {
  changedMessage,
  unsafeCode = 'UNSAFE_TEMP'
}) {
  let current;
  let currentParent;
  try {
    [current, currentParent] = await Promise.all([
      lstat(workspace.path, { bigint: true }),
      lstat(path.dirname(workspace.path), { bigint: true })
    ]);
  } catch (error) {
    throw new MvxError(changedMessage, { code: unsafeCode, cause: error });
  }
  if (!current.isDirectory()
    || !currentParent.isDirectory()
    || !sameIdentity(current, workspace.stat)
    || !sameIdentity(currentParent, workspace.parent.stat)) {
    throw new MvxError(changedMessage, { code: unsafeCode });
  }
  return workspace.path;
}

export async function removePrivateWorkspace(workspace, {
  changedMessage,
  cleanupMessage,
  unsafeCode = 'UNSAFE_TEMP',
  cleanupCode = 'TEMP_CLEANUP_FAILED'
}) {
  await assertPrivateWorkspace(workspace, { changedMessage, unsafeCode });
  try {
    await rm(workspace.path, { recursive: true, force: true });
  } catch (error) {
    throw new MvxError(cleanupMessage, { code: cleanupCode, cause: error });
  }
}
