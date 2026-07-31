import { chmod, lstat, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { auditExtension } from './analyzer.js';
import { prepareDirectorySnapshot } from './audit-verification.js';
import { MvxError } from './errors.js';
import { loadLabScenario } from './lab.js';
import { assertOptionsObject } from './options.js';
import {
  assertPrivateWorkspace, removePrivateWorkspace
} from './private-workspace.js';

const SNAPSHOTS = new WeakMap();

function sanitizeSnapshotError(error, workspace) {
  if (!workspace || typeof error?.message !== 'string' || !error.message.includes(workspace)) return error;
  const message = error.message.split(workspace).join('<private lab snapshot>');
  if (error instanceof MvxError) return new MvxError(message, { code: error.code });
  const sanitized = new Error(message);
  sanitized.name = error?.name ?? 'Error';
  if (error?.code !== undefined) sanitized.code = error.code;
  return sanitized;
}

async function assertExtensionDirectoryInput(input) {
  if (typeof input !== 'string' || input.length === 0) {
    throw new MvxError('Lab extension path must be a non-empty string', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const absolute = path.resolve(input);
  let stat;
  try { stat = await lstat(absolute); } catch (error) {
    throw new MvxError('Lab extension does not exist', {
      code: 'LAB_INPUT_NOT_FOUND',
      cause: error
    });
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new MvxError('Lab extension must be a real directory', {
      code: 'UNSAFE_LAB_INPUT'
    });
  }
}

function mapLabSnapshotError(error) {
  if (!(error instanceof MvxError)) return error;
  const mapped = {
    AUDIT_SNAPSHOT_CLEANUP_FAILED: 'LAB_SNAPSHOT_CLEANUP_FAILED',
    AUDIT_SNAPSHOT_FAILED: 'LAB_SNAPSHOT_FAILED',
    INPUT_NOT_FOUND: 'LAB_INPUT_NOT_FOUND',
    INVALID_INPUT: 'UNSAFE_LAB_INPUT',
    SCAN_LIMIT: 'LAB_LIMIT',
    TEMP_NOT_FOUND: 'LAB_INPUT_NOT_FOUND',
    UNSAFE_INPUT: 'UNSAFE_LAB_INPUT',
    UNSAFE_TEMP: 'UNSAFE_LAB_INPUT'
  }[error.code];
  if (!mapped) return error;
  const message = error.message
    .replaceAll('Audit verification', 'Lab execution')
    .replaceAll('Audit snapshot', 'Lab snapshot')
    .replaceAll('audit snapshot', 'lab snapshot')
    .replaceAll('Private audit', 'Private lab');
  return new MvxError(message, { code: mapped, cause: error });
}

export async function assertLabTreeHasNoLinks(root) {
  let visited = 0;
  async function visit(directory, depth) {
    if (depth > 64) throw new MvxError('Extension tree exceeds 64 directory levels', { code: 'LAB_LIMIT' });
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      visited += 1;
      if (visited > 10_000) throw new MvxError('Extension tree exceeds 10000 entries', { code: 'LAB_LIMIT' });
      const child = path.join(directory, entry.name);
      const childStat = await lstat(child);
      if (childStat.isSymbolicLink()) throw new MvxError(`Extension tree contains a symbolic link: ${child}`, { code: 'UNSAFE_LAB_INPUT' });
      if (childStat.isDirectory()) await visit(child, depth + 1);
      else if (!childStat.isFile()) throw new MvxError(`Extension tree contains a special file: ${child}`, { code: 'UNSAFE_LAB_INPUT' });
    }
  }
  await visit(root, 0);
}

async function makeLabTreeMountReadable(root) {
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const child = path.join(directory, entry.name);
      if (entry.isDirectory()) await visit(child);
      else await chmod(child, 0o444);
    }
    await chmod(directory, 0o755);
  }
  await visit(root);
}

export async function prepareLabInputSnapshot(extensionPath, scenarioPath, options = {}) {
  assertOptionsObject(options, 'Lab snapshot');
  const unknown = Object.getOwnPropertyNames(options).filter((key) => key !== 'temporaryDirectory');
  if (unknown.length > 0) throw new MvxError(`Unknown lab snapshot option: ${unknown.sort().join(', ')}`, { code: 'INVALID_ARGUMENT' });
  const temporaryDirectory = Object.getOwnPropertyDescriptor(
    options,
    'temporaryDirectory'
  )?.value;
  if (temporaryDirectory !== undefined
    && (typeof temporaryDirectory !== 'string' || temporaryDirectory.length === 0)) {
    throw new MvxError('temporaryDirectory must be a non-empty string', {
      code: 'INVALID_ARGUMENT'
    });
  }
  await assertExtensionDirectoryInput(extensionPath);
  const { bytes: scenarioBytes } = await loadLabScenario(scenarioPath);
  let prepared;
  try {
    prepared = await prepareDirectorySnapshot(
      extensionPath,
      temporaryDirectory,
      undefined
    );
  } catch (error) {
    throw mapLabSnapshotError(error);
  }
  const workspace = prepared.workspace.path;
  try {
    await assertPrivateWorkspace(prepared.workspace, {
      changedMessage: 'Private lab snapshot workspace changed before analysis'
    });
    await assertLabTreeHasNoLinks(prepared.input);
    await makeLabTreeMountReadable(prepared.input);
    const scenarioSnapshot = path.join(workspace, 'scenario.json');
    await writeFile(scenarioSnapshot, scenarioBytes, { flag: 'wx', mode: 0o444 });
    const audit = await auditExtension(prepared.input);
    const snapshot = Object.freeze({
      workspace,
      extension: prepared.input,
      scenario: scenarioSnapshot,
      scenarioBytes: Buffer.from(scenarioBytes),
      package: audit.package,
      analysis: audit.analysis
    });
    SNAPSHOTS.set(snapshot, prepared.workspace);
    return snapshot;
  } catch (error) {
    const failure = sanitizeSnapshotError(mapLabSnapshotError(error), workspace);
    try {
      await removePrivateWorkspace(prepared.workspace, {
        changedMessage: 'Private lab snapshot workspace changed before cleanup',
        cleanupMessage: 'Private lab snapshot workspace cleanup failed',
        cleanupCode: 'LAB_SNAPSHOT_CLEANUP_FAILED'
      });
    } catch (cleanupError) {
      const cleanup = sanitizeSnapshotError(cleanupError, workspace);
      throw new MvxError(
        `Private lab snapshot cleanup failed after ${failure.code ?? 'snapshot failure'}: ${cleanup.message}`,
        { code: 'LAB_SNAPSHOT_CLEANUP_FAILED' }
      );
    }
    throw failure;
  }
}

export async function removeLabInputSnapshot(snapshot) {
  const workspace = snapshot && SNAPSHOTS.get(snapshot);
  if (!workspace) {
    throw new MvxError('Lab input snapshot is invalid', { code: 'INVALID_ARGUMENT' });
  }
  try {
    await removePrivateWorkspace(workspace, {
      changedMessage: 'Private lab snapshot workspace changed before cleanup',
      cleanupMessage: 'Private lab snapshot workspace cleanup failed',
      cleanupCode: 'LAB_SNAPSHOT_CLEANUP_FAILED'
    });
  } catch (error) {
    const failure = sanitizeSnapshotError(error, workspace.path);
    throw new MvxError(
      `Private lab snapshot cleanup failed; cleanup may be retried after the workspace is restored: ${failure.message}`,
      { code: 'LAB_SNAPSHOT_CLEANUP_FAILED', cause: error }
    );
  }
  SNAPSHOTS.delete(snapshot);
}
