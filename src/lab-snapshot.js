import { cp, lstat, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { auditExtension } from './analyzer.js';
import { MvxError } from './errors.js';
import { loadLabScenario } from './lab.js';
import { assertOptionsObject } from './options.js';

const SNAPSHOTS = new WeakSet();

function sanitizeSnapshotError(error, workspace) {
  if (!workspace || typeof error?.message !== 'string' || !error.message.includes(workspace)) return error;
  const message = error.message.split(workspace).join('<private lab snapshot>');
  if (error instanceof MvxError) return new MvxError(message, { code: error.code });
  const sanitized = new Error(message);
  sanitized.name = error?.name ?? 'Error';
  if (error?.code !== undefined) sanitized.code = error.code;
  return sanitized;
}

async function realDirectory(input, label) {
  if (typeof input !== 'string' || input.length === 0) {
    throw new MvxError(`${label} path must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
  }
  const absolute = path.resolve(input);
  let stat;
  try { stat = await lstat(absolute); } catch (error) {
    throw new MvxError(`${label} does not exist`, { code: 'LAB_INPUT_NOT_FOUND', cause: error });
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new MvxError(`${label} must be a real directory`, { code: 'UNSAFE_LAB_INPUT' });
  }
  return realpath(absolute);
}

async function realFile(input, label) {
  if (typeof input !== 'string' || input.length === 0) {
    throw new MvxError(`${label} path must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
  }
  const absolute = path.resolve(input);
  let stat;
  try { stat = await lstat(absolute); } catch (error) {
    throw new MvxError(`${label} does not exist`, { code: 'LAB_INPUT_NOT_FOUND', cause: error });
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new MvxError(`${label} must be a real regular file`, { code: 'UNSAFE_LAB_INPUT' });
  }
  return realpath(absolute);
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

export async function prepareLabInputSnapshot(extensionPath, scenarioPath, options = {}) {
  assertOptionsObject(options, 'Lab snapshot');
  const unknown = Object.getOwnPropertyNames(options).filter((key) => key !== 'temporaryDirectory');
  if (unknown.length > 0) throw new MvxError(`Unknown lab snapshot option: ${unknown.sort().join(', ')}`, { code: 'INVALID_ARGUMENT' });
  const [extension, scenario, temporaryParent] = await Promise.all([
    realDirectory(extensionPath, 'Lab extension'),
    realFile(scenarioPath, 'Lab scenario'),
    realDirectory(options.temporaryDirectory ?? os.tmpdir(), 'Lab temporary directory')
  ]);
  await assertLabTreeHasNoLinks(extension);
  const { bytes: scenarioBytes } = await loadLabScenario(scenario);
  const workspace = await mkdtemp(path.join(temporaryParent, 'mvx-lab-input-'));
  try {
    const extensionSnapshot = path.join(workspace, 'extension');
    const scenarioSnapshot = path.join(workspace, 'scenario.json');
    await cp(extension, extensionSnapshot, { recursive: true, dereference: false, errorOnExist: true, force: false });
    await assertLabTreeHasNoLinks(extensionSnapshot);
    await writeFile(scenarioSnapshot, scenarioBytes, { flag: 'wx', mode: 0o400 });
    const audit = await auditExtension(extensionSnapshot);
    const snapshot = Object.freeze({
      workspace,
      extension: extensionSnapshot,
      scenario: scenarioSnapshot,
      scenarioBytes: Buffer.from(scenarioBytes),
      package: audit.package,
      analysis: audit.analysis
    });
    SNAPSHOTS.add(snapshot);
    return snapshot;
  } catch (error) {
    try { await rm(workspace, { recursive: true, force: true }); } catch {}
    throw sanitizeSnapshotError(error, workspace);
  }
}

export async function removeLabInputSnapshot(snapshot) {
  if (!snapshot || !SNAPSHOTS.has(snapshot)) {
    throw new MvxError('Lab input snapshot is invalid', { code: 'INVALID_ARGUMENT' });
  }
  SNAPSHOTS.delete(snapshot);
  try { await rm(snapshot.workspace, { recursive: true, force: true }); } catch (error) {
    throw sanitizeSnapshotError(error, snapshot.workspace);
  }
}
