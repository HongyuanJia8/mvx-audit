import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { MvxError } from './errors.js';

const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.html', '.htm', '.json']);
const IGNORED_DIRECTORIES = new Set(['.git', 'node_modules', 'coverage', 'dist', 'vendor']);
const DEFAULT_LIMITS = Object.freeze({ maxFiles: 5_000, maxFileBytes: 2_000_000, maxTotalBytes: 50_000_000 });

async function resolveRoot(inputPath) {
  const absolute = path.resolve(inputPath);
  let stat;
  try {
    stat = await lstat(absolute);
  } catch (error) {
    throw new MvxError(`Input does not exist: ${absolute}`, { code: 'INPUT_NOT_FOUND', cause: error });
  }
  if (stat.isSymbolicLink()) {
    throw new MvxError('The extension root may not be a symbolic link', { code: 'UNSAFE_INPUT' });
  }
  if (stat.isFile()) {
    if (path.basename(absolute) !== 'manifest.json') {
      throw new MvxError('A file input must be named manifest.json', { code: 'INVALID_INPUT' });
    }
    return { root: path.dirname(absolute), manifestPath: absolute };
  }
  if (!stat.isDirectory()) {
    throw new MvxError('Input must be an extension directory or manifest.json', { code: 'INVALID_INPUT' });
  }
  return { root: absolute, manifestPath: path.join(absolute, 'manifest.json') };
}

async function walk(root, current, state, limits) {
  const entries = await readdir(current, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    if (state.fileCount >= limits.maxFiles) {
      throw new MvxError(`Extension contains more than ${limits.maxFiles} files`, { code: 'SCAN_LIMIT' });
    }
    const absolute = path.join(current, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join('/');
    if (entry.isSymbolicLink()) {
      state.warnings.push(`Skipped symbolic link: ${relative}`);
      continue;
    }
    if (entry.isDirectory()) {
      if (!IGNORED_DIRECTORIES.has(entry.name)) await walk(root, absolute, state, limits);
      continue;
    }
    if (!entry.isFile()) continue;
    state.fileCount += 1;
    if (relative === 'manifest.json' || !SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
    const stat = await lstat(absolute);
    if (stat.size > limits.maxFileBytes) {
      state.warnings.push(`Skipped file larger than ${limits.maxFileBytes} bytes: ${relative}`);
      continue;
    }
    state.totalBytes += stat.size;
    if (state.totalBytes > limits.maxTotalBytes) {
      throw new MvxError(`Scannable source exceeds ${limits.maxTotalBytes} bytes`, { code: 'SCAN_LIMIT' });
    }
    state.sources.push({ path: relative, content: await readFile(absolute, 'utf8') });
  }
}

export async function loadExtension(inputPath, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const { root, manifestPath } = await resolveRoot(inputPath);
  let manifestSource;
  try {
    manifestSource = await readFile(manifestPath, 'utf8');
  } catch (error) {
    throw new MvxError(`Cannot read manifest: ${manifestPath}`, { code: 'MANIFEST_NOT_FOUND', cause: error });
  }
  if (Buffer.byteLength(manifestSource) > limits.maxFileBytes) {
    throw new MvxError('manifest.json exceeds the per-file scan limit', { code: 'SCAN_LIMIT' });
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestSource);
  } catch (error) {
    throw new MvxError(`Invalid JSON in ${manifestPath}: ${error.message}`, { code: 'INVALID_MANIFEST', cause: error });
  }
  if (!manifest || Array.isArray(manifest) || typeof manifest !== 'object') {
    throw new MvxError('manifest.json must contain a JSON object', { code: 'INVALID_MANIFEST' });
  }
  const state = { fileCount: 0, totalBytes: 0, sources: [], warnings: [] };
  await walk(root, root, state, limits);
  return {
    root: await realpath(root),
    manifest,
    manifestSource,
    sources: state.sources,
    metadata: {
      filesVisited: state.fileCount,
      sourceFilesScanned: state.sources.length,
      sourceBytesScanned: state.totalBytes,
      warnings: state.warnings
    }
  };
}

