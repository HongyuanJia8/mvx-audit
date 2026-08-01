import { createHash } from 'node:crypto';
import { lstat, readdir, readlink, realpath } from 'node:fs/promises';
import path from 'node:path';
import { extractEncodedPayloads } from './encoded-payloads.js';
import { MvxError } from './errors.js';
import { executableFormat, packageInventory } from './package.js';
import { readBoundedRegularFile } from './safe-file.js';

const SOURCE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.html', '.htm', '.svg', '.json'
]);
export const SCAN_LIMITS = Object.freeze({
  maxFiles: 5_000,
  maxEntries: 10_000,
  maxDepth: 64,
  maxFileBytes: 10_000_000,
  maxTotalBytes: 50_000_000,
  maxPackageFileBytes: 100_000_000,
  maxPackageBytes: 250_000_000
});
const ANALYSIS_PROFILE = 'mvx-static-v4';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function normalizeScanLimits(options) {
  if (!options || Array.isArray(options) || typeof options !== 'object') {
    throw new MvxError('Scan limits must be an object', { code: 'INVALID_ARGUMENT' });
  }
  const supported = new Set(Object.keys(SCAN_LIMITS));
  const unknown = Object.keys(options).filter((key) => !supported.has(key)).sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown scan limit: ${unknown.join(', ')}`, { code: 'INVALID_ARGUMENT' });
  }
  const limits = {};
  for (const [key, fallback] of Object.entries(SCAN_LIMITS)) {
    const value = Object.hasOwn(options, key) ? options[key] : fallback;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new MvxError(`${key} must be a positive safe integer`, { code: 'INVALID_ARGUMENT' });
    }
    limits[key] = value;
  }
  return limits;
}

function analysisProvenance(manifestBytes, state, limits, inventory, encodedPayloads, context) {
  const manifest = {
    path: 'manifest.json',
    bytes: manifestBytes.length,
    sha256: sha256(manifestBytes)
  };
  const sources = state.sources.map(({ path: sourcePath, bytes, sha256: digest }) => ({
    path: sourcePath,
    bytes,
    sha256: digest
  })).sort((left, right) => compareText(left.path, right.path));
  const layout = state.layout.map(({ path: entryPath, type }) => ({ path: entryPath, type }))
    .sort((left, right) => compareText(left.path, right.path) || compareText(left.type, right.type));
  const packageLayoutSha256 = sha256(JSON.stringify(layout));
  const identity = {
    profile: ANALYSIS_PROFILE,
    manifest,
    packageLayoutSha256,
    packageSha256: inventory.sha256,
    sources,
    limits,
    encodedPayloads: {
      profile: encodedPayloads.profile,
      parserProfiles: encodedPayloads.parserProfiles,
      browserEventHandlerProfile: encodedPayloads.browserEventHandlerProfile,
      limits: encodedPayloads.limits,
      sha256: encodedPayloads.sha256
    },
    rulePacks: context.rulePacks,
    rulePackLimits: context.rulePackLimits
  };
  return { ...identity, sha256: sha256(JSON.stringify(identity)) };
}

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
    const root = path.dirname(absolute);
    const rootStat = await lstat(root);
    if (rootStat.isSymbolicLink()) {
      throw new MvxError('The extension root may not be a symbolic link', { code: 'UNSAFE_INPUT' });
    }
    return { root, manifestPath: absolute };
  }
  if (!stat.isDirectory()) {
    throw new MvxError('Input must be an extension directory or manifest.json', { code: 'INVALID_INPUT' });
  }
  return { root: absolute, manifestPath: path.join(absolute, 'manifest.json') };
}

function fileInventoryEntry(relative, bytes) {
  return {
    path: relative,
    type: 'file',
    bytes: bytes.length,
    sha256: sha256(bytes)
  };
}

async function walk(root, current, state, limits, manifestBytes, depth = 0) {
  if (depth > limits.maxDepth) {
    throw new MvxError(`Extension directory depth exceeds ${limits.maxDepth}`, { code: 'SCAN_LIMIT' });
  }
  const entries = await readdir(current, { withFileTypes: true });
  entries.sort((a, b) => compareText(a.name, b.name));
  for (const entry of entries) {
    state.entryCount += 1;
    if (state.entryCount > limits.maxEntries) throw new MvxError(`Extension contains more than ${limits.maxEntries} entries`, { code: 'SCAN_LIMIT' });
    const absolute = path.join(current, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join('/');
    if (entry.isSymbolicLink()) {
      const target = await readlink(absolute, { encoding: 'buffer' });
      const inventoryEntry = { path: relative, type: 'symlink', targetBytes: target.length, targetSha256: sha256(target) };
      state.layout.push(inventoryEntry);
      state.inventory.push(inventoryEntry);
      state.warnings.push(`Skipped symbolic link: ${relative}`);
      continue;
    }
    if (entry.isDirectory()) {
      const inventoryEntry = { path: relative, type: 'directory' };
      state.layout.push(inventoryEntry);
      state.inventory.push(inventoryEntry);
      await walk(root, absolute, state, limits, manifestBytes, depth + 1);
      continue;
    }
    if (!entry.isFile()) {
      const inventoryEntry = { path: relative, type: 'other' };
      state.layout.push(inventoryEntry);
      state.inventory.push(inventoryEntry);
      state.warnings.push(`Skipped non-regular filesystem entry: ${relative}`);
      continue;
    }
    if (state.fileCount >= limits.maxFiles) throw new MvxError(`Extension contains more than ${limits.maxFiles} files`, { code: 'SCAN_LIMIT' });
    state.fileCount += 1;
    state.files.push(relative);
    const source = relative !== 'manifest.json' && SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase());
    const maxBytes = source ? Math.min(limits.maxFileBytes, limits.maxPackageFileBytes) : limits.maxPackageFileBytes;
    const bytes = relative === 'manifest.json' ? manifestBytes : await readBoundedRegularFile(absolute, {
      maxBytes,
      label: `${source ? 'Source file' : 'Package file'} ${relative}`,
      missingCode: 'INVALID_INPUT'
    });
    if (state.packageBytes + bytes.length > limits.maxPackageBytes) {
      throw new MvxError(`Package content exceeds ${limits.maxPackageBytes} bytes`, { code: 'SCAN_LIMIT' });
    }
    state.packageBytes += bytes.length;
    const inventoryEntry = fileInventoryEntry(relative, bytes);
    state.layout.push({ path: relative, type: 'file' });
    state.inventory.push(inventoryEntry);
    const format = executableFormat(bytes);
    if (format) state.executableFiles.push({ ...inventoryEntry, format });
    if (!source) continue;
    if (state.totalBytes + bytes.length > limits.maxTotalBytes) {
      throw new MvxError(`Scannable source exceeds ${limits.maxTotalBytes} bytes`, { code: 'SCAN_LIMIT' });
    }
    state.totalBytes += bytes.length;
    state.sources.push({ path: relative, content: bytes.toString('utf8'), bytes: bytes.length, sha256: inventoryEntry.sha256 });
  }
}

export async function loadExtension(inputPath, options = {}, context = { rulePacks: [], rulePackLimits: {} }) {
  const limits = normalizeScanLimits(options);
  const { root, manifestPath } = await resolveRoot(inputPath);
  let manifestStat;
  try {
    manifestStat = await lstat(manifestPath);
  } catch (error) {
    throw new MvxError(`Cannot read manifest: ${manifestPath}`, { code: 'MANIFEST_NOT_FOUND', cause: error });
  }
  if (manifestStat.isSymbolicLink()) throw new MvxError('manifest.json may not be a symbolic link', { code: 'UNSAFE_INPUT' });
  if (!manifestStat.isFile()) throw new MvxError('manifest.json must be a regular file', { code: 'UNSAFE_INPUT' });
  const manifestBytes = await readBoundedRegularFile(manifestPath, {
    maxBytes: Math.min(limits.maxFileBytes, limits.maxPackageFileBytes),
    label: 'manifest.json',
    missingCode: 'MANIFEST_NOT_FOUND'
  });
  const manifestSource = manifestBytes.toString('utf8');
  let manifest;
  try {
    manifest = JSON.parse(manifestSource);
  } catch (error) {
    throw new MvxError(`Invalid JSON in ${manifestPath}: ${error.message}`, { code: 'INVALID_MANIFEST', cause: error });
  }
  if (!manifest || Array.isArray(manifest) || typeof manifest !== 'object') {
    throw new MvxError('manifest.json must contain a JSON object', { code: 'INVALID_MANIFEST' });
  }
  const state = {
    entryCount: 0,
    fileCount: 0,
    totalBytes: 0,
    packageBytes: 0,
    files: [],
    sources: [],
    warnings: [],
    layout: [],
    inventory: [],
    executableFiles: []
  };
  await walk(root, root, state, limits, manifestBytes);
  const inventory = packageInventory(state.inventory);
  const encodedPayloads = extractEncodedPayloads(
    state.sources.filter((source) => !/\.json$/i.test(source.path))
  );
  return {
    root: await realpath(root),
    manifest,
    manifestSource,
    files: state.files,
    sources: state.sources,
    executableFiles: state.executableFiles,
    inventory,
    encodedPayloads,
    decodedSources: encodedPayloads.decodedSources,
    provenance: analysisProvenance(
      manifestBytes, state, limits, inventory, encodedPayloads, context
    ),
    metadata: {
      filesVisited: state.fileCount,
      entriesVisited: state.entryCount,
      sourceFilesScanned: state.sources.length,
      sourceBytesScanned: state.totalBytes,
      packageFilesHashed: inventory.fileCount,
      packageBytesHashed: inventory.totalBytes,
      encodedPayloadCandidateChars: encodedPayloads.candidateEncodedChars,
      encodedPayloadParserTokens: encodedPayloads.parserTokens,
      encodedPayloadAstNodes: encodedPayloads.astNodes,
      encodedPayloadHtmlTokens: encodedPayloads.htmlTokens,
      encodedPayloadHtmlAttributes: encodedPayloads.htmlAttributes,
      encodedPayloadHtmlNodes: encodedPayloads.htmlNodes,
      encodedPayloadHtmlTreeWork: encodedPayloads.htmlTreeWork,
      encodedPayloadHtmlMaxDepth: encodedPayloads.htmlMaxDepth,
      encodedPayloadHtmlMaxDocumentDepth: encodedPayloads.htmlMaxDocumentDepth,
      encodedPayloadHtmlNestedChars: encodedPayloads.htmlNestedChars,
      encodedPayloadsDecoded: encodedPayloads.decodedCount,
      encodedPayloadBytesDecoded: encodedPayloads.totalDecodedBytes,
      warnings: state.warnings,
      limits
    }
  };
}
