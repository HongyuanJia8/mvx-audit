import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, open, readFile, realpath, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { MvxError } from './errors.js';

const DEFAULT_MAX_BYTES = 25_000_000;
const HARD_MAX_BYTES = 100_000_000;
const DEFAULT_BATCH_LIMIT = 100;
const DEFAULT_BATCH_BYTES = 250_000_000;
const HARD_BATCH_BYTES = 10_000_000_000;
const ALLOWED_HOSTS = new Set([
  'raw.githubusercontent.com',
  'media.githubusercontent.com',
  'objects.githubusercontent.com'
]);

async function ensureSafeDirectory(directory) {
  const absolute = path.resolve(directory);
  try {
    const existing = await lstat(absolute);
    if (existing.isSymbolicLink() || !existing.isDirectory()) {
      throw new MvxError(`Quarantine path is not a safe directory: ${absolute}`, { code: 'UNSAFE_QUARANTINE' });
    }
  } catch (error) {
    if (error instanceof MvxError) throw error;
    if (error.code !== 'ENOENT') throw error;
    await mkdir(absolute, { recursive: true, mode: 0o700 });
    const created = await lstat(absolute);
    if (created.isSymbolicLink() || !created.isDirectory()) {
      throw new MvxError(`Quarantine path is not a safe directory: ${absolute}`, { code: 'UNSAFE_QUARANTINE' });
    }
  }
  return realpath(absolute);
}

async function digestFile(filePath) {
  const sha256 = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(filePath)) {
    size += chunk.length;
    sha256.update(chunk);
  }
  return { size, sha256: sha256.digest('hex') };
}

function rawArtifactUrl(record, artifact, source) {
  if (artifact.provider !== 'gherardo-crx' || source.id !== 'gherardo-crx') {
    throw new MvxError('Artifact provider is not supported for download', { code: 'UNSUPPORTED_PROVIDER' });
  }
  const encodedPath = artifact.path.split('/').map(encodeURIComponent).join('/');
  return `https://raw.githubusercontent.com/GherardoFiori/MaliciousBrowserExtensions/${source.ref}/${encodedPath}`;
}

async function fetchAllowed(url, fetcher) {
  let current = new URL(url);
  for (let redirects = 0; redirects <= 3; redirects += 1) {
    if (current.protocol !== 'https:' || !ALLOWED_HOSTS.has(current.hostname)) {
      throw new MvxError(`Download host is not allowlisted: ${current.hostname}`, { code: 'UNSAFE_DOWNLOAD' });
    }
    const response = await fetcher(current, {
      redirect: 'manual',
      headers: { 'User-Agent': 'mvx-audit-quarantine-fetcher' }
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location || redirects === 3) throw new MvxError('Artifact redirect chain is invalid', { code: 'UNSAFE_DOWNLOAD' });
      current = new URL(location, current);
      continue;
    }
    if (!response.ok || !response.body) {
      throw new MvxError(`Artifact download failed: HTTP ${response.status}`, { code: 'SAMPLE_FETCH_FAILED' });
    }
    return { response, url: current.href };
  }
  throw new MvxError('Artifact redirect chain is invalid', { code: 'UNSAFE_DOWNLOAD' });
}

export function planSample(record, sources) {
  if (!record || !Array.isArray(record.artifacts)) throw new MvxError('Intelligence record has no artifact index', { code: 'SAMPLE_NOT_AVAILABLE' });
  const source = sources.find((entry) => entry.id === 'gherardo-crx');
  if (!source) throw new MvxError('Artifact source metadata is missing', { code: 'SAMPLE_NOT_AVAILABLE' });
  const artifacts = record.artifacts.map((artifact, index) => ({
    index,
    path: artifact.path,
    bytes: artifact.size,
    reportedSha256: artifact.reportedSha256 ?? null,
    gitBlobSha: artifact.gitBlobSha,
    downloadable: true,
    url: rawArtifactUrl(record, artifact, source)
  }));
  return { extensionId: record.extensionId, source: source.id, ref: source.ref, artifacts };
}

export function samplePlanToText(plan) {
  const rows = plan.artifacts.map((artifact) =>
    `  [${artifact.index}] ${artifact.bytes} bytes  reported SHA-256 ${artifact.reportedSha256 ?? 'UNAVAILABLE'}  ${artifact.path}`
  );
  return [
    `Extension: ${plan.extensionId}`,
    `Pinned source: ${plan.source} @ ${plan.ref}`,
    'Artifacts:',
    ...rows,
    '',
    'The actual SHA-256 is computed after Git blob and size verification. Fetching requires --acknowledge-risk.'
  ].join('\n') + '\n';
}

function recordPriority(record) {
  if (record.labels?.includes('behavior-confirmed-malicious')) return 0;
  if (record.labels?.includes('malware')) return 1;
  if (record.labels?.includes('reported-malicious')) return 2;
  return 3;
}

export function planSampleBatch(records, sources, options = {}) {
  const limit = options.limit ?? DEFAULT_BATCH_LIMIT;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxTotalBytes = options.maxTotalBytes ?? DEFAULT_BATCH_BYTES;
  const label = options.label;
  if (!Array.isArray(records)) throw new MvxError('Batch planning requires intelligence records', { code: 'INVALID_ARGUMENT' });
  if (!Number.isSafeInteger(limit) || limit <= 0 || limit > 10_000) throw new MvxError('Batch limit must be between 1 and 10000', { code: 'INVALID_ARGUMENT' });
  if (!Number.isSafeInteger(maxTotalBytes) || maxTotalBytes <= 0 || maxTotalBytes > HARD_BATCH_BYTES) {
    throw new MvxError(`Batch byte budget must be between 1 and ${HARD_BATCH_BYTES}`, { code: 'INVALID_ARGUMENT' });
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > HARD_MAX_BYTES) {
    throw new MvxError(`maxBytes must be between 1 and ${HARD_MAX_BYTES}`, { code: 'INVALID_ARGUMENT' });
  }
  if (label !== undefined && (typeof label !== 'string' || label.length === 0)) {
    throw new MvxError('Batch label must be a non-empty string', { code: 'INVALID_ARGUMENT' });
  }
  const candidates = records
    .filter((record) => !label || record.labels?.includes(label))
    .flatMap((record) => {
      let plan;
      try { plan = planSample(record, sources); } catch { return []; }
      const artifact = [...plan.artifacts]
        .filter((entry) => entry.bytes <= maxBytes)
        .sort((a, b) => a.bytes - b.bytes || a.path.localeCompare(b.path))[0];
      return artifact ? [{ extensionId: record.extensionId, labels: record.labels ?? [], priority: recordPriority(record), artifact }] : [];
    })
    .sort((a, b) => a.priority - b.priority || a.artifact.bytes - b.artifact.bytes || a.extensionId.localeCompare(b.extensionId));
  const selections = [];
  let totalBytes = 0;
  for (const candidate of candidates) {
    if (selections.length >= limit) break;
    if (totalBytes + candidate.artifact.bytes > maxTotalBytes) continue;
    selections.push({ extensionId: candidate.extensionId, labels: candidate.labels, artifact: candidate.artifact });
    totalBytes += candidate.artifact.bytes;
  }
  return {
    schemaVersion: 1,
    source: 'gherardo-crx',
    label: label ?? null,
    limits: { count: limit, maxArtifactBytes: maxBytes, maxTotalBytes },
    availableCandidates: candidates.length,
    selected: selections.length,
    totalBytes,
    selections
  };
}

export function sampleBatchPlanToText(plan) {
  return [
    'Quarantine batch plan',
    `Source: ${plan.source}`,
    `Label filter: ${plan.label ?? 'none'}`,
    `Eligible artifacts: ${plan.availableCandidates}`,
    `Selected: ${plan.selected}`,
    `Pinned bytes: ${plan.totalBytes}`,
    '',
    ...plan.selections.map((entry) => `  ${entry.extensionId}  ${entry.artifact.bytes} bytes  ${entry.labels.join(',')}`),
    '',
    'Planning does not download or execute extension code.'
  ].join('\n') + '\n';
}

export async function fetchSampleBatch({ records, sources, quarantineDir, limit, maxBytes, maxTotalBytes, label, acknowledgeRisk, fetcher = fetch }) {
  if (!acknowledgeRisk) throw new MvxError('Refusing live malware batch download without --acknowledge-risk', { code: 'RISK_ACK_REQUIRED' });
  const plan = planSampleBatch(records, sources, { limit, maxBytes, maxTotalBytes, label });
  const byId = new Map(records.map((record) => [record.extensionId, record]));
  const fetched = [];
  const failures = [];
  for (const selection of plan.selections) {
    try {
      fetched.push(await fetchSample({
        record: byId.get(selection.extensionId),
        sources,
        artifactIndex: selection.artifact.index,
        quarantineDir,
        maxBytes: plan.limits.maxArtifactBytes,
        acknowledgeRisk: true,
        fetcher
      }));
    } catch (error) {
      failures.push({ extensionId: selection.extensionId, code: error.code ?? 'UNEXPECTED_ERROR', message: error.message });
    }
  }
  return { schemaVersion: 1, plan, fetched, failures, complete: failures.length === 0 };
}

export async function fetchSample({
  record,
  sources,
  artifactIndex = 0,
  quarantineDir = 'quarantine',
  maxBytes = DEFAULT_MAX_BYTES,
  acknowledgeRisk = false,
  fetcher = fetch
}) {
  if (!acknowledgeRisk) {
    throw new MvxError('Refusing live malware download without --acknowledge-risk', { code: 'RISK_ACK_REQUIRED' });
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > HARD_MAX_BYTES) {
    throw new MvxError(`maxBytes must be between 1 and ${HARD_MAX_BYTES}`, { code: 'INVALID_ARGUMENT' });
  }
  const plan = planSample(record, sources);
  const artifact = plan.artifacts[artifactIndex];
  if (!artifact) throw new MvxError(`Artifact index ${artifactIndex} does not exist`, { code: 'INVALID_ARGUMENT' });
  if (artifact.bytes > maxBytes) throw new MvxError(`Artifact exceeds the ${maxBytes}-byte download limit`, { code: 'SAMPLE_LIMIT' });

  const root = await ensureSafeDirectory(quarantineDir);
  const extensionDirectory = path.join(root, record.extensionId);
  await mkdir(extensionDirectory, { recursive: true, mode: 0o700 });
  const extensionStat = await lstat(extensionDirectory);
  if (extensionStat.isSymbolicLink() || !extensionStat.isDirectory()) {
    throw new MvxError('Extension quarantine directory is unsafe', { code: 'UNSAFE_QUARANTINE' });
  }
  const pointer = path.join(extensionDirectory, `${artifact.gitBlobSha}.json`);
  try {
    const pointerStat = await lstat(pointer);
    if (pointerStat.isSymbolicLink() || !pointerStat.isFile() || pointerStat.size > 10_000) {
      throw new MvxError('Existing quarantine pointer is unsafe', { code: 'UNSAFE_QUARANTINE' });
    }
    const metadata = JSON.parse(await readFile(pointer, 'utf8'));
    if (metadata.gitBlobSha !== artifact.gitBlobSha || metadata.bytes !== artifact.bytes || !/^[a-f0-9]{64}$/.test(metadata.sha256 ?? '')) {
      throw new MvxError('Existing quarantine pointer does not match the pinned artifact', { code: 'SAMPLE_CHECKSUM' });
    }
    const target = path.join(extensionDirectory, `${metadata.sha256}.crx`);
    const existing = await lstat(target);
    if (existing.isSymbolicLink() || !existing.isFile()) throw new MvxError('Existing quarantine target is unsafe', { code: 'UNSAFE_QUARANTINE' });
    const digest = await digestFile(target);
    if (digest.sha256 !== metadata.sha256 || digest.size !== artifact.bytes) {
      throw new MvxError('Existing quarantine file does not match the pinned artifact', { code: 'SAMPLE_CHECKSUM' });
    }
    return {
      extensionId: record.extensionId,
      path: target,
      bytes: digest.size,
      sha256: digest.sha256,
      reportedSha256: artifact.reportedSha256,
      reportedSha256Match: artifact.reportedSha256 ? artifact.reportedSha256 === digest.sha256 : null,
      gitBlobSha: artifact.gitBlobSha,
      cached: true,
      sourceUrl: artifact.url
    };
  } catch (error) {
    if (error instanceof MvxError) throw error;
    if (error instanceof SyntaxError) throw new MvxError('Existing quarantine pointer is invalid JSON', { code: 'SAMPLE_CHECKSUM', cause: error });
    if (error.code !== 'ENOENT') throw error;
  }

  const temporary = path.join(extensionDirectory, `.${artifact.gitBlobSha}.${randomUUID()}.partial`);
  let handle;
  try {
    const { response, url } = await fetchAllowed(artifact.url, fetcher);
    const contentLength = Number.parseInt(response.headers.get('content-length') ?? '', 10);
    if (Number.isFinite(contentLength) && (contentLength > maxBytes || contentLength !== artifact.bytes)) {
      throw new MvxError('Artifact Content-Length does not match the pinned size', { code: 'SAMPLE_CHECKSUM' });
    }
    handle = await open(temporary, 'wx', 0o600);
    const sha256 = createHash('sha256');
    const sha1 = createHash('sha1');
    sha1.update(`blob ${artifact.bytes}\0`);
    let bytes = 0;
    const reader = response.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      bytes += chunk.length;
      if (bytes > maxBytes || bytes > artifact.bytes) throw new MvxError('Artifact exceeded its pinned size while downloading', { code: 'SAMPLE_LIMIT' });
      sha256.update(chunk);
      sha1.update(chunk);
      await handle.write(chunk);
    }
    await handle.sync();
    await handle.close();
    handle = null;
    const actualSha256 = sha256.digest('hex');
    const actualGitBlob = sha1.digest('hex');
    if (bytes !== artifact.bytes || actualGitBlob !== artifact.gitBlobSha) {
      throw new MvxError('Downloaded artifact failed size or checksum verification', { code: 'SAMPLE_CHECKSUM' });
    }
    const target = path.join(extensionDirectory, `${actualSha256}.crx`);
    try {
      const existing = await lstat(target);
      if (existing.isSymbolicLink() || !existing.isFile()) throw new MvxError('Existing quarantine target is unsafe', { code: 'UNSAFE_QUARANTINE' });
      const digest = await digestFile(target);
      if (digest.sha256 !== actualSha256 || digest.size !== bytes) throw new MvxError('Existing quarantine target has conflicting content', { code: 'SAMPLE_CHECKSUM' });
      await unlink(temporary);
    } catch (error) {
      if (error instanceof MvxError) throw error;
      if (error.code !== 'ENOENT') throw error;
      await rename(temporary, target);
    }
    const targetStat = await stat(target);
    if (!targetStat.isFile() || targetStat.size !== bytes) throw new MvxError('Quarantine write verification failed', { code: 'SAMPLE_CHECKSUM' });
    const metadata = {
      schemaVersion: 1,
      extensionId: record.extensionId,
      bytes,
      sha256: actualSha256,
      reportedSha256: artifact.reportedSha256 ?? null,
      reportedSha256Match: artifact.reportedSha256 ? artifact.reportedSha256 === actualSha256 : null,
      gitBlobSha: actualGitBlob,
      sourceUrl: url,
      sourceRef: plan.ref
    };
    let pointerHandle;
    try {
      pointerHandle = await open(pointer, 'wx', 0o600);
      await pointerHandle.writeFile(`${JSON.stringify(metadata, null, 2)}\n`, 'utf8');
      await pointerHandle.sync();
      await pointerHandle.close();
      pointerHandle = null;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    } finally {
      if (pointerHandle) await pointerHandle.close().catch(() => {});
    }
    return { ...metadata, path: target, cached: false };
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await unlink(temporary).catch((unlinkError) => {
      if (unlinkError.code !== 'ENOENT') throw unlinkError;
    });
    throw error;
  }
}

export { DEFAULT_BATCH_BYTES, DEFAULT_BATCH_LIMIT, DEFAULT_MAX_BYTES, HARD_BATCH_BYTES, HARD_MAX_BYTES };
