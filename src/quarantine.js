import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, open, readFile, realpath, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { MvxError } from './errors.js';

const DEFAULT_MAX_BYTES = 25_000_000;
const HARD_MAX_BYTES = 100_000_000;
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

export { DEFAULT_MAX_BYTES, HARD_MAX_BYTES };
