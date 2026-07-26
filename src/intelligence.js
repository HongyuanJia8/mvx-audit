import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MvxError } from './errors.js';

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_INTEL_META_PATH = path.join(PROJECT_ROOT, 'intel/catalog-meta.json');
export const DEFAULT_INTEL_RECORDS_PATH = path.join(PROJECT_ROOT, 'intel/catalog.jsonl');
const EXTENSION_ID = /^[a-p]{32}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MAX_CATALOG_BYTES = 20_000_000;
const MAX_RECORDS = 25_000;

function validateRecord(record, line, ids, hashes, errors) {
  const label = `record line ${line}`;
  if (!record || Array.isArray(record) || typeof record !== 'object') {
    errors.push(`${label}: must be a JSON object`);
    return;
  }
  if (!EXTENSION_ID.test(record.extensionId ?? '')) errors.push(`${label}: invalid extensionId`);
  else if (ids.has(record.extensionId)) errors.push(`${label}: duplicate extensionId ${record.extensionId}`);
  else ids.add(record.extensionId);
  for (const field of ['names', 'stores', 'labels', 'threatTypes', 'sha256', 'provenance', 'artifacts']) {
    if (!Array.isArray(record[field])) errors.push(`${label}: ${field} must be an array`);
  }
  for (const field of ['names', 'stores', 'labels', 'threatTypes']) {
    if (Array.isArray(record[field]) && record[field].some((value) => typeof value !== 'string' || value.length === 0)) {
      errors.push(`${label}: ${field} must contain non-empty strings`);
    }
  }
  if (!['active', 'removed', 'unknown'].includes(record.status)) errors.push(`${label}: invalid status`);
  if (typeof record.ownershipTransfer !== 'boolean') errors.push(`${label}: ownershipTransfer must be boolean`);
  if (!record.verification || Array.isArray(record.verification) || typeof record.verification !== 'object') {
    errors.push(`${label}: verification must be an object`);
  }
  for (const hash of Array.isArray(record.sha256) ? record.sha256 : []) {
    if (!SHA256.test(hash)) errors.push(`${label}: invalid SHA-256`);
    const owners = hashes.get(hash) ?? [];
    owners.push(record.extensionId);
    hashes.set(hash, owners);
  }
  for (const artifact of Array.isArray(record.artifacts) ? record.artifacts : []) {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
      errors.push(`${label}: artifact must be an object`);
      continue;
    }
    if (artifact.provider !== 'gherardo-crx') errors.push(`${label}: unsupported artifact provider`);
    if (typeof artifact.path !== 'string' || !artifact.path.endsWith('.crx') || artifact.path.includes('..')) {
      errors.push(`${label}: unsafe artifact path`);
    }
    if (!Number.isSafeInteger(artifact.size) || artifact.size <= 0) errors.push(`${label}: invalid artifact size`);
    if (!/^[a-f0-9]{40}$/.test(artifact.gitBlobSha ?? '')) errors.push(`${label}: invalid Git blob SHA`);
    if (artifact.reportedSha256 !== undefined && !SHA256.test(artifact.reportedSha256)) errors.push(`${label}: invalid reported artifact SHA-256`);
  }
  for (const provenance of Array.isArray(record.provenance) ? record.provenance : []) {
    if (!provenance || typeof provenance !== 'object' || typeof provenance.provider !== 'string') {
      errors.push(`${label}: invalid provenance`);
    }
  }
}

export async function loadIntelCatalog(options = {}) {
  const metaPath = path.resolve(options.metaPath ?? DEFAULT_INTEL_META_PATH);
  const recordsPath = path.resolve(options.recordsPath ?? DEFAULT_INTEL_RECORDS_PATH);
  let metaSource;
  let recordSource;
  try {
    [metaSource, recordSource] = await Promise.all([readFile(metaPath, 'utf8'), readFile(recordsPath, 'utf8')]);
  } catch (error) {
    throw new MvxError(`Cannot read intelligence catalog: ${error.message}`, { code: 'INTEL_NOT_FOUND', cause: error });
  }
  if (Buffer.byteLength(recordSource) > MAX_CATALOG_BYTES) {
    throw new MvxError(`Intelligence catalog exceeds ${MAX_CATALOG_BYTES} bytes`, { code: 'INTEL_LIMIT' });
  }
  let meta;
  try {
    meta = JSON.parse(metaSource);
  } catch (error) {
    throw new MvxError(`Invalid intelligence metadata JSON: ${error.message}`, { code: 'INVALID_INTEL', cause: error });
  }
  const lines = recordSource.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length > MAX_RECORDS) throw new MvxError(`Intelligence catalog exceeds ${MAX_RECORDS} records`, { code: 'INTEL_LIMIT' });
  const records = lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      throw new MvxError(`Invalid intelligence JSONL at line ${index + 1}: ${error.message}`, { code: 'INVALID_INTEL', cause: error });
    }
  });
  return { meta, records, metaPath, recordsPath };
}

export async function validateIntelCatalog(options = {}) {
  const { meta, records, metaPath, recordsPath } = await loadIntelCatalog(options);
  const errors = [];
  if (!meta || Array.isArray(meta) || typeof meta !== 'object') errors.push('metadata must be a JSON object');
  if (meta?.schemaVersion !== 1) errors.push('metadata schemaVersion must equal 1');
  if (!Array.isArray(meta?.sources) || meta.sources.length === 0) errors.push('metadata sources must be a non-empty array');
  if (!meta?.summary || typeof meta.summary !== 'object') errors.push('metadata summary must be an object');
  const ids = new Set();
  const hashes = new Map();
  records.forEach((record, index) => validateRecord(record, index + 1, ids, hashes, errors));
  if (meta?.summary?.records !== records.length) errors.push('metadata record count does not match JSONL');
  const artifactCount = records.reduce((total, record) => total + (Array.isArray(record.artifacts) ? record.artifacts.length : 0), 0);
  if (meta?.summary?.artifacts !== artifactCount) errors.push('metadata artifact count does not match JSONL');
  const recordsWithSha256 = records.filter((record) => Array.isArray(record.sha256) && record.sha256.length > 0).length;
  if (meta?.summary?.recordsWithSha256 !== recordsWithSha256) errors.push('metadata SHA-256 record count does not match JSONL');
  return {
    valid: errors.length === 0,
    errors,
    metaPath,
    recordsPath,
    summary: meta?.summary ?? null,
    duplicateHashes: [...hashes.entries()].filter(([, owners]) => new Set(owners).size > 1).length
  };
}

export async function lookupIntel(value, options = {}) {
  const query = String(value ?? '').trim().toLowerCase();
  if (!EXTENSION_ID.test(query) && !SHA256.test(query)) {
    throw new MvxError('Lookup requires a 32-character extension ID or 64-character SHA-256', { code: 'INVALID_ARGUMENT' });
  }
  const { records } = await loadIntelCatalog(options);
  return records.filter((record) => record.extensionId === query || (Array.isArray(record.sha256) && record.sha256.includes(query)));
}

export function intelStatsToText(meta) {
  const summary = meta.summary;
  const sourceLines = meta.sources.map((source) => `  ${source.id}: ${source.records} records @ ${source.ref.slice(0, 12)}`);
  return [
    'MVX real-world threat intelligence',
    `Snapshot: ${meta.generatedAt}`,
    `Unique extension IDs: ${summary.records}`,
    `Records with confirmed-malware evidence: ${summary.confirmedMalware}`,
    `Researcher-reported records: ${summary.researcherReported}`,
    `Records explicitly labeled malware: ${summary.malwareLabeled}`,
    `Non-empty CRX artifacts indexed: ${summary.artifacts}`,
    `Extension IDs with SHA-256: ${summary.recordsWithSha256}`,
    `Threat labels: ${summary.labels}`,
    'Sources:',
    ...sourceLines,
    '',
    'Live CRX files are not bundled. Artifact availability is metadata, not permission to execute a sample.'
  ].join('\n') + '\n';
}

export function intelRecordToText(records, query) {
  if (records.length === 0) return `No intelligence match for ${query}\n`;
  return records.map((record) => [
    `Extension: ${record.extensionId}`,
    `Names: ${record.names.join(', ') || 'unknown'}`,
    `Stores: ${record.stores.join(', ') || 'unknown'}`,
    `Labels: ${record.labels.join(', ') || 'unknown'}`,
    `Threat types: ${record.threatTypes.join(', ') || 'unknown'}`,
    `SHA-256: ${record.sha256.join(', ') || 'not available'}`,
    `Artifacts: ${record.artifacts.length}`,
    `Sources: ${record.provenance.map((entry) => entry.provider).join(', ')}`
  ].join('\n')).join('\n\n') + '\n';
}
