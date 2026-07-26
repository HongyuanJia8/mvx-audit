#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';
import { parseCsv } from '../src/csv.js';
import { MvxError } from '../src/errors.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE_PATH = path.join(ROOT, 'intel/sources.json');
const META_PATH = path.join(ROOT, 'intel/catalog-meta.json');
const RECORDS_PATH = path.join(ROOT, 'intel/catalog.jsonl');
const EXTENSION_ID = /^[a-p]{32}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MAX_SOURCE_BYTES = 15_000_000;

function unique(values) {
  return [...new Set(values.filter((value) => typeof value === 'string' && value.length > 0))].sort();
}

function minDate(left, right) {
  const values = [left, right].filter((value) => /^\d{4}-\d{2}-\d{2}$/.test(value ?? ''));
  return values.length > 0 ? values.sort()[0] : null;
}

function normalizeStore(value) {
  const store = String(value ?? '').toLowerCase();
  if (store.includes('edge')) return 'edge';
  if (store.includes('chrome')) return 'chrome';
  if (store === 'both') return 'both';
  return 'unknown';
}

function normalizeLabel(value) {
  const label = String(value ?? '').trim().toLowerCase();
  const aliases = new Map([
    ['malware', 'malware'],
    ['adware', 'adware'],
    ['policy violation', 'policy-violation'],
    ['bundling unwanted software', 'potentially-unwanted'],
    ['search hijacking', 'browser-hijack'],
    ['suspicious', 'suspicious'],
    ['removal reason unknown', 'unknown']
  ]);
  return aliases.get(label) ?? (label.replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'unknown');
}

function createRecord(extensionId) {
  return {
    extensionId,
    names: [],
    stores: [],
    labels: [],
    threatTypes: [],
    firstReported: null,
    status: 'unknown',
    ownershipTransfer: false,
    verification: {},
    sha256: [],
    provenance: [],
    artifacts: []
  };
}

function addProvenance(record, entry) {
  const normalized = Object.fromEntries(Object.entries(entry).filter(([, value]) => typeof value === 'string' && value.length > 0));
  const key = JSON.stringify(normalized);
  if (!record.provenance.some((existing) => JSON.stringify(existing) === key)) record.provenance.push(normalized);
}

function parseJson(source, label) {
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new MvxError(`Invalid JSON from ${label}: ${error.message}`, { code: 'INVALID_INTEL_SOURCE', cause: error });
  }
}

async function fetchPinned(file, label, fetcher) {
  const response = await fetcher(file.url, { headers: { 'User-Agent': 'mvx-audit-intelligence-updater' } });
  if (!response.ok) throw new MvxError(`Cannot fetch ${label}: HTTP ${response.status}`, { code: 'INTEL_FETCH_FAILED' });
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_SOURCE_BYTES) throw new MvxError(`${label} exceeds the source size limit`, { code: 'INTEL_LIMIT' });
  if (file.sha256) {
    const actual = createHash('sha256').update(bytes).digest('hex');
    if (actual !== file.sha256) throw new MvxError(`${label} checksum mismatch`, { code: 'INTEL_CHECKSUM' });
  }
  return bytes.toString('utf8');
}

export async function downloadSources(config, fetcher = fetch) {
  const source = (id) => config.sources.find((entry) => entry.id === id);
  const malext = source('malext-sentry');
  const tpci = source('tpci-chrome-mal-ids');
  const gherardo = source('gherardo-crx');
  if (![malext, tpci, gherardo].every(Boolean)) throw new MvxError('Required intelligence source is missing', { code: 'INVALID_INTEL_SOURCE' });
  const [malextCsv, tpciCsv, gherardoJson, gherardoTree] = await Promise.all([
    fetchPinned(malext.files.labels, malext.id, fetcher),
    fetchPinned(tpci.files.labels, tpci.id, fetcher),
    fetchPinned(gherardo.files.metadata, gherardo.id, fetcher),
    fetchPinned(gherardo.files.tree, `${gherardo.id} tree`, fetcher)
  ]);
  return { malextCsv, tpciCsv, gherardoJson, gherardoTree };
}

export function buildIntelCatalog(config, input) {
  const records = new Map();
  const getRecord = (id) => {
    if (!EXTENSION_ID.test(id ?? '')) return null;
    if (!records.has(id)) records.set(id, createRecord(id));
    return records.get(id);
  };
  const malextRows = parseCsv(input.malextCsv);
  const tpciRows = parseCsv(input.tpciCsv);
  const gherardo = parseJson(input.gherardoJson, 'gherardo-crx metadata');
  const tree = parseJson(input.gherardoTree, 'gherardo-crx tree');

  for (const row of malextRows) {
    const record = getRecord(row.extension_id);
    if (!record) continue;
    if (row.name && row.name !== 'UNKNOWN') record.names.push(row.name);
    record.stores.push(normalizeStore(row.store));
    record.labels.push(normalizeLabel(row.reason));
    record.firstReported = minDate(record.firstReported, row.insert_date_fmt);
    addProvenance(record, { provider: 'malext-sentry', source: row.source });
  }

  for (const row of tpciRows) {
    const record = getRecord(row.EXTID);
    if (!record) continue;
    if (row['EXTID-NAME'] && row['EXTID-NAME'] !== 'UNKNOWN') record.names.push(row['EXTID-NAME']);
    record.stores.push(normalizeStore(row.BROWSER));
    record.firstReported = minDate(record.firstReported, row['DATE-DIS'] === 'UNKNOWN' ? null : row['DATE-DIS']);
    record.ownershipTransfer ||= row['OWNERSHIP-TRANSFER'] === '1';
    if (row['STILL-ACTIVE'] === '1') record.status = 'active';
    else if (row['STILL-ACTIVE'] === '0' && record.status !== 'active') record.status = 'removed';
    const confirmLevel = Number.parseInt(row['CONFIRM-MAL'], 10);
    const verifyLevel = Number.parseInt(row['TPCI-VERIFY'], 10);
    if (Number.isInteger(confirmLevel)) record.verification.tpciConfirmation = Math.max(record.verification.tpciConfirmation ?? 0, confirmLevel);
    if (Number.isInteger(verifyLevel)) record.verification.tpciVerification = Math.max(record.verification.tpciVerification ?? 0, verifyLevel);
    if (row['REPORTED-MAL'] === '1') {
      record.verification.researcherReported = true;
      record.labels.push('reported-malicious');
    }
    if (confirmLevel >= 2) record.labels.push('google-confirmed-malware');
    const behavioral = String(row['TPCI-BEHAVIORAL'] ?? '').toLowerCase();
    if (['malicious', 'suspicious', 'elevated', 'clean'].includes(behavioral)) record.verification.behavioral = behavioral;
    if (behavioral === 'malicious') record.labels.push('behavior-confirmed-malicious');
    record.threatTypes.push(...String(row['THREAT-TYPE'] ?? '').split(',').map(normalizeLabel));
    if (SHA256.test(row['TPCI-CRX-HASH'] ?? '')) record.sha256.push(row['TPCI-CRX-HASH']);
    addProvenance(record, { provider: 'tpci-chrome-mal-ids', source: row.SOURCE, article: row.ARTICLE });
  }

  const hashesById = new Map();
  for (const entry of Array.isArray(gherardo.extensions) ? gherardo.extensions : []) {
    const record = getRecord(entry.extension_id);
    if (!record) continue;
    record.labels.push('reported-malicious');
    record.firstReported = minDate(record.firstReported, entry.date_reported === 'null' ? entry.date_added : entry.date_reported);
    if (SHA256.test(entry.crx_sha256 ?? '')) {
      record.sha256.push(entry.crx_sha256);
      const hashes = hashesById.get(entry.extension_id) ?? new Set();
      hashes.add(entry.crx_sha256);
      hashesById.set(entry.extension_id, hashes);
    }
    addProvenance(record, {
      provider: 'gherardo-crx',
      source: entry.source_url === 'null' ? 'https://github.com/GherardoFiori/MaliciousBrowserExtensions' : entry.source_url
    });
  }

  let artifactCount = 0;
  let artifactBytes = 0;
  for (const blob of Array.isArray(tree.tree) ? tree.tree : []) {
    if (blob?.type !== 'blob' || typeof blob.path !== 'string' || !blob.path.endsWith('.crx') || !Number.isSafeInteger(blob.size) || blob.size <= 0) continue;
    const extensionId = path.basename(blob.path, '.crx');
    const record = getRecord(extensionId);
    if (!record || !/^[a-f0-9]{40}$/.test(blob.sha ?? '')) continue;
    const hashes = [...(hashesById.get(extensionId) ?? [])];
    record.labels.push('artifact-available');
    record.artifacts.push({
      provider: 'gherardo-crx',
      path: blob.path,
      size: blob.size,
      gitBlobSha: blob.sha,
      ...(hashes.length === 1 ? { reportedSha256: hashes[0] } : {})
    });
    artifactCount += 1;
    artifactBytes += blob.size;
  }

  const normalized = [...records.values()].map((record) => ({
    ...record,
    names: unique(record.names),
    stores: unique(record.stores),
    labels: unique(record.labels),
    threatTypes: unique(record.threatTypes.filter((value) => value !== 'unknown')),
    sha256: unique(record.sha256),
    provenance: record.provenance.sort((left, right) => `${left.provider}:${left.source ?? ''}`.localeCompare(`${right.provider}:${right.source ?? ''}`)),
    artifacts: record.artifacts.sort((left, right) => left.path.localeCompare(right.path))
  })).sort((left, right) => left.extensionId.localeCompare(right.extensionId));
  const labels = unique(normalized.flatMap((record) => record.labels));
  const labelCounts = Object.fromEntries(labels.map((label) => [
    label,
    normalized.filter((record) => record.labels.includes(label)).length
  ]));
  const confirmedMalware = normalized.filter((record) =>
    record.labels.includes('google-confirmed-malware') || record.labels.includes('behavior-confirmed-malicious')
  ).length;
  const sourceCounts = {
    'malext-sentry': malextRows.length,
    'tpci-chrome-mal-ids': tpciRows.length,
    'gherardo-crx': Array.isArray(gherardo.extensions) ? gherardo.extensions.length : 0
  };
  const meta = {
    schemaVersion: 1,
    generatedAt: config.snapshotDate,
    sources: config.sources.map((source) => ({
      id: source.id,
      name: source.name,
      repository: source.repository,
      license: source.license,
      ref: source.ref,
      records: sourceCounts[source.id]
    })),
    summary: {
      records: normalized.length,
      confirmedMalware,
      researcherReported: normalized.filter((record) => record.verification.researcherReported === true).length,
      malwareLabeled: normalized.filter((record) => record.labels.includes('malware')).length,
      artifacts: artifactCount,
      artifactBytes,
      recordsWithSha256: normalized.filter((record) => record.sha256.length > 0).length,
      labels: labels.length,
      labelCounts
    }
  };
  return { meta, records: normalized };
}

export function serializeCatalog(catalog) {
  return {
    meta: `${JSON.stringify(catalog.meta, null, 2)}\n`,
    records: `${catalog.records.map((record) => JSON.stringify(record)).join('\n')}\n`
  };
}

export async function updateIntelligence({ check = false, fetcher = fetch } = {}) {
  const config = parseJson(await readFile(SOURCE_PATH, 'utf8'), 'intel/sources.json');
  const catalog = buildIntelCatalog(config, await downloadSources(config, fetcher));
  const output = serializeCatalog(catalog);
  if (check) {
    const [currentMeta, currentRecords] = await Promise.all([readFile(META_PATH, 'utf8'), readFile(RECORDS_PATH, 'utf8')]);
    if (currentMeta !== output.meta || currentRecords !== output.records) {
      throw new MvxError('Intelligence snapshot is not reproducible from pinned sources', { code: 'INTEL_OUTDATED' });
    }
  } else {
    await Promise.all([writeFile(META_PATH, output.meta, 'utf8'), writeFile(RECORDS_PATH, output.records, 'utf8')]);
  }
  return catalog.meta.summary;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const check = process.argv.slice(2).includes('--check');
  try {
    const summary = await updateIntelligence({ check });
    process.stdout.write(`${check ? 'Verified' : 'Updated'} intelligence: ${summary.records} IDs, ${summary.artifacts} CRX artifacts\n`);
  } catch (error) {
    process.stderr.write(`${error.code ?? 'UNEXPECTED_ERROR'}: ${error.message}\n`);
    process.exitCode = 1;
  }
}
