import { createHash } from 'node:crypto';
import path from 'node:path';
import { MvxError } from './errors.js';
import { findingKey } from './fingerprints.js';
import { summarizeFindings } from './model.js';
import { assertOptionsObject } from './options.js';
import { readBoundedRegularFile } from './safe-file.js';

const PREPARED = new WeakSet();
const POLICY_ID = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const FINGERPRINT = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,255}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const UNSAFE_DISPLAY = /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u2028-\u202e\u2066-\u2069]/;
const DISPOSITIONS = new Set(['accepted-risk', 'false-positive', 'compensating-control']);

export const DEFAULT_DISPOSITION_POLICY_LIMITS = Object.freeze({
  maxPolicies: 32,
  maxPolicyBytes: 1_000_000,
  maxTotalBytes: 5_000_000,
  maxEntries: 5_000
});

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) deepFreeze(value[key], seen);
  return Object.freeze(value);
}

function rejectDuplicateJsonKeys(source, label) {
  let cursor = 0;
  const whitespace = () => { while (/\s/.test(source[cursor] ?? '')) cursor += 1; };
  const jsonString = () => {
    const start = cursor;
    cursor += 1;
    while (cursor < source.length) {
      if (source[cursor] === '\\') cursor += 2;
      else if (source[cursor++] === '"') break;
    }
    return JSON.parse(source.slice(start, cursor));
  };
  const value = (depth) => {
    if (depth > 128) throw new MvxError(`${label} exceeds 128 JSON nesting levels`, { code: 'DISPOSITION_POLICY_LIMIT' });
    whitespace();
    if (source[cursor] === '{') {
      cursor += 1;
      whitespace();
      const seen = new Set();
      while (source[cursor] !== '}') {
        const key = jsonString();
        if (seen.has(key)) throw new MvxError(`${label} contains duplicate JSON field: ${key}`, { code: 'INVALID_DISPOSITION_POLICY' });
        seen.add(key);
        whitespace();
        cursor += 1;
        value(depth + 1);
        whitespace();
        if (source[cursor] === ',') { cursor += 1; whitespace(); }
      }
      cursor += 1;
      return;
    }
    if (source[cursor] === '[') {
      cursor += 1;
      whitespace();
      while (source[cursor] !== ']') {
        value(depth + 1);
        whitespace();
        if (source[cursor] === ',') { cursor += 1; whitespace(); }
      }
      cursor += 1;
      return;
    }
    if (source[cursor] === '"') { jsonString(); return; }
    while (cursor < source.length && !/[\s,}\]]/.test(source[cursor])) cursor += 1;
  };
  value(0);
}

function object(value, label) {
  if (!value || Array.isArray(value) || typeof value !== 'object') {
    throw new MvxError(`${label} must be a JSON object`, { code: 'INVALID_DISPOSITION_POLICY' });
  }
  return value;
}

function keys(value, allowed, label) {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key)).sort(compareText);
  if (unknown.length > 0) throw new MvxError(`${label} has unknown field(s): ${unknown.join(', ')}`, { code: 'INVALID_DISPOSITION_POLICY' });
}

function string(value, label, { min = 1, max, pattern, display = false } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max || (pattern && !pattern.test(value))) {
    throw new MvxError(`${label} is invalid`, { code: 'INVALID_DISPOSITION_POLICY' });
  }
  if (display && (value.trim() !== value || UNSAFE_DISPLAY.test(value))) {
    throw new MvxError(`${label} may not contain surrounding whitespace or unsafe display characters`, { code: 'INVALID_DISPOSITION_POLICY' });
  }
  return value;
}

function canonicalTime(value, label, code = 'INVALID_DISPOSITION_POLICY') {
  if (typeof value !== 'string' || value.length === 0 || value.length > 24) {
    throw new MvxError(`${label} must be a canonical UTC timestamp with milliseconds`, { code });
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new MvxError(`${label} must be a canonical UTC timestamp with milliseconds`, { code });
  }
  return value;
}

function ticketUrl(value, label) {
  if (value === undefined) return null;
  string(value, label, { max: 2_048, display: true });
  let parsed;
  try { parsed = new URL(value); } catch {
    throw new MvxError(`${label} must be an absolute HTTPS URL`, { code: 'INVALID_DISPOSITION_POLICY' });
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new MvxError(`${label} must be an HTTPS URL without credentials`, { code: 'INVALID_DISPOSITION_POLICY' });
  }
  return parsed.href;
}

function normalizeEntry(input, label) {
  const entry = object(input, label);
  keys(entry, new Set([
    'fingerprint', 'packageSha256', 'analysisSha256', 'artifactSha256', 'disposition', 'owner', 'justification', 'expiresAt', 'ticketUrl'
  ]), label);
  const disposition = string(entry.disposition, `${label}.disposition`, { max: 32 });
  if (!DISPOSITIONS.has(disposition)) throw new MvxError(`${label}.disposition is unsupported`, { code: 'INVALID_DISPOSITION_POLICY' });
  return {
    fingerprint: string(entry.fingerprint, `${label}.fingerprint`, { max: 256, pattern: FINGERPRINT }),
    packageSha256: string(entry.packageSha256, `${label}.packageSha256`, { max: 64, pattern: SHA256 }),
    analysisSha256: string(entry.analysisSha256, `${label}.analysisSha256`, { max: 64, pattern: SHA256 }),
    artifactSha256: entry.artifactSha256 === null
      ? null
      : string(entry.artifactSha256, `${label}.artifactSha256`, { max: 64, pattern: SHA256 }),
    disposition,
    owner: string(entry.owner, `${label}.owner`, { max: 200, display: true }),
    justification: string(entry.justification, `${label}.justification`, { min: 20, max: 2_000, display: true }),
    expiresAt: canonicalTime(entry.expiresAt, `${label}.expiresAt`),
    ticketUrl: ticketUrl(entry.ticketUrl, `${label}.ticketUrl`)
  };
}

function normalizePolicy(input, label, limits) {
  const policy = object(input, label);
  keys(policy, new Set(['schemaVersion', 'policyId', 'name', 'version', 'entries']), label);
  if (policy.schemaVersion !== 1) throw new MvxError(`${label}.schemaVersion must equal 1`, { code: 'INVALID_DISPOSITION_POLICY' });
  if (!Array.isArray(policy.entries) || policy.entries.length === 0 || policy.entries.length > limits.maxEntries) {
    throw new MvxError(`${label}.entries must contain between 1 and ${limits.maxEntries} items`, { code: 'INVALID_DISPOSITION_POLICY' });
  }
  return {
    schemaVersion: 1,
    policyId: string(policy.policyId, `${label}.policyId`, { max: 128, pattern: POLICY_ID }),
    name: string(policy.name, `${label}.name`, { max: 200, display: true }),
    version: string(policy.version, `${label}.version`, { max: 64, display: true }),
    entries: policy.entries.map((entry, index) => normalizeEntry(entry, `${label}.entries[${index}]`))
  };
}

function normalizeLimits(options) {
  if (!options || Array.isArray(options) || typeof options !== 'object') throw new MvxError('Disposition-policy limits must be an object', { code: 'INVALID_ARGUMENT' });
  const unknown = Object.keys(options).filter((key) => !Object.hasOwn(DEFAULT_DISPOSITION_POLICY_LIMITS, key)).sort(compareText);
  if (unknown.length > 0) throw new MvxError(`Unknown disposition-policy limit: ${unknown.join(', ')}`, { code: 'INVALID_ARGUMENT' });
  return Object.fromEntries(Object.entries(DEFAULT_DISPOSITION_POLICY_LIMITS).map(([key, fallback]) => {
    const value = Object.hasOwn(options, key) ? options[key] : fallback;
    if (!Number.isSafeInteger(value) || value <= 0) throw new MvxError(`${key} must be a positive safe integer`, { code: 'INVALID_ARGUMENT' });
    return [key, value];
  }));
}

export async function loadDispositionPolicies(inputs = [], options = {}) {
  if (!Array.isArray(inputs) || inputs.some((input) => typeof input !== 'string' || input.length === 0)) {
    throw new MvxError('dispositionPolicies must be an array of file paths', { code: 'INVALID_ARGUMENT' });
  }
  assertOptionsObject(options, 'Disposition-policy loader');
  const { evaluationTime: requestedTime, ...limitOptions } = options;
  const limits = normalizeLimits(limitOptions);
  if (inputs.length > limits.maxPolicies) throw new MvxError(`More than ${limits.maxPolicies} disposition policies requested`, { code: 'DISPOSITION_POLICY_LIMIT' });
  const evaluationTime = canonicalTime(requestedTime ?? new Date().toISOString(), 'evaluationTime', 'INVALID_ARGUMENT');
  const policies = [];
  let totalBytes = 0;
  let totalEntries = 0;
  for (const input of inputs) {
    const bytes = await readBoundedRegularFile(path.resolve(input), {
      maxBytes: limits.maxPolicyBytes,
      label: `Disposition policy ${input}`,
      limitCode: 'DISPOSITION_POLICY_LIMIT',
      missingCode: 'DISPOSITION_POLICY_NOT_FOUND',
      unsafeCode: 'UNSAFE_DISPOSITION_POLICY'
    });
    totalBytes += bytes.length;
    if (totalBytes > limits.maxTotalBytes) throw new MvxError(`Disposition policies exceed ${limits.maxTotalBytes} bytes`, { code: 'DISPOSITION_POLICY_LIMIT' });
    let source;
    try { source = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (error) {
      throw new MvxError(`Disposition policy ${input} is not valid UTF-8`, { code: 'INVALID_DISPOSITION_POLICY', cause: error });
    }
    let parsed;
    try { parsed = JSON.parse(source); } catch (error) {
      throw new MvxError(`Invalid JSON in disposition policy ${input}: ${error.message}`, { code: 'INVALID_DISPOSITION_POLICY', cause: error });
    }
    rejectDuplicateJsonKeys(source, `Disposition policy ${input}`);
    const policy = normalizePolicy(parsed, `Disposition policy ${input}`, limits);
    totalEntries += policy.entries.length;
    if (totalEntries > limits.maxEntries) throw new MvxError(`Disposition policies exceed ${limits.maxEntries} entries`, { code: 'DISPOSITION_POLICY_LIMIT' });
    policies.push({ ...policy, provenance: {
      schemaVersion: 1, policyId: policy.policyId, name: policy.name, version: policy.version,
      bytes: bytes.length, sha256: sha256(bytes), entries: policy.entries.length
    } });
  }
  policies.sort((left, right) => compareText(left.policyId, right.policyId) || compareText(left.provenance.sha256, right.provenance.sha256));
  const policyIds = new Set();
  const identities = new Set();
  for (const policy of policies) {
    if (policyIds.has(policy.policyId)) throw new MvxError(`Duplicate disposition policy ID: ${policy.policyId}`, { code: 'INVALID_DISPOSITION_POLICY' });
    policyIds.add(policy.policyId);
    for (const entry of policy.entries) {
      const identity = `${entry.packageSha256}\0${entry.analysisSha256}\0${entry.artifactSha256 ?? '<unpacked>'}\0${entry.fingerprint}`;
      if (identities.has(identity)) throw new MvxError(`Conflicting disposition for ${entry.packageSha256}:${entry.analysisSha256}:${entry.artifactSha256 ?? '<unpacked>'}:${entry.fingerprint}`, { code: 'INVALID_DISPOSITION_POLICY' });
      identities.add(identity);
    }
  }
  const prepared = deepFreeze({
    policies,
    provenance: policies.map((policy) => policy.provenance),
    evaluationTime,
    limits,
    summary: { policies: policies.length, entries: totalEntries, bytes: totalBytes }
  });
  PREPARED.add(prepared);
  return prepared;
}

export async function resolveDispositionPolicies(options = {}) {
  assertOptionsObject(options, 'Disposition-policy resolver');
  if (options._preparedDispositionPolicies !== undefined) {
    const conflicts = ['dispositionPolicies', 'dispositionPolicyLimits', 'dispositionAt']
      .filter((key) => Object.hasOwn(options, key));
    if (conflicts.length > 0) {
      throw new MvxError(`Prepared disposition policies cannot be combined with public option(s): ${conflicts.join(', ')}`, { code: 'INVALID_ARGUMENT' });
    }
    if (!PREPARED.has(options._preparedDispositionPolicies)) throw new MvxError('Prepared disposition policies are invalid', { code: 'INVALID_ARGUMENT' });
    return options._preparedDispositionPolicies;
  }
  return loadDispositionPolicies(options.dispositionPolicies ?? [], {
    ...(options.dispositionPolicyLimits ?? {}),
    ...(options.dispositionAt !== undefined ? { evaluationTime: options.dispositionAt } : {})
  });
}

export function applyDispositionPolicies(findings, identity, prepared) {
  if (!PREPARED.has(prepared)) throw new MvxError('Prepared disposition policies are invalid', { code: 'INVALID_ARGUMENT' });
  if (!Array.isArray(findings)) throw new MvxError('Disposition evaluation requires a findings array', { code: 'INVALID_ARGUMENT' });
  assertOptionsObject(identity, 'Disposition identity');
  const identityKeys = Object.keys(identity).sort(compareText);
  if (identityKeys.join(',') !== 'analysisSha256,artifactSha256,packageSha256'
    || typeof identity.packageSha256 !== 'string' || !SHA256.test(identity.packageSha256)
    || typeof identity.analysisSha256 !== 'string' || !SHA256.test(identity.analysisSha256)
    || (identity.artifactSha256 !== null
      && (typeof identity.artifactSha256 !== 'string' || !SHA256.test(identity.artifactSha256)))) {
    throw new MvxError('Disposition evaluation requires package, analysis, and artifact SHA-256 identities', { code: 'INVALID_ARGUMENT' });
  }
  const entries = new Map();
  for (const policy of prepared.policies) {
    for (const entry of policy.entries) {
      if (entry.packageSha256 === identity.packageSha256
        && entry.analysisSha256 === identity.analysisSha256
        && entry.artifactSha256 === identity.artifactSha256) {
        entries.set(entry.fingerprint, { policy, entry });
      }
    }
  }
  const matchedEntries = new Set();
  let activeFindings = 0;
  let expiredFindings = 0;
  const annotated = findings.map((finding) => {
    const match = entries.get(findingKey(finding));
    if (!match) return finding;
    matchedEntries.add(match.entry.fingerprint);
    const status = match.entry.expiresAt > prepared.evaluationTime ? 'active' : 'expired';
    if (status === 'active') activeFindings += 1;
    else expiredFindings += 1;
    return { ...finding, disposition: {
      profile: 'mvx-disposition-v1', status, disposition: match.entry.disposition,
      owner: match.entry.owner, justification: match.entry.justification,
      expiresAt: match.entry.expiresAt, ticketUrl: match.entry.ticketUrl,
      policyId: match.policy.policyId, policyVersion: match.policy.version,
      policySha256: match.policy.provenance.sha256
    } };
  });
  const unreviewed = annotated.filter((finding) => finding.disposition?.status !== 'active');
  return {
    findings: annotated,
    reviewSummary: summarizeFindings(unreviewed),
    evaluation: {
      profile: 'mvx-disposition-v1', evaluatedAt: prepared.evaluationTime,
      policies: prepared.summary.policies, entries: prepared.summary.entries,
      identityEntries: entries.size, matchedEntries: matchedEntries.size,
      activeFindings, expiredFindings,
      unusedIdentityEntries: entries.size - matchedEntries.size
    }
  };
}

export function dispositionPoliciesToText(prepared) {
  return [
    `Disposition policies valid: ${prepared.summary.policies}`,
    `Entries: ${prepared.summary.entries}`,
    `Bytes: ${prepared.summary.bytes}`,
    `Evaluation time: ${prepared.evaluationTime}`,
    ...prepared.provenance.map((policy) => `${policy.policyId}@${policy.version}: ${policy.sha256}`)
  ].join('\n') + '\n';
}
