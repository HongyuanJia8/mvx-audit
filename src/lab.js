import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import { isDeepStrictEqual } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditExtension } from './analyzer.js';
import { auditDirectorySnapshot } from './audit-verification.js';
import { MvxError } from './errors.js';
import { assertOptionsObject } from './options.js';
import { readBoundedRegularFile } from './safe-file.js';
import { VERSION } from './version.js';

export const LAB_EVIDENCE_PROFILE = 'mvx-lab-evidence-v1';
export const LAB_EVALUATION_PROFILE = 'mvx-lab-evaluation-v1';
export const LAB_EXECUTION_PROFILE = 'mvx-lab-execution-v1';
export const LAB_VERIFICATION_PROFILE = 'mvx-lab-verification-v1';

export const DEFAULT_LAB_EVIDENCE_LIMITS = Object.freeze({
  maxScenarioBytes: 1_000_000,
  maxEventBytes: 20_000_000,
  maxEvents: 100_000,
  maxReportBytes: 25_000_000
});

const DEFAULT_SECCOMP_PROFILE = fileURLToPath(new URL('../lab/seccomp-chromium.json', import.meta.url));
const VERDICTS = ['confirmed_attack', 'suspicious_activity', 'no_trigger_observed', 'inconclusive'];
const EVENT_TYPES = new Set([
  'lab.started',
  'extension.loaded',
  'network.request',
  'navigation.attempt',
  'download.attempt',
  'dom.mutation',
  'lab.error',
  'lab.completed'
]);
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const IMAGE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$/;
const TOOL_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const UNSAFE_DISPLAY = /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u2028-\u202e\u2066-\u2069]/;
const LAB_VERIFICATION_OPTIONS = new Set([
  'expectedAnalysisSha256',
  'expectedEvaluationSha256',
  'expectedEventsSha256',
  'expectedImageId',
  'expectedPackageSha256',
  'expectedReportSha256',
  'expectedScenarioSha256',
  'expectedSeccompSha256',
  'seccompProfile',
  'temporaryDirectory'
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function ownValue(object, key) {
  return Object.getOwnPropertyDescriptor(object, key)?.value;
}

function snapshotLabVerificationOptions(options) {
  assertOptionsObject(options, 'Lab verification');
  const unknown = Object.getOwnPropertyNames(options)
    .filter((key) => !LAB_VERIFICATION_OPTIONS.has(key))
    .sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown lab verification option(s): ${unknown.join(', ')}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  const stable = Object.assign(Object.create(null), Object.fromEntries(
    [...LAB_VERIFICATION_OPTIONS].map((key) => [key, ownValue(options, key)])
  ));
  for (const key of [
    'expectedAnalysisSha256',
    'expectedEvaluationSha256',
    'expectedEventsSha256',
    'expectedPackageSha256',
    'expectedReportSha256',
    'expectedScenarioSha256',
    'expectedSeccompSha256'
  ]) {
    if (stable[key] !== undefined
      && (typeof stable[key] !== 'string' || !SHA256.test(stable[key]))) {
      throw new MvxError(`${key} must be a lowercase SHA-256 digest`, {
        code: 'INVALID_ARGUMENT'
      });
    }
  }
  if (stable.expectedImageId !== undefined
    && (typeof stable.expectedImageId !== 'string'
      || !IMAGE_ID.test(stable.expectedImageId))) {
    throw new MvxError('expectedImageId must be a canonical sha256 Docker image ID', {
      code: 'INVALID_ARGUMENT'
    });
  }
  for (const key of ['seccompProfile', 'temporaryDirectory']) {
    if (stable[key] !== undefined
      && (typeof stable[key] !== 'string' || stable[key].length === 0)) {
      throw new MvxError(`${key} must be a non-empty string`, {
        code: 'INVALID_ARGUMENT'
      });
    }
  }
  return Object.freeze(stable);
}

function assertExpected(actual, expected, label) {
  if (expected !== undefined && actual !== expected) {
    throw new MvxError(
      `${label} does not match its independently expected identity`,
      { code: 'LAB_IDENTITY_MISMATCH' }
    );
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
    .replaceAll('Audit verification', 'Lab verification')
    .replaceAll('Audit snapshot', 'Lab snapshot')
    .replaceAll('audit snapshot', 'lab snapshot')
    .replaceAll('Private audit', 'Private lab');
  return new MvxError(message, { code: mapped, cause: error });
}

function profileDigest(profile, value) {
  return sha256(Buffer.concat([Buffer.from(`${profile}\0`, 'utf8'), Buffer.from(JSON.stringify(value), 'utf8')]));
}

function rejectDuplicateJsonKeys(source, label, invalidCode, limitCode) {
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
    if (depth > 128) throw new MvxError(`${label} exceeds 128 JSON nesting levels`, { code: limitCode });
    whitespace();
    if (source[cursor] === '{') {
      cursor += 1;
      whitespace();
      const seen = new Set();
      while (source[cursor] !== '}') {
        const key = jsonString();
        if (seen.has(key)) throw new MvxError(`${label} contains duplicate JSON field: ${key}`, { code: invalidCode });
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

function parseJson(source, label, invalidCode, limitCode) {
  let parsed;
  try { parsed = JSON.parse(source); } catch (error) {
    throw new MvxError(`Invalid ${label} JSON: ${error.message}`, { code: invalidCode, cause: error });
  }
  rejectDuplicateJsonKeys(source, label, invalidCode, limitCode);
  return parsed;
}

function decodeUtf8(bytes, label, code) {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (error) {
    throw new MvxError(`${label} is not valid UTF-8`, { code, cause: error });
  }
}

async function readLabFile(filePath, { maxBytes, label, limitCode, missingCode, unsafeCode }) {
  if (typeof filePath !== 'string' || filePath.length === 0) {
    throw new MvxError(`${label} path must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
  }
  return readBoundedRegularFile(path.resolve(filePath), {
    maxBytes, label, limitCode, missingCode, unsafeCode
  });
}

function exactKeys(value, allowed, label, code) {
  const unknown = Object.getOwnPropertyNames(value).filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new MvxError(`${label} has unknown field(s): ${unknown.join(', ')}`, { code });
}

function assertPlainObject(value, label, code) {
  if (!value || Array.isArray(value) || typeof value !== 'object' || utilTypes.isProxy(value)) {
    throw new MvxError(`${label} must be a plain non-proxy object`, { code });
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new MvxError(`${label} must be a plain non-proxy object`, { code });
  }
  if (Object.getOwnPropertySymbols(value).length > 0
    || Object.values(Object.getOwnPropertyDescriptors(value)).some((descriptor) =>
      !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true)) {
    throw new MvxError(`${label} must contain enumerable data properties only`, { code });
  }
  return value;
}

function displayString(value, label, max, code) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max
    || value.trim() !== value || UNSAFE_DISPLAY.test(value)) {
    throw new MvxError(`${label} is invalid`, { code });
  }
  return value;
}

function assertDataArray(value, label, code) {
  if (!Array.isArray(value) || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw new MvxError(`${label} must be a standard non-proxy array`, { code });
  }
  const keys = Reflect.ownKeys(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor) throw new MvxError(`${label} may not be sparse`, { code });
    if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      throw new MvxError(`${label} entries must be enumerable data properties`, { code });
    }
  }
  if (keys.some((key) => key !== 'length' && (typeof key !== 'string' || !/^(0|[1-9]\d*)$/.test(key)))) {
    throw new MvxError(`${label} may not contain extra properties`, { code });
  }
  return value;
}

function validateJsonData(value, label, depth = 0, seen = new Set()) {
  if (depth > 8) throw new MvxError(`${label} exceeds the data nesting limit`, { code: 'LAB_LIMIT' });
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    if (typeof value === 'string' && value.length > 16_384) throw new MvxError(`${label} string exceeds 16384 characters`, { code: 'LAB_LIMIT' });
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new MvxError(`${label} contains a non-finite number`, { code: 'INVALID_LAB_EVENTS' });
    return;
  }
  if (!value || typeof value !== 'object' || seen.has(value)) {
    throw new MvxError(`${label} must contain acyclic JSON data`, { code: 'INVALID_LAB_EVENTS' });
  }
  seen.add(value);
  if (Array.isArray(value)) {
    assertDataArray(value, label, 'INVALID_LAB_EVENTS');
    if (value.length > 100) throw new MvxError(`${label} array exceeds 100 entries`, { code: 'LAB_LIMIT' });
    for (let index = 0; index < value.length; index += 1) {
      const entry = Object.getOwnPropertyDescriptor(value, String(index)).value;
      validateJsonData(entry, `${label}[${index}]`, depth + 1, seen);
    }
  } else {
    assertPlainObject(value, label, 'INVALID_LAB_EVENTS');
    const entries = Object.entries(value);
    if (entries.length > 100) throw new MvxError(`${label} object exceeds 100 fields`, { code: 'LAB_LIMIT' });
    entries.forEach(([key, entry]) => validateJsonData(entry, `${label}.${key}`, depth + 1, seen));
  }
  seen.delete(value);
}

function validateScenario(scenario) {
  assertPlainObject(scenario, 'Lab scenario', 'INVALID_LAB_SCENARIO');
  exactKeys(scenario, new Set(['schemaVersion', 'id', 'targetUrl', 'canaries', 'durationMs']), 'Lab scenario', 'INVALID_LAB_SCENARIO');
  if (scenario.schemaVersion !== 1) throw new MvxError('Lab scenario schemaVersion must equal 1', { code: 'INVALID_LAB_SCENARIO' });
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(scenario.id ?? '')) throw new MvxError('Lab scenario has an invalid id', { code: 'INVALID_LAB_SCENARIO' });
  let target;
  try { target = new URL(scenario.targetUrl); } catch (error) {
    throw new MvxError('Lab scenario targetUrl is invalid', { code: 'INVALID_LAB_SCENARIO', cause: error });
  }
  if (target.protocol !== 'https:' || target.username || target.password
    || target.hash || target.href !== scenario.targetUrl) {
    throw new MvxError('Lab scenario targetUrl must be canonical HTTPS without credentials or a fragment', { code: 'INVALID_LAB_SCENARIO' });
  }
  assertPlainObject(scenario.canaries, 'Lab scenario canaries', 'INVALID_LAB_SCENARIO');
  const canaries = Object.entries(scenario.canaries);
  if (canaries.length === 0 || canaries.length > 100 || canaries.some(([name, value]) =>
    !/^[a-z][a-zA-Z0-9]+$/.test(name) || typeof value !== 'string' || value.length < 16 || value.length > 4_096)) {
    throw new MvxError('Lab canaries require 1-100 named synthetic strings of 16-4096 characters', { code: 'INVALID_LAB_SCENARIO' });
  }
  if (scenario.durationMs !== undefined
    && (!Number.isSafeInteger(scenario.durationMs) || scenario.durationMs < 1_000 || scenario.durationMs > 30_000)) {
    throw new MvxError('Lab scenario durationMs must be an integer from 1000 to 30000', { code: 'INVALID_LAB_SCENARIO' });
  }
  return target;
}

function canonicalTime(value) {
  if (typeof value !== 'string' || value.length !== 24) return false;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) return false;
  return true;
}

function validateEvent(event, line) {
  assertPlainObject(event, `Lab event line ${line}`, 'INVALID_LAB_EVENTS');
  exactKeys(event, new Set(['schemaVersion', 'timestamp', 'type', 'target', 'data']), `Lab event line ${line}`, 'INVALID_LAB_EVENTS');
  if (event.schemaVersion !== 1) throw new MvxError(`Lab event line ${line} has an unsupported schema`, { code: 'INVALID_LAB_EVENTS' });
  if (!EVENT_TYPES.has(event.type)) throw new MvxError(`Lab event line ${line} has an unknown type`, { code: 'INVALID_LAB_EVENTS' });
  if (!canonicalTime(event.timestamp)) throw new MvxError(`Lab event line ${line} has a non-canonical timestamp`, { code: 'INVALID_LAB_EVENTS' });
  if (event.target !== undefined && (typeof event.target !== 'string' || event.target.length > 16_384)) {
    throw new MvxError(`Lab event line ${line} target is invalid`, { code: 'INVALID_LAB_EVENTS' });
  }
  if (event.data !== undefined) {
    assertPlainObject(event.data, `Lab event line ${line} data`, 'INVALID_LAB_EVENTS');
    validateJsonData(event.data, `Lab event line ${line} data`);
  }
  return event;
}

function validateEventSequence(events) {
  if (events.length > DEFAULT_LAB_EVIDENCE_LIMITS.maxEvents) {
    throw new MvxError(`Lab events exceed ${DEFAULT_LAB_EVIDENCE_LIMITS.maxEvents} entries`, { code: 'LAB_LIMIT' });
  }
  let previous = null;
  let started = 0;
  let completed = 0;
  for (let index = 0; index < events.length; index += 1) {
    const event = Object.getOwnPropertyDescriptor(events, String(index)).value;
    validateEvent(event, index + 1);
    if (previous !== null && event.timestamp < previous) {
      throw new MvxError(`Lab event line ${index + 1} precedes the prior timestamp`, { code: 'INVALID_LAB_EVENTS' });
    }
    previous = event.timestamp;
    if (event.type === 'lab.started') {
      started += 1;
      if (index !== 0) throw new MvxError('lab.started must be the first event', { code: 'INVALID_LAB_EVENTS' });
    }
    if (event.type === 'lab.completed') {
      completed += 1;
      if (index !== events.length - 1) throw new MvxError('lab.completed must be the final event', { code: 'INVALID_LAB_EVENTS' });
    }
  }
  if (started > 1 || completed > 1) throw new MvxError('Lab events contain duplicate lifecycle events', { code: 'INVALID_LAB_EVENTS' });
}

export function parseLabEvents(source) {
  if (typeof source !== 'string') throw new MvxError('Lab events must be JSONL text', { code: 'INVALID_LAB_EVENTS' });
  if (Buffer.byteLength(source) > DEFAULT_LAB_EVIDENCE_LIMITS.maxEventBytes) {
    throw new MvxError(`Lab events exceed ${DEFAULT_LAB_EVIDENCE_LIMITS.maxEventBytes} bytes`, { code: 'LAB_LIMIT' });
  }
  const lines = source.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length > DEFAULT_LAB_EVIDENCE_LIMITS.maxEvents) {
    throw new MvxError(`Lab events exceed ${DEFAULT_LAB_EVIDENCE_LIMITS.maxEvents} entries`, { code: 'LAB_LIMIT' });
  }
  const events = lines.map((line, index) => parseJson(
    line, `lab event line ${index + 1}`, 'INVALID_LAB_EVENTS', 'LAB_LIMIT'
  ));
  validateEventSequence(events);
  return events;
}

function stringsIn(value, output = []) {
  if (typeof value === 'string') output.push(value);
  else if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) stringsIn(value[index], output);
  }
  else if (value && typeof value === 'object') Object.values(value).forEach((entry) => stringsIn(entry, output));
  return output;
}

function evidence(event, index, details = {}) {
  return { event: index + 1, timestamp: event.timestamp, type: event.type, target: event.target ?? null, ...details };
}

function executionProvenance(events, scenarioSha256) {
  const started = events.find((event) => event.type === 'lab.started');
  if (!started || started.data?.profile === undefined) return null;
  const data = started.data;
  exactKeys(data, new Set([
    'profile', 'browser', 'imageId', 'imageReference', 'network', 'durationMs',
    'packageSha256', 'analysisSha256', 'scenarioSha256', 'seccompSha256', 'toolVersion'
  ]), 'lab.started provenance', 'INVALID_LAB_EVENTS');
  if (data.profile !== LAB_EXECUTION_PROFILE
    || !SHA256.test(data.packageSha256 ?? '') || !SHA256.test(data.analysisSha256 ?? '')
    || !SHA256.test(data.scenarioSha256 ?? '') || !SHA256.test(data.seccompSha256 ?? '')
    || !IMAGE_ID.test(data.imageId ?? '') || !IMAGE_REFERENCE.test(data.imageReference ?? '')
    || data.network !== 'none' || !Number.isSafeInteger(data.durationMs)
    || data.durationMs < 1_000 || data.durationMs > 30_000 || !TOOL_VERSION.test(data.toolVersion ?? '')) {
    throw new MvxError('lab.started contains invalid execution provenance', { code: 'INVALID_LAB_EVENTS' });
  }
  displayString(data.browser, 'lab.started browser', 200, 'INVALID_LAB_EVENTS');
  if (data.scenarioSha256 !== scenarioSha256) {
    throw new MvxError('Lab execution scenario identity does not match the evaluated scenario bytes', { code: 'LAB_IDENTITY_MISMATCH' });
  }
  return {
    profile: LAB_EXECUTION_PROFILE,
    startedAt: started.timestamp,
    tool: { version: data.toolVersion },
    extension: { packageSha256: data.packageSha256, analysisSha256: data.analysisSha256 },
    scenarioSha256: data.scenarioSha256,
    browser: data.browser,
    container: { imageReference: data.imageReference, imageId: data.imageId, network: data.network },
    isolation: { seccompSha256: data.seccompSha256 },
    durationMs: data.durationMs
  };
}

export function evaluateLabRun(scenario, events) {
  const target = validateScenario(scenario);
  assertDataArray(events, 'Lab events', 'INVALID_LAB_EVENTS');
  validateEventSequence(events);
  const objectives = Object.fromEntries(Object.keys(scenario.canaries).map((name) => [name, { status: 'not_observed', evidence: [] }]));
  objectives.contentManipulation = { status: 'not_observed', evidence: [] };
  objectives.navigationHijack = { status: 'not_observed', evidence: [] };
  objectives.unauthorizedDownload = { status: 'not_observed', evidence: [] };
  const suspicious = [];
  const errors = [];
  let completed = false;
  let blockedExternal = 0;
  let uncontainedExternal = 0;

  for (let index = 0; index < events.length; index += 1) {
    const event = Object.getOwnPropertyDescriptor(events, String(index)).value;
    const data = event.data ?? {};
    if (event.type === 'lab.completed') completed = true;
    if (event.type === 'lab.error') errors.push(evidence(event, index, { message: data.message ?? 'lab error' }));
    if (event.type === 'network.request') {
      let requestUrl;
      try { requestUrl = new URL(data.url); } catch { requestUrl = null; }
      const external = requestUrl && ['http:', 'https:'].includes(requestUrl.protocol) && data.disposition !== 'fulfilled-canary'
        && (requestUrl.hostname !== target.hostname || (data.initiator === 'extension' && requestUrl.href !== target.href));
      if (external && data.disposition === 'blocked-external') blockedExternal += 1;
      else if (external) uncontainedExternal += 1;
      if (external) {
        const haystack = stringsIn({ url: data.url, headers: data.headers, postData: data.postData }).join('\n');
        let canaryFound = false;
        for (const [name, token] of Object.entries(scenario.canaries)) {
          if (haystack.includes(token)) {
            canaryFound = true;
            objectives[name].status = 'confirmed';
            objectives[name].evidence.push(evidence(event, index, { url: data.url, disposition: data.disposition }));
          }
        }
        if (!canaryFound) suspicious.push(evidence(event, index, { reason: 'external-request', url: data.url, disposition: data.disposition }));
      }
    }
    if (event.type === 'navigation.attempt') {
      let destination;
      try { destination = new URL(data.to); } catch { destination = null; }
      if (destination && ['http:', 'https:'].includes(destination.protocol)
        && destination.href !== target.href && data.initiator === 'extension') {
        objectives.navigationHijack.status = 'confirmed';
        objectives.navigationHijack.evidence.push(evidence(event, index, { from: data.from, to: data.to }));
      }
    }
    if (event.type === 'dom.mutation' && data.protectedCanaryChanged === true) {
      const observedUrl = data.details && !Array.isArray(data.details) && typeof data.details === 'object'
        ? data.details.url
        : null;
      if (typeof observedUrl === 'string' && observedUrl !== target.href) {
        errors.push(evidence(event, index, { message: 'DOM observation did not occur on the canary target', observedUrl }));
      } else {
        objectives.contentManipulation.status = 'confirmed';
        objectives.contentManipulation.evidence.push(evidence(event, index, { details: data.details ?? null }));
      }
    }
    if (event.type === 'download.attempt') {
      objectives.unauthorizedDownload.status = data.userGesture === false ? 'confirmed' : 'observed';
      objectives.unauthorizedDownload.evidence.push(evidence(event, index, { url: data.url, userGesture: data.userGesture }));
      if (data.userGesture !== false) suspicious.push(evidence(event, index, { reason: 'download-attempt', url: data.url }));
    }
  }

  const confirmed = Object.values(objectives).filter((objective) => objective.status === 'confirmed').length;
  let verdict;
  if (confirmed > 0) verdict = 'confirmed_attack';
  else if (suspicious.length > 0) verdict = 'suspicious_activity';
  else if (!completed || errors.length > 0) verdict = 'inconclusive';
  else verdict = 'no_trigger_observed';
  return {
    schemaVersion: 1,
    scenarioId: scenario.id,
    verdict,
    contained: uncontainedExternal === 0,
    summary: {
      eventsAnalyzed: events.length,
      confirmedObjectives: confirmed,
      suspiciousEvents: suspicious.length,
      errors: errors.length,
      blockedExternalRequests: blockedExternal,
      uncontainedExternalRequests: uncontainedExternal,
      completed
    },
    objectives,
    suspicious,
    errors,
    caveats: [
      'confirmed_attack means a canary reached an observable sink or a protected test state was changed; containment may have blocked delivery.',
      'no_trigger_observed is not a benign verdict: dormant logic, dead C2, gating, or anti-analysis behavior may prevent activation.',
      'inconclusive means infrastructure or collection errors prevent a behavioral conclusion.'
    ]
  };
}

export async function loadLabScenario(scenarioPath) {
  const bytes = await readLabFile(scenarioPath, {
    maxBytes: DEFAULT_LAB_EVIDENCE_LIMITS.maxScenarioBytes,
    label: 'Lab scenario', limitCode: 'LAB_LIMIT', missingCode: 'LAB_INPUT_NOT_FOUND', unsafeCode: 'UNSAFE_LAB_INPUT'
  });
  const source = decodeUtf8(bytes, 'Lab scenario', 'INVALID_LAB_SCENARIO');
  const scenario = parseJson(source, 'lab scenario', 'INVALID_LAB_SCENARIO', 'LAB_LIMIT');
  validateScenario(scenario);
  return { scenario, bytes: Buffer.from(bytes), provenance: { bytes: bytes.length, sha256: sha256(bytes) } };
}

export async function evaluateLabFiles(scenarioPath, eventsPath) {
  const [loadedScenario, eventsBytes] = await Promise.all([
    loadLabScenario(scenarioPath),
    readLabFile(eventsPath, {
      maxBytes: DEFAULT_LAB_EVIDENCE_LIMITS.maxEventBytes,
      label: 'Lab events', limitCode: 'LAB_LIMIT', missingCode: 'LAB_INPUT_NOT_FOUND', unsafeCode: 'UNSAFE_LAB_INPUT'
    })
  ]);
  const eventsSource = decodeUtf8(eventsBytes, 'Lab events', 'INVALID_LAB_EVENTS');
  const events = parseLabEvents(eventsSource);
  const scenarioIdentity = loadedScenario.provenance;
  const eventsIdentity = { bytes: eventsBytes.length, sha256: sha256(eventsBytes), records: events.length };
  const core = evaluateLabRun(loadedScenario.scenario, events);
  const execution = executionProvenance(events, scenarioIdentity.sha256);
  const evaluated = { ...core, ...(execution ? { execution } : {}) };
  return {
    ...evaluated,
    evidenceProvenance: {
      profile: LAB_EVIDENCE_PROFILE,
      scenario: scenarioIdentity,
      events: eventsIdentity,
      evaluation: {
        profile: LAB_EVALUATION_PROFILE,
        sha256: profileDigest(LAB_EVALUATION_PROFILE, evaluated)
      }
    }
  };
}

export async function verifyLabReport(reportPath, extensionPath, scenarioPath, eventsPath, options = {}) {
  for (const [label, value] of Object.entries({ reportPath, extensionPath, scenarioPath, eventsPath })) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new MvxError(`${label} must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
    }
  }
  const stable = snapshotLabVerificationOptions(options);
  const reportBytes = await readLabFile(reportPath, {
    maxBytes: DEFAULT_LAB_EVIDENCE_LIMITS.maxReportBytes,
    label: 'Lab report', limitCode: 'LAB_REPORT_LIMIT', missingCode: 'LAB_REPORT_NOT_FOUND', unsafeCode: 'UNSAFE_LAB_REPORT'
  });
  const reportSha256 = sha256(reportBytes);
  assertExpected(reportSha256, stable.expectedReportSha256, 'Lab report SHA-256');
  const reportSource = decodeUtf8(reportBytes, 'Lab report', 'INVALID_LAB_REPORT');
  const report = parseJson(reportSource, 'lab report', 'INVALID_LAB_REPORT', 'LAB_REPORT_LIMIT');
  const expected = await evaluateLabFiles(scenarioPath, eventsPath);
  assertExpected(
    expected.evidenceProvenance.scenario.sha256,
    stable.expectedScenarioSha256,
    'Lab scenario SHA-256'
  );
  assertExpected(
    expected.evidenceProvenance.events.sha256,
    stable.expectedEventsSha256,
    'Lab events SHA-256'
  );
  assertExpected(
    expected.evidenceProvenance.evaluation.sha256,
    stable.expectedEvaluationSha256,
    'Lab evaluation SHA-256'
  );
  if (!expected.execution) {
    throw new MvxError('Lab report has no verifiable execution provenance', { code: 'LAB_PROVENANCE_MISSING' });
  }
  assertExpected(
    expected.execution.container.imageId,
    stable.expectedImageId,
    'Lab container image ID'
  );
  const [auditOutcome, seccompOutcome] = await Promise.allSettled([
    auditDirectorySnapshot(extensionPath, Object.create(null), stable.temporaryDirectory),
    readLabFile(stable.seccompProfile ?? DEFAULT_SECCOMP_PROFILE, {
      maxBytes: 1_000_000,
      label: 'Lab seccomp profile', limitCode: 'LAB_LIMIT', missingCode: 'LAB_INPUT_NOT_FOUND', unsafeCode: 'UNSAFE_LAB_INPUT'
    })
  ]);
  if (auditOutcome.status === 'rejected') throw mapLabSnapshotError(auditOutcome.reason);
  if (seccompOutcome.status === 'rejected') throw seccompOutcome.reason;
  const audit = auditOutcome.value.actual;
  const seccompBytes = seccompOutcome.value;
  assertExpected(audit.package.sha256, stable.expectedPackageSha256, 'Lab package SHA-256');
  assertExpected(audit.analysis.sha256, stable.expectedAnalysisSha256, 'Lab analysis SHA-256');
  const seccompSha256 = sha256(seccompBytes);
  assertExpected(seccompSha256, stable.expectedSeccompSha256, 'Lab seccomp SHA-256');
  if (audit.package.sha256 !== expected.execution.extension.packageSha256
    || audit.analysis.sha256 !== expected.execution.extension.analysisSha256) {
    throw new MvxError('Lab report extension identity does not match the supplied extension', { code: 'LAB_IDENTITY_MISMATCH' });
  }
  if (seccompSha256 !== expected.execution.isolation.seccompSha256) {
    throw new MvxError('Lab report seccomp identity does not match the supplied verifier profile', { code: 'LAB_IDENTITY_MISMATCH' });
  }
  if (expected.execution.tool.version !== VERSION) {
    throw new MvxError('Lab report tool version does not match this verifier', { code: 'LAB_IDENTITY_MISMATCH' });
  }
  if (!isDeepStrictEqual(report, expected)) {
    throw new MvxError('Lab report does not match deterministic evaluation of the supplied scenario and events', { code: 'LAB_REPORT_MISMATCH' });
  }
  const independent = {
    reportSha256: stable.expectedReportSha256 === undefined ? null : true,
    packageSha256: stable.expectedPackageSha256 === undefined ? null : true,
    analysisSha256: stable.expectedAnalysisSha256 === undefined ? null : true,
    scenarioSha256: stable.expectedScenarioSha256 === undefined ? null : true,
    eventsSha256: stable.expectedEventsSha256 === undefined ? null : true,
    evaluationSha256: stable.expectedEvaluationSha256 === undefined ? null : true,
    seccompSha256: stable.expectedSeccompSha256 === undefined ? null : true,
    imageId: stable.expectedImageId === undefined ? null : true
  };
  const noIndependentIdentity = Object.values(independent)
    .every((value) => value === null);
  const imageCaveat = stable.expectedImageId === undefined
    ? 'The recorded container image ID is content-addressed but was not compared with an independently supplied expected image ID.'
    : null;
  return {
    schemaVersion: 1,
    profile: LAB_VERIFICATION_PROFILE,
    valid: true,
    verdict: expected.verdict,
    report: { bytes: reportBytes.length, sha256: reportSha256 },
    evidence: expected.evidenceProvenance,
    execution: expected.execution,
    identities: {
      packageSha256: audit.package.sha256,
      analysisSha256: audit.analysis.sha256,
      scenarioSha256: expected.evidenceProvenance.scenario.sha256,
      eventsSha256: expected.evidenceProvenance.events.sha256,
      evaluationSha256: expected.evidenceProvenance.evaluation.sha256,
      seccompSha256,
      imageId: expected.execution.container.imageId
    },
    checks: {
      deterministicEvaluation: true,
      privateExtensionSnapshot: true,
      extensionIdentity: true,
      scenarioIdentity: true,
      eventStreamIdentity: true,
      seccompIdentity: true,
      toolVersion: true,
      expectedImageIdentity: independent.imageId,
      independent
    },
    caveat: imageCaveat,
    caveats: [
      ...(imageCaveat ? [imageCaveat] : []),
      ...(noIndependentIdentity ? [
        'The report is reproducible from the supplied bundle, but no independently trusted identity was supplied.'
      ] : [])
    ]
  };
}

export function labReportToText(report) {
  const objectiveLines = Object.entries(report.objectives)
    .filter(([, objective]) => objective.status !== 'not_observed')
    .map(([name, objective]) => `  ${name}: ${objective.status} (${objective.evidence.length} evidence events)`);
  return [
    `Lab verdict: ${report.verdict}`,
    `Scenario: ${report.scenarioId}`,
    `Contained: ${report.contained ? 'yes' : 'NO'}`,
    `Events: ${report.summary.eventsAnalyzed}`,
    `Confirmed objectives: ${report.summary.confirmedObjectives}`,
    `Suspicious events: ${report.summary.suspiciousEvents}`,
    ...(report.evidenceProvenance ? [
      `Scenario SHA-256: ${report.evidenceProvenance.scenario.sha256}`,
      `Events SHA-256: ${report.evidenceProvenance.events.sha256}`,
      `Evaluation SHA-256: ${report.evidenceProvenance.evaluation.sha256}`
    ] : []),
    ...(report.execution ? [
      `Extension package SHA-256: ${report.execution.extension.packageSha256}`,
      `Extension analysis SHA-256: ${report.execution.extension.analysisSha256}`,
      `Container image: ${report.execution.container.imageId}`,
      `Seccomp SHA-256: ${report.execution.isolation.seccompSha256}`
    ] : []),
    'Observed objectives:',
    ...(objectiveLines.length > 0 ? objectiveLines : ['  none']),
    '',
    ...report.caveats.map((caveat) => `Caveat: ${caveat}`)
  ].join('\n') + '\n';
}

export function labVerificationToText(result) {
  const independentCount = Object.values(result.checks.independent ?? {})
    .filter((value) => value === true).length;
  const independentTotal = Object.keys(result.checks.independent ?? {}).length;
  return [
    `Lab report valid: ${result.valid ? 'yes' : 'NO'}`,
    `Verdict: ${result.verdict}`,
    `Report SHA-256: ${result.report.sha256}`,
    `Package SHA-256: ${result.execution.extension.packageSha256}`,
    `Analysis SHA-256: ${result.execution.extension.analysisSha256}`,
    `Scenario SHA-256: ${result.evidence.scenario.sha256}`,
    `Events SHA-256: ${result.evidence.events.sha256}`,
    `Evaluation SHA-256: ${result.evidence.evaluation.sha256}`,
    `Container image ID: ${result.execution.container.imageId}`,
    `Private extension snapshot: ${result.checks.privateExtensionSnapshot === true ? 'yes' : 'no'}`,
    `Independent identities checked: ${independentCount}/${independentTotal}`,
    `Expected image checked: ${result.checks.expectedImageIdentity === true ? 'yes' : 'no'}`,
    ...(result.caveats ?? (result.caveat ? [result.caveat] : []))
      .map((caveat) => `Caveat: ${caveat}`)
  ].join('\n') + '\n';
}

export { VERDICTS };
