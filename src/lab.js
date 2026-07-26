import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { MvxError } from './errors.js';

const MAX_EVENT_BYTES = 20_000_000;
const MAX_EVENTS = 100_000;
const VERDICTS = ['confirmed_attack', 'suspicious_activity', 'no_trigger_observed', 'inconclusive'];
const EVENT_TYPES = new Set([
  'lab.started',
  'network.request',
  'navigation.attempt',
  'download.attempt',
  'dom.mutation',
  'lab.error',
  'lab.completed'
]);

function validateScenario(scenario) {
  if (!scenario || Array.isArray(scenario) || typeof scenario !== 'object') throw new MvxError('Lab scenario must be a JSON object', { code: 'INVALID_LAB_SCENARIO' });
  if (scenario.schemaVersion !== 1) throw new MvxError('Lab scenario schemaVersion must equal 1', { code: 'INVALID_LAB_SCENARIO' });
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(scenario.id ?? '')) throw new MvxError('Lab scenario has an invalid id', { code: 'INVALID_LAB_SCENARIO' });
  let target;
  try {
    target = new URL(scenario.targetUrl);
  } catch (error) {
    throw new MvxError('Lab scenario targetUrl is invalid', { code: 'INVALID_LAB_SCENARIO', cause: error });
  }
  if (target.protocol !== 'https:') throw new MvxError('Lab scenario targetUrl must use HTTPS', { code: 'INVALID_LAB_SCENARIO' });
  if (!scenario.canaries || Array.isArray(scenario.canaries) || typeof scenario.canaries !== 'object') {
    throw new MvxError('Lab scenario canaries must be an object', { code: 'INVALID_LAB_SCENARIO' });
  }
  const canaries = Object.entries(scenario.canaries);
  if (canaries.length === 0 || canaries.some(([name, value]) => !/^[a-z][a-zA-Z0-9]+$/.test(name) || typeof value !== 'string' || value.length < 16)) {
    throw new MvxError('Lab canaries require named synthetic strings of at least 16 characters', { code: 'INVALID_LAB_SCENARIO' });
  }
  return target;
}

function validateEvent(event, line) {
  if (!event || Array.isArray(event) || typeof event !== 'object') throw new MvxError(`Lab event line ${line} must be an object`, { code: 'INVALID_LAB_EVENTS' });
  if (event.schemaVersion !== 1) throw new MvxError(`Lab event line ${line} has an unsupported schema`, { code: 'INVALID_LAB_EVENTS' });
  if (!EVENT_TYPES.has(event.type)) throw new MvxError(`Lab event line ${line} has an unknown type`, { code: 'INVALID_LAB_EVENTS' });
  if (typeof event.timestamp !== 'string' || Number.isNaN(Date.parse(event.timestamp))) {
    throw new MvxError(`Lab event line ${line} has an invalid timestamp`, { code: 'INVALID_LAB_EVENTS' });
  }
  if (event.data !== undefined && (!event.data || Array.isArray(event.data) || typeof event.data !== 'object')) {
    throw new MvxError(`Lab event line ${line} data must be an object`, { code: 'INVALID_LAB_EVENTS' });
  }
  return event;
}

export function parseLabEvents(source) {
  if (typeof source !== 'string') throw new MvxError('Lab events must be JSONL text', { code: 'INVALID_LAB_EVENTS' });
  if (Buffer.byteLength(source) > MAX_EVENT_BYTES) throw new MvxError(`Lab events exceed ${MAX_EVENT_BYTES} bytes`, { code: 'LAB_LIMIT' });
  const lines = source.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length > MAX_EVENTS) throw new MvxError(`Lab events exceed ${MAX_EVENTS} entries`, { code: 'LAB_LIMIT' });
  return lines.map((line, index) => {
    let event;
    try {
      event = JSON.parse(line);
    } catch (error) {
      throw new MvxError(`Invalid lab event JSON at line ${index + 1}: ${error.message}`, { code: 'INVALID_LAB_EVENTS', cause: error });
    }
    return validateEvent(event, index + 1);
  });
}

function stringsIn(value, output = []) {
  if (typeof value === 'string') output.push(value);
  else if (Array.isArray(value)) value.forEach((entry) => stringsIn(entry, output));
  else if (value && typeof value === 'object') Object.values(value).forEach((entry) => stringsIn(entry, output));
  return output;
}

function evidence(event, index, details = {}) {
  return { event: index + 1, timestamp: event.timestamp, type: event.type, target: event.target ?? null, ...details };
}

export function evaluateLabRun(scenario, events) {
  const target = validateScenario(scenario);
  if (!Array.isArray(events)) throw new MvxError('Lab events must be an array', { code: 'INVALID_LAB_EVENTS' });
  events.forEach((event, index) => validateEvent(event, index + 1));
  const objectives = Object.fromEntries(Object.keys(scenario.canaries).map((name) => [name, { status: 'not_observed', evidence: [] }]));
  objectives.contentManipulation = { status: 'not_observed', evidence: [] };
  objectives.navigationHijack = { status: 'not_observed', evidence: [] };
  objectives.unauthorizedDownload = { status: 'not_observed', evidence: [] };
  const suspicious = [];
  const errors = [];
  let completed = false;
  let blockedExternal = 0;
  let uncontainedExternal = 0;

  events.forEach((event, index) => {
    const data = event.data ?? {};
    if (event.type === 'lab.completed') completed = true;
    if (event.type === 'lab.error') errors.push(evidence(event, index, { message: data.message ?? 'lab error' }));
    if (event.type === 'network.request') {
      let requestUrl;
      try { requestUrl = new URL(data.url); } catch { requestUrl = null; }
      const external = requestUrl && ['http:', 'https:'].includes(requestUrl.protocol) && data.disposition !== 'fulfilled-canary' && requestUrl.hostname !== target.hostname;
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
      if (destination && destination.href !== target.href && data.initiator === 'extension') {
        objectives.navigationHijack.status = 'confirmed';
        objectives.navigationHijack.evidence.push(evidence(event, index, { from: data.from, to: data.to }));
      }
    }
    if (event.type === 'dom.mutation' && data.protectedCanaryChanged === true) {
      objectives.contentManipulation.status = 'confirmed';
      objectives.contentManipulation.evidence.push(evidence(event, index, { details: data.details ?? null }));
    }
    if (event.type === 'download.attempt') {
      objectives.unauthorizedDownload.status = data.userGesture === false ? 'confirmed' : 'observed';
      objectives.unauthorizedDownload.evidence.push(evidence(event, index, { url: data.url, userGesture: data.userGesture }));
      if (data.userGesture !== false) suspicious.push(evidence(event, index, { reason: 'download-attempt', url: data.url }));
    }
  });

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

export async function evaluateLabFiles(scenarioPath, eventsPath) {
  const [scenarioSource, eventsSource] = await Promise.all([
    readFile(path.resolve(scenarioPath), 'utf8'),
    readFile(path.resolve(eventsPath), 'utf8')
  ]).catch((error) => {
    throw new MvxError(`Cannot read lab input: ${error.message}`, { code: 'LAB_INPUT_NOT_FOUND', cause: error });
  });
  let scenario;
  try { scenario = JSON.parse(scenarioSource); } catch (error) {
    throw new MvxError(`Invalid lab scenario JSON: ${error.message}`, { code: 'INVALID_LAB_SCENARIO', cause: error });
  }
  return evaluateLabRun(scenario, parseLabEvents(eventsSource));
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
    'Observed objectives:',
    ...(objectiveLines.length > 0 ? objectiveLines : ['  none']),
    '',
    ...report.caveats.map((caveat) => `Caveat: ${caveat}`)
  ].join('\n') + '\n';
}

export { VERDICTS };
