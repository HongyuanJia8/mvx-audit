import { createHash } from 'node:crypto';
import { MvxError } from './errors.js';
import { lineAt, lineStarts } from './text-locations.js';
import { createFinding, REFERENCES } from './model.js';
import { assertOptionsObject } from './options.js';

export const DNR_RULE_PROFILE = 'mvx-dnr-static-v1';
export const DNR_RULE_LIMITS = Object.freeze({
  maxRulesets: 100,
  maxRules: 300_000,
  maxTrackedRules: 20_000,
  maxJsonDepth: 128,
  maxJsonValues: 5_000_000
});

const ACTION_TYPES = Object.freeze([
  'allow', 'allowAllRequests', 'block', 'modifyHeaders', 'redirect', 'upgradeScheme'
]);
const ACTION_TYPE_SET = new Set(ACTION_TYPES);
const HEADER_OPERATIONS = new Set(['append', 'remove', 'set']);
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u2028-\u202e\u2066-\u2069]/;

class InvalidDnrJson extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) deepFreeze(value[key], seen);
  return Object.freeze(value);
}

export function normalizeDnrRuleLimits(options = {}) {
  assertOptionsObject(options, 'DNR-rule limits');
  const unknown = Object.getOwnPropertyNames(options)
    .filter((key) => !Object.hasOwn(DNR_RULE_LIMITS, key))
    .sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown DNR-rule limit: ${unknown.join(', ')}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  const limits = {};
  for (const [key, fallback] of Object.entries(DNR_RULE_LIMITS)) {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    const value = descriptor ? descriptor.value : fallback;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new MvxError(`${key} must be a positive safe integer`, {
        code: 'INVALID_ARGUMENT'
      });
    }
    limits[key] = value;
  }
  return Object.freeze(limits);
}

function inspectJson(source, label, limits, budget) {
  let cursor = 0;
  const rootArrayOffsets = [];
  const whitespace = () => {
    while (/[\t\n\r ]/.test(source[cursor] ?? '')) cursor += 1;
  };
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
    if (depth > limits.maxJsonDepth) {
      throw new MvxError(`${label} exceeds ${limits.maxJsonDepth} JSON nesting levels`, {
        code: 'DNR_RULE_LIMIT'
      });
    }
    budget.jsonValues += 1;
    if (budget.jsonValues > limits.maxJsonValues) {
      throw new MvxError(`DNR rule JSON exceeds ${limits.maxJsonValues} values`, {
        code: 'DNR_RULE_LIMIT'
      });
    }
    whitespace();
    if (source[cursor] === '{') {
      cursor += 1;
      whitespace();
      const keys = new Set();
      while (source[cursor] !== '}') {
        const key = jsonString();
        if (keys.has(key)) throw new InvalidDnrJson('duplicate-json-key');
        keys.add(key);
        whitespace();
        cursor += 1;
        value(depth + 1);
        whitespace();
        if (source[cursor] === ',') {
          cursor += 1;
          whitespace();
        }
      }
      cursor += 1;
      return;
    }
    if (source[cursor] === '[') {
      const root = depth === 0;
      cursor += 1;
      whitespace();
      while (source[cursor] !== ']') {
        if (root) rootArrayOffsets.push(cursor);
        value(depth + 1);
        whitespace();
        if (source[cursor] === ',') {
          cursor += 1;
          whitespace();
        }
      }
      cursor += 1;
      return;
    }
    if (source[cursor] === '"') {
      jsonString();
      return;
    }
    while (cursor < source.length && !/[\t\n\r ,}\]]/.test(source[cursor])) cursor += 1;
  };
  value(0);
  return rootArrayOffsets;
}

function dataObject(value) {
  return value !== null && !Array.isArray(value) && typeof value === 'object';
}

function validDisplayString(value, max = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && !UNSAFE_TEXT.test(value);
}

function validHeaderModification(value) {
  if (!dataObject(value) || !validDisplayString(value.header)
    || !HEADER_OPERATIONS.has(value.operation)) return false;
  if (value.operation === 'remove') return value.value === undefined;
  return typeof value.value === 'string';
}

function validRedirect(value) {
  if (!dataObject(value)) return false;
  const selectors = ['extensionPath', 'regexSubstitution', 'transform', 'url']
    .filter((key) => value[key] !== undefined);
  if (selectors.length !== 1) return false;
  if (selectors[0] === 'transform') return dataObject(value.transform);
  if (!validDisplayString(value[selectors[0]], 8_192)) return false;
  if (selectors[0] === 'url' && /^javascript:/i.test(value.url)) return false;
  return true;
}

function validateRule(rule, seenIds) {
  if (!dataObject(rule)) return { reason: 'rule-not-object' };
  if (!Number.isSafeInteger(rule.id) || rule.id < 1) return { reason: 'invalid-rule-id' };
  if (seenIds.has(rule.id)) return { reason: 'duplicate-rule-id', ruleId: rule.id };
  seenIds.add(rule.id);
  if (rule.priority !== undefined
    && (!Number.isSafeInteger(rule.priority) || rule.priority < 1)) {
    return { reason: 'invalid-rule-priority', ruleId: rule.id };
  }
  if (!dataObject(rule.action) || !dataObject(rule.condition)) {
    return { reason: 'invalid-rule-shape', ruleId: rule.id };
  }
  const type = rule.action.type;
  if (!ACTION_TYPE_SET.has(type)) {
    return { reason: 'unsupported-action-type', ruleId: rule.id };
  }
  const hasRedirect = rule.action.redirect !== undefined;
  const hasHeaders = rule.action.requestHeaders !== undefined
    || rule.action.responseHeaders !== undefined;
  if (type === 'redirect') {
    if (!validRedirect(rule.action.redirect) || hasHeaders) {
      return { reason: 'invalid-redirect-action', ruleId: rule.id };
    }
  } else if (type === 'modifyHeaders') {
    const request = rule.action.requestHeaders === undefined
      ? [] : rule.action.requestHeaders;
    const response = rule.action.responseHeaders === undefined
      ? [] : rule.action.responseHeaders;
    if (hasRedirect || !Array.isArray(request) || !Array.isArray(response)
      || request.length + response.length === 0
      || ![...request, ...response].every(validHeaderModification)) {
      return { reason: 'invalid-header-action', ruleId: rule.id };
    }
  } else if (hasRedirect || hasHeaders) {
    return { reason: 'action-fields-do-not-match-type', ruleId: rule.id };
  }
  return { type, ruleId: rule.id };
}

function normalizeRulesetPath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1_024
    || value.includes('\\') || value.startsWith('/') || /^[a-z]:/i.test(value)
    || UNSAFE_TEXT.test(value)) return null;
  const normalized = value.replace(/^\.\//, '');
  const segments = normalized.split('/');
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) return null;
  return segments.join('/');
}

export function declaredStaticDnrPaths(manifest) {
  const resources = dataObject(manifest?.declarative_net_request)
    && Array.isArray(manifest.declarative_net_request.rule_resources)
    ? manifest.declarative_net_request.rule_resources : [];
  return new Set(resources
    .map((resource) => dataObject(resource) ? normalizeRulesetPath(resource.path) : null)
    .filter(Boolean));
}

function emptyActionCounts() {
  return Object.fromEntries(ACTION_TYPES.map((type) => [type, 0]));
}

function trackedEntry(entry, entries, budget, limits) {
  budget.trackedRules += 1;
  if (budget.trackedRules > limits.maxTrackedRules) {
    throw new MvxError(`Tracked DNR rules exceed ${limits.maxTrackedRules}`, {
      code: 'DNR_RULE_LIMIT'
    });
  }
  entries.push(entry);
}

function invalidRulesetEntry(ruleset, reason, entries, budget, limits) {
  trackedEntry({
    kind: 'ruleset', path: ruleset.path, line: 1, rulesetId: ruleset.id,
    enabled: ruleset.enabled, reason
  }, entries, budget, limits);
}

function parseRuleset(ruleset, source, limits, budget, entries) {
  const summary = {
    id: ruleset.id,
    path: ruleset.path,
    enabled: ruleset.enabled,
    bytes: source?.bytes ?? null,
    sha256: source?.sha256 ?? null,
    status: 'parsed',
    rules: 0,
    validRules: 0,
    invalidRules: 0,
    actionCounts: emptyActionCounts()
  };
  if (!source) return { ...summary, status: 'missing' };
  if (source.validUtf8 === false) {
    invalidRulesetEntry(ruleset, 'invalid-utf8', entries, budget, limits);
    return { ...summary, status: 'invalid-utf8' };
  }
  let parsed;
  try {
    parsed = JSON.parse(source.content);
  } catch {
    invalidRulesetEntry(ruleset, 'invalid-json', entries, budget, limits);
    return { ...summary, status: 'invalid-json' };
  }
  let offsets;
  try {
    offsets = inspectJson(source.content, `DNR ruleset ${ruleset.path}`, limits, budget);
  } catch (error) {
    if (!(error instanceof InvalidDnrJson)) throw error;
    invalidRulesetEntry(ruleset, error.reason, entries, budget, limits);
    return { ...summary, status: error.reason };
  }
  if (!Array.isArray(parsed)) {
    invalidRulesetEntry(ruleset, 'root-not-array', entries, budget, limits);
    return { ...summary, status: 'root-not-array' };
  }
  budget.rules += parsed.length;
  if (budget.rules > limits.maxRules) {
    throw new MvxError(`Static DNR rules exceed ${limits.maxRules}`, {
      code: 'DNR_RULE_LIMIT'
    });
  }
  summary.rules = parsed.length;
  const starts = lineStarts(source.content);
  const seenIds = new Set();
  parsed.forEach((rule, index) => {
    const result = validateRule(rule, seenIds);
    const line = lineAt(starts, offsets[index] ?? 0);
    if (result.reason) {
      summary.invalidRules += 1;
      trackedEntry({
        kind: 'rule', path: ruleset.path, line, rulesetId: ruleset.id,
        enabled: ruleset.enabled, ruleId: result.ruleId ?? null,
        action: 'invalid', reason: result.reason
      }, entries, budget, limits);
      return;
    }
    summary.validRules += 1;
    summary.actionCounts[result.type] += 1;
    if (result.type === 'modifyHeaders' || result.type === 'redirect') {
      trackedEntry({
        kind: 'rule', path: ruleset.path, line, rulesetId: ruleset.id,
        enabled: ruleset.enabled, ruleId: result.ruleId, action: result.type
      }, entries, budget, limits);
    }
  });
  return summary;
}

export function extractStaticDnrRules(manifest, sources, options = {}) {
  const limits = normalizeDnrRuleLimits(options);
  const dnrDeclaration = manifest.declarative_net_request;
  const invalidDnrDeclaration = dnrDeclaration !== undefined && !dataObject(dnrDeclaration);
  const declaredResources = dataObject(dnrDeclaration)
    ? dnrDeclaration.rule_resources : undefined;
  const declarations = Array.isArray(declaredResources) ? declaredResources : [];
  if (declarations.length > limits.maxRulesets) {
    throw new MvxError(`Static DNR rulesets exceed ${limits.maxRulesets}`, {
      code: 'DNR_RULE_LIMIT'
    });
  }
  const sourceMap = new Map(sources.map((source) => [source.path, source]));
  const entries = [];
  const rulesets = [];
  const seenIds = new Set();
  const budget = { jsonValues: 0, rules: 0, trackedRules: 0 };
  if (invalidDnrDeclaration
    || (declaredResources !== undefined && !Array.isArray(declaredResources))) {
    const reason = invalidDnrDeclaration
      ? 'invalid-declarative-net-request' : 'invalid-rule-resources';
    trackedEntry({
      kind: 'ruleset', path: 'manifest.json', line: 1,
      rulesetId: '<invalid-rule-resources>', enabled: null,
      reason
    }, entries, budget, limits);
    rulesets.push({
      id: '<invalid-rule-resources>', path: null, enabled: null, bytes: null,
      sha256: null, status: reason, rules: 0, validRules: 0,
      invalidRules: 0, actionCounts: emptyActionCounts()
    });
  }
  declarations.forEach((declaration, index) => {
    const descriptor = dataObject(declaration) ? declaration : {};
    const validId = validDisplayString(descriptor.id);
    const id = validId ? descriptor.id : `<invalid-${index}>`;
    const path = normalizeRulesetPath(descriptor.path);
    const enabled = typeof descriptor.enabled === 'boolean' ? descriptor.enabled : null;
    if (!path || enabled === null || seenIds.has(id) || !validId) {
      const ruleset = { id, path, enabled };
      trackedEntry({
        kind: 'ruleset', path: 'manifest.json', line: 1, rulesetId: id,
        enabled, reason: 'invalid-manifest-descriptor'
      }, entries, budget, limits);
      rulesets.push({
        id, path, enabled, bytes: path ? sourceMap.get(path)?.bytes ?? null : null,
        sha256: path ? sourceMap.get(path)?.sha256 ?? null : null,
        status: 'invalid-manifest-descriptor', rules: 0, validRules: 0,
        invalidRules: 0, actionCounts: emptyActionCounts()
      });
      return;
    }
    seenIds.add(id);
    rulesets.push(parseRuleset({ id, path, enabled }, sourceMap.get(path), limits, budget, entries));
  });
  const totals = {
    rulesets: rulesets.length,
    parsedRulesets: rulesets.filter((ruleset) => ruleset.status === 'parsed').length,
    invalidRulesets: rulesets.filter((ruleset) => !['parsed', 'missing'].includes(ruleset.status)).length,
    missingRulesets: rulesets.filter((ruleset) => ruleset.status === 'missing').length,
    rules: rulesets.reduce((count, ruleset) => count + ruleset.rules, 0),
    validRules: rulesets.reduce((count, ruleset) => count + ruleset.validRules, 0),
    invalidRules: rulesets.reduce((count, ruleset) => count + ruleset.invalidRules, 0),
    jsonValues: budget.jsonValues,
    trackedRules: budget.trackedRules,
    actionCounts: emptyActionCounts()
  };
  for (const ruleset of rulesets) {
    for (const type of ACTION_TYPES) totals.actionCounts[type] += ruleset.actionCounts[type];
  }
  const identity = { profile: DNR_RULE_PROFILE, limits, totals, rulesets, entries };
  return deepFreeze({ ...identity, sha256: sha256(JSON.stringify(identity)) });
}

function evidence(entry) {
  const scope = entry.kind === 'ruleset'
    ? `Ruleset ${entry.rulesetId}`
    : `Rule ${entry.ruleId ?? 'unknown'} in ruleset ${entry.rulesetId}`;
  return {
    file: entry.path ?? 'manifest.json',
    line: entry.line,
    rulesetId: entry.rulesetId,
    rulesetEnabled: entry.enabled,
    ...(entry.ruleId !== undefined ? { ruleId: entry.ruleId } : {}),
    ...(entry.action ? { action: entry.action } : {}),
    ...(entry.reason ? { reason: entry.reason } : {}),
    snippet: `${scope}: ${entry.action ?? entry.reason}`
  };
}

export function analyzeStaticDnrRules(inventory) {
  const findings = [];
  const headerRules = inventory.entries.filter((entry) => entry.action === 'modifyHeaders');
  if (headerRules.length > 0) {
    findings.push(createFinding({
      id: 'MVX113',
      title: 'Declarative header modification rules',
      severity: 'high',
      category: 'network-control',
      description: 'Static Declarative Net Request rules can add, remove, or set request and response headers.',
      remediation: 'Constrain filters, resource types, domains, and header operations to the minimum required scope.',
      references: [REFERENCES.dnr]
    }, headerRules.map(evidence)));
  }
  const redirectRules = inventory.entries.filter((entry) => entry.action === 'redirect');
  if (redirectRules.length > 0) {
    findings.push(createFinding({
      id: 'MVX114',
      title: 'Declarative request redirect rules',
      severity: 'high',
      category: 'network-control',
      description: 'Static Declarative Net Request rules can redirect matching browser requests to another URL or extension resource.',
      remediation: 'Review every redirect destination and constrain request, initiator, domain, and resource-type filters.',
      references: [REFERENCES.dnr]
    }, redirectRules.map(evidence)));
  }
  const invalid = inventory.entries.filter((entry) => entry.reason);
  if (invalid.length > 0) {
    findings.push(createFinding({
      id: 'MVX115',
      title: 'Unverifiable static DNR rules',
      severity: 'high',
      category: 'integrity',
      description: 'A declared static Declarative Net Request ruleset is malformed or outside the bounded structural profile, so its network behavior cannot be classified reliably.',
      remediation: 'Use unique positive rule IDs, supported action shapes, normalized declared paths, strict UTF-8 JSON, and no duplicate JSON keys.',
      references: [REFERENCES.dnr]
    }, invalid.map(evidence)));
  }
  return findings;
}
