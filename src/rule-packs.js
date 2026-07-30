import { createHash } from 'node:crypto';
import path from 'node:path';
import { MvxError } from './errors.js';
import { CONFIDENCE, SEVERITIES } from './model.js';
import { readBoundedRegularFile } from './safe-file.js';

const PREPARED = Symbol('mvx-prepared-rule-packs');
const NAMESPACE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const RULE_ID = /^[A-Z][A-Z0-9_-]*$/;
const CATEGORY = /^[a-z][a-z0-9-]*$/;
const SHA256 = /^[a-f0-9]{64}$/;
const TEXT_SCOPES = new Set(['source', 'manifest', 'all-text']);
const PATH_MATCHES = new Set(['exact', 'basename']);

export const DEFAULT_RULE_PACK_LIMITS = Object.freeze({
  maxPacks: 32,
  maxPackBytes: 1_000_000,
  maxTotalBytes: 5_000_000,
  maxRules: 1_000,
  maxIndicators: 5_000,
  maxLiteralBytes: 4_096,
  maxTotalLiteralBytes: 1_000_000,
  maxMatches: 10_000
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function rejectDuplicateJsonKeys(source, label) {
  let cursor = 0;
  const whitespace = () => {
    while (/\s/.test(source[cursor] ?? '')) cursor += 1;
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
    if (depth > 128) throw new MvxError(`${label} exceeds 128 JSON nesting levels`, { code: 'RULE_PACK_LIMIT' });
    whitespace();
    if (source[cursor] === '{') {
      cursor += 1;
      whitespace();
      const seen = new Set();
      while (source[cursor] !== '}') {
        const key = jsonString();
        if (seen.has(key)) throw new MvxError(`${label} contains duplicate JSON field: ${key}`, { code: 'INVALID_RULE_PACK' });
        seen.add(key);
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
      cursor += 1;
      whitespace();
      while (source[cursor] !== ']') {
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
    while (cursor < source.length && !/[\s,}\]]/.test(source[cursor])) cursor += 1;
  };
  value(0);
}

function object(value, label) {
  if (!value || Array.isArray(value) || typeof value !== 'object') {
    throw new MvxError(`${label} must be a JSON object`, { code: 'INVALID_RULE_PACK' });
  }
  return value;
}

function keys(value, allowed, label) {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key)).sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`${label} has unknown field(s): ${unknown.join(', ')}`, { code: 'INVALID_RULE_PACK' });
  }
}

function string(value, label, maxLength, pattern) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || (pattern && !pattern.test(value))) {
    throw new MvxError(`${label} is invalid`, { code: 'INVALID_RULE_PACK' });
  }
  return value;
}

function displayString(value, label, maxLength) {
  const result = string(value, label, maxLength);
  if (result.trim() !== result || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/i.test(result)) {
    throw new MvxError(`${label} may not contain surrounding whitespace or control characters`, { code: 'INVALID_RULE_PACK' });
  }
  return result;
}

function array(value, label, { min = 0, max = Infinity } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    throw new MvxError(`${label} must contain between ${min} and ${max} items`, { code: 'INVALID_RULE_PACK' });
  }
  return value;
}

function normalizeLimits(options) {
  if (!options || Array.isArray(options) || typeof options !== 'object') {
    throw new MvxError('Rule-pack limits must be an object', { code: 'INVALID_ARGUMENT' });
  }
  const supported = new Set(Object.keys(DEFAULT_RULE_PACK_LIMITS));
  const unknown = Object.keys(options).filter((key) => !supported.has(key)).sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown rule-pack limit: ${unknown.join(', ')}`, { code: 'INVALID_ARGUMENT' });
  }
  const limits = {};
  for (const [key, fallback] of Object.entries(DEFAULT_RULE_PACK_LIMITS)) {
    const value = Object.hasOwn(options, key) ? options[key] : fallback;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new MvxError(`${key} must be a positive safe integer`, { code: 'INVALID_ARGUMENT' });
    }
    limits[key] = value;
  }
  return limits;
}

function normalizePath(value, match, label) {
  string(value, label, 1_024);
  if (value.includes('\0') || value.includes('\\') || value.startsWith('/') || /^[a-z]:/i.test(value)) {
    throw new MvxError(`${label} must be an extension-relative POSIX path`, { code: 'INVALID_RULE_PACK' });
  }
  if (match === 'basename') {
    if (value.includes('/') || value === '.' || value === '..') {
      throw new MvxError(`${label} basename is invalid`, { code: 'INVALID_RULE_PACK' });
    }
    return value;
  }
  const segments = value.split('/');
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new MvxError(`${label} must be a normalized extension-relative path`, { code: 'INVALID_RULE_PACK' });
  }
  return segments.join('/');
}

function normalizeIndicator(input, label, limits) {
  const indicator = object(input, label);
  const type = string(indicator.type, `${label}.type`, 32);
  if (type === 'text') {
    keys(indicator, new Set(['type', 'value', 'scope', 'caseSensitive']), label);
    const value = string(indicator.value, `${label}.value`, limits.maxPackBytes);
    if (Buffer.byteLength(value) > limits.maxLiteralBytes || value.includes('\0')) {
      throw new MvxError(`${label}.value exceeds the literal-byte limit or contains NUL`, { code: 'RULE_PACK_LIMIT' });
    }
    const scope = indicator.scope ?? 'all-text';
    if (!TEXT_SCOPES.has(scope)) throw new MvxError(`${label}.scope is invalid`, { code: 'INVALID_RULE_PACK' });
    const caseSensitive = indicator.caseSensitive ?? true;
    if (typeof caseSensitive !== 'boolean') throw new MvxError(`${label}.caseSensitive must be boolean`, { code: 'INVALID_RULE_PACK' });
    if (!caseSensitive && !/^[\x01-\x7f]+$/.test(value)) {
      throw new MvxError(`${label} case-insensitive literals must be ASCII`, { code: 'INVALID_RULE_PACK' });
    }
    return { type, value, scope, caseSensitive };
  }
  if (type === 'path') {
    keys(indicator, new Set(['type', 'value', 'match']), label);
    const match = indicator.match ?? 'exact';
    if (!PATH_MATCHES.has(match)) throw new MvxError(`${label}.match is invalid`, { code: 'INVALID_RULE_PACK' });
    return { type, value: normalizePath(indicator.value, match, `${label}.value`), match };
  }
  if (type === 'file-sha256' || type === 'package-sha256') {
    keys(indicator, new Set(['type', 'value']), label);
    return { type, value: string(indicator.value, `${label}.value`, 64, SHA256) };
  }
  throw new MvxError(`${label}.type is unsupported`, { code: 'INVALID_RULE_PACK' });
}

function normalizeReferences(value, label) {
  return array(value ?? [], label, { max: 20 }).map((item, index) => {
    const reference = string(item, `${label}[${index}]`, 2_048);
    let url;
    try { url = new URL(reference); } catch {
      throw new MvxError(`${label}[${index}] must be an absolute HTTPS URL`, { code: 'INVALID_RULE_PACK' });
    }
    if (url.protocol !== 'https:') {
      throw new MvxError(`${label}[${index}] must use HTTPS`, { code: 'INVALID_RULE_PACK' });
    }
    if (url.username || url.password) {
      throw new MvxError(`${label}[${index}] may not contain credentials`, { code: 'INVALID_RULE_PACK' });
    }
    return url.href;
  });
}

function normalizeRule(input, packLabel, index, limits) {
  const label = `${packLabel}.rules[${index}]`;
  const rule = object(input, label);
  keys(rule, new Set([
    'id', 'title', 'severity', 'confidence', 'category', 'description', 'remediation',
    'references', 'condition', 'indicators'
  ]), label);
  const severity = string(rule.severity, `${label}.severity`, 16);
  if (!SEVERITIES.includes(severity)) throw new MvxError(`${label}.severity is invalid`, { code: 'INVALID_RULE_PACK' });
  const confidence = rule.confidence ?? CONFIDENCE.HIGH;
  if (!Object.values(CONFIDENCE).includes(confidence)) throw new MvxError(`${label}.confidence is invalid`, { code: 'INVALID_RULE_PACK' });
  const condition = rule.condition ?? 'any';
  if (!['any', 'all'].includes(condition)) throw new MvxError(`${label}.condition is invalid`, { code: 'INVALID_RULE_PACK' });
  const indicators = array(rule.indicators, `${label}.indicators`, { min: 1, max: limits.maxIndicators })
    .map((indicator, indicatorIndex) => normalizeIndicator(indicator, `${label}.indicators[${indicatorIndex}]`, limits));
  const seen = new Set();
  for (const indicator of indicators) {
    const identity = JSON.stringify(indicator);
    if (seen.has(identity)) throw new MvxError(`${label} contains a duplicate indicator`, { code: 'INVALID_RULE_PACK' });
    seen.add(identity);
  }
  return {
    id: string(rule.id, `${label}.id`, 64, RULE_ID),
    title: displayString(rule.title, `${label}.title`, 200),
    severity,
    confidence,
    category: string(rule.category, `${label}.category`, 64, CATEGORY),
    description: displayString(rule.description, `${label}.description`, 2_000),
    remediation: displayString(rule.remediation, `${label}.remediation`, 2_000),
    references: normalizeReferences(rule.references, `${label}.references`),
    condition,
    indicators
  };
}

function normalizePack(input, label, limits) {
  const pack = object(input, label);
  keys(pack, new Set(['schemaVersion', 'namespace', 'name', 'version', 'rules']), label);
  if (pack.schemaVersion !== 1) throw new MvxError(`${label}.schemaVersion must equal 1`, { code: 'INVALID_RULE_PACK' });
  const rules = array(pack.rules, `${label}.rules`, { min: 1, max: limits.maxRules })
    .map((rule, index) => normalizeRule(rule, label, index, limits));
  const ids = new Set();
  for (const rule of rules) {
    if (ids.has(rule.id)) throw new MvxError(`${label} contains duplicate rule ID: ${rule.id}`, { code: 'INVALID_RULE_PACK' });
    ids.add(rule.id);
  }
  return {
    schemaVersion: 1,
    namespace: string(pack.namespace, `${label}.namespace`, 128, NAMESPACE),
    name: displayString(pack.name, `${label}.name`, 200),
    version: displayString(pack.version, `${label}.version`, 64),
    rules
  };
}

export async function loadRulePacks(inputs = [], options = {}) {
  const limits = normalizeLimits(options);
  if (!Array.isArray(inputs) || inputs.some((input) => typeof input !== 'string' || input.length === 0)) {
    throw new MvxError('rulePacks must be an array of file paths', { code: 'INVALID_ARGUMENT' });
  }
  if (inputs.length > limits.maxPacks) throw new MvxError(`More than ${limits.maxPacks} rule packs requested`, { code: 'RULE_PACK_LIMIT' });
  const packs = [];
  let totalBytes = 0;
  let totalRules = 0;
  let totalIndicators = 0;
  let totalLiteralBytes = 0;
  for (const input of inputs) {
    const absolute = path.resolve(input);
    const bytes = await readBoundedRegularFile(absolute, {
      maxBytes: limits.maxPackBytes,
      label: `Rule pack ${input}`,
      limitCode: 'RULE_PACK_LIMIT',
      missingCode: 'RULE_PACK_NOT_FOUND',
      unsafeCode: 'UNSAFE_RULE_PACK'
    });
    totalBytes += bytes.length;
    if (totalBytes > limits.maxTotalBytes) throw new MvxError(`Rule packs exceed ${limits.maxTotalBytes} bytes`, { code: 'RULE_PACK_LIMIT' });
    let source;
    try { source = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (error) {
      throw new MvxError(`Rule pack ${input} is not valid UTF-8`, { code: 'INVALID_RULE_PACK', cause: error });
    }
    let parsed;
    try { parsed = JSON.parse(source); } catch (error) {
      throw new MvxError(`Invalid JSON in rule pack ${input}: ${error.message}`, { code: 'INVALID_RULE_PACK', cause: error });
    }
    rejectDuplicateJsonKeys(source, `Rule pack ${input}`);
    const pack = normalizePack(parsed, `Rule pack ${input}`, limits);
    const indicatorCount = pack.rules.reduce((count, rule) => count + rule.indicators.length, 0);
    const literalBytes = pack.rules.flatMap((rule) => rule.indicators)
      .filter((indicator) => indicator.type === 'text')
      .reduce((count, indicator) => count + Buffer.byteLength(indicator.value), 0);
    totalRules += pack.rules.length;
    totalIndicators += indicatorCount;
    totalLiteralBytes += literalBytes;
    if (totalRules > limits.maxRules) throw new MvxError(`Rule packs exceed ${limits.maxRules} rules`, { code: 'RULE_PACK_LIMIT' });
    if (totalIndicators > limits.maxIndicators) throw new MvxError(`Rule packs exceed ${limits.maxIndicators} indicators`, { code: 'RULE_PACK_LIMIT' });
    if (totalLiteralBytes > limits.maxTotalLiteralBytes) {
      throw new MvxError(`Rule packs exceed ${limits.maxTotalLiteralBytes} literal bytes`, { code: 'RULE_PACK_LIMIT' });
    }
    const provenance = {
      schemaVersion: 1,
      namespace: pack.namespace,
      name: pack.name,
      version: pack.version,
      bytes: bytes.length,
      sha256: sha256(bytes),
      rules: pack.rules.length,
      indicators: indicatorCount
    };
    packs.push({ ...pack, provenance });
  }
  packs.sort((left, right) => compareText(left.namespace, right.namespace) || compareText(left.provenance.sha256, right.provenance.sha256));
  for (let index = 1; index < packs.length; index += 1) {
    if (packs[index - 1].namespace === packs[index].namespace) {
      throw new MvxError(`Duplicate rule-pack namespace: ${packs[index].namespace}`, { code: 'INVALID_RULE_PACK' });
    }
  }
  const prepared = {
    packs,
    provenance: packs.map((pack) => pack.provenance),
    limits,
    summary: { packs: packs.length, bytes: totalBytes, rules: totalRules, indicators: totalIndicators, literalBytes: totalLiteralBytes }
  };
  Object.defineProperty(prepared, PREPARED, { value: true });
  return prepared;
}

export async function resolveRulePacks(options = {}) {
  if (options._preparedRulePacks !== undefined) {
    if (!options._preparedRulePacks?.[PREPARED]) {
      throw new MvxError('Prepared rule packs are invalid', { code: 'INVALID_ARGUMENT' });
    }
    return options._preparedRulePacks;
  }
  return loadRulePacks(options.rulePacks ?? [], options.rulePackLimits ?? {});
}

export function rulePacksToText(prepared) {
  return [
    `Rule packs valid: ${prepared.summary.packs}`,
    `Rules: ${prepared.summary.rules}`,
    `Indicators: ${prepared.summary.indicators}`,
    `Bytes: ${prepared.summary.bytes}`,
    ...prepared.provenance.map((pack) => `${pack.namespace}@${pack.version}: ${pack.sha256}`)
  ].join('\n') + '\n';
}
