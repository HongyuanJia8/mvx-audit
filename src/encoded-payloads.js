import { createHash } from 'node:crypto';
import { MvxError } from './errors.js';
import { createFinding, REFERENCES } from './model.js';
import { assertOptionsObject } from './options.js';

export const ENCODED_PAYLOAD_PROFILE = 'mvx-encoded-payloads-v1';
export const ENCODED_PAYLOAD_LIMITS = Object.freeze({
  maxCandidates: 4_096,
  maxPayloads: 128,
  maxEncodedChars: 1_500_000,
  maxTotalEncodedChars: 8_000_000,
  maxDecodedBytes: 1_000_000,
  maxTotalDecodedBytes: 5_000_000,
  maxDepth: 2,
  minDecodedBytes: 16
});

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const ASCII_SPACE = /[\t\n\r ]/;
const IDENTIFIER_CONTINUE = /[$\u200c\u200d\p{ID_Continue}]/u;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function supportedAtobReference(content, index) {
  const previous = content[index - 1];
  let dot = index - 1;
  while (ASCII_SPACE.test(content[dot] ?? '')) dot -= 1;
  if (content[dot] === '.') {
    let cursor = dot - 1;
    while (ASCII_SPACE.test(content[cursor] ?? '')) cursor -= 1;
    const end = cursor + 1;
    while (/[A-Za-z]/.test(content[cursor] ?? '')) cursor -= 1;
    const qualifier = content.slice(cursor + 1, end);
    return ['globalThis', 'self', 'window'].includes(qualifier)
      && !IDENTIFIER_CONTINUE.test(content[cursor] ?? '');
  }
  if (ASCII_SPACE.test(previous ?? '')) return true;
  return previous === undefined || !IDENTIFIER_CONTINUE.test(previous);
}

function normalizeLimits(options) {
  assertOptionsObject(options, 'Encoded-payload limits');
  const unknown = Object.getOwnPropertyNames(options)
    .filter((key) => !Object.hasOwn(ENCODED_PAYLOAD_LIMITS, key))
    .sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown encoded-payload limit: ${unknown.join(', ')}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  const limits = {};
  for (const [key, fallback] of Object.entries(ENCODED_PAYLOAD_LIMITS)) {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    const value = descriptor?.value ?? fallback;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new MvxError(`${key} must be a positive safe integer`, {
        code: 'INVALID_ARGUMENT'
      });
    }
    limits[key] = value;
  }
  return Object.freeze(limits);
}

function* directAtobLiterals(content) {
  const pattern = /atob/g;
  let line = 1;
  let lineCursor = 0;
  for (const match of content.matchAll(pattern)) {
    if (!supportedAtobReference(content, match.index)
      || IDENTIFIER_CONTINUE.test(content[match.index + match[0].length] ?? '')) continue;
    for (let newline = content.indexOf('\n', lineCursor);
      newline !== -1 && newline < match.index;
      newline = content.indexOf('\n', lineCursor)) {
      line += 1;
      lineCursor = newline + 1;
    }
    let cursor = match.index + match[0].length;
    while (ASCII_SPACE.test(content[cursor] ?? '')) cursor += 1;
    if (content[cursor++] !== '(') continue;
    while (ASCII_SPACE.test(content[cursor] ?? '')) cursor += 1;
    const quote = content[cursor];
    if (quote !== "'" && quote !== '"') continue;
    const valueStart = ++cursor;
    let escaped = false;
    let closed = false;
    while (cursor < content.length) {
      const character = content[cursor];
      if (character === '\n' || character === '\r'
        || character === '\u2028' || character === '\u2029') break;
      if (character === '\\') {
        escaped = true;
        cursor += 2;
        continue;
      }
      if (character === quote) {
        closed = true;
        break;
      }
      cursor += 1;
    }
    if (!closed) continue;
    const valueEnd = cursor++;
    while (ASCII_SPACE.test(content[cursor] ?? '')) cursor += 1;
    if (content[cursor] !== ')') continue;
    yield {
      encoded: content.slice(valueStart, valueEnd),
      escaped,
      line
    };
  }
}

function normalizeBase64(source) {
  const compact = source.replace(/[\t\n\r ]/g, '');
  if (compact.length === 0 || !BASE64.test(compact) || compact.length % 4 === 1) return null;
  if (compact.includes('=') && compact.length % 4 !== 0) return null;
  return compact;
}

function decodeCanonicalBase64(compact) {
  const unpadded = compact.replace(/=+$/, '');
  const decoded = Buffer.from(compact, 'base64');
  if (decoded.toString('base64').replace(/=+$/, '') !== unpadded) return null;
  return decoded;
}

function decodedLength(compact) {
  const padding = compact.endsWith('==') ? 2 : compact.endsWith('=') ? 1 : 0;
  return Math.floor(compact.length * 3 / 4) - padding;
}

function utf8Text(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function extractEncodedPayloads(sources, options = ENCODED_PAYLOAD_LIMITS) {
  const limits = options === ENCODED_PAYLOAD_LIMITS
    ? ENCODED_PAYLOAD_LIMITS
    : normalizeLimits(options);
  const queue = sources.map((source) => ({
    path: source.path,
    content: source.content,
    sha256: source.sha256,
    depth: 0,
    originLine: null
  }));
  const decodedSources = [];
  const entries = [];
  let candidates = 0;
  let candidateEncodedChars = 0;
  let totalDecodedBytes = 0;

  for (let queueIndex = 0; queueIndex < queue.length; queueIndex += 1) {
    const source = queue[queueIndex];
    if (source.depth >= limits.maxDepth) continue;
    for (const candidate of directAtobLiterals(source.content)) {
      candidates += 1;
      if (candidates > limits.maxCandidates) {
        throw new MvxError(`Encoded-payload candidates exceed ${limits.maxCandidates}`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      if (candidate.escaped) continue;
      if (candidate.encoded.length > limits.maxEncodedChars) {
        throw new MvxError(`Encoded payload exceeds ${limits.maxEncodedChars} characters`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      const compact = normalizeBase64(candidate.encoded);
      if (!compact) continue;
      if (compact.length > limits.maxEncodedChars) {
        throw new MvxError(`Encoded payload exceeds ${limits.maxEncodedChars} characters`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      if (candidateEncodedChars + compact.length > limits.maxTotalEncodedChars) {
        throw new MvxError(`Encoded-payload candidate characters exceed ${limits.maxTotalEncodedChars}`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      candidateEncodedChars += compact.length;
      if (decodedLength(compact) > limits.maxDecodedBytes) {
        throw new MvxError(`Decoded payload exceeds ${limits.maxDecodedBytes} bytes`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      const decoded = decodeCanonicalBase64(compact);
      if (!decoded || decoded.length < limits.minDecodedBytes) continue;
      if (entries.length >= limits.maxPayloads) {
        throw new MvxError(`Decoded payload count exceeds ${limits.maxPayloads}`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      if (totalDecodedBytes + decoded.length > limits.maxTotalDecodedBytes) {
        throw new MvxError(`Decoded payload bytes exceed ${limits.maxTotalDecodedBytes}`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      totalDecodedBytes += decoded.length;
      const text = utf8Text(decoded);
      const digest = sha256(decoded);
      const entry = Object.freeze({
        path: source.path,
        line: source.originLine ?? candidate.line,
        encodedLine: candidate.line,
        depth: source.depth + 1,
        encoding: 'base64-atob',
        parentSha256: source.sha256,
        encodedChars: compact.length,
        decodedBytes: decoded.length,
        sha256: digest,
        utf8: text !== null
      });
      entries.push(entry);
      if (text !== null) {
        const decodedSource = Object.freeze({
          path: source.path,
          content: text,
          bytes: decoded.length,
          sha256: digest,
          decodedFrom: Object.freeze({
            profile: ENCODED_PAYLOAD_PROFILE,
            line: entry.line,
            encodedLine: entry.encodedLine,
            depth: entry.depth,
            encoding: entry.encoding,
            parentSha256: entry.parentSha256,
            sha256: entry.sha256
          })
        });
        decodedSources.push(decodedSource);
        queue.push({
          path: decodedSource.path,
          content: decodedSource.content,
          sha256: decodedSource.sha256,
          depth: entry.depth,
          originLine: entry.line
        });
      }
    }
  }

  entries.sort((left, right) => compareText(left.path, right.path)
    || left.line - right.line
    || left.depth - right.depth
    || left.encodedLine - right.encodedLine
    || compareText(left.sha256, right.sha256));
  const frozenEntries = Object.freeze(entries);
  const identity = Object.freeze({
    profile: ENCODED_PAYLOAD_PROFILE,
    limits,
    candidates,
    candidateEncodedChars,
    entries: frozenEntries
  });
  return Object.freeze({
    ...identity,
    decodedCount: frozenEntries.length,
    utf8Count: frozenEntries.filter((entry) => entry.utf8).length,
    totalDecodedBytes,
    sha256: sha256(JSON.stringify(identity)),
    decodedSources: Object.freeze(decodedSources)
  });
}

export function analyzeEncodedPayloads(inventory) {
  if (inventory.entries.length === 0) return [];
  return [createFinding({
    id: 'MVX213',
    title: 'Direct literal Base64 decoding pattern',
    severity: 'medium',
    confidence: 'high',
    category: 'obfuscation',
    description: 'Source contains a direct atob-call pattern with a packaged Base64 literal. Encoded content increases review cost and can conceal executable behavior.',
    remediation: 'Store reviewable packaged source or data directly, document any required encoding, and avoid passing decoded text to executable sinks.',
    references: [REFERENCES.security, REFERENCES.remoteCode]
  }, inventory.entries.map((entry) => ({
    file: entry.path,
    line: entry.line,
    encodedLine: entry.encodedLine,
    encoding: entry.encoding,
    depth: entry.depth,
    decodedBytes: entry.decodedBytes,
    decodedSha256: entry.sha256,
    utf8: entry.utf8,
    snippet: `${entry.encoding} decoded ${entry.decodedBytes} byte(s) at depth ${entry.depth}`
  })) )];
}
