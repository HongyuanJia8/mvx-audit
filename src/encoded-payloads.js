import { createHash } from 'node:crypto';
import { MvxError } from './errors.js';
import { createFinding, REFERENCES } from './model.js';
import { assertOptionsObject } from './options.js';
import { lineAt, lineStarts } from './text-locations.js';

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
const IDENTIFIER_START = /[$_\p{ID_Start}]/u;
const IDENTIFIER_CONTINUE = /[$\u200c\u200d\p{ID_Continue}]/u;
const REGEX_PREFIX_KEYWORDS = new Set([
  'await', 'case', 'delete', 'do', 'else', 'in', 'instanceof', 'new', 'return',
  'throw', 'typeof', 'void', 'yield'
]);
const JAVASCRIPT_TYPES = new Set([
  'application/ecmascript', 'application/javascript', 'module',
  'text/ecmascript', 'text/javascript'
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
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

function isLineTerminator(character) {
  return character === '\r' || character === '\n'
    || character === '\u2028' || character === '\u2029';
}

function isSpace(character) {
  return character === ' ' || character === '\t' || character === '\v'
    || character === '\f' || character === '\u00a0' || isLineTerminator(character);
}

function codePoint(content, index) {
  const point = content.codePointAt(index);
  if (point === undefined) return null;
  return { character: String.fromCodePoint(point), width: point > 0xffff ? 2 : 1 };
}

function identifierAt(content, index) {
  const first = codePoint(content, index);
  if (!first || !IDENTIFIER_START.test(first.character)) return null;
  let cursor = index + first.width;
  while (cursor < content.length) {
    const next = codePoint(content, cursor);
    if (!next || !IDENTIFIER_CONTINUE.test(next.character)) break;
    cursor += next.width;
  }
  return { value: content.slice(index, cursor), end: cursor };
}

function skipLineRemainder(content, index) {
  let cursor = index;
  while (cursor < content.length && !isLineTerminator(content[cursor])) cursor += 1;
  return cursor;
}

function skipLineComment(content, index) {
  return skipLineRemainder(content, index + 2);
}

function skipBlockComment(content, index) {
  const close = content.indexOf('*/', index + 2);
  return close === -1 ? content.length : close + 2;
}

function skipTrivia(content, index, end) {
  let cursor = index;
  while (cursor < end) {
    if (isSpace(content[cursor])) {
      cursor += 1;
    } else if (content.startsWith('//', cursor)) {
      cursor = Math.min(skipLineComment(content, cursor), end);
    } else if (content.startsWith('/*', cursor)) {
      cursor = Math.min(skipBlockComment(content, cursor), end);
    } else break;
  }
  return Math.min(cursor, end);
}

function skipQuoted(content, index, quote, end) {
  let cursor = index + 1;
  while (cursor < end) {
    const character = content[cursor];
    if (character === '\\') cursor = Math.min(cursor + 2, end);
    else if (character === quote) return cursor + 1;
    else if (isLineTerminator(character) && quote !== '`') return cursor;
    else cursor += 1;
  }
  return cursor;
}

function skipRegex(content, index, end) {
  let cursor = index + 1;
  let inClass = false;
  while (cursor < end) {
    const character = content[cursor];
    if (character === '\\') cursor = Math.min(cursor + 2, end);
    else if (isLineTerminator(character)) return cursor;
    else if (character === '[') { inClass = true; cursor += 1; }
    else if (character === ']') { inClass = false; cursor += 1; }
    else if (character === '/' && !inClass) {
      cursor += 1;
      while (cursor < end && identifierAt(content, cursor)) {
        cursor = identifierAt(content, cursor).end;
      }
      return cursor;
    } else cursor += 1;
  }
  return cursor;
}

function supportedReference(tokens) {
  const previous = tokens.at(-1);
  if (previous?.value !== '.') return true;
  return ['globalThis', 'self', 'window'].includes(tokens.at(-2)?.value);
}

function startAttempt(budget, limits) {
  budget.candidates += 1;
  if (budget.candidates > limits.maxCandidates) {
    throw new MvxError(`Encoded-payload candidates exceed ${limits.maxCandidates}`, {
      code: 'ENCODED_PAYLOAD_LIMIT'
    });
  }
}

function checkAttemptCharacters(budget, limits, characters) {
  if (characters > limits.maxEncodedChars) {
    throw new MvxError(`Encoded payload exceeds ${limits.maxEncodedChars} characters`, {
      code: 'ENCODED_PAYLOAD_LIMIT'
    });
  }
  if (budget.candidateEncodedChars + characters > limits.maxTotalEncodedChars) {
    throw new MvxError(`Encoded-payload candidate characters exceed ${limits.maxTotalEncodedChars}`, {
      code: 'ENCODED_PAYLOAD_LIMIT'
    });
  }
}

function parseAtobLiteral(content, tokenEnd, end, budget, limits) {
  let cursor = skipTrivia(content, tokenEnd, end);
  if (content[cursor] !== '(') return null;
  cursor = skipTrivia(content, cursor + 1, end);
  const quote = content[cursor];
  if (quote !== "'" && quote !== '"') return null;
  startAttempt(budget, limits);
  const valueStart = cursor + 1;
  cursor = valueStart;
  let escaped = false;
  while (cursor < end && content[cursor] !== quote && !isLineTerminator(content[cursor])) {
    if (content[cursor] === '\\') {
      escaped = true;
      cursor += 1;
      if (cursor < end) cursor += 1;
    } else cursor += 1;
    checkAttemptCharacters(budget, limits, cursor - valueStart);
  }
  const characters = cursor - valueStart;
  checkAttemptCharacters(budget, limits, characters);
  budget.candidateEncodedChars += characters;
  if (cursor >= end || content[cursor] !== quote) return { end: cursor };
  const valueEnd = cursor;
  cursor = skipTrivia(content, cursor + 1, end);
  if (content[cursor] !== ')') return { end: cursor };
  return {
    end: cursor + 1,
    candidate: { encoded: content.slice(valueStart, valueEnd), escaped }
  };
}

function* javascriptAtobLiterals(content, start, end, starts, budget, limits) {
  let cursor = start;
  let canStartRegex = true;
  const tokens = [];
  const remember = (token) => {
    tokens.push(token);
    if (tokens.length > 3) tokens.shift();
  };
  while (cursor < end) {
    const character = content[cursor];
    if (isSpace(character)) { cursor += 1; continue; }
    if (content.startsWith('<!--', cursor) || content.startsWith('-->', cursor)) {
      cursor = Math.min(skipLineRemainder(content, cursor + 3), end);
      continue;
    }
    if (content.startsWith('//', cursor)) {
      cursor = Math.min(skipLineComment(content, cursor), end);
      continue;
    }
    if (content.startsWith('/*', cursor)) {
      cursor = Math.min(skipBlockComment(content, cursor), end);
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      cursor = skipQuoted(content, cursor, character, end);
      remember({ type: 'atom', value: character });
      canStartRegex = false;
      continue;
    }
    if (character === '/' && canStartRegex) {
      cursor = skipRegex(content, cursor, end);
      remember({ type: 'atom', value: 'regex' });
      canStartRegex = false;
      continue;
    }
    const identifier = identifierAt(content, cursor);
    if (identifier) {
      if (identifier.value === 'atob' && supportedReference(tokens)) {
        const parsed = parseAtobLiteral(content, identifier.end, end, budget, limits);
        if (parsed) {
          if (parsed.candidate) yield {
            ...parsed.candidate,
            line: lineAt(starts, cursor)
          };
          cursor = Math.max(parsed.end, identifier.end);
          remember({ type: 'atom', value: 'call' });
          canStartRegex = false;
          continue;
        }
      }
      remember({ type: 'identifier', value: identifier.value });
      canStartRegex = REGEX_PREFIX_KEYWORDS.has(identifier.value);
      cursor = identifier.end;
      continue;
    }
    if (/[0-9]/.test(character)) {
      cursor += 1;
      while (cursor < end && /[0-9A-Fa-f_xXobOBn.eE]/.test(content[cursor])) cursor += 1;
      remember({ type: 'atom', value: 'number' });
      canStartRegex = false;
      continue;
    }
    remember({ type: 'punctuator', value: character });
    canStartRegex = ![')', ']', '}'].includes(character) && character !== '.';
    cursor += 1;
  }
}

function parseTag(content, start, end) {
  let cursor = start + 1;
  let closing = false;
  if (content[cursor] === '/') { closing = true; cursor += 1; }
  while (isSpace(content[cursor])) cursor += 1;
  const nameStart = cursor;
  while (/[A-Za-z0-9:-]/.test(content[cursor] ?? '')) cursor += 1;
  if (cursor === nameStart) return null;
  const name = content.slice(nameStart, cursor).toLowerCase();
  const attributes = [];
  while (cursor < end) {
    while (isSpace(content[cursor])) cursor += 1;
    if (content[cursor] === '>') return { name, closing, attributes, end: cursor + 1 };
    if (content[cursor] === '/' && content[cursor + 1] === '>') {
      return { name, closing, attributes, end: cursor + 2 };
    }
    const attributeStart = cursor;
    while (cursor < end && !isSpace(content[cursor])
      && !['=', '>', '/'].includes(content[cursor])) cursor += 1;
    if (cursor === attributeStart) { cursor += 1; continue; }
    const attribute = { name: content.slice(attributeStart, cursor).toLowerCase() };
    while (isSpace(content[cursor])) cursor += 1;
    if (content[cursor] === '=') {
      cursor += 1;
      while (isSpace(content[cursor])) cursor += 1;
      const quote = content[cursor];
      if (quote === "'" || quote === '"') {
        attribute.valueStart = cursor + 1;
        const close = content.indexOf(quote, attribute.valueStart);
        attribute.valueEnd = close === -1 || close >= end ? end : close;
        cursor = close === -1 || close >= end ? end : close + 1;
      } else {
        attribute.valueStart = cursor;
        while (cursor < end && !isSpace(content[cursor]) && content[cursor] !== '>') cursor += 1;
        attribute.valueEnd = cursor;
      }
      attribute.value = content.slice(attribute.valueStart, attribute.valueEnd);
    }
    attributes.push(attribute);
  }
  return null;
}

function executableScript(tag) {
  if (tag.attributes.some((attribute) => attribute.name === 'src')) return false;
  const type = tag.attributes.find((attribute) => attribute.name === 'type')?.value;
  if (type === undefined || type.trim() === '') return true;
  const normalized = type.trim().toLowerCase().split(';', 1)[0];
  return JAVASCRIPT_TYPES.has(normalized)
    || normalized.endsWith('+javascript') || normalized.endsWith('+ecmascript');
}

function* htmlAtobLiterals(content, starts, budget, limits) {
  const lower = content.toLowerCase();
  let cursor = 0;
  while (cursor < content.length) {
    const open = content.indexOf('<', cursor);
    if (open === -1) return;
    if (content.startsWith('<!--', open)) {
      const close = content.indexOf('-->', open + 4);
      cursor = close === -1 ? content.length : close + 3;
      continue;
    }
    const tag = parseTag(content, open, content.length);
    if (!tag) { cursor = open + 1; continue; }
    if (!tag.closing) {
      for (const attribute of tag.attributes) {
        if (/^on[a-z]/.test(attribute.name) && attribute.valueStart !== undefined) {
          yield* javascriptAtobLiterals(
            content, attribute.valueStart, attribute.valueEnd, starts, budget, limits
          );
        }
      }
    }
    if (!tag.closing && tag.name === 'script') {
      const close = lower.indexOf('</script', tag.end);
      const bodyEnd = close === -1 ? content.length : close;
      if (executableScript(tag)) {
        yield* javascriptAtobLiterals(content, tag.end, bodyEnd, starts, budget, limits);
      }
      if (close === -1) return;
      const closingTag = parseTag(content, close, content.length);
      cursor = closingTag?.end ?? close + 2;
    } else cursor = tag.end;
  }
}

function directAtobLiterals(source, budget, limits) {
  const starts = lineStarts(source.content);
  if (/\.html?$/i.test(source.path) && source.depth === 0) {
    return htmlAtobLiterals(source.content, starts, budget, limits);
  }
  return javascriptAtobLiterals(
    source.content, 0, source.content.length, starts, budget, limits
  );
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
  const candidateBudget = { candidates: 0, candidateEncodedChars: 0 };
  let totalDecodedBytes = 0;

  for (let queueIndex = 0; queueIndex < queue.length; queueIndex += 1) {
    const source = queue[queueIndex];
    if (source.depth >= limits.maxDepth) continue;
    for (const candidate of directAtobLiterals(source, candidateBudget, limits)) {
      if (candidate.escaped) continue;
      const compact = normalizeBase64(candidate.encoded);
      if (!compact) continue;
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
    candidates: candidateBudget.candidates,
    candidateEncodedChars: candidateBudget.candidateEncodedChars,
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
    confidence: 'medium',
    category: 'obfuscation',
    description: 'An executable source context contains a syntactic atob-call pattern with a packaged Base64 literal. Static analysis does not prove which runtime binding receives the call. Encoded content increases review cost and can conceal executable behavior.',
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
