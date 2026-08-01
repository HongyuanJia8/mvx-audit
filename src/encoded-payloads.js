import { createHash } from 'node:crypto';
import { Parser } from 'acorn';
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
  maxParserTokens: 1_000_000,
  maxAstNodes: 2_000_000,
  maxDepth: 2,
  minDecodedBytes: 16
});

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
// WHATWG MIME Sniffing §4.6: JavaScript MIME type essence strings.
const JAVASCRIPT_TYPES = new Set([
  'application/ecmascript', 'application/javascript', 'application/x-ecmascript',
  'application/x-javascript', 'text/ecmascript', 'text/javascript',
  'text/javascript1.0', 'text/javascript1.1', 'text/javascript1.2',
  'text/javascript1.3', 'text/javascript1.4', 'text/javascript1.5',
  'text/jscript', 'text/livescript', 'text/x-ecmascript', 'text/x-javascript'
]);
const HANDLER_PREFIX = 'function __mvx_event_handler__(){';
const HANDLER_SUFFIX = '\n}';
// Fixed browser event-handler profile: WHATWG HTML plus Pointer Events, Touch
// Events, Selection API, and CSS animation, transition, and scroll-snap mixins.
const HTML_EVENT_HANDLER_ATTRIBUTES = new Set([
  'onabort', 'onanimationcancel', 'onanimationend', 'onanimationiteration',
  'onanimationstart', 'onauxclick', 'onbeforeinput', 'onbeforematch',
  'onbeforetoggle', 'onblur', 'oncancel', 'oncanplay', 'oncanplaythrough',
  'onchange', 'onclick', 'onclose', 'oncommand', 'oncontextlost',
  'oncontextmenu', 'oncontextrestored', 'oncopy', 'oncuechange', 'oncut',
  'ondblclick', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave',
  'ondragover', 'ondragstart', 'ondrop', 'ondurationchange', 'onemptied',
  'onended', 'onerror', 'onfocus', 'onformdata', 'ongotpointercapture',
  'oninput', 'oninvalid', 'onkeydown', 'onkeypress', 'onkeyup', 'onload',
  'onloadeddata', 'onloadedmetadata', 'onloadstart', 'onlostpointercapture',
  'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout',
  'onmouseover', 'onmouseup', 'onpaste', 'onpause', 'onplay', 'onplaying',
  'onpointercancel', 'onpointerdown', 'onpointerenter', 'onpointerleave',
  'onpointermove', 'onpointerout', 'onpointerover', 'onpointerrawupdate',
  'onpointerup', 'onprogress', 'onratechange', 'onreset', 'onresize',
  'onscroll', 'onscrollend', 'onscrollsnapchange', 'onscrollsnapchanging',
  'onsecuritypolicyviolation', 'onseeked', 'onseeking', 'onselect',
  'onselectionchange', 'onselectstart', 'onslotchange', 'onstalled',
  'onsubmit', 'onsuspend', 'ontimeupdate', 'ontoggle', 'ontouchcancel',
  'ontouchend', 'ontouchmove', 'ontouchstart', 'ontransitioncancel',
  'ontransitionend', 'ontransitionrun', 'ontransitionstart', 'onvolumechange',
  'onwaiting', 'onwebkitanimationend', 'onwebkitanimationiteration',
  'onwebkitanimationstart', 'onwebkittransitionend', 'onwheel'
]);
const WINDOW_EVENT_HANDLER_ATTRIBUTES = new Set([
  'onafterprint', 'onbeforeprint', 'onbeforeunload', 'onhashchange',
  'onlanguagechange', 'onmessage', 'onmessageerror', 'onoffline', 'ononline',
  'onpagehide', 'onpagereveal', 'onpageshow', 'onpageswap', 'onpopstate',
  'onrejectionhandled', 'onstorage', 'onunhandledrejection', 'onunload'
]);
const HTML_CHARACTER_REFERENCES = Object.freeze({
  AMP: '&', amp: '&', apos: "'", bsol: '\\', colon: ':', comma: ',', dollar: '$',
  equals: '=', excl: '!', grave: '`', GT: '>', gt: '>', lcub: '{', lpar: '(',
  lsqb: '[', LT: '<', lt: '<', minus: '-', NewLine: '\n', num: '#', period: '.',
  plus: '+', quest: '?', QUOT: '"', quot: '"', rcub: '}', rpar: ')', rsqb: ']',
  semi: ';', sol: '/', Tab: '\t'
});

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

function isHtmlSpace(character) {
  return character === ' ' || character === '\t' || character === '\n'
    || character === '\f' || character === '\r';
}

function trimHtmlSpace(value) {
  return value.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
}

function asciiLower(value) {
  return value.replace(
    /[A-Z]/g, (character) => String.fromCharCode(character.charCodeAt(0) + 32)
  );
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

function chargeStringAttempt(raw, budget, limits) {
  const characters = Math.max(0, raw.length - 2);
  startAttempt(budget, limits);
  checkAttemptCharacters(budget, limits, characters);
  budget.candidateEncodedChars += characters;
  return {
    encoded: raw.slice(1, -1),
    escaped: raw.slice(1, -1).includes('\\')
  };
}

function chargeMalformedSource(segment, budget, limits) {
  const pattern = /(?<![$\u200c\u200d\p{ID_Continue}])atob\s*\(\s*(['"])/gu;
  for (let match = pattern.exec(segment); match; match = pattern.exec(segment)) {
    const quote = pattern.lastIndex - 1;
    startAttempt(budget, limits);
    let cursor = quote + 1;
    while (cursor < segment.length && !isLineTerminator(segment[cursor])) {
      const character = segment[cursor];
      if (character === match[1]) { cursor += 1; break; }
      cursor = Math.min(segment.length, cursor + (character === '\\' ? 2 : 1));
      checkAttemptCharacters(budget, limits, cursor - quote - 1);
    }
    const characters = Math.max(0, cursor - quote - 1 - (segment[cursor - 1] === match[1] ? 1 : 0));
    checkAttemptCharacters(budget, limits, characters);
    budget.candidateEncodedChars += characters;
    pattern.lastIndex = Math.max(pattern.lastIndex, cursor);
  }
}

function parseJavaScriptGoal(segment, sourceType, parserBudget, limits, handler = false) {
  const prefix = handler ? HANDLER_PREFIX : '';
  const input = handler ? `${prefix}${segment}${HANDLER_SUFFIX}` : segment;
  const chargeAstNode = () => {
    parserBudget.astNodes += 1;
    if (parserBudget.astNodes > limits.maxAstNodes) {
      throw new MvxError(`ECMAScript AST nodes exceed ${limits.maxAstNodes}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  };
  class BoundedParser extends Parser {
    startNode() {
      chargeAstNode();
      return super.startNode();
    }

    startNodeAt(position, location) {
      chargeAstNode();
      return super.startNodeAt(position, location);
    }

    copyNode(node) {
      chargeAstNode();
      return super.copyNode(node);
    }
  }
  const options = {
    allowHashBang: true,
    ecmaVersion: 'latest',
    onToken: () => {
      parserBudget.parserTokens += 1;
      if (parserBudget.parserTokens > limits.maxParserTokens) {
        throw new MvxError(`ECMAScript tokens exceed ${limits.maxParserTokens}`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
    },
    sourceType
  };
  try {
    return { offset: prefix.length, program: BoundedParser.parse(input, options) };
  } catch (error) {
    if (error instanceof MvxError) throw error;
    if (error instanceof SyntaxError && /^Not enough stack space to parse input\b/.test(error.message)) {
      throw new MvxError('ECMAScript parser exhausted its stack safety bound', {
        code: 'ENCODED_PAYLOAD_LIMIT', cause: error
      });
    }
    if (!(error instanceof SyntaxError)) {
      throw new MvxError('ECMAScript parser exceeded a safe runtime resource', {
        code: 'ENCODED_PAYLOAD_LIMIT', cause: error
      });
    }
    return null;
  }
}

function parseJavaScript(segment, mode, parserBudget, limits) {
  if (mode === 'script') {
    return parseJavaScriptGoal(segment, 'script', parserBudget, limits);
  }
  if (mode === 'module') {
    return parseJavaScriptGoal(segment, 'module', parserBudget, limits);
  }
  if (mode === 'handler') {
    return parseJavaScriptGoal(segment, 'script', parserBudget, limits, true);
  }
  const script = parseJavaScriptGoal(segment, 'script', parserBudget, limits);
  return script ?? parseJavaScriptGoal(segment, 'module', parserBudget, limits);
}

function directAtobCall(node) {
  if (node.type !== 'CallExpression') return false;
  if (node.callee.type === 'Identifier') return node.callee.name === 'atob';
  return node.callee.type === 'MemberExpression'
    && !node.callee.computed
    && node.callee.object.type === 'Identifier'
    && ['globalThis', 'self', 'window'].includes(node.callee.object.name)
    && node.callee.property.type === 'Identifier'
    && node.callee.property.name === 'atob';
}

function* javascriptAtobLiterals(
  content, start, end, starts, budget, limits, originalOffsets = null, mode = 'unknown'
) {
  const segment = content.slice(start, end);
  const parsed = parseJavaScript(segment, mode, budget, limits);
  if (!parsed) {
    chargeMalformedSource(segment, budget, limits);
    return;
  }
  const { offset, program } = parsed;
  const stack = [program];
  while (stack.length > 0) {
    const node = stack.pop();
    if (directAtobCall(node)) {
      const first = node.arguments[0];
      if (first?.type === 'Literal' && typeof first.value === 'string') {
        const literalStart = first.start - offset;
        const literalEnd = first.end - offset;
        const calleeStart = node.callee.start - offset;
        const raw = segment.slice(literalStart, literalEnd);
        if (raw[0] === "'" || raw[0] === '"') {
          const original = originalOffsets?.[calleeStart] ?? start + calleeStart;
          yield {
            ...chargeStringAttempt(raw, budget, limits),
            line: lineAt(starts, original)
          };
        }
      }
    }
    const children = [];
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) if (child?.type) children.push(child);
      } else if (value?.type) children.push(value);
    }
    for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
  }
}

function parseTag(content, start, end) {
  let cursor = start + 1;
  let closing = false;
  if (content[cursor] === '/') { closing = true; cursor += 1; }
  while (isHtmlSpace(content[cursor])) cursor += 1;
  const nameStart = cursor;
  while (/[A-Za-z0-9:-]/.test(content[cursor] ?? '')) cursor += 1;
  if (cursor === nameStart) return null;
  const name = asciiLower(content.slice(nameStart, cursor));
  const attributes = [];
  while (cursor < end) {
    while (isHtmlSpace(content[cursor])) cursor += 1;
    if (content[cursor] === '>') return { name, closing, attributes, end: cursor + 1 };
    if (content[cursor] === '/' && content[cursor + 1] === '>') {
      return { name, closing, attributes, end: cursor + 2 };
    }
    const attributeStart = cursor;
    while (cursor < end && !isHtmlSpace(content[cursor])
      && !['=', '>', '/'].includes(content[cursor])) cursor += 1;
    if (cursor === attributeStart) { cursor += 1; continue; }
    const attribute = { name: asciiLower(content.slice(attributeStart, cursor)) };
    while (isHtmlSpace(content[cursor])) cursor += 1;
    if (content[cursor] === '=') {
      cursor += 1;
      while (isHtmlSpace(content[cursor])) cursor += 1;
      const quote = content[cursor];
      if (quote === "'" || quote === '"') {
        attribute.valueStart = cursor + 1;
        const close = content.indexOf(quote, attribute.valueStart);
        attribute.valueEnd = close === -1 || close >= end ? end : close;
        cursor = close === -1 || close >= end ? end : close + 1;
      } else {
        attribute.valueStart = cursor;
        while (cursor < end && !isHtmlSpace(content[cursor]) && content[cursor] !== '>') cursor += 1;
        attribute.valueEnd = cursor;
      }
      attribute.value = content.slice(attribute.valueStart, attribute.valueEnd);
    }
    attributes.push(attribute);
  }
  return null;
}

function decodeHtmlAttribute(content, start, end) {
  let decoded = '';
  const offsets = [];
  let cursor = start;
  while (cursor < end) {
    let replacement = null;
    let consumed = 0;
    if (content[cursor] === '&') {
      const tail = content.slice(cursor, Math.min(end, cursor + 40));
      const numeric = tail.match(/^&#(?:x([0-9A-Fa-f]+)|([0-9]+));?/);
      if (numeric) {
        const value = Number.parseInt(numeric[1] ?? numeric[2], numeric[1] ? 16 : 10);
        replacement = value > 0 && value <= 0x10ffff && !(value >= 0xd800 && value <= 0xdfff)
          ? String.fromCodePoint(value)
          : '\ufffd';
        consumed = numeric[0].length;
      } else {
        const named = tail.match(/^&([A-Za-z][A-Za-z0-9]+);/);
        if (named && Object.hasOwn(HTML_CHARACTER_REFERENCES, named[1])) {
          replacement = HTML_CHARACTER_REFERENCES[named[1]];
          consumed = named[0].length;
        }
      }
    }
    if (replacement !== null) {
      decoded += replacement;
      for (let index = 0; index < replacement.length; index += 1) offsets.push(cursor);
      cursor += consumed;
    } else {
      decoded += content[cursor];
      offsets.push(cursor);
      cursor += 1;
    }
  }
  offsets.push(end);
  return { content: decoded, offsets };
}

function asciiEqualAt(content, index, expected) {
  if (index + expected.length > content.length) return false;
  for (let offset = 0; offset < expected.length; offset += 1) {
    const actualCode = content.charCodeAt(index + offset);
    const folded = actualCode >= 65 && actualCode <= 90 ? actualCode + 32 : actualCode;
    if (folded !== expected.charCodeAt(offset)) return false;
  }
  return true;
}

function findScriptEnd(content, start) {
  let cursor = start;
  while (cursor < content.length) {
    const open = content.indexOf('<', cursor);
    if (open === -1) return -1;
    if (asciiEqualAt(content, open, '</script')) {
      const boundary = content[open + 8];
      if (boundary === '>' || boundary === '/' || isHtmlSpace(boundary)) return open;
    }
    cursor = open + 1;
  }
  return -1;
}

function scriptMode(content, tag) {
  if (tag.attributes.some((attribute) => attribute.name === 'src')) return null;
  const type = tag.attributes.find((attribute) => attribute.name === 'type');
  let mode;
  if (type) {
    const decoded = type.valueStart === undefined ? ''
      : decodeHtmlAttribute(content, type.valueStart, type.valueEnd).content;
    const normalized = asciiLower(trimHtmlSpace(decoded));
    mode = normalized === '' || JAVASCRIPT_TYPES.has(normalized) ? 'script'
      : normalized === 'module' ? 'module' : null;
  } else {
    const language = tag.attributes.find((attribute) => attribute.name === 'language');
    if (!language || language.valueStart === undefined) {
      mode = 'script';
    } else {
      const decoded = decodeHtmlAttribute(
        content, language.valueStart, language.valueEnd
      ).content;
      const normalized = asciiLower(decoded);
      mode = normalized === '' || JAVASCRIPT_TYPES.has(`text/${normalized}`) ? 'script' : null;
    }
  }
  if (mode === 'script' && tag.attributes.some((attribute) => attribute.name === 'nomodule')) {
    return null;
  }
  const event = tag.attributes.find((attribute) => attribute.name === 'event');
  const target = tag.attributes.find((attribute) => attribute.name === 'for');
  if (mode === 'script' && event && target) {
    const eventValue = event.valueStart === undefined ? '' : trimHtmlSpace(
      decodeHtmlAttribute(content, event.valueStart, event.valueEnd).content
    );
    const targetValue = target.valueStart === undefined ? '' : trimHtmlSpace(
      decodeHtmlAttribute(content, target.valueStart, target.valueEnd).content
    );
    if (asciiLower(targetValue) !== 'window'
      || !['onload', 'onload()'].includes(asciiLower(eventValue))) return null;
  }
  return mode;
}

function* htmlAtobLiterals(content, starts, budget, limits) {
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
        const eventHandler = HTML_EVENT_HANDLER_ATTRIBUTES.has(attribute.name)
          || (['body', 'frameset'].includes(tag.name)
            && WINDOW_EVENT_HANDLER_ATTRIBUTES.has(attribute.name));
        if (eventHandler && attribute.valueStart !== undefined) {
          const decoded = decodeHtmlAttribute(
            content, attribute.valueStart, attribute.valueEnd
          );
          yield* javascriptAtobLiterals(
            decoded.content, 0, decoded.content.length, starts, budget, limits,
            decoded.offsets, 'handler'
          );
        }
      }
    }
    if (!tag.closing && tag.name === 'script') {
      const close = findScriptEnd(content, tag.end);
      const bodyEnd = close === -1 ? content.length : close;
      const mode = scriptMode(content, tag);
      if (mode) {
        yield* javascriptAtobLiterals(
          content, tag.end, bodyEnd, starts, budget, limits, null, mode
        );
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
    source.content, 0, source.content.length, starts, budget, limits, null,
    source.depth > 0 ? 'unknown' : /\.mjs$/i.test(source.path) ? 'module'
      : /\.cjs$/i.test(source.path) ? 'script' : 'unknown'
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
  const candidateBudget = {
    candidates: 0,
    candidateEncodedChars: 0,
    parserTokens: 0,
    astNodes: 0
  };
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
    parserTokens: candidateBudget.parserTokens,
    astNodes: candidateBudget.astNodes,
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
