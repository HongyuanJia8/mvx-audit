import { createHash } from 'node:crypto';
import { Parser as AcornParser } from 'acorn';
import { DecodingMode, EntityDecoder, htmlDecodeTree } from 'entities/decode';
import {
  defaultTreeAdapter, Parser as HtmlParser, Tokenizer as HtmlTokenizer
} from 'parse5';
import { SaxesParser } from 'saxes';
import {
  BROWSER_EVENT_HANDLER_PROFILE, htmlEventHandlerMode
} from './browser-event-handlers.js';
import { MvxError } from './errors.js';
import { createFinding, REFERENCES } from './model.js';
import { assertOptionsObject } from './options.js';
import { lineAt, lineStarts } from './text-locations.js';

export const ENCODED_PAYLOAD_PROFILE = 'mvx-encoded-payloads-v1';
export const ENCODED_PAYLOAD_PARSER_PROFILES = Object.freeze({
  ecmascript: 'acorn-8.18.0',
  html: 'parse5-7.3.0',
  htmlEntities: 'entities-6.0.1',
  xml: 'saxes-6.0.0',
  xmlCharacters: 'xmlchars-2.2.0'
});
export const ENCODED_PAYLOAD_LIMITS = Object.freeze({
  maxCandidates: 4_096,
  maxPayloads: 128,
  maxEncodedChars: 1_500_000,
  maxTotalEncodedChars: 8_000_000,
  maxDecodedBytes: 1_000_000,
  maxTotalDecodedBytes: 5_000_000,
  maxParserTokens: 1_000_000,
  maxAstNodes: 2_000_000,
  maxHtmlTokens: 1_000_000,
  maxHtmlAttributes: 16_384,
  maxHtmlNodes: 100_000,
  maxHtmlTreeDepth: 2_048,
  maxHtmlTreeWork: 4_000_000,
  maxHtmlDocumentDepth: 16,
  maxNestedHtmlChars: 5_000_000,
  maxXmlEntityDeclarations: 256,
  maxXmlEntityDepth: 16,
  maxXmlExpandedChars: 1_000_000,
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
const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';
const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
const XLINK_NAMESPACE = 'http://www.w3.org/1999/xlink';
const HANDLER_PREFIX = 'function __mvx_event_handler__(event){';
const ERROR_HANDLER_PREFIX =
  'function __mvx_event_handler__(event, source, lineno, colno, error){';
const SVG_HANDLER_PREFIX = 'function __mvx_event_handler__(evt){';
const HANDLER_SUFFIX = '\n}';

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

function parseJavaScriptGoal(segment, sourceType, parserBudget, limits, handler = null) {
  const prefix = handler === 'error' ? ERROR_HANDLER_PREFIX
    : handler === 'event' ? HANDLER_PREFIX
      : handler === 'svg-event' ? SVG_HANDLER_PREFIX : '';
  const input = handler ? `${prefix}${segment}${HANDLER_SUFFIX}` : segment;
  const chargeAstNode = () => {
    parserBudget.astNodes += 1;
    if (parserBudget.astNodes > limits.maxAstNodes) {
      throw new MvxError(`ECMAScript AST nodes exceed ${limits.maxAstNodes}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  };
  class BoundedParser extends AcornParser {
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
    return parseJavaScriptGoal(segment, 'script', parserBudget, limits, 'event');
  }
  if (mode === 'error-handler') {
    return parseJavaScriptGoal(segment, 'script', parserBudget, limits, 'error');
  }
  if (mode === 'svg-handler') {
    return parseJavaScriptGoal(segment, 'script', parserBudget, limits, 'svg-event');
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

function decodeHtmlRange(content, start, end, mode) {
  let decoded = '';
  const offsets = [];
  const raw = content.slice(start, end);
  let entityOffset = start;
  const decoder = new EntityDecoder(htmlDecodeTree, (codePoint) => {
    const replacement = String.fromCodePoint(codePoint);
    decoded += replacement;
    for (let index = 0; index < replacement.length; index += 1) {
      offsets.push(entityOffset);
    }
  });
  let cursor = 0;
  while (cursor < raw.length) {
    const ampersand = raw.indexOf('&', cursor);
    const literalEnd = ampersand === -1 ? raw.length : ampersand;
    while (cursor < literalEnd) {
      decoded += raw[cursor];
      offsets.push(start + cursor);
      cursor += 1;
    }
    if (ampersand === -1) break;
    entityOffset = start + ampersand;
    decoder.startEntity(mode);
    let consumed = decoder.write(raw, ampersand + 1);
    if (consumed < 0) consumed = decoder.end();
    if (consumed === 0) {
      decoded += '&';
      offsets.push(entityOffset);
      cursor = ampersand + 1;
    } else cursor = ampersand + consumed;
  }
  offsets.push(end);
  return { content: decoded, offsets };
}

function decodeHtmlAttribute(content, start, end) {
  return decodeHtmlRange(content, start, end, DecodingMode.Attribute);
}

function decodeHtmlText(content, start, end) {
  return decodeHtmlRange(content, start, end, DecodingMode.Legacy);
}

function composeOriginalOffsets(offsets, parentOffsets) {
  if (!parentOffsets) return offsets;
  const fallback = parentOffsets.at(-1);
  return offsets.map((offset) => parentOffsets[offset] ?? fallback);
}

function originalOffsetsForRange(parentOffsets, start, end) {
  return parentOffsets ? parentOffsets.slice(start, end + 1) : null;
}

function decodeSvgTextRange(content, start, end) {
  let decoded = '';
  const offsets = [];
  let cursor = start;
  let finalOffset = end;
  while (cursor < end) {
    const marker = content.indexOf('<![CDATA[', cursor);
    if (marker < 0 || marker >= end) {
      const part = decodeHtmlText(content, cursor, end);
      decoded += part.content;
      offsets.push(...part.offsets.slice(0, -1));
      finalOffset = part.offsets.at(-1);
      break;
    }
    const prefix = decodeHtmlText(content, cursor, marker);
    decoded += prefix.content;
    offsets.push(...prefix.offsets.slice(0, -1));
    const close = content.indexOf(']]>', marker + 9);
    const valueEnd = close < 0 || close >= end ? end : close;
    for (let index = marker + 9; index < valueEnd; index += 1) {
      decoded += content[index];
      offsets.push(index);
    }
    cursor = close < 0 || close >= end ? end : close + 3;
    finalOffset = cursor;
  }
  offsets.push(finalOffset);
  return { content: decoded, offsets };
}

function decodeSvgScript(content, node) {
  let decoded = '';
  const offsets = [];
  let finalOffset = node.sourceCodeLocation.startTag.endOffset;
  for (const child of node.childNodes ?? []) {
    if (child.nodeName !== '#text' || !child.sourceCodeLocation) continue;
    const part = decodeSvgTextRange(
      content,
      child.sourceCodeLocation.startOffset,
      child.sourceCodeLocation.endOffset
    );
    decoded += part.content;
    offsets.push(...part.offsets.slice(0, -1));
    finalOffset = part.offsets.at(-1);
  }
  offsets.push(finalOffset);
  return { content: decoded, offsets };
}

function attributeValueBounds(content, location) {
  let cursor = location.startOffset;
  while (cursor < location.endOffset && !isHtmlSpace(content[cursor])
    && content[cursor] !== '=') cursor += 1;
  while (cursor < location.endOffset && isHtmlSpace(content[cursor])) cursor += 1;
  if (content[cursor] !== '=') return null;
  cursor += 1;
  while (cursor < location.endOffset && isHtmlSpace(content[cursor])) cursor += 1;
  const quote = content[cursor];
  if (quote === "'" || quote === '"') {
    return { start: cursor + 1, end: Math.max(cursor + 1, location.endOffset - 1) };
  }
  return { start: cursor, end: location.endOffset };
}

function parseBoundedHtml(content, budget, limits) {
  let activeStartTag = null;
  const mergedAttributeLocations = new WeakMap();
  const adoptedAttributeNames = new WeakMap();
  const chargeTreeWork = (units) => {
    budget.htmlTreeWork += units;
    if (budget.htmlTreeWork > limits.maxHtmlTreeWork) {
      throw new MvxError(`HTML tree-construction work exceeds ${limits.maxHtmlTreeWork}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  };
  const chargeNode = () => {
    budget.htmlNodes += 1;
    if (budget.htmlNodes > limits.maxHtmlNodes) {
      throw new MvxError(`HTML node allocations exceed ${limits.maxHtmlNodes}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  };
  const adapter = {
    ...defaultTreeAdapter,
    createDocument() {
      chargeNode();
      return defaultTreeAdapter.createDocument();
    },
    createDocumentFragment() {
      chargeNode();
      return defaultTreeAdapter.createDocumentFragment();
    },
    createElement(tagName, namespaceURI, attrs) {
      chargeNode();
      return defaultTreeAdapter.createElement(tagName, namespaceURI, attrs);
    },
    createCommentNode(data) {
      chargeNode();
      return defaultTreeAdapter.createCommentNode(data);
    },
    createTextNode(value) {
      chargeNode();
      return defaultTreeAdapter.createTextNode(value);
    },
    setDocumentType(document, name, publicId, systemId) {
      if (!document.childNodes.some((node) => node.nodeName === '#documentType')) chargeNode();
      defaultTreeAdapter.setDocumentType(document, name, publicId, systemId);
    },
    insertText(parentNode, value) {
      const previous = parentNode.childNodes.at(-1);
      if (!previous || !defaultTreeAdapter.isTextNode(previous)) chargeNode();
      defaultTreeAdapter.insertText(parentNode, value);
    },
    insertTextBefore(parentNode, value, referenceNode) {
      const previous = parentNode.childNodes[
        parentNode.childNodes.indexOf(referenceNode) - 1
      ];
      if (!previous || !defaultTreeAdapter.isTextNode(previous)) chargeNode();
      defaultTreeAdapter.insertTextBefore(parentNode, value, referenceNode);
    },
    adoptAttributes(recipient, attrs) {
      chargeTreeWork(attrs.length);
      let existing = adoptedAttributeNames.get(recipient);
      if (!existing) {
        existing = new Set(recipient.attrs.map((attribute) => attribute.name));
        adoptedAttributeNames.set(recipient, existing);
      }
      const locations = activeStartTag?.location?.attrs ?? {};
      for (const attribute of attrs) {
        if (existing.has(attribute.name)) continue;
        existing.add(attribute.name);
        recipient.attrs.push(attribute);
        if (locations[attribute.name]) {
          let merged = mergedAttributeLocations.get(recipient);
          if (!merged) {
            merged = new Map();
            mergedAttributeLocations.set(recipient, merged);
          }
          merged.set(attribute.name, locations[attribute.name]);
        }
      }
    }
  };
  const chargeToken = () => {
    budget.htmlTokens += 1;
    if (budget.htmlTokens > limits.maxHtmlTokens) {
      throw new MvxError(`HTML tokens exceed ${limits.maxHtmlTokens}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  };
  const chargeTagWork = (parser) => {
    const depth = Math.max(1, parser.openElements.stackTop + 2);
    budget.htmlMaxDepth = Math.max(budget.htmlMaxDepth, depth);
    if (depth > limits.maxHtmlTreeDepth) {
      throw new MvxError(`HTML tree depth exceeds ${limits.maxHtmlTreeDepth}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
    chargeTreeWork(depth);
  };
  class BoundedHtmlTokenizer extends HtmlTokenizer {
    _createAttr(firstCharacter) {
      budget.htmlAttributes += 1;
      if (budget.htmlAttributes > limits.maxHtmlAttributes) {
        throw new MvxError(`HTML attributes exceed ${limits.maxHtmlAttributes}`, {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      return super._createAttr(firstCharacter);
    }
  }
  class BoundedHtmlParser extends HtmlParser {
    constructor(options) {
      super(options);
      this.tokenizer = new BoundedHtmlTokenizer(this.options, this);
    }

    onStartTag(token) {
      chargeToken();
      chargeTagWork(this);
      activeStartTag = token;
      try {
        return super.onStartTag(token);
      } finally {
        activeStartTag = null;
      }
    }

    onEndTag(token) {
      chargeToken();
      chargeTagWork(this);
      return super.onEndTag(token);
    }

    onComment(token) { chargeToken(); return super.onComment(token); }

    onDoctype(token) { chargeToken(); return super.onDoctype(token); }

    onCharacter(token) { chargeToken(); return super.onCharacter(token); }

    onNullCharacter(token) { chargeToken(); return super.onNullCharacter(token); }

    onWhitespaceCharacter(token) {
      chargeToken();
      return super.onWhitespaceCharacter(token);
    }

    onEof(token) { chargeToken(); return super.onEof(token); }
  }
  try {
    return {
      document: BoundedHtmlParser.parse(content, {
        sourceCodeLocationInfo: true,
        treeAdapter: adapter
      }),
      mergedAttributeLocations
    };
  } catch (error) {
    if (error instanceof MvxError) throw error;
    throw new MvxError('HTML parser exceeded a safe runtime resource', {
      code: 'ENCODED_PAYLOAD_LIMIT', cause: error
    });
  }
}

function sourceTag(content, node, mergedAttributeLocations) {
  const locations = node.sourceCodeLocation?.attrs ?? {};
  const mergedLocations = mergedAttributeLocations.get(node) ?? new Map();
  return {
    name: node.tagName,
    attributes: node.attrs.map((attribute) => {
      const location = locations[attribute.name] ?? mergedLocations.get(attribute.name);
      const bounds = location ? attributeValueBounds(content, location) : null;
      return {
        name: attribute.name,
        ...(bounds ? { valueStart: bounds.start, valueEnd: bounds.end } : {})
      };
    })
  };
}

function scriptModeForValues(attributes, namespace) {
  if (namespace !== HTML_NAMESPACE && namespace !== SVG_NAMESPACE) return null;
  if (namespace === HTML_NAMESPACE
    && attributes.some((attribute) => attribute.name === 'src')) return null;
  if (namespace === SVG_NAMESPACE
    && attributes.some((attribute) => attribute.name === 'href')) return null;
  const type = attributes.find((attribute) => attribute.name === 'type');
  let mode;
  if (type) {
    const normalized = asciiLower(trimHtmlSpace(type.value));
    mode = normalized === '' || JAVASCRIPT_TYPES.has(normalized) ? 'script'
      : normalized === 'module' ? 'module' : null;
  } else if (namespace === SVG_NAMESPACE) {
    mode = 'script';
  } else {
    const language = attributes.find((attribute) => attribute.name === 'language');
    if (!language) {
      mode = 'script';
    } else {
      const normalized = asciiLower(language.value);
      mode = normalized === '' || JAVASCRIPT_TYPES.has(`text/${normalized}`) ? 'script' : null;
    }
  }
  if (namespace === SVG_NAMESPACE) return mode;
  if (mode === 'script' && attributes.some((attribute) => attribute.name === 'nomodule')) {
    return null;
  }
  const event = attributes.find((attribute) => attribute.name === 'event');
  const target = attributes.find((attribute) => attribute.name === 'for');
  if (mode === 'script' && event && target) {
    const eventValue = trimHtmlSpace(event.value);
    const targetValue = trimHtmlSpace(target.value);
    if (asciiLower(targetValue) !== 'window'
      || !['onload', 'onload()'].includes(asciiLower(eventValue))) return null;
  }
  return mode;
}

function scriptMode(content, tag, namespace) {
  return scriptModeForValues(tag.attributes.map((attribute) => ({
    name: attribute.name,
    value: attribute.valueStart === undefined ? '' : decodeHtmlAttribute(
      content, attribute.valueStart, attribute.valueEnd
    ).content
  })), namespace);
}

function* htmlAtobLiterals(
  content, starts, budget, limits, originalOffsets = null, documentDepth = 1
) {
  if (documentDepth > limits.maxHtmlDocumentDepth) {
    throw new MvxError(`HTML document depth exceeds ${limits.maxHtmlDocumentDepth}`, {
      code: 'ENCODED_PAYLOAD_LIMIT'
    });
  }
  budget.htmlMaxDocumentDepth = Math.max(
    budget.htmlMaxDocumentDepth, documentDepth
  );
  if (documentDepth > 1) {
    budget.htmlNestedChars += content.length;
    if (budget.htmlNestedChars > limits.maxNestedHtmlChars) {
      throw new MvxError(`Nested HTML exceeds ${limits.maxNestedHtmlChars} characters`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  }
  const { document, mergedAttributeLocations } = parseBoundedHtml(
    content, budget, limits
  );
  const stack = [{ node: document, inTemplate: false }];
  while (stack.length > 0) {
    const { node, inTemplate } = stack.pop();
    if (node.tagName && (node.sourceCodeLocation?.startTag
      || mergedAttributeLocations.has(node))) {
      const tag = sourceTag(content, node, mergedAttributeLocations);
      for (const attribute of tag.attributes) {
        const mode = htmlEventHandlerMode(
          node.namespaceURI, tag.name, attribute.name
        );
        if (mode && attribute.valueStart !== undefined) {
          const decoded = decodeHtmlAttribute(
            content, attribute.valueStart, attribute.valueEnd
          );
          yield* javascriptAtobLiterals(
            decoded.content, 0, decoded.content.length, starts, budget, limits,
            composeOriginalOffsets(decoded.offsets, originalOffsets), mode
          );
        }
      }
      if (node.namespaceURI === HTML_NAMESPACE && tag.name === 'iframe') {
        const srcdoc = tag.attributes.find((attribute) => attribute.name === 'srcdoc');
        const sandbox = tag.attributes.find((attribute) => attribute.name === 'sandbox');
        const sandboxValue = sandbox?.valueStart === undefined ? '' : decodeHtmlAttribute(
          content, sandbox.valueStart, sandbox.valueEnd
        ).content;
        const allowsScripts = !sandbox || asciiLower(trimHtmlSpace(sandboxValue))
          .split(/[\t\n\f\r ]+/).includes('allow-scripts');
        if (srcdoc?.valueStart !== undefined && allowsScripts) {
          const decoded = decodeHtmlAttribute(
            content, srcdoc.valueStart, srcdoc.valueEnd
          );
          yield* htmlAtobLiterals(
            decoded.content,
            starts,
            budget,
            limits,
            composeOriginalOffsets(decoded.offsets, originalOffsets),
            documentDepth + 1
          );
        }
      }
      if (tag.name === 'script' && node.sourceCodeLocation?.startTag && !inTemplate) {
        const bodyStart = node.sourceCodeLocation.startTag.endOffset;
        const bodyEnd = node.sourceCodeLocation.endTag?.startOffset ?? content.length;
        const mode = scriptMode(content, tag, node.namespaceURI);
        if (mode) {
          if (node.namespaceURI === SVG_NAMESPACE) {
            const decoded = decodeSvgScript(content, node);
            yield* javascriptAtobLiterals(
              decoded.content, 0, decoded.content.length, starts, budget, limits,
              composeOriginalOffsets(decoded.offsets, originalOffsets), mode
            );
          } else {
            yield* javascriptAtobLiterals(
              content, bodyStart, bodyEnd, starts, budget, limits,
              originalOffsetsForRange(originalOffsets, bodyStart, bodyEnd), mode
            );
          }
        }
      }
    }
    const children = (node.childNodes ?? []).map((child) => ({
      node: child, inTemplate
    }));
    if (node.content) children.push({ node: node.content, inTemplate: true });
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push(children[index]);
    }
  }
}

const XML_ENTITIES = Object.freeze(Object.assign(Object.create(null), {
  amp: '&', apos: "'", gt: '>', lt: '<', quot: '"'
}));

function decodeXmlSourceRange(
  content, start, end,
  {
    attribute = false, entities = true, entityValues = XML_ENTITIES,
    version = '1.0'
  } = {}
) {
  let decoded = '';
  let parserDecoded = '';
  const offsets = [];
  let cursor = start;
  while (cursor < end) {
    const character = content[cursor];
    if (character === '\r') {
      const replacement = attribute ? ' ' : '\n';
      decoded += replacement;
      parserDecoded += replacement;
      offsets.push(cursor);
      cursor += content[cursor + 1] === '\n'
        || (version === '1.1' && content[cursor + 1] === '\u0085') ? 2 : 1;
      continue;
    }
    if (version === '1.1' && (character === '\u0085' || character === '\u2028')) {
      const replacement = attribute ? ' ' : '\n';
      decoded += replacement;
      parserDecoded += replacement;
      offsets.push(cursor);
      cursor += 1;
      continue;
    }
    if (attribute && (character === '\n' || character === '\t')) {
      decoded += ' ';
      parserDecoded += ' ';
      offsets.push(cursor);
      cursor += 1;
      continue;
    }
    if (entities && character === '&') {
      const semicolon = content.indexOf(';', cursor + 1);
      if (semicolon < 0 || semicolon >= end) {
        throw new MvxError('XML entity source mapping is incomplete', {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      const entity = content.slice(cursor + 1, semicolon);
      let replacement = entityValues[entity];
      if (replacement === undefined && /^#x[0-9a-f]+$/i.test(entity)) {
        replacement = String.fromCodePoint(Number.parseInt(entity.slice(2), 16));
      } else if (replacement === undefined && /^#[0-9]+$/.test(entity)) {
        replacement = String.fromCodePoint(Number.parseInt(entity.slice(1), 10));
      }
      if (replacement === undefined) {
        throw new MvxError('XML entity source mapping is unsupported', {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      parserDecoded += replacement;
      const normalized = attribute && !entity.startsWith('#')
        && !Object.hasOwn(XML_ENTITIES, entity)
        ? replacement.replace(
          /[\t\n\r]/g, ' '
        ) : replacement;
      decoded += normalized;
      for (let index = 0; index < normalized.length; index += 1) offsets.push(cursor);
      cursor = semicolon + 1;
      continue;
    }
    decoded += character;
    parserDecoded += character;
    offsets.push(cursor);
    cursor += 1;
  }
  offsets.push(end);
  return { content: decoded, offsets, parserContent: parserDecoded };
}

function xmlLineStarts(content, version = '1.0') {
  const starts = [0];
  for (let index = 0; index < content.length; index += 1) {
    const character = content[index];
    if (character === '\r') {
      if (content[index + 1] === '\n'
        || (version === '1.1' && content[index + 1] === '\u0085')) index += 1;
      starts.push(index + 1);
    } else if (character === '\n' || character === '\u2028' || character === '\u2029'
      || (version === '1.1' && character === '\u0085')) {
      starts.push(index + 1);
    }
  }
  return starts;
}

function invalidXmlDtd(message) {
  return new MvxError(message, { code: 'INVALID_INPUT' });
}

function xmlCharacterReference(reference, version) {
  let codePoint;
  if (/^#x[0-9a-f]+$/i.test(reference)) {
    codePoint = Number.parseInt(reference.slice(2), 16);
  } else if (/^#[0-9]+$/.test(reference)) {
    codePoint = Number.parseInt(reference.slice(1), 10);
  } else return undefined;
  const valid = version === '1.1'
    ? (codePoint >= 0x1 && codePoint <= 0xd7ff)
      || (codePoint >= 0xe000 && codePoint <= 0xfffd)
      || (codePoint >= 0x10000 && codePoint <= 0x10ffff)
    : codePoint === 0x9 || codePoint === 0xa || codePoint === 0xd
      || (codePoint >= 0x20 && codePoint <= 0xd7ff)
      || (codePoint >= 0xe000 && codePoint <= 0xfffd)
      || (codePoint >= 0x10000 && codePoint <= 0x10ffff);
  return valid ? String.fromCodePoint(codePoint) : undefined;
}

function xmlEntityValue(
  raw, name, rawValues, resolvedValues, resolving, depth, version, budget, limits
) {
  if (depth > limits.maxXmlEntityDepth) {
    throw new MvxError(`XML entity depth exceeds ${limits.maxXmlEntityDepth}`, {
      code: 'ENCODED_PAYLOAD_LIMIT'
    });
  }
  const cached = resolvedValues[name];
  if (cached !== undefined) return cached;
  if (resolving.has(name)) throw invalidXmlDtd('Recursive XML entity declaration');
  resolving.add(name);
  const parts = [];
  let characters = 0;
  let cursor = 0;
  const append = (value) => {
    characters += value.length;
    if (characters > limits.maxXmlExpandedChars) {
      throw new MvxError(`XML entity expansion exceeds ${limits.maxXmlExpandedChars} characters`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
    parts.push(value);
  };
  while (cursor < raw.length) {
    const ampersand = raw.indexOf('&', cursor);
    if (ampersand < 0) {
      append(raw.slice(cursor));
      break;
    }
    append(raw.slice(cursor, ampersand));
    const semicolon = raw.indexOf(';', ampersand + 1);
    if (semicolon < 0) throw invalidXmlDtd(`Incomplete XML entity value: ${name}`);
    const reference = raw.slice(ampersand + 1, semicolon);
    let replacement = XML_ENTITIES[reference];
    if (replacement === undefined && reference.startsWith('#')) {
      replacement = xmlCharacterReference(reference, version);
      if (replacement === '<' || replacement === '&') {
        throw invalidXmlDtd(
          'Markup-bearing numeric references in XML entities are unsupported'
        );
      }
    } else if (replacement === undefined && Object.hasOwn(rawValues, reference)) {
      replacement = xmlEntityValue(
        rawValues[reference], reference, rawValues, resolvedValues,
        resolving, depth + 1, version, budget, limits
      );
    }
    if (replacement === undefined) {
      throw invalidXmlDtd(`Undefined XML entity in declaration: ${reference}`);
    }
    append(replacement);
    cursor = semicolon + 1;
  }
  resolving.delete(name);
  const value = parts.join('');
  budget.xmlExpandedChars += value.length;
  if (budget.xmlExpandedChars > limits.maxXmlExpandedChars) {
    throw new MvxError(
      `XML entity expansions exceed ${limits.maxXmlExpandedChars} characters`,
      { code: 'ENCODED_PAYLOAD_LIMIT' }
    );
  }
  resolvedValues[name] = value;
  return value;
}

function chargeXmlEntityReferences(source, resolvedValues, budget, limits) {
  const referencePattern = /&([A-Za-z_:][A-Za-z0-9_.:-]*);/y;
  const chargeReference = (cursor, textContent) => {
    referencePattern.lastIndex = cursor;
    const match = referencePattern.exec(source);
    if (!match) return 0;
    const value = resolvedValues[match[1]];
    if (value === undefined) return match[0].length;
    if (textContent && value.includes(']]>')) {
      throw invalidXmlDtd("XML entity replacement creates a forbidden ']]>' sequence");
    }
    budget.xmlExpandedChars += value.length;
    if (budget.xmlExpandedChars > limits.maxXmlExpandedChars) {
      throw new MvxError(
        `XML entity expansions exceed ${limits.maxXmlExpandedChars} characters`,
        { code: 'ENCODED_PAYLOAD_LIMIT' }
      );
    }
    return match[0].length;
  };
  let cursor = 0;
  let inTag = false;
  let quote = null;
  while (cursor < source.length) {
    if (!inTag) {
      let terminator = null;
      let width = 0;
      if (source.startsWith('<!--', cursor)) {
        terminator = '-->';
        width = 3;
      } else if (source.startsWith('<![CDATA[', cursor)) {
        terminator = ']]>';
        width = 3;
      } else if (source.startsWith('<?', cursor)) {
        terminator = '?>';
        width = 2;
      }
      if (terminator) {
        const end = source.indexOf(terminator, cursor + 2);
        cursor = end < 0 ? source.length : end + width;
        continue;
      }
      if (source[cursor] === '<') {
        inTag = true;
        cursor += 1;
        continue;
      }
      if (source[cursor] === '&') {
        const consumed = chargeReference(cursor, true);
        if (consumed > 0) {
          cursor += consumed;
          continue;
        }
      }
      cursor += 1;
      continue;
    }
    if (quote) {
      if (source[cursor] === quote) {
        quote = null;
      } else if (source[cursor] === '&') {
        const consumed = chargeReference(cursor, false);
        if (consumed > 0) {
          cursor += consumed;
          continue;
        }
      }
    } else if (source[cursor] === '"' || source[cursor] === "'") {
      quote = source[cursor];
    } else if (source[cursor] === '>') {
      inTag = false;
    }
    cursor += 1;
  }
}

function parseXmlEntityDeclarations(doctype, remainingSource, version, budget, limits) {
  const open = doctype.indexOf('[');
  const declarationHead = open < 0 ? doctype : doctype.slice(0, open);
  if (/(?:^|[\t\n\r ])(?:PUBLIC|SYSTEM)(?=[\t\n\r ])/.test(declarationHead)) {
    throw invalidXmlDtd('External XML DTD subsets are outside the static analysis profile');
  }
  if (open < 0) return XML_ENTITIES;
  const close = doctype.lastIndexOf(']');
  if (close < open || trimHtmlSpace(doctype.slice(close + 1)) !== '') {
    throw invalidXmlDtd('Malformed XML DTD internal subset');
  }
  const subset = doctype.slice(open + 1, close);
  const rawValues = Object.create(null);
  let cursor = 0;
  const skipSpace = () => {
    while (cursor < subset.length && isHtmlSpace(subset[cursor])) cursor += 1;
  };
  while (cursor < subset.length) {
    skipSpace();
    if (cursor >= subset.length) break;
    if (subset.startsWith('<!--', cursor)) {
      const end = subset.indexOf('-->', cursor + 4);
      if (end < 0) throw invalidXmlDtd('Malformed XML DTD comment');
      cursor = end + 3;
      continue;
    }
    if (subset.startsWith('<?', cursor)) {
      const end = subset.indexOf('?>', cursor + 2);
      if (end < 0) throw invalidXmlDtd('Malformed XML DTD processing instruction');
      cursor = end + 2;
      continue;
    }
    if (!subset.startsWith('<!ENTITY', cursor)
      || !isHtmlSpace(subset[cursor + '<!ENTITY'.length])) {
      throw invalidXmlDtd('Unsupported XML DTD declaration');
    }
    cursor += '<!ENTITY'.length;
    skipSpace();
    if (subset[cursor] === '%') {
      throw invalidXmlDtd('Parameter XML entities are outside the static analysis profile');
    }
    const nameMatch = /^[A-Za-z_:][A-Za-z0-9_.:-]*/.exec(subset.slice(cursor));
    if (!nameMatch) throw invalidXmlDtd('Unsupported XML entity name');
    const name = nameMatch[0];
    cursor += name.length;
    if (!isHtmlSpace(subset[cursor])) throw invalidXmlDtd('Malformed XML entity declaration');
    skipSpace();
    const quote = subset[cursor];
    if (quote !== "'" && quote !== '"') {
      throw invalidXmlDtd('External XML entities are outside the static analysis profile');
    }
    const valueStart = cursor + 1;
    const valueEnd = subset.indexOf(quote, valueStart);
    if (valueEnd < 0) throw invalidXmlDtd('Malformed XML entity declaration');
    const raw = subset.slice(valueStart, valueEnd);
    if (raw.includes('<') || /%[A-Za-z_:][A-Za-z0-9_.:-]*;/.test(raw)) {
      throw invalidXmlDtd('Markup and parameter references in XML entities are unsupported');
    }
    cursor = valueEnd + 1;
    skipSpace();
    if (subset[cursor] !== '>') throw invalidXmlDtd('Malformed XML entity declaration');
    cursor += 1;
    if (Object.hasOwn(rawValues, name) || Object.hasOwn(XML_ENTITIES, name)) {
      throw invalidXmlDtd(`Duplicate XML entity declaration: ${name}`);
    }
    budget.xmlEntityDeclarations += 1;
    if (budget.xmlEntityDeclarations > limits.maxXmlEntityDeclarations) {
      throw new MvxError(
        `XML entity declarations exceed ${limits.maxXmlEntityDeclarations}`,
        { code: 'ENCODED_PAYLOAD_LIMIT' }
      );
    }
    rawValues[name] = raw;
  }
  const resolvedValues = Object.create(null);
  const resolving = new Set();
  for (const name of Object.keys(rawValues)) {
    xmlEntityValue(
      rawValues[name], name, rawValues, resolvedValues, resolving, 1,
      version, budget, limits
    );
  }
  const entityValues = Object.assign(Object.create(null), XML_ENTITIES, resolvedValues);
  chargeXmlEntityReferences(remainingSource, resolvedValues, budget, limits);
  return entityValues;
}

function xmlAttributeValueBounds(content, name, searchStart, end) {
  const nameStart = content.indexOf(name, searchStart);
  if (nameStart < 0 || nameStart >= end) return null;
  let cursor = nameStart + name.length;
  while (cursor < end && isHtmlSpace(content[cursor])) cursor += 1;
  if (content[cursor] !== '=') return null;
  cursor += 1;
  while (cursor < end && isHtmlSpace(content[cursor])) cursor += 1;
  const quote = content[cursor];
  if (quote !== "'" && quote !== '"') return null;
  const valueEnd = content.indexOf(quote, cursor + 1);
  if (valueEnd < 0 || valueEnd >= end) return null;
  return { start: cursor + 1, end: valueEnd };
}

function joinDecodedParts(parts, fallbackOffset) {
  let content = '';
  const offsets = [];
  let finalOffset = fallbackOffset;
  for (const part of parts) {
    content += part.content;
    offsets.push(...part.offsets.slice(0, -1));
    finalOffset = part.offsets.at(-1);
  }
  offsets.push(finalOffset);
  return { content, offsets };
}

function* svgDocumentAtobLiterals(content, budget, limits) {
  budget.htmlMaxDocumentDepth = Math.max(budget.htmlMaxDocumentDepth, 1);
  const chargeToken = () => {
    budget.htmlTokens += 1;
    if (budget.htmlTokens > limits.maxHtmlTokens) {
      throw new MvxError(`XML tokens exceed ${limits.maxHtmlTokens}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  };
  const chargeNode = () => {
    budget.htmlNodes += 1;
    if (budget.htmlNodes > limits.maxHtmlNodes) {
      throw new MvxError(`XML node allocations exceed ${limits.maxHtmlNodes}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  };
  const chargeWork = (units) => {
    budget.htmlTreeWork += units;
    if (budget.htmlTreeWork > limits.maxHtmlTreeWork) {
      throw new MvxError(`XML tree work exceeds ${limits.maxHtmlTreeWork}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
  };
  chargeNode();
  const parser = new SaxesParser({ xmlns: true, position: true });
  const elements = [];
  const contexts = [];
  let attributes = [];
  let attributeSearchStart = 0;
  let sourceCursor = 0;
  let syntaxError = false;
  let entityValues = XML_ENTITIES;
  let xmlVersion = '1.0';
  let starts = xmlLineStarts(content);
  const chargeLeaf = () => {
    chargeToken();
    chargeNode();
    chargeWork(Math.max(1, elements.length));
  };
  parser.on('opentagstart', () => {
    attributes = [];
    attributeSearchStart = Math.max(sourceCursor, parser.position - 1);
  });
  parser.on('attribute', (attribute) => {
    budget.htmlAttributes += 1;
    if (budget.htmlAttributes > limits.maxHtmlAttributes) {
      throw new MvxError(`XML attributes exceed ${limits.maxHtmlAttributes}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
    chargeWork(1);
    if (syntaxError) {
      attributeSearchStart = parser.position;
      return;
    }
    const bounds = xmlAttributeValueBounds(
      content, attribute.name, attributeSearchStart, parser.position
    );
    if (!bounds) {
      throw new MvxError('XML attribute source mapping is incomplete', {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
    const decoded = decodeXmlSourceRange(content, bounds.start, bounds.end, {
      attribute: true, entityValues, version: xmlVersion
    });
    if (decoded.parserContent !== attribute.value) {
      throw new MvxError('XML attribute source mapping does not match the parser', {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
    attributes.push({
      qualifiedName: attribute.name,
      localName: attribute.local,
      prefix: attribute.prefix,
      value: attribute.value,
      decoded
    });
    attributeSearchStart = parser.position;
  });
  parser.on('opentag', (tag) => {
    chargeToken();
    chargeNode();
    const depth = elements.length + 1;
    budget.htmlMaxDepth = Math.max(budget.htmlMaxDepth, depth);
    if (depth > limits.maxHtmlTreeDepth) {
      throw new MvxError(`XML tree depth exceeds ${limits.maxHtmlTreeDepth}`, {
        code: 'ENCODED_PAYLOAD_LIMIT'
      });
    }
    chargeWork(depth);
    for (const attribute of attributes) {
      const resolved = tag.attributes[attribute.qualifiedName];
      if (attribute.prefix !== '' || resolved?.uri !== '') continue;
      const mode = htmlEventHandlerMode(tag.uri, tag.local, attribute.localName);
      if (mode) contexts.push({ ...attribute.decoded, mode });
    }
    const scriptAttributes = attributes.map((attribute) => ({
      name: attribute.localName === 'href'
        && (tag.attributes[attribute.qualifiedName]?.uri === ''
          || tag.attributes[attribute.qualifiedName]?.uri === XLINK_NAMESPACE) ? 'href'
        : attribute.prefix === '' ? attribute.localName : attribute.qualifiedName,
      value: attribute.value
    }));
    const mode = tag.local === 'script'
      ? scriptModeForValues(scriptAttributes, tag.uri) : null;
    elements.push({
      script: mode ? { mode, parts: [], startOffset: parser.position } : null
    });
    sourceCursor = parser.position;
  });
  parser.on('text', (value) => {
    chargeLeaf();
    // Saxes has already consumed the opening '<' of the next markup token when
    // it publishes a text event. Keep that delimiter for the following event.
    const end = content[parser.position - 1] === '<'
      ? parser.position - 1 : parser.position;
    if (!syntaxError && elements.at(-1)?.script) {
      const decoded = decodeXmlSourceRange(content, sourceCursor, end, {
        entityValues, version: xmlVersion
      });
      if (decoded.content !== value) {
        throw new MvxError('XML text source mapping does not match the parser', {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      elements.at(-1).script.parts.push(decoded);
    }
    sourceCursor = end;
  });
  parser.on('cdata', (value) => {
    chargeLeaf();
    const start = sourceCursor + 9;
    const end = parser.position - 3;
    if (!syntaxError && elements.at(-1)?.script) {
      const decoded = decodeXmlSourceRange(content, start, end, {
        entities: false, version: xmlVersion
      });
      if (decoded.content !== value) {
        throw new MvxError('XML CDATA source mapping does not match the parser', {
          code: 'ENCODED_PAYLOAD_LIMIT'
        });
      }
      elements.at(-1).script.parts.push(decoded);
    }
    sourceCursor = parser.position;
  });
  parser.on('closetag', () => {
    chargeToken();
    chargeWork(Math.max(1, elements.length));
    const element = elements.pop();
    if (element?.script) {
      contexts.push({
        ...joinDecodedParts(element.script.parts, element.script.startOffset),
        mode: element.script.mode
      });
    }
    sourceCursor = parser.position;
  });
  parser.on('doctype', (value) => {
    chargeLeaf();
    entityValues = parseXmlEntityDeclarations(
      value, content.slice(parser.position), xmlVersion, budget, limits
    );
    for (const [name, replacement] of Object.entries(entityValues)) {
      Object.defineProperty(parser.ENTITIES, name, {
        configurable: true, enumerable: true, value: replacement, writable: true
      });
    }
    sourceCursor = parser.position;
  });
  parser.on('xmldecl', (declaration) => {
    chargeLeaf();
    xmlVersion = declaration.version ?? '1.0';
    starts = xmlLineStarts(content, xmlVersion);
    sourceCursor = parser.position;
  });
  for (const event of ['comment', 'processinginstruction']) {
    parser.on(event, () => {
      chargeLeaf();
      sourceCursor = content[parser.position] === '>'
        ? parser.position + 1 : parser.position;
    });
  }
  parser.on('error', () => { syntaxError = true; });
  try {
    parser.write(content).close();
  } catch (error) {
    if (error instanceof MvxError) throw error;
    syntaxError = true;
  }
  if (syntaxError) return;
  for (const context of contexts) {
    yield* javascriptAtobLiterals(
      context.content, 0, context.content.length, starts, budget, limits,
      context.offsets, context.mode
    );
  }
}

function directAtobLiterals(source, budget, limits) {
  const starts = lineStarts(source.content);
  if (/\.svg$/i.test(source.path) && source.depth === 0) {
    return svgDocumentAtobLiterals(source.content, budget, limits);
  }
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
  const compact = source.replace(/[\t\n\f\r ]/g, '');
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
    astNodes: 0,
    htmlTokens: 0,
    htmlAttributes: 0,
    htmlNodes: 0,
    htmlTreeWork: 0,
    htmlMaxDepth: 0,
    htmlMaxDocumentDepth: 0,
    htmlNestedChars: 0,
    xmlEntityDeclarations: 0,
    xmlExpandedChars: 0
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
    parserProfiles: ENCODED_PAYLOAD_PARSER_PROFILES,
    browserEventHandlerProfile: BROWSER_EVENT_HANDLER_PROFILE,
    limits,
    candidates: candidateBudget.candidates,
    candidateEncodedChars: candidateBudget.candidateEncodedChars,
    parserTokens: candidateBudget.parserTokens,
    astNodes: candidateBudget.astNodes,
    htmlTokens: candidateBudget.htmlTokens,
    htmlAttributes: candidateBudget.htmlAttributes,
    htmlNodes: candidateBudget.htmlNodes,
    htmlTreeWork: candidateBudget.htmlTreeWork,
    htmlMaxDepth: candidateBudget.htmlMaxDepth,
    htmlMaxDocumentDepth: candidateBudget.htmlMaxDocumentDepth,
    htmlNestedChars: candidateBudget.htmlNestedChars,
    xmlEntityDeclarations: candidateBudget.xmlEntityDeclarations,
    xmlExpandedChars: candidateBudget.xmlExpandedChars,
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
