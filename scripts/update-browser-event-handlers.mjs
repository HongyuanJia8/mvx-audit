#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const REVISION = '3c06821a384385ee5f355148a5fcd427f5230118';
const CAPTURED_AT = '2026-07-31';
const PROFILE_VERSION = 1;
const MAX_ENCODED_SOURCE_BYTES = 2_000_000;
const MAX_DECODED_SOURCE_BYTES = 1_500_000;
const FETCH_TIMEOUT_MS = 15_000;
const SVG_SMIL_EVENT_HANDLERS = Object.freeze(['onbegin', 'onend', 'onrepeat']);
const SVG_SCRIPT_SOURCE =
  'third_party/blink/renderer/core/svg/svg_script_element.cc';
const SVG_SCRIPT_ONERROR_MODE = 'error-handler';
const SVG_SMIL_ELEMENT_SOURCES = Object.freeze([
  Object.freeze({
    name: 'animate',
    path: 'third_party/blink/renderer/core/svg/svg_animate_element.h',
    inheritance: 'SVGAnimateElement : public SVGAnimationElement'
  }),
  Object.freeze({
    name: 'animateMotion',
    path: 'third_party/blink/renderer/core/svg/svg_animate_motion_element.h',
    inheritance: 'SVGAnimateMotionElement final : public SVGAnimationElement'
  }),
  Object.freeze({
    name: 'animateTransform',
    path: 'third_party/blink/renderer/core/svg/svg_animate_transform_element.h',
    inheritance: 'SVGAnimateTransformElement final : public SVGAnimateElement'
  }),
  Object.freeze({
    name: 'set',
    path: 'third_party/blink/renderer/core/svg/svg_set_element.h',
    inheritance: 'SVGSetElement final : public SVGAnimateElement'
  })
]);
const SOURCE_PATHS = Object.freeze([
  'third_party/blink/renderer/core/html/html_body_element.cc',
  'third_party/blink/renderer/core/html/html_element.cc',
  'third_party/blink/renderer/core/html/html_frame_set_element.cc',
  'third_party/blink/renderer/core/mathml/mathml_element.cc',
  'third_party/blink/renderer/core/svg/svg_attribute_names.json5',
  'third_party/blink/renderer/core/svg/animation/svg_smil_element.cc',
  'third_party/blink/renderer/core/svg/svg_animation_element.h',
  ...SVG_SMIL_ELEMENT_SOURCES.map((entry) => entry.path),
  SVG_SCRIPT_SOURCE
]);
const REQUIRED_GENERIC_HANDLERS = Object.freeze([
  'onbeforecopy', 'onbeforecut', 'onbeforepaste',
  'oncontentvisibilityautostatechange', 'onmousewheel',
  'onwebkitfullscreenchange', 'onwebkitfullscreenerror'
]);

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.join(projectRoot, 'src/browser-event-handlers.js');

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function boundedResponseText(response, sourcePath) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_ENCODED_SOURCE_BYTES) {
    throw new Error(`Chromium source exceeds encoded limit: ${sourcePath}`);
  }
  if (!response.body) throw new Error(`Chromium source has no body: ${sourcePath}`);
  const chunks = [];
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.byteLength;
    if (bytes > MAX_ENCODED_SOURCE_BYTES) {
      throw new Error(`Chromium source exceeds encoded limit: ${sourcePath}`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, bytes).toString('ascii');
}

async function chromiumSource(sourcePath) {
  const url = `https://chromium.googlesource.com/chromium/src/+/${REVISION}/${sourcePath}?format=TEXT`;
  const response = await fetch(url, {
    redirect: 'error', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)
  });
  if (!response.ok) throw new Error(`Chromium source fetch failed (${response.status}): ${sourcePath}`);
  const encoded = (await boundedResponseText(response, sourcePath)).replace(/[\r\n]/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded) || encoded.length % 4 !== 0) {
    throw new Error(`Chromium source is not canonical Base64: ${sourcePath}`);
  }
  const decoded = Buffer.from(encoded, 'base64');
  if (decoded.length > MAX_DECODED_SOURCE_BYTES
    || decoded.toString('base64') !== encoded) {
    throw new Error(`Chromium source exceeds decoded limit or is non-canonical: ${sourcePath}`);
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(decoded);
}

function cppHandlers(source, startMarker = null, endMarker = null) {
  const start = startMarker ? source.indexOf(startMarker) : 0;
  if (start < 0) throw new Error(`Chromium source marker missing: ${startMarker}`);
  const end = endMarker ? source.indexOf(endMarker, start) : source.length;
  if (end < 0) throw new Error(`Chromium source marker missing: ${endMarker}`);
  return sortedUnique([...source.slice(start, end).matchAll(
    /html_names::kOn([A-Za-z0-9]+)Attr/g
  )].map((match) => `on${match[1].toLowerCase()}`));
}

function quotedLines(values, indentation = '  ') {
  return values.map((value) => `${indentation}'${value}'`).join(',\n');
}

function renderProfile(profile, digest, handlerLists) {
  const { body, frameset, html, svg, svgSmilElements } = handlerLists;
  return `// Generated by scripts/update-browser-event-handlers.mjs. Update as one\n// reviewed unit when advancing the browser revision; never resolve HEAD at\n// audit time.\nexport const BROWSER_EVENT_HANDLER_PROFILE =\n  '${profile}';\n\nexport const BROWSER_EVENT_HANDLER_PROVENANCE = Object.freeze({\n  browser: 'Chromium',\n  revision: '${REVISION}',\n  capturedAt: '${CAPTURED_AT}',\n  sha256: '${digest}',\n  sources: Object.freeze([\n${quotedLines(SOURCE_PATHS, '    ')}\n  ])\n});\n\nexport const HTML_EVENT_HANDLER_ATTRIBUTES = Object.freeze([\n${quotedLines(html)}\n]);\n\nexport const BODY_EVENT_HANDLER_ATTRIBUTES = Object.freeze([\n${quotedLines(body)}\n]);\n\nexport const FRAMESET_EVENT_HANDLER_ATTRIBUTES = Object.freeze([\n${quotedLines(frameset)}\n]);\n\nexport const SVG_EVENT_HANDLER_ATTRIBUTES = Object.freeze([\n${quotedLines(svg)}\n]);\n\nexport const SVG_SMIL_EVENT_HANDLER_ATTRIBUTES = Object.freeze([\n${quotedLines(SVG_SMIL_EVENT_HANDLERS)}\n]);\n\nexport const SVG_SMIL_EVENT_HANDLER_ELEMENTS = Object.freeze([\n${quotedLines(svgSmilElements)}\n]);\n\nconst HTML_EVENT_HANDLER_SET = new Set(HTML_EVENT_HANDLER_ATTRIBUTES);\nconst BODY_EVENT_HANDLER_SET = new Set(BODY_EVENT_HANDLER_ATTRIBUTES);\nconst FRAMESET_EVENT_HANDLER_SET = new Set(FRAMESET_EVENT_HANDLER_ATTRIBUTES);\nconst SVG_EVENT_HANDLER_SET = new Set(SVG_EVENT_HANDLER_ATTRIBUTES);\nconst SVG_SMIL_EVENT_HANDLER_SET = new Set(SVG_SMIL_EVENT_HANDLER_ATTRIBUTES);\nconst SVG_SMIL_EVENT_HANDLER_ELEMENT_SET = new Set(SVG_SMIL_EVENT_HANDLER_ELEMENTS);\nconst HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';\nconst SVG_NAMESPACE = 'http://www.w3.org/2000/svg';\nconst MATHML_NAMESPACE = 'http://www.w3.org/1998/Math/MathML';\n\nexport function htmlEventHandlerMode(namespace, tagName, attributeName) {\n  if (namespace === HTML_NAMESPACE) {\n    const tagSpecific = tagName === 'body' ? BODY_EVENT_HANDLER_SET\n      : tagName === 'frameset' ? FRAMESET_EVENT_HANDLER_SET : null;\n    if (tagSpecific?.has(attributeName)) {\n      return attributeName === 'onerror' ? 'error-handler' : 'handler';\n    }\n    return HTML_EVENT_HANDLER_SET.has(attributeName) ? 'handler' : null;\n  }\n  if (namespace === MATHML_NAMESPACE) {\n    return HTML_EVENT_HANDLER_SET.has(attributeName) ? 'handler' : null;\n  }\n  if (namespace === SVG_NAMESPACE) {\n    if (SVG_SMIL_EVENT_HANDLER_SET.has(attributeName)\n      && !SVG_SMIL_EVENT_HANDLER_ELEMENT_SET.has(tagName)) return null;\n    if (HTML_EVENT_HANDLER_SET.has(attributeName)\n      || SVG_EVENT_HANDLER_SET.has(attributeName)) return 'svg-handler';\n  }\n  return null;\n}\n`;
}

const sources = new Map();
for (const sourcePath of SOURCE_PATHS) {
  sources.set(sourcePath, await chromiumSource(sourcePath));
}
const html = cppHandlers(
  sources.get(SOURCE_PATHS[1]), 'attribute_triggers =', '// Begin ARIA attributes.'
);
const body = cppHandlers(sources.get(SOURCE_PATHS[0]), 'HTMLBodyElement::ParseAttribute');
const frameset = cppHandlers(
  sources.get(SOURCE_PATHS[2]), 'HTMLFrameSetElement::ParseAttribute'
);
if (!sources.get(SOURCE_PATHS[3]).includes('HTMLElement::EventNameForAttributeName')) {
  throw new Error('MathML generic event-handler delegation is missing');
}
const svg = sortedUnique([...sources.get(SOURCE_PATHS[4]).matchAll(
  /^\s+"(on[a-z0-9]+)",$/gm
)].map((match) => match[1]));
for (const required of REQUIRED_GENERIC_HANDLERS) {
  if (!html.includes(required)) throw new Error(`Required handler missing: ${required}`);
}
if (!['onactivate', 'onbegin', 'onend', 'onrepeat'].every((name) => svg.includes(name))) {
  throw new Error('Required SVG event handlers are missing');
}
const smilSource = sources.get(SOURCE_PATHS[5]);
for (const handler of SVG_SMIL_EVENT_HANDLERS) {
  const attribute = `svg_names::kOn${handler.slice(2)}Attr`;
  if (!smilSource.includes(attribute)) {
    throw new Error(`SVG SMIL handler implementation is missing: ${handler}`);
  }
}
if (!sources.get(SOURCE_PATHS[6]).includes(
  'SVGAnimationElement : public SVGSMILElement'
)) throw new Error('SVG animation-to-SMIL inheritance is missing');
for (const entry of SVG_SMIL_ELEMENT_SOURCES) {
  if (!sources.get(entry.path).includes(entry.inheritance)) {
    throw new Error(`SVG SMIL element inheritance is missing: ${entry.name}`);
  }
}
const svgScriptSource = sources.get(SVG_SCRIPT_SOURCE);
if (!svgScriptSource.includes('SVGScriptElement::ParseAttribute')
  || !svgScriptSource.includes('JSEventHandler::HandlerType::kOnErrorEventHandler')) {
  throw new Error('SVG script onerror handler grammar is missing');
}

const identity = {
  revision: REVISION,
  sources: SOURCE_PATHS,
  body,
  frameset,
  html,
  svg,
  svgSmilHandlers: SVG_SMIL_EVENT_HANDLERS,
  svgSmilElements: sortedUnique(SVG_SMIL_ELEMENT_SOURCES.map((entry) => entry.name)),
  svgScriptOnerror: Object.freeze({
    attribute: 'onerror', element: 'script', mode: SVG_SCRIPT_ONERROR_MODE
  })
};
const digest = sha256(JSON.stringify(identity));
const profile = `mvx-chromium-event-handlers-v${PROFILE_VERSION}-sha256-${digest}`;
const baseRendered = renderProfile(profile, digest, identity);
const svgNamespaceAnchor = '  if (namespace === SVG_NAMESPACE) {\n';
if (baseRendered.split(svgNamespaceAnchor).length !== 2) {
  throw new Error('Generated SVG namespace handler anchor is ambiguous');
}
const rendered = baseRendered.replace(
  svgNamespaceAnchor,
  "  if (namespace === SVG_NAMESPACE) {\n    if (tagName === 'script'"
    + ` && attributeName === 'onerror') return '${SVG_SCRIPT_ONERROR_MODE}';\n`
);
if (process.argv.includes('--check')) {
  if (await readFile(outputPath, 'utf8') !== rendered) {
    throw new Error('Browser event-handler profile is stale; run npm run handlers:update');
  }
} else {
  await writeFile(outputPath, rendered, 'utf8');
}
