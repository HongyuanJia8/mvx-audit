import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { runCli } from '../src/cli.js';
import { compareExtensions } from '../src/compare.js';
import { verifyComparisonReport } from '../src/comparison-verification.js';
import {
  BROWSER_EVENT_HANDLER_PROFILE, BROWSER_EVENT_HANDLER_PROVENANCE,
  BODY_EVENT_HANDLER_ATTRIBUTES, FRAMESET_EVENT_HANDLER_ATTRIBUTES,
  HTML_EVENT_HANDLER_ATTRIBUTES, SVG_EVENT_HANDLER_ATTRIBUTES,
  SVG_SMIL_EVENT_HANDLER_ATTRIBUTES, SVG_SMIL_EVENT_HANDLER_ELEMENTS
} from '../src/browser-event-handlers.js';
import {
  analyzeEncodedPayloads, ENCODED_PAYLOAD_LIMITS,
  ENCODED_PAYLOAD_PARSER_PROFILES, ENCODED_PAYLOAD_PROFILE, extractEncodedPayloads
} from '../src/encoded-payloads.js';
import {
  ENCODED_PAYLOAD_LIMITS as PUBLIC_ENCODED_PAYLOAD_LIMITS,
  ENCODED_PAYLOAD_PARSER_PROFILES as PUBLIC_ENCODED_PAYLOAD_PARSER_PROFILES,
  ENCODED_PAYLOAD_PROFILE as PUBLIC_ENCODED_PAYLOAD_PROFILE,
  BROWSER_EVENT_HANDLER_PROFILE as PUBLIC_BROWSER_EVENT_HANDLER_PROFILE,
  BROWSER_EVENT_HANDLER_PROVENANCE as PUBLIC_BROWSER_EVENT_HANDLER_PROVENANCE,
  BODY_EVENT_HANDLER_ATTRIBUTES as PUBLIC_BODY_EVENT_HANDLER_ATTRIBUTES,
  FRAMESET_EVENT_HANDLER_ATTRIBUTES as PUBLIC_FRAMESET_EVENT_HANDLER_ATTRIBUTES,
  HTML_EVENT_HANDLER_ATTRIBUTES as PUBLIC_HTML_EVENT_HANDLER_ATTRIBUTES,
  SVG_EVENT_HANDLER_ATTRIBUTES as PUBLIC_SVG_EVENT_HANDLER_ATTRIBUTES,
  SVG_SMIL_EVENT_HANDLER_ATTRIBUTES as PUBLIC_SVG_SMIL_EVENT_HANDLER_ATTRIBUTES,
  SVG_SMIL_EVENT_HANDLER_ELEMENTS as PUBLIC_SVG_SMIL_EVENT_HANDLER_ELEMENTS
} from '../src/index.js';
import { verifyAuditReport } from '../src/audit-verification.js';
import { auditToSarif, auditToText, comparisonToMarkdown } from '../src/reporters.js';
import { captureStreams, writeExtension } from '../support/helpers.js';

function base64(value) {
  return Buffer.from(value).toString('base64');
}

function source(content, sourcePath = 'worker.js') {
  return {
    path: sourcePath,
    content,
    sha256: createHash('sha256').update(content).digest('hex')
  };
}

const PARSER_PROFILE_GOLDEN = Object.freeze({
  ecmascript: 'acorn-8.18.0',
  html: 'parse5-7.3.0',
  htmlEntities: 'entities-6.0.1',
  xml: 'saxes-6.0.0',
  xmlCharacters: 'xmlchars-2.2.0'
});

const HANDLER_PROFILE_GOLDEN = Object.freeze({
  profile: 'mvx-chromium-event-handlers-v1-sha256-eb73431ee6afe8d0d75a6f58744136e74ca5ba7ef8ecee9fe02dff4d9a86f14c',
  lists: Object.freeze({
    body: Object.freeze({ count: 23, sha256: '4ddd4a6e31f75be8eb3d0f339a432333f93e35c1d7b4d63ff63e8d6cb64f5dca' }),
    frameset: Object.freeze({ count: 23, sha256: 'ec184fa2af1bf99c1dbc41b3bbbf199f7b5d5cd76f38fa7a9028ca2c8be1a985' }),
    html: Object.freeze({ count: 115, sha256: 'c93522e21c1c8e010b0ae87f4888ca36301e36946a2fef6d9929203ce4f70000' }),
    svg: Object.freeze({ count: 6, sha256: 'f3c1555b121deca7b728d41730c4b5f1de1257d20733afa3152e80f691929672' }),
    svgSmilHandlers: Object.freeze({ count: 3, sha256: 'ba241ea684f08f4e179cd32686fe97b32474b3bf1d84fee706609f59834cbb0e' }),
    svgSmilElements: Object.freeze({ count: 4, sha256: 'e0cb45d18ac1b4379b739bc882e54494a608d835866fce503473f2200a253765' })
  })
});

function pack(indicator) {
  return {
    schemaVersion: 1,
    namespace: 'encoded.research',
    name: 'Encoded campaign indicators',
    version: '2026.07.31',
    rules: [{
      id: 'CAMPAIGN_TEXT',
      title: 'Decoded campaign indicator',
      severity: 'high',
      confidence: 'high',
      category: 'campaign-ioc',
      description: 'A campaign marker appears in statically decoded text.',
      remediation: 'Correlate the decoded evidence with independently sourced intelligence.',
      references: ['https://example.invalid/research'],
      indicators: [{ type: 'text', value: indicator, scope: 'source' }]
    }]
  };
}

test('audit inventories direct Base64 literals and scans decoded behavior without execution', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-encoded-audit-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const hidden = 'eval(secretPayload);\u001b[31m\u202e\n';
  await writeExtension(temp, {
    manifest_version: 3, name: 'Encoded fixture', version: '1.0.0'
  }, { 'worker.js': `const stage = atob('${base64(hidden)}');\n` });

  const result = await auditExtension(temp);
  assert.equal(result.analysis.profile, 'mvx-static-v4');
  assert.equal(result.encodedPayloads.profile, ENCODED_PAYLOAD_PROFILE);
  assert.equal(result.encodedPayloads.parserProfiles, ENCODED_PAYLOAD_PARSER_PROFILES);
  assert.equal(Object.isFrozen(ENCODED_PAYLOAD_PARSER_PROFILES), true);
  assert.deepEqual(ENCODED_PAYLOAD_PARSER_PROFILES, PARSER_PROFILE_GOLDEN);
  assert.equal(
    result.encodedPayloads.browserEventHandlerProfile,
    BROWSER_EVENT_HANDLER_PROFILE
  );
  assert.equal(result.encodedPayloads.decodedCount, 1);
  assert.equal(result.encodedPayloads.candidateEncodedChars, base64(hidden).length);
  assert.ok(result.encodedPayloads.parserTokens > 0);
  assert.ok(result.encodedPayloads.astNodes > 0);
  assert.equal(result.encodedPayloads.utf8Count, 1);
  assert.equal(result.encodedPayloads.totalDecodedBytes, Buffer.byteLength(hidden));
  assert.equal(result.analysis.encodedPayloads.sha256, result.encodedPayloads.sha256);
  assert.equal(result.scan.encodedPayloadsDecoded, 1);
  assert.deepEqual(result.findings.map((finding) => finding.id), ['MVX201', 'MVX213']);

  const decodedFinding = result.findings.find((finding) => finding.id === 'MVX201');
  assert.equal(decodedFinding.confidence, 'medium');
  assert.deepEqual(decodedFinding.evidence[0], {
    file: 'worker.js',
    line: 1,
    decodedLine: 1,
    decodedFrom: {
      profile: ENCODED_PAYLOAD_PROFILE,
      line: 1,
      encodedLine: 1,
      depth: 1,
      encoding: 'base64-atob',
      parentSha256: result.analysis.sources[0].sha256,
      sha256: result.encodedPayloads.entries[0].sha256
    },
    snippet: `decoded match at line 1; SHA-256 ${result.encodedPayloads.entries[0].sha256}`
  });
  const text = auditToText(result);
  assert.match(text, /Encoded payloads \(mvx-encoded-payloads-v1\): 1 decoded/);
  assert.match(text, /decoded depth 1, encoded line 1, decoded line 1, SHA-256 [a-f0-9]{64}/);
  assert.match(text, new RegExp(
    `base64-atob depth 1, encoded line 1, ${Buffer.byteLength(hidden)} bytes, SHA-256 [a-f0-9]{64}`
  ));
  assert.equal(text.includes('\u001b'), false);
  assert.equal(JSON.stringify(result).includes('\u202e'), false);
  assert.equal(JSON.stringify(result).includes('eval(secretPayload)'), false);
  const sarif = auditToSarif(result);
  assert.deepEqual(sarif.runs[0].properties.encodedPayloads, result.encodedPayloads);
  const decodedSarif = sarif.runs[0].results.find((item) => item.ruleId === 'MVX201');
  assert.equal(decodedSarif.locations[0].physicalLocation.region.startLine, 1);
  assert.equal(decodedSarif.properties.decodedFrom.sha256, result.encodedPayloads.entries[0].sha256);

  const captured = captureStreams();
  assert.equal(await runCli(['audit', temp, '--format', 'json'], captured.streams), 0);
  const cliResult = JSON.parse(captured.output().stdout);
  assert.equal(cliResult.encodedPayloads.sha256, result.encodedPayloads.sha256);
  assert.deepEqual(cliResult.findings.map((finding) => finding.id), ['MVX201', 'MVX213']);
});

test('nested decoding is deterministic, depth-bounded, and maps evidence to the packaged line', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-encoded-nested-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const hiddenThirdStage = `eval(finalPayload); ${'x'.repeat(16)}`;
  const secondStage = `const third = atob('${base64(hiddenThirdStage)}');`;
  const firstStage = `chrome.cookies.getAll({});\nconst second = atob('${base64(secondStage)}');`;
  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Nested encoded fixture',
    version: '1.0.0',
    permissions: ['cookies'],
    host_permissions: ['<all_urls>']
  }, { 'worker.js': `void 0;\nconst first = atob('${base64(firstStage)}');\n` });

  const first = await auditExtension(temp);
  const second = await auditExtension(temp);
  assert.deepEqual(first.encodedPayloads, second.encodedPayloads);
  assert.equal(first.encodedPayloads.decodedCount, 2);
  assert.deepEqual(first.encodedPayloads.entries.map((entry) => entry.depth), [1, 2]);
  assert.equal(first.findings.some((finding) => finding.id === 'MVX201'), false);
  const cookie = first.findings.find((finding) => finding.id === 'MVX206');
  assert.equal(cookie.evidence[0].file, 'worker.js');
  assert.equal(cookie.evidence[0].line, 2);
  assert.equal(cookie.evidence[0].decodedLine, 1);
  assert.equal(cookie.evidence[0].decodedFrom.depth, 1);
});

test('declarative source indicators match decoded text with content-bound provenance', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-encoded-rule-pack-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const marker = 'campaign.example.invalid';
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'Decoded indicator fixture', version: '1.0.0'
  }, { 'worker.js': [
    `const first = atob('${base64(`endpoint=${marker};`)}');`,
    `const second = window.atob('${base64(`backup=${marker};`)}');`
  ].join('\n') });
  const rulePack = path.join(temp, 'pack.json');
  await writeFile(rulePack, `${JSON.stringify(pack(marker), null, 2)}\n`, 'utf8');

  const result = await auditExtension(extension, { rulePacks: [rulePack] });
  const finding = result.findings.find((item) => item.id === 'RP:encoded.research:CAMPAIGN_TEXT');
  assert.ok(finding);
  assert.deepEqual(finding.evidence.map((evidence) => evidence.line), [1, 2]);
  assert.ok(finding.evidence.every((evidence) => evidence.file === 'worker.js'));
  assert.ok(finding.evidence.every((evidence) => evidence.decodedLine === 1));
  assert.deepEqual(finding.evidence.map((evidence) => evidence.decodedFrom.sha256),
    result.encodedPayloads.entries.map((entry) => entry.sha256));
});

test('binary payloads remain hashed evidence while malformed, dynamic, escaped, and tiny inputs are ignored', () => {
  const binary = Buffer.alloc(16, 0xff).toString('base64');
  const content = [
    `atob('${binary}')`,
    "atob('%%%not-base64%%%')",
    "atob('YR==')",
    "atob('YQ==')",
    "atob('QUJD\\\\RA==')",
    'atob(runtimeValue)',
    `decoder.atob('${base64('not the global decoder')}')`,
    `somewindow.atob('${base64('not the global decoder')}')`,
    `$atob('${base64('not the global decoder')}')`,
    `\u00e9atob('${base64('not the global decoder')}')`,
    `atob\u00e9('${base64('not the global decoder')}')`
  ].join(';\n');
  const result = extractEncodedPayloads([source(content)]);
  assert.equal(result.candidates, 5);
  assert.equal(result.decodedCount, 1);
  assert.equal(result.utf8Count, 0);
  assert.equal(result.decodedSources.length, 0);
  assert.equal(result.entries[0].utf8, false);
  assert.equal(result.entries[0].sha256,
    createHash('sha256').update(Buffer.alloc(16, 0xff)).digest('hex'));

  const globalForms = extractEncodedPayloads([source([
    `window.atob('${base64('window payload data')}')`,
    `self . atob('${base64('self payload data!!')}')`,
    `globalThis\n.\n atob('${base64('global payload data')}')`
  ].join(';\n'))]);
  assert.equal(globalForms.decodedCount, 3);

  const formFeed = extractEncodedPayloads([source(
    `atob('${base64('form-feed payload!').replace(/^(.{5})/, '$1\f')}')`
  )]);
  assert.equal(formFeed.decodedCount, 1);
});

test('token-aware extraction excludes non-executable text and preserves syntactic confidence', () => {
  const payload = base64('eval(hiddenPayload);');
  const javascript = [
    `// atob('${payload}')`,
    `/* atob('${payload}') */`,
    `const single = "atob('${payload}')";`,
    `const template = \`atob('${payload}')\`;`,
    `const pattern = /atob\\('${payload}'\\)/;`,
    `if (true) /atob\\('${payload}'\\)/.test('x');`,
    `while (false) /atob\\('${payload}'\\)/.test('x');`,
    `for (;;) /atob\\('${payload}'\\)/.test('x');`,
    `if (true) {} /atob\\('${payload}'\\)/.test('x');`,
    `<!-- atob('${payload}')`,
    `--> atob('${payload}')`,
    `const astral = 𐐀atob('${payload}');`,
    `class PrivateDecoder { #atob(value) { return value; } run() { return this.#atob('${payload}'); } }`,
    `function shadowed(atob) { return atob('${payload}'); }`
  ].join('\n');
  const result = extractEncodedPayloads([source(javascript)]);
  assert.equal(result.candidates, 1);
  assert.equal(result.decodedCount, 1);
  const finding = analyzeEncodedPayloads(result)[0];
  assert.equal(finding.confidence, 'medium');
  assert.match(finding.description, /does not prove which runtime binding/);

  const html = [
    '<!-- <script>atob(\'' + payload + '\')</script> -->',
    '<div data-example="atob(\'' + payload + '\')"></div>',
    '<script type="application/json">"atob(\'' + payload + '\')"</script>',
    '<script src="packaged.js">atob(\'' + payload + '\')</script>',
    '<script>const value = atob(\'' + payload + '\');</script>',
    '<button onclick="atob(\'' + payload + '\')">run</button>'
  ].join('\n');
  const htmlResult = extractEncodedPayloads([source(html, 'page.html')]);
  assert.equal(htmlResult.candidates, 2);
  assert.equal(htmlResult.decodedCount, 2);
  assert.deepEqual(htmlResult.entries.map((entry) => entry.encodedLine), [5, 6]);

  const syntaxVariants = extractEncodedPayloads([source([
    `atob('${payload}', undefined);`,
    `atob('${payload}',);`,
    'let x = 2, y = 1; x++ / y;',
    `atob('${payload}');`,
    `const divided = ready ? {} / atob('${payload}') / 2 : 0;`,
    `if (atob('${payload}', true)) /atob\\('${payload}'\\)/.test(input);`,
    `async function consume(xs) { for await (const x of xs) /atob\\('${payload}'\\)/.test(x); }`,
    `while (true) { break\n/atob\\('${payload}'\\)/.test(input); }`,
    `\\u0061tob('${payload}');`,
    `const expression = \`\${atob('${payload}')}\`;`
  ].join('\n'))]);
  assert.equal(syntaxVariants.candidates, 7);
  assert.equal(syntaxVariants.decodedCount, 7);
  const incompleteCall = extractEncodedPayloads([
    source(`atob('${payload}',`)
  ]);
  assert.equal(incompleteCall.candidates, 1);
  assert.equal(incompleteCall.decodedCount, 0);

  const browserHtml = [
    `<script>const marker = "</scripty>"; atob('${payload}')</script>`,
    `<button onclick="atob(&quot;${payload}&quot;)">quoted</button>`,
    `<button onclick="&#97;tob('${payload}')">numeric</button>`,
    `<script type="text&#x2f;javascript">atob('${payload}')</script>`,
    `<script>${'İ'.repeat(80)}</script><script>atob('${payload}')</script>`,
    `<script>const marker = "</script\u00a0x>"; atob('${payload}')</script>`,
    `<script type="module;garbage">atob('${payload}')</script>`,
    `<script>import value from './x.js'; atob('${payload}')</script>`,
    `<script type="module">with (value) atob('${payload}')</script>`,
    `<script>return atob('${payload}')</script>`,
    `<script type="module">import value from './x.js'; atob('${payload}')</script>`,
    `<script type="module">await 1; atob('${payload}')</script>`,
    `<button onclick="return atob('${payload}')">handler</button>`
  ].join('\n');
  const browserHtmlResult = extractEncodedPayloads([source(browserHtml, 'browser.html')]);
  assert.equal(browserHtmlResult.candidates, 12);
  assert.equal(browserHtmlResult.decodedCount, 9);
  assert.deepEqual(browserHtmlResult.entries.map((entry) => entry.encodedLine), [
    1, 2, 3, 4, 5, 6, 11, 12, 13
  ]);
});

test('HTML script selection and handlers follow browser execution contexts', () => {
  const payload = base64('eval(browserContext);xxxx');
  const javascriptTypes = [
    'application/ecmascript', 'application/javascript', 'application/x-ecmascript',
    'application/x-javascript', 'text/ecmascript', 'text/javascript',
    'text/javascript1.0', 'text/javascript1.1', 'text/javascript1.2',
    'text/javascript1.3', 'text/javascript1.4', 'text/javascript1.5',
    'text/jscript', 'text/livescript', 'text/x-ecmascript', 'text/x-javascript'
  ];
  const accepted = [
    ...javascriptTypes.map((type) => `<script type="${type}">atob('${payload}')</script>`),
    `<script type="TEXT/JAVASCRIPT">atob('${payload}')</script>`,
    `<script language="javascript">atob('${payload}')</script>`,
    `<script language="JScript">atob('${payload}')</script>`,
    `<script language="">atob('${payload}')</script>`,
    `<script for=" window " event=" onload() ">atob('${payload}')</script>`,
    `<script type="module" nomodule>atob('${payload}')</script>`
  ];
  const rejected = [
    `<script type="text/javascript; charset=utf-8">atob('${payload}')</script>`,
    `<script type="vendor/example+javascript">atob('${payload}')</script>`,
    `<script language="json">atob('${payload}')</script>`,
    `<script type="application/json" language="javascript">atob('${payload}')</script>`,
    `<script nomodule>atob('${payload}')</script>`,
    `<script type="text/javascripK">atob('${payload}')</script>`,
    `<script language="javascripK">atob('${payload}')</script>`,
    `<script for="document" event="onload">atob('${payload}')</script>`,
    `<script for="window" event="onclick">atob('${payload}')</script>`
  ];
  const scripts = extractEncodedPayloads([
    source([...accepted, ...rejected].join('\n'), 'contexts.html')
  ]);
  assert.equal(scripts.candidates, accepted.length);
  assert.equal(scripts.decodedCount, accepted.length);
  assert.deepEqual(
    scripts.entries.map((entry) => entry.encodedLine),
    accepted.map((_, index) => index + 1)
  );

  const handlers = extractEncodedPayloads([source([
    `<body onafterprint="atob('${payload}')">window`,
    `<button onclick="new.target; (() => new.target)(); atob('${payload}')">valid</button>`,
    `<button onclick="#!comment&#10;return atob('${payload}')">invalid</button>`,
    `<div onfoobar="atob('${payload}')">inert</div>`,
    `<div once="atob('${payload}')">inert</div>`,
    `<div onpointerdown="atob('${payload}')">pointer</div>`,
    `<div onafterprint="atob('${payload}')">inert window handler</div>`,
    `<div onanimationend="atob('${payload}')">animation</div></body>`
  ].join('\n'), 'handlers.html')]);
  assert.equal(handlers.candidates, 5);
  assert.equal(handlers.decodedCount, 4);
  assert.deepEqual(handlers.entries.map((entry) => entry.encodedLine), [1, 2, 6, 8]);
});

test('frozen Chromium handler profile matches independent goldens and contexts', () => {
  const payload = base64('eval(profilePayload);xxxx');
  const lists = {
    body: BODY_EVENT_HANDLER_ATTRIBUTES,
    frameset: FRAMESET_EVENT_HANDLER_ATTRIBUTES,
    html: HTML_EVENT_HANDLER_ATTRIBUTES,
    svg: SVG_EVENT_HANDLER_ATTRIBUTES,
    svgSmilHandlers: SVG_SMIL_EVENT_HANDLER_ATTRIBUTES,
    svgSmilElements: SVG_SMIL_EVENT_HANDLER_ELEMENTS
  };
  assert.equal(BROWSER_EVENT_HANDLER_PROFILE, HANDLER_PROFILE_GOLDEN.profile);
  for (const [name, values] of Object.entries(lists)) {
    assert.equal(Object.isFrozen(values), true);
    assert.deepEqual(values, [...values].sort());
    assert.equal(new Set(values).size, values.length);
    assert.equal(values.length, HANDLER_PROFILE_GOLDEN.lists[name].count);
    assert.equal(
      createHash('sha256').update(JSON.stringify(values)).digest('hex'),
      HANDLER_PROFILE_GOLDEN.lists[name].sha256
    );
  }
  assert.equal(Object.isFrozen(BROWSER_EVENT_HANDLER_PROVENANCE), true);
  assert.equal(Object.isFrozen(BROWSER_EVENT_HANDLER_PROVENANCE.sources), true);
  const identity = {
    revision: BROWSER_EVENT_HANDLER_PROVENANCE.revision,
    sources: BROWSER_EVENT_HANDLER_PROVENANCE.sources,
    body: BODY_EVENT_HANDLER_ATTRIBUTES,
    frameset: FRAMESET_EVENT_HANDLER_ATTRIBUTES,
    html: HTML_EVENT_HANDLER_ATTRIBUTES,
    svg: SVG_EVENT_HANDLER_ATTRIBUTES,
    svgSmilHandlers: SVG_SMIL_EVENT_HANDLER_ATTRIBUTES,
    svgSmilElements: SVG_SMIL_EVENT_HANDLER_ELEMENTS,
    svgScriptOnerror: {
      attribute: 'onerror', element: 'script', mode: 'error-handler'
    }
  };
  const identityHash = createHash('sha256')
    .update(JSON.stringify(identity)).digest('hex');
  assert.equal(identityHash, BROWSER_EVENT_HANDLER_PROVENANCE.sha256);
  assert.match(BROWSER_EVENT_HANDLER_PROFILE, new RegExp(`${identityHash}$`));

  const htmlResult = extractEncodedPayloads(
    [source(HTML_EVENT_HANDLER_ATTRIBUTES.map(
      (name) => `<div ${name}="atob('${payload}')"></div>`
    ).join('\n'), 'profile.html')],
    { maxCandidates: 512, maxPayloads: 512 }
  );
  assert.equal(htmlResult.browserEventHandlerProfile, BROWSER_EVENT_HANDLER_PROFILE);
  assert.equal(htmlResult.decodedCount, HTML_EVENT_HANDLER_ATTRIBUTES.length);

  const bodyResult = extractEncodedPayloads([source(
    `<body ${BODY_EVENT_HANDLER_ATTRIBUTES.map(
      (name) => `${name}="atob('${payload}')"`
    ).join(' ')}></body>`, 'body-profile.html'
  )], { maxCandidates: 512, maxPayloads: 512 });
  assert.equal(bodyResult.decodedCount, BODY_EVENT_HANDLER_ATTRIBUTES.length);

  const framesetResult = extractEncodedPayloads([source(
    `<frameset ${FRAMESET_EVENT_HANDLER_ATTRIBUTES.map(
      (name) => `${name}="atob('${payload}')"`
    ).join(' ')}></frameset>`, 'frameset-profile.html'
  )], { maxCandidates: 512, maxPayloads: 512 });
  assert.equal(framesetResult.decodedCount, FRAMESET_EVENT_HANDLER_ATTRIBUTES.length);

  const svgResult = extractEncodedPayloads([source(
    `<svg><animate ${SVG_EVENT_HANDLER_ATTRIBUTES.map(
      (name) => `${name}="atob('${payload}')"`
    ).join(' ')}></animate></svg>`, 'svg-profile.html'
  )]);
  assert.equal(svgResult.decodedCount, SVG_EVENT_HANDLER_ATTRIBUTES.length);

  const inert = extractEncodedPayloads([source([
    ...BODY_EVENT_HANDLER_ATTRIBUTES.filter(
      (name) => !HTML_EVENT_HANDLER_ATTRIBUTES.includes(name)
    ).map((name) => `<div ${name}="atob('${payload}')"></div>`),
    ...[
      'onautofill', 'onbeforematch', 'onbeforexrselect', 'ondismiss',
      'onresolve', 'onsearch', 'onshow', 'ontransitioncancel',
      'ontransitionrun', 'ontransitionstart'
    ].map((name) => `<div ${name}="atob('${payload}')"></div>`),
    `<div onfoobar="atob('${payload}')"></div>`,
    `<div once="atob('${payload}')"></div>`
  ].join('\n'), 'inert-profile.html')]);
  assert.equal(inert.candidates, 0);
  assert.equal(inert.decodedCount, 0);
});

test('HTML5 parsing excludes inert text and duplicates and includes foreign handlers', () => {
  const payload = base64('eval(htmlTokenizerPayload);');
  const result = extractEncodedPayloads([source([
    `<textarea><button onclick="atob('${payload}')"></button></textarea>`,
    `<title><button onclick="atob('${payload}')"></button></title>`,
    `<style><button onclick="atob('${payload}')"></button></style>`,
    `<button onclick="void 0" onclick="atob('${payload}')"></button>`,
    `<button onclick="atob('${payload}')" onclick="void 0"></button>`,
    `<svg><animate onbegin="atob('${payload}')"></animate></svg>`,
    `<math><mrow onclick="atob('${payload}')"></mrow></math>`
  ].join('\n'), 'tokenizer.html')]);
  assert.equal(result.candidates, 3);
  assert.equal(result.decodedCount, 3);
  assert.deepEqual(result.entries.map((entry) => entry.encodedLine), [5, 6, 7]);

  const formalParameters = extractEncodedPayloads([source([
    `<button onclick="let event; atob('${payload}')"></button>`,
    `<body onerror="let source; atob('${payload}')"></body>`
  ].join('\n'), 'handler-parameters.html')]);
  assert.equal(formalParameters.decodedCount, 0);
});

test('HTML templates and tree-corrected root attributes retain executable locations', () => {
  const payload = base64('eval(templatePayload);xxxx');
  const templates = extractEncodedPayloads([source([
    `<template><button onclick="atob('${payload}')"></button></template>`,
    `<template><script>atob('${payload}')</script></template>`
  ].join('\n'), 'templates.html')]);
  assert.equal(templates.candidates, 1);
  assert.equal(templates.decodedCount, 1);
  assert.deepEqual(templates.entries.map((entry) => entry.encodedLine), [1]);

  const mergedRoots = extractEncodedPayloads([source([
    '<p>x</p>',
    `<body onclick="atob('${payload}')">`,
    `<html onclick="atob('${payload}')">`
  ].join('\n'), 'merged-roots.html')]);
  assert.equal(mergedRoots.candidates, 2);
  assert.equal(mergedRoots.decodedCount, 2);
  assert.deepEqual(mergedRoots.entries.map((entry) => entry.encodedLine), [2, 3]);
});

test('SVG handlers, SMIL scope, and scripts follow SVG execution grammar', () => {
  const payload = base64('eval(svgPayload);xxxxxxxx');
  const smil = extractEncodedPayloads([source(
    `<svg>${SVG_SMIL_EVENT_HANDLER_ELEMENTS.flatMap((tagName) =>
      SVG_SMIL_EVENT_HANDLER_ATTRIBUTES.map((attributeName) =>
        `<${tagName} ${attributeName}="atob('${payload}')"></${tagName}>`)
    ).join('\n')}</svg>`,
    'smil.html'
  )]);
  assert.equal(
    smil.decodedCount,
    SVG_SMIL_EVENT_HANDLER_ELEMENTS.length * SVG_SMIL_EVENT_HANDLER_ATTRIBUTES.length
  );

  const contexts = extractEncodedPayloads([source([
    `<svg><rect onbegin="atob('${payload}')"></rect></svg>`,
    `<svg><circle onend="atob('${payload}')"></circle></svg>`,
    `<svg onrepeat="atob('${payload}')"></svg>`,
    `<svg><animate onbegin="let event; atob('${payload}')"></animate></svg>`,
    `<svg><animate onbegin="let evt; atob('${payload}')"></animate></svg>`,
    `<svg><rect onclick="let event; atob('${payload}')"></rect></svg>`,
    `<svg><script onerror="let source; atob('${payload}')"></script></svg>`,
    `<svg><script onerror="let evt; atob('${payload}')"></script></svg>`
  ].join('\n'), 'svg-handlers.html')]);
  assert.equal(contexts.candidates, 5);
  assert.equal(contexts.decodedCount, 3);
  assert.deepEqual(contexts.entries.map((entry) => entry.encodedLine), [4, 6, 8]);

  const scripts = extractEncodedPayloads([source([
    `<svg><script nomodule>atob('${payload}')</script></svg>`,
    `<svg><script language="json">atob('${payload}')</script></svg>`,
    `<svg><script src="ignored.js">atob('${payload}')</script></svg>`,
    `<svg><script for="document" event="onclick">atob('${payload}')</script></svg>`,
    `<svg><script>atob(&quot;${payload}&quot;)</script></svg>`,
    `<svg><script><![CDATA[atob("${payload}")]]></script></svg>`,
    `<svg><script href="external.js">atob('${payload}')</script></svg>`,
    `<math><script>atob('${payload}')</script></math>`
  ].join('\n'), 'svg-scripts.html')]);
  assert.equal(scripts.candidates, 6);
  assert.equal(scripts.decodedCount, 6);
  assert.deepEqual(scripts.entries.map((entry) => entry.encodedLine), [1, 2, 3, 4, 5, 6]);
});

test('srcdoc and standalone SVG documents retain bounded executable contexts', async (t) => {
  const payload = base64('eval(documentPayload);xxxx');
  const srcdoc = `&lt;script>atob(&quot;${payload}&quot;)&lt;/script>`;
  const documents = extractEncodedPayloads([source([
    '<p>outer</p>',
    `<iframe srcdoc="${srcdoc}"></iframe>`,
    `<iframe sandbox srcdoc="${srcdoc}"></iframe>`,
    `<iframe sandbox="ALLOW-SCRIPTS" srcdoc="${srcdoc}"></iframe>`
  ].join('\n'), 'documents.html')]);
  assert.equal(documents.candidates, 2);
  assert.equal(documents.decodedCount, 2);
  assert.equal(documents.htmlMaxDocumentDepth, 2);
  assert.ok(documents.htmlNestedChars > 0);
  assert.deepEqual(documents.entries.map((entry) => entry.encodedLine), [2, 4]);

  const standalone = extractEncodedPayloads([source([
    '<?xml version="1.0"?>',
    '<s:svg xmlns:s="http://www.w3.org/2000/svg"',
    ' xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:v="urn:vendor">',
    `  <s:script><![CDATA[atob('${payload}')]]></s:script>`,
    `  <s:rect onclick="atob(&quot;${payload}&quot;)"/>`,
    `  <s:script v:href="metadata">atob('${payload}')</s:script>`,
    `  <s:SCRIPT>atob('${payload}')</s:SCRIPT>`,
    `  <s:rect onClick="atob('${payload}')" v:onclick="atob('${payload}')"/>`,
    `  <s:script xlink:href="external.js">atob('${payload}')</s:script>`,
    `  <s:script type="application/json">atob('${payload}')</s:script>`,
    '</s:svg>'
  ].join('\r\n'), 'namespaced.svg')]);
  assert.equal(standalone.decodedCount, 3);
  assert.deepEqual(standalone.entries.map((entry) => entry.encodedLine), [4, 5, 6]);
  assert.ok(standalone.htmlTokens > 0);
  assert.ok(standalone.htmlAttributes > 0);
  assert.ok(standalone.htmlNodes > 0);
  assert.ok(standalone.htmlTreeWork > 0);
  assert.equal(standalone.htmlMaxDocumentDepth, 1);

  const entities = extractEncodedPayloads([source([
    '<!DOCTYPE s:svg [',
    '  <!ENTITY label "safe">',
    `  <!ENTITY call "atob(&quot;${payload}&quot;)">`,
    '  <!ENTITY nested "&call;">',
    '  <!ENTITY __proto__ "&nested;">',
    '  <!ENTITY toString "&__proto__;">',
    ']>',
    '<s:svg xmlns:s="http://www.w3.org/2000/svg"><s:text>&label;</s:text><s:script>',
    '&toString;',
    '</s:script></s:svg>'
  ].join('\n'), 'entities.svg')]);
  assert.equal(entities.decodedCount, 1);
  assert.equal(entities.entries[0].encodedLine, 9);
  assert.equal(entities.xmlEntityDeclarations, 5);
  assert.equal(entities.xmlExpandedChars, 8 + `atob("${payload}")`.length * 5);

  const malformed = extractEncodedPayloads([source(
    `<svg xmlns="http://www.w3.org/2000/svg"><script>atob('${payload}')</svg>`,
    'malformed.svg'
  )]);
  assert.equal(malformed.decodedCount, 0);

  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-encoded-svg-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, {
    manifest_version: 3, name: 'SVG source fixture', version: '1.0.0'
  }, {
    'page.svg': `<s:svg xmlns:s="http://www.w3.org/2000/svg"><s:script><![CDATA[atob("${payload}")]]></s:script></s:svg>`
  });
  const result = await auditExtension(temp);
  assert.equal(result.encodedPayloads.decodedCount, 1);
  assert.equal(result.encodedPayloads.entries[0].path, 'page.svg');
});

test('malformed literal attempts consume fixed budgets without repeated rescans', () => {
  const twoIncompleteLines = source("atob('unterminated\natob('unterminated");
  assert.throws(
    () => extractEncodedPayloads([twoIncompleteLines], { maxCandidates: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /candidates/.test(error.message)
  );
  const oversizedIncomplete = source(`atob('${'x'.repeat(128)}`);
  assert.throws(
    () => extractEncodedPayloads([oversizedIncomplete], { maxTotalEncodedChars: 64 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /candidate characters/.test(error.message)
  );
  const manyMalformedTokens = source('atob('.repeat(100_000));
  const started = process.hrtime.bigint();
  assert.throws(
    () => extractEncodedPayloads([manyMalformedTokens]),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /stack safety/.test(error.message)
  );
  const elapsedMilliseconds = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(elapsedMilliseconds < 2_000, `single-pass scan took ${elapsedMilliseconds}ms`);

  const overlapping = source("atob('".repeat(20_000));
  assert.throws(
    () => extractEncodedPayloads([overlapping], { maxCandidates: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /candidates/.test(error.message)
  );
  const overlapStarted = process.hrtime.bigint();
  const overlapResult = extractEncodedPayloads([overlapping], { maxCandidates: 20_000 });
  const overlapMilliseconds = Number(process.hrtime.bigint() - overlapStarted) / 1e6;
  assert.equal(overlapResult.candidates, 10_000);
  assert.ok(overlapMilliseconds < 2_000, `overlap scan took ${overlapMilliseconds}ms`);

  const unmatchedRegexes = source('/[ '.repeat(8_000));
  const regexStarted = process.hrtime.bigint();
  const regexResult = extractEncodedPayloads([unmatchedRegexes]);
  const regexMilliseconds = Number(process.hrtime.bigint() - regexStarted) / 1e6;
  assert.equal(regexResult.candidates, 0);
  assert.ok(regexMilliseconds < 2_000, `unmatched regex scan took ${regexMilliseconds}ms`);

  const malformedHtml = source('<a'.repeat(16_000), 'malformed.html');
  const htmlStarted = process.hrtime.bigint();
  const htmlResult = extractEncodedPayloads([malformedHtml]);
  const htmlMilliseconds = Number(process.hrtime.bigint() - htmlStarted) / 1e6;
  assert.equal(htmlResult.candidates, 0);
  assert.ok(htmlMilliseconds < 2_000, `malformed HTML scan took ${htmlMilliseconds}ms`);

  const adversarialHtml = source(
    '<div>'.repeat(32_000) + '</span>'.repeat(32_000), 'adversarial.html'
  );
  const adversarialStarted = process.hrtime.bigint();
  assert.throws(
    () => extractEncodedPayloads([adversarialHtml]),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /HTML tree depth/.test(error.message)
  );
  const adversarialMilliseconds = Number(
    process.hrtime.bigint() - adversarialStarted
  ) / 1e6;
  assert.ok(
    adversarialMilliseconds < 2_000,
    `adversarial HTML scan took ${adversarialMilliseconds}ms`
  );

  const mergedAttributes = source(
    `<p>x</p>${Array.from({ length: 12_000 }, (_, index) =>
      `<body x${index}>`).join('')}`,
    'merged-attributes.html'
  );
  const mergedStarted = process.hrtime.bigint();
  const mergedResult = extractEncodedPayloads([mergedAttributes]);
  const mergedMilliseconds = Number(process.hrtime.bigint() - mergedStarted) / 1e6;
  assert.equal(mergedResult.htmlAttributes, 12_000);
  assert.ok(mergedResult.htmlTreeWork >= 12_000);
  assert.ok(
    mergedMilliseconds < 2_000,
    `merged HTML attributes took ${mergedMilliseconds}ms`
  );

  const oversizedTag = source(
    `<div ${Array.from({ length: 20_000 }, (_, index) => `x${index}`).join(' ')}>`,
    'oversized-tag.html'
  );
  const oversizedTagStarted = process.hrtime.bigint();
  assert.throws(
    () => extractEncodedPayloads([oversizedTag]),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /HTML attributes/.test(error.message)
  );
  const oversizedTagMilliseconds = Number(
    process.hrtime.bigint() - oversizedTagStarted
  ) / 1e6;
  assert.ok(
    oversizedTagMilliseconds < 2_000,
    `oversized HTML tag took ${oversizedTagMilliseconds}ms`
  );
});

test('all ECMAScript line terminators preserve encoded and decoded provenance', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-encoded-lines-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const hidden = ['first', 'eval(lineTwoPayload);'].join('\r');
  const separators = ['\r\n', '\r', '\n', '\u2028', '\u2029'];
  await writeExtension(temp, {
    manifest_version: 3, name: 'Encoded line fixture', version: '1.0.0'
  }, { 'worker.js': `${separators.map((separator) => `void 0;${separator}`).join('')}atob('${base64(hidden)}');` });
  const result = await auditExtension(temp);
  assert.equal(result.encodedPayloads.entries[0].encodedLine, 6);
  const finding = result.findings.find((item) => item.id === 'MVX201');
  assert.equal(finding.evidence[0].line, 6);
  assert.equal(finding.evidence[0].decodedLine, 2);
});

test('JSON data is not misclassified as executable runtime decoding', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-encoded-json-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const encodedText = `atob('${base64('eval(dataOnlyPayload);')}')`;
  await writeExtension(temp, {
    manifest_version: 3, name: 'Encoded JSON fixture', version: '1.0.0'
  }, {
    'lower.json': JSON.stringify({ documentation: encodedText }),
    'upper.JSON': JSON.stringify({ documentation: encodedText })
  });
  const result = await auditExtension(temp);
  assert.equal(result.encodedPayloads.candidates, 0);
  assert.equal(result.encodedPayloads.decodedCount, 0);
  assert.equal(result.findings.some((finding) => finding.id === 'MVX201'), false);
  assert.equal(result.findings.some((finding) => finding.id === 'MVX213'), false);
});

test('encoded-payload resource limits fail closed and malformed limits are rejected', () => {
  assert.equal(PUBLIC_ENCODED_PAYLOAD_LIMITS, ENCODED_PAYLOAD_LIMITS);
  assert.equal(PUBLIC_ENCODED_PAYLOAD_PARSER_PROFILES, ENCODED_PAYLOAD_PARSER_PROFILES);
  assert.equal(PUBLIC_ENCODED_PAYLOAD_PROFILE, ENCODED_PAYLOAD_PROFILE);
  assert.equal(PUBLIC_BROWSER_EVENT_HANDLER_PROFILE, BROWSER_EVENT_HANDLER_PROFILE);
  assert.equal(
    PUBLIC_BROWSER_EVENT_HANDLER_PROVENANCE,
    BROWSER_EVENT_HANDLER_PROVENANCE
  );
  assert.equal(PUBLIC_BODY_EVENT_HANDLER_ATTRIBUTES, BODY_EVENT_HANDLER_ATTRIBUTES);
  assert.equal(
    PUBLIC_FRAMESET_EVENT_HANDLER_ATTRIBUTES,
    FRAMESET_EVENT_HANDLER_ATTRIBUTES
  );
  assert.equal(PUBLIC_HTML_EVENT_HANDLER_ATTRIBUTES, HTML_EVENT_HANDLER_ATTRIBUTES);
  assert.equal(PUBLIC_SVG_EVENT_HANDLER_ATTRIBUTES, SVG_EVENT_HANDLER_ATTRIBUTES);
  assert.equal(
    PUBLIC_SVG_SMIL_EVENT_HANDLER_ATTRIBUTES,
    SVG_SMIL_EVENT_HANDLER_ATTRIBUTES
  );
  assert.equal(PUBLIC_SVG_SMIL_EVENT_HANDLER_ELEMENTS, SVG_SMIL_EVENT_HANDLER_ELEMENTS);
  const payload = base64('x'.repeat(16));
  const two = source(`atob('${payload}'); atob('${payload}');`);
  assert.throws(
    () => extractEncodedPayloads([two], { maxCandidates: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /candidates/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([two], { maxPayloads: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /count/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([two], { maxEncodedChars: 16 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /characters/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([two], { maxTotalEncodedChars: payload.length + 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /candidate characters/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([two], { maxDecodedBytes: 15 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /payload/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([two], { maxTotalDecodedBytes: 20 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /bytes/.test(error.message)
  );
  assert.throws(() => extractEncodedPayloads([two], { unknown: 1 }),
    (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(() => extractEncodedPayloads([two], { maxDepth: 0 }),
    (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(() => extractEncodedPayloads([two], new Proxy({}, {})),
    (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(
    () => extractEncodedPayloads([source(';'.repeat(1_001))], { maxParserTokens: 1_000 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /tokens/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([source('0;'.repeat(500))], {
      maxParserTokens: 5_000,
      maxAstNodes: 500
    }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /AST nodes/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([source('const o={x};')], { maxAstNodes: 7 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /AST nodes/.test(error.message)
  );
  assert.equal(
    extractEncodedPayloads([source('const o={x};')], { maxAstNodes: 8 }).astNodes,
    8
  );
  const html = source('<div id="x" class="y"><span>text</span></div>', 'limits.html');
  const htmlResult = extractEncodedPayloads([html]);
  assert.ok(htmlResult.htmlTokens > 0);
  assert.ok(htmlResult.htmlAttributes > 0);
  assert.ok(htmlResult.htmlNodes > 0);
  assert.ok(htmlResult.htmlTreeWork > 0);
  assert.ok(htmlResult.htmlMaxDepth > 0);
  assert.equal(htmlResult.htmlMaxDocumentDepth, 1);
  assert.throws(
    () => extractEncodedPayloads([html], { maxHtmlTokens: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /HTML tokens/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([html], { maxHtmlNodes: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /HTML node/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([html], { maxHtmlAttributes: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /HTML attributes/.test(error.message)
  );
  const svg = source(
    '<svg xmlns="http://www.w3.org/2000/svg"><g id="x">text</g></svg>',
    'limits.svg'
  );
  assert.throws(
    () => extractEncodedPayloads([svg], { maxHtmlTokens: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /XML tokens/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([svg], { maxHtmlNodes: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /XML node/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([svg], { maxHtmlAttributes: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /XML attributes/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([svg], { maxHtmlTreeDepth: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /XML tree depth/.test(error.message)
  );
  const entitySvg = source([
    '<!DOCTYPE svg [<!ENTITY a "safe"><!ENTITY b "&a;">]>',
    '<svg xmlns="http://www.w3.org/2000/svg"><script>&b;</script></svg>'
  ].join('\n'), 'entity-limits.svg');
  assert.throws(
    () => extractEncodedPayloads([entitySvg], { maxXmlEntityDeclarations: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /entity declarations/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([entitySvg], { maxXmlEntityDepth: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /entity depth/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([entitySvg], { maxXmlExpandedChars: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /entity expansion/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([source(
      '<!DOCTYPE svg SYSTEM "external.dtd"><svg/>', 'external-dtd.svg'
    )]),
    (error) => error.code === 'INVALID_INPUT' && /External XML DTD/.test(error.message)
  );
  const unsupportedDtds = [
    ['parameter', '<!DOCTYPE svg [<!ENTITY % p "x">]><svg/>', /Parameter XML entities/],
    ['recursive', '<!DOCTYPE svg [<!ENTITY a "&a;">]><svg/>', /Recursive XML entity/],
    ['markup', '<!DOCTYPE svg [<!ENTITY a "<g/>">]><svg/>', /Markup and parameter/],
    ['default-attribute', '<!DOCTYPE svg [<!ATTLIST svg onclick CDATA #IMPLIED>]><svg/>', /Unsupported XML DTD/],
    ['duplicate', '<!DOCTYPE svg [<!ENTITY a "x"><!ENTITY a "y">]><svg/>', /Duplicate XML entity/],
    ['undefined', '<!DOCTYPE svg [<!ENTITY a "&missing;">]><svg/>', /Undefined XML entity/],
    ['public', '<!DOCTYPE svg PUBLIC "identifier" "external.dtd"><svg/>', /External XML DTD/],
    ['xml10-control', '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "&#1;">]><svg/>', /Undefined XML entity/]
  ];
  for (const [name, content, message] of unsupportedDtds) {
    assert.throws(
      () => extractEncodedPayloads([source(content, `${name}.svg`)]),
      (error) => error.code === 'INVALID_INPUT' && message.test(error.message)
    );
  }
  const xml11 = extractEncodedPayloads([source(
    '<?xml version="1.1"?><!DOCTYPE svg [<!ENTITY a "&#1;">]>'
      + '<svg xmlns="http://www.w3.org/2000/svg"><text>&a;</text></svg>',
    'xml11.svg'
  )]);
  assert.equal(xml11.xmlEntityDeclarations, 1);
  assert.throws(
    () => extractEncodedPayloads([
      source('<div>'.repeat(16), 'depth.html')
    ], { maxHtmlTreeDepth: 8 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /HTML tree depth/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([
      source('<div>'.repeat(16), 'work.html')
    ], { maxHtmlTreeDepth: 32, maxHtmlTreeWork: 16 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /tree-construction work/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([source(
      '<iframe srcdoc="&lt;p>nested&lt;/p>"></iframe>', 'document-depth.html'
    )], { maxHtmlDocumentDepth: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /HTML document depth/.test(error.message)
  );
  assert.throws(
    () => extractEncodedPayloads([source(
      '<iframe srcdoc="&lt;p>nested&lt;/p>"></iframe>', 'nested-size.html'
    )], { maxNestedHtmlChars: 1 }),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /Nested HTML/.test(error.message)
  );
  const deeplyNested = source(
    '['.repeat(3_000) + `atob('${base64('eval(deepPayload);xxxx')}')` + ']'.repeat(3_000)
  );
  assert.throws(
    () => extractEncodedPayloads([deeplyNested]),
    (error) => error.code === 'ENCODED_PAYLOAD_LIMIT' && /stack safety/.test(error.message)
  );

  const nested = source(`atob('${base64(`atob('${base64('eval(payload);xxxxx')}')`)}')`);
  const shallow = extractEncodedPayloads([nested], { maxDepth: 1 });
  assert.equal(shallow.decodedCount, 1);
  assert.equal(shallow.decodedSources.length, 1);
  assert.deepEqual(shallow.limits, { ...ENCODED_PAYLOAD_LIMITS, maxDepth: 1 });
});

test('audit verification reproduces and binds the decoded-payload inventory', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-encoded-verification-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'Encoded verification fixture', version: '1.0.0'
  }, { 'worker.js': `atob('${base64('eval(replayedPayload);')}');\n` });
  const report = await auditExtension(extension);
  const reportPath = path.join(temp, 'report.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  assert.equal((await verifyAuditReport(reportPath, extension)).valid, true);

  const tampered = structuredClone(report);
  tampered.encodedPayloads.entries[0].sha256 = '0'.repeat(64);
  await writeFile(reportPath, `${JSON.stringify(tampered, null, 2)}\n`, 'utf8');
  await assert.rejects(
    () => verifyAuditReport(reportPath, extension),
    (error) => error.code === 'AUDIT_REPORT_MISMATCH'
  );
});

test('comparison and offline replay preserve encoded-payload deltas', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-encoded-comparison-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const manifest = {
    manifest_version: 3, name: 'Encoded comparison fixture', version: '1.0.0'
  };
  const before = await writeExtension(path.join(temp, 'before'), manifest, {
    'worker.js': 'const packaged = true;\n'
  });
  const after = await writeExtension(path.join(temp, 'after'), manifest, {
    'worker.js': `atob('${base64('eval(comparisonPayload);')}');\n`
  });
  const comparison = await compareExtensions(before, after);
  assert.equal(comparison.before.encodedPayloads.decodedCount, 0);
  assert.equal(comparison.after.encodedPayloads.decodedCount, 1);
  assert.deepEqual(comparison.delta.introducedFindings.map((finding) => finding.id), [
    'MVX201', 'MVX213'
  ]);
  assert.match(comparisonToMarkdown(comparison), /\| Encoded payloads decoded \| 0 \| 1 \|/);

  const reportPath = path.join(temp, 'comparison.json');
  await writeFile(reportPath, `${JSON.stringify(comparison, null, 2)}\n`, 'utf8');
  assert.equal((await verifyComparisonReport(reportPath, before, after)).valid, true);
});
