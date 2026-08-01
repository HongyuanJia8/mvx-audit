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
  analyzeEncodedPayloads, ENCODED_PAYLOAD_LIMITS, ENCODED_PAYLOAD_PROFILE,
  extractEncodedPayloads
} from '../src/encoded-payloads.js';
import {
  ENCODED_PAYLOAD_LIMITS as PUBLIC_ENCODED_PAYLOAD_LIMITS,
  ENCODED_PAYLOAD_PROFILE as PUBLIC_ENCODED_PAYLOAD_PROFILE
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
  assert.equal(result.encodedPayloads.decodedCount, 1);
  assert.equal(result.encodedPayloads.candidateEncodedChars, base64(hidden).length);
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
    `atob('${payload}');`
  ].join('\n'))]);
  assert.equal(syntaxVariants.candidates, 3);
  assert.equal(syntaxVariants.decodedCount, 3);

  const browserHtml = [
    `<script>const marker = "</scripty>"; atob('${payload}')</script>`,
    `<button onclick="atob(&quot;${payload}&quot;)">quoted</button>`,
    `<button onclick="&#97;tob('${payload}')">numeric</button>`,
    `<script type="text&#x2f;javascript">atob('${payload}')</script>`,
    `<script>${'İ'.repeat(80)}</script><script>atob('${payload}')</script>`
  ].join('\n');
  const browserHtmlResult = extractEncodedPayloads([source(browserHtml, 'browser.html')]);
  assert.equal(browserHtmlResult.candidates, 5);
  assert.equal(browserHtmlResult.decodedCount, 5);
  assert.deepEqual(browserHtmlResult.entries.map((entry) => entry.encodedLine), [1, 2, 3, 4, 5]);
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
  const result = extractEncodedPayloads([manyMalformedTokens]);
  const elapsedMilliseconds = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(result.candidates, 0);
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
  assert.equal(PUBLIC_ENCODED_PAYLOAD_PROFILE, ENCODED_PAYLOAD_PROFILE);
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
