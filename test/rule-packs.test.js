import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { compareExtensions } from '../src/compare.js';
import { auditToSarif, auditToText, comparisonToMarkdown } from '../src/reporters.js';
import { loadRulePacks, resolveRulePacks } from '../src/rule-packs.js';
import { runCli } from '../src/cli.js';
import { captureStreams, writeExtension } from '../support/helpers.js';

function rule(overrides = {}) {
  return {
    id: 'IOC_TEXT',
    title: 'Campaign indicator',
    severity: 'high',
    confidence: 'high',
    category: 'campaign-ioc',
    description: 'A local research indicator matched the extension package.',
    remediation: 'Correlate the match with provenance and inspect the surrounding behavior.',
    references: ['https://example.invalid/research'],
    indicators: [{ type: 'text', value: 'campaign.example.invalid' }],
    ...overrides
  };
}

function pack(overrides = {}) {
  return {
    schemaVersion: 1,
    namespace: 'research.demo',
    name: 'Research demo indicators',
    version: '2026.07.30',
    rules: [rule()],
    ...overrides
  };
}

async function writePack(filePath, value, pretty = true) {
  const content = pretty ? `${JSON.stringify(value, null, 2)}\n` : JSON.stringify(value);
  await writeFile(filePath, content, 'utf8');
  return Buffer.from(content);
}

test('checked-in example rule pack remains valid and publishable', async () => {
  const loaded = await loadRulePacks([path.resolve('examples/campaign-rule-pack.json')]);
  assert.equal(loaded.summary.packs, 1);
  assert.equal(loaded.summary.rules, 2);
  assert.equal(loaded.provenance[0].namespace, 'example.campaign');
});

test('rule-pack loader is path-independent, ordered, bounded, and rejects symlinks or duplicate namespaces', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-rule-loader-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const first = path.join(temp, 'first.json');
  const copied = path.join(temp, 'copied.json');
  const second = path.join(temp, 'second.json');
  const bytes = await writePack(first, pack());
  await writeFile(copied, bytes);
  await writePack(second, pack({ namespace: 'alpha.indicators', name: 'Alpha indicators' }));

  const loadedFirst = await loadRulePacks([first]);
  const loadedCopy = await loadRulePacks([copied]);
  assert.deepEqual(loadedFirst.provenance, loadedCopy.provenance);
  assert.equal(loadedFirst.provenance[0].sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(JSON.stringify(loadedFirst.provenance).includes(temp), false);
  assert.equal(Object.isFrozen(loadedFirst), true);
  assert.equal(Object.isFrozen(loadedFirst.packs[0].rules[0].indicators[0]), true);
  assert.throws(() => {
    loadedFirst.packs[0].rules[0].title = 'mutated\nheading';
  }, TypeError);
  assert.equal(loadedFirst.packs[0].rules[0].title, 'Campaign indicator');
  await assert.rejects(
    () => resolveRulePacks({ _preparedRulePacks: structuredClone(loadedFirst) }),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
  assert.deepEqual((await loadRulePacks([first, second])).provenance.map((item) => item.namespace), [
    'alpha.indicators', 'research.demo'
  ]);
  await assert.rejects(() => loadRulePacks([first, copied]),
    (error) => error.code === 'INVALID_RULE_PACK' && /Duplicate rule-pack namespace/.test(error.message));

  const linked = path.join(temp, 'linked.json');
  await symlink(first, linked);
  await assert.rejects(() => loadRulePacks([linked]), (error) => error.code === 'UNSAFE_RULE_PACK');
  await assert.rejects(() => loadRulePacks(first), (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => loadRulePacks([first], { maxPackBytes: bytes.length - 1 }),
    (error) => error.code === 'RULE_PACK_LIMIT');
  await assert.rejects(() => loadRulePacks([first], { unknown: 1 }),
    (error) => error.code === 'INVALID_ARGUMENT');
});

test('strict rule-pack schema rejects executable matchers, unsafe metadata, and ambiguous indicators', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-rule-schema-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const cases = [
    ['unknown pack field', { ...pack(), plugin: './code.js' }, 'INVALID_RULE_PACK'],
    ['unsupported regex', pack({ rules: [rule({ indicators: [{ type: 'regex', value: '.*' }] })] }), 'INVALID_RULE_PACK'],
    ['path traversal', pack({ rules: [rule({ indicators: [{ type: 'path', value: '../escape.js' }] })] }), 'INVALID_RULE_PACK'],
    ['path NUL', pack({ rules: [rule({ indicators: [{ type: 'path', value: 'payload\0.js' }] })] }), 'INVALID_RULE_PACK'],
    ['path display control', pack({ rules: [rule({ indicators: [{ type: 'path', value: 'x\n# injected.md' }] })] }), 'INVALID_RULE_PACK'],
    ['path Arabic letter mark', pack({ rules: [rule({ indicators: [{ type: 'path', value: 'x\u061c.js' }] })] }), 'INVALID_RULE_PACK'],
    ['path left-to-right mark', pack({ rules: [rule({ indicators: [{ type: 'path', value: 'x\u200e.js' }] })] }), 'INVALID_RULE_PACK'],
    ['path right-to-left mark', pack({ rules: [rule({ indicators: [{ type: 'path', value: 'x\u200f.js' }] })] }), 'INVALID_RULE_PACK'],
    ['literal NUL', pack({ rules: [rule({ indicators: [{ type: 'text', value: 'ioc\0marker' }] })] }), 'RULE_PACK_LIMIT'],
    ['non-ASCII folding', pack({ rules: [rule({ indicators: [{ type: 'text', value: 'İOC', caseSensitive: false }] })] }), 'INVALID_RULE_PACK'],
    ['terminal control', pack({ rules: [rule({ title: 'unsafe\nheading' })] }), 'INVALID_RULE_PACK'],
    ['insecure reference', pack({ rules: [rule({ references: ['http://example.invalid/research'] })] }), 'INVALID_RULE_PACK'],
    ['duplicate indicator', pack({ rules: [rule({ indicators: [
      { type: 'text', value: 'duplicate' }, { type: 'text', value: 'duplicate' }
    ] })] }), 'INVALID_RULE_PACK'],
    ['literal limit', pack({ rules: [rule({ indicators: [{ type: 'text', value: 'three' }] })] }), 'RULE_PACK_LIMIT']
  ];
  for (let index = 0; index < cases.length; index += 1) {
    const [label, value, code] = cases[index];
    const input = path.join(temp, `${index}.json`);
    await writePack(input, value);
    await assert.rejects(
      () => loadRulePacks([input], label === 'literal limit' ? { maxLiteralBytes: 2 } : {}),
      (error) => error.code === code,
      label
    );
  }
  const duplicate = path.join(temp, 'duplicate-key.json');
  await writeFile(duplicate, JSON.stringify(pack()).replace(
    '"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'
  ), 'utf8');
  await assert.rejects(() => loadRulePacks([duplicate]),
    (error) => error.code === 'INVALID_RULE_PACK' && /duplicate JSON field/.test(error.message));

  const invalidUtf8 = path.join(temp, 'invalid-utf8.json');
  await writeFile(invalidUtf8, Buffer.from([0xff, 0xfe, 0x7b, 0x7d]));
  await assert.rejects(() => loadRulePacks([invalidUtf8]),
    (error) => error.code === 'INVALID_RULE_PACK' && /valid UTF-8/.test(error.message));

  const excessiveDepth = path.join(temp, 'deep.json');
  await writeFile(excessiveDepth, `${'['.repeat(130)}0${']'.repeat(130)}`, 'utf8');
  await assert.rejects(() => loadRulePacks([excessiveDepth]),
    (error) => error.code === 'RULE_PACK_LIMIT' && /nesting levels/.test(error.message));
});

test('declarative rules match text, paths, file and package hashes with deterministic any/all evidence', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-rule-match-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'Campaign Fixture', version: '1.0.0', background: { service_worker: 'worker.js' }
  }, {
    'worker.js': [
      "const endpoint = 'HTTPS://C2.EXAMPLE.INVALID/v1';",
      'WebAssembly.instantiate(bytes);',
      "const unicodeMarker = '☃';",
      "const overlap = 'ushers';",
      ''
    ].join('\n'),
    'nested/payload.wasm': Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    'assets/marker.bin': 'marker bytes'
  });
  const baseline = await auditExtension(extension);
  const markerSha256 = createHash('sha256').update('marker bytes').digest('hex');
  const value = pack({ rules: [
    rule({ id: 'TEXT_SOURCE', indicators: [{ type: 'text', value: 'c2.example.invalid', scope: 'source', caseSensitive: false }] }),
    rule({ id: 'TEXT_MANIFEST', indicators: [{ type: 'text', value: 'Campaign Fixture', scope: 'manifest' }] }),
    rule({ id: 'ALL_CHAIN', condition: 'all', indicators: [
      { type: 'text', value: 'WebAssembly.instantiate', scope: 'source' },
      { type: 'path', value: 'nested/payload.wasm' },
      { type: 'file-sha256', value: markerSha256 }
    ] }),
    rule({ id: 'BASENAME', indicators: [{ type: 'path', value: 'payload.wasm', match: 'basename' }] }),
    rule({ id: 'PACKAGE_HASH', indicators: [{ type: 'package-sha256', value: baseline.package.sha256 }] }),
    rule({ id: 'UNICODE', indicators: [{ type: 'text', value: '☃', scope: 'source' }] }),
    rule({ id: 'OVERLAP_HE', indicators: [{ type: 'text', value: 'he', scope: 'source' }] }),
    rule({ id: 'OVERLAP_SHE', indicators: [{ type: 'text', value: 'she', scope: 'source' }] }),
    rule({ id: 'REGEX_IS_LITERAL', indicators: [{ type: 'text', value: '(.+)+$', scope: 'source' }] }),
    rule({ id: 'INCOMPLETE_ALL', condition: 'all', indicators: [
      { type: 'path', value: 'worker.js' }, { type: 'text', value: 'missing-indicator', scope: 'source' }
    ] })
  ] });
  const input = path.join(temp, 'campaign.json');
  const raw = await writePack(input, value);
  const result = await auditExtension(extension, { rulePacks: [input] });
  const custom = result.findings.filter((finding) => finding.id.startsWith('RP:'));
  assert.deepEqual(custom.map((finding) => finding.id).sort(), [
    'RP:research.demo:ALL_CHAIN',
    'RP:research.demo:BASENAME',
    'RP:research.demo:OVERLAP_HE',
    'RP:research.demo:OVERLAP_SHE',
    'RP:research.demo:PACKAGE_HASH',
    'RP:research.demo:TEXT_MANIFEST',
    'RP:research.demo:TEXT_SOURCE',
    'RP:research.demo:UNICODE'
  ]);
  const all = custom.find((finding) => finding.id.endsWith(':ALL_CHAIN'));
  assert.equal(all.condition, 'all');
  assert.deepEqual(all.evidence.map((evidence) => evidence.indicator), [2, 1, 0]);
  assert.equal(custom.find((finding) => finding.id.endsWith(':TEXT_SOURCE')).evidence[0].line, 1);
  assert.equal(custom.find((finding) => finding.id.endsWith(':TEXT_MANIFEST')).evidence[0].file, 'manifest.json');
  assert.equal(custom.find((finding) => finding.id.endsWith(':PACKAGE_HASH')).evidence[0].file, undefined);
  assert.equal(result.package.sha256, baseline.package.sha256);
  assert.notEqual(result.analysis.sha256, baseline.analysis.sha256);
  assert.equal(result.analysis.profile, 'mvx-static-v5');
  assert.deepEqual(result.analysis.rulePacks, result.rulePacks);
  assert.equal(result.rulePacks[0].sha256, createHash('sha256').update(raw).digest('hex'));
  assert.equal(JSON.stringify(result.rulePacks).includes(temp), false);
  assert.deepEqual([
    result.scan.rulePacksApplied, result.scan.customRulesApplied, result.scan.customIndicatorsApplied
  ], [1, 10, 13]);
  assert.match(result.assumptions.at(-1), /Analyst-supplied declarative rule-pack/);

  const text = auditToText(result);
  assert.match(text, /Rule packs: 1 \(research\.demo@2026\.07\.30\)/);
  assert.match(text, /at package/);
  const sarif = auditToSarif(result);
  assert.deepEqual(sarif.runs[0].properties.rulePacks, result.rulePacks);
  const packageResult = sarif.runs[0].results.find((item) => item.ruleId.endsWith(':PACKAGE_HASH'));
  assert.equal(packageResult.locations, undefined);
  assert.equal(packageResult.properties.rulePack.namespace, 'research.demo');
  assert.equal(packageResult.properties.condition, 'any');

  await writePack(input, value, false);
  const reformatted = await auditExtension(extension, { rulePacks: [input] });
  assert.equal(reformatted.package.sha256, result.package.sha256);
  assert.notEqual(reformatted.rulePacks[0].sha256, result.rulePacks[0].sha256);
  assert.notEqual(reformatted.analysis.sha256, result.analysis.sha256);
  assert.deepEqual(
    reformatted.findings.filter((finding) => finding.id.startsWith('RP:')).map((finding) => finding.id),
    custom.map((finding) => finding.id)
  );
});

test('match limits fail closed and normalized limits participate in analysis identity', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-rule-limits-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'Limit fixture', version: '1.0.0'
  }, { 'worker.js': 'ioc ioc\n' });
  const input = path.join(temp, 'limits.json');
  await writePack(input, pack({ rules: [rule({ indicators: [{ type: 'text', value: 'ioc', scope: 'source' }] })] }));
  await assert.rejects(
    () => auditExtension(extension, { rulePacks: [input], rulePackLimits: { maxMatches: 1 } }),
    (error) => error.code === 'RULE_PACK_LIMIT' && /matches exceed/.test(error.message)
  );
  const accepted = await auditExtension(extension, { rulePacks: [input], rulePackLimits: { maxMatches: 2, maxPacks: 3 } });
  const reversed = await auditExtension(extension, { rulePacks: [input], rulePackLimits: { maxPacks: 3, maxMatches: 2 } });
  assert.equal(accepted.analysis.sha256, reversed.analysis.sha256);
  assert.equal(accepted.findings.find((finding) => finding.id.startsWith('RP:')).evidence.length, 1);
});

test('CLI validates repeated rule packs and applies them to audit and compare', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-rule-cli-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'CLI campaign', version: '1.0.0'
  }, { 'worker.js': "const endpoint = 'campaign.example.invalid';\n" });
  const first = path.join(temp, 'first.json');
  const second = path.join(temp, 'second.json');
  await writePack(first, pack());
  await writePack(second, pack({
    namespace: 'research.second',
    name: 'Second pack',
    rules: [rule({ id: 'SECOND_IOC', indicators: [{ type: 'path', value: 'worker.js' }] })]
  }));

  const validation = captureStreams();
  assert.equal(await runCli(['rules', 'validate', first, second, '--format', 'json'], validation.streams), 0);
  const validated = JSON.parse(validation.output().stdout);
  assert.equal(validated.valid, true);
  assert.equal(validated.summary.packs, 2);

  const audit = captureStreams();
  assert.equal(await runCli([
    'audit', extension, '--format', 'json', '--rule-pack', second, '--rule-pack', first
  ], audit.streams), 0);
  const result = JSON.parse(audit.output().stdout);
  assert.deepEqual(result.rulePacks.map((item) => item.namespace), ['research.demo', 'research.second']);
  assert.equal(result.findings.filter((finding) => finding.id.startsWith('RP:')).length, 2);

  const comparison = await compareExtensions(extension, extension, { rulePacks: [first, second] });
  assert.equal(comparison.before.rulePacks.length, 2);
  assert.equal(comparison.before.analysis.sha256, comparison.after.analysis.sha256);

  await writeFile(first, '{broken', 'utf8');
  const invalid = captureStreams();
  assert.equal(await runCli(['rules', 'validate', first], invalid.streams), 2);
  assert.match(invalid.output().stderr, /INVALID_RULE_PACK/);
  assert.equal((await readFile(second, 'utf8')).includes('Second pack'), true);
});

test('custom display text is escaped in Markdown and SARIF markdown fields', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-rule-render-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const before = await writeExtension(path.join(temp, 'before'), {
    manifest_version: 3, name: 'Before', version: '1.0.0'
  }, { 'worker.js': 'const marker = "absent";\n' });
  const after = await writeExtension(path.join(temp, 'after'), {
    manifest_version: 3, name: 'After', version: '1.0.0'
  }, { 'worker.js': 'const marker = "render-ioc";\n' });
  const input = path.join(temp, 'render.json');
  await writePack(input, pack({ rules: [
    rule({
      id: 'RENDER_IOC',
      title: '<img src=x> *campaign*',
      remediation: 'Use *manual* [review] for this indicator.',
      indicators: [{ type: 'text', value: 'render-ioc', scope: 'source' }]
    }),
    rule({
      id: 'SARIF_NAME',
      title: '***',
      indicators: [{ type: 'text', value: 'render-ioc', scope: 'source' }]
    })
  ] }));
  const comparison = await compareExtensions(before, after, { rulePacks: [input] });
  const markdown = comparisonToMarkdown(comparison);
  assert.doesNotMatch(markdown, /<img src=x>/);
  assert.match(markdown, /\\<img src=x\\> \\\*campaign\\\*/);
  const sarif = auditToSarif(comparison.after);
  const customRule = sarif.runs[0].tool.driver.rules.find((item) => item.id.endsWith(':RENDER_IOC'));
  assert.match(customRule.help.markdown, /Use \\\*manual\\\* \\\[review\\\]/);
  const fallbackName = sarif.runs[0].tool.driver.rules.find((item) => item.id.endsWith(':SARIF_NAME'));
  assert.match(fallbackName.name, /^RP/);
});

test('control characters in package filenames cannot inject text, Markdown, or SARIF locations', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-rule-path-render-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const unsafePath = 'x\u061c\u200e\u200f\n# injected.md';
  const before = await writeExtension(path.join(temp, 'before'), {
    manifest_version: 3, name: 'Before', version: '1.0.0'
  });
  const after = await writeExtension(path.join(temp, 'after'), {
    manifest_version: 3, name: 'After', version: '1.0.0'
  }, { [unsafePath]: 'marker bytes' });
  const input = path.join(temp, 'file-hash.json');
  await writePack(input, pack({ rules: [rule({
    id: 'FILE_HASH',
    indicators: [{
      type: 'file-sha256',
      value: createHash('sha256').update('marker bytes').digest('hex')
    }]
  })] }));

  const comparison = await compareExtensions(before, after, { rulePacks: [input] });
  const text = auditToText(comparison.after);
  assert.equal(text.includes(unsafePath), false);
  assert.ok(text.includes('at x\\u061C\\u200E\\u200F\\u000A# injected.md'));

  const markdown = comparisonToMarkdown(comparison);
  assert.equal(markdown.includes(unsafePath), false);
  assert.ok(markdown.includes('x\\\\u061C\\\\u200E\\\\u200F\\\\u000A# injected.md'));

  const sarif = auditToSarif(comparison.after);
  const result = sarif.runs[0].results.find((item) => item.ruleId.endsWith(':FILE_HASH'));
  assert.equal(
    result.locations[0].physicalLocation.artifactLocation.uri,
    'x%D8%9C%E2%80%8E%E2%80%8F%0A%23%20injected.md'
  );
});
