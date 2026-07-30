import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { auditToSarif, auditToText, comparisonToMarkdown } from '../src/reporters.js';
import { compareExtensions } from '../src/compare.js';

const ROOT = path.resolve('corpus/fixtures');

test('SARIF output maps every evidence location to a result', async () => {
  const audit = await auditExtension(path.join(ROOT, 'cookie-access/mv3'));
  const sarif = auditToSarif(audit);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].results.length, audit.findings.reduce((count, finding) => count + finding.evidence.length, 0));
  assert.ok(sarif.runs[0].tool.driver.rules.some((rule) => rule.id === 'MVX103'));
  assert.deepEqual(sarif.runs[0].properties.analysis, audit.analysis);
  assert.deepEqual(sarif.runs[0].properties.package, audit.package);
});

test('Markdown comparison includes caveat and permission delta', async () => {
  const comparison = await compareExtensions(path.join(ROOT, 'request-tampering/mv2'), path.join(ROOT, 'request-tampering/mv3'));
  const markdown = comparisonToMarkdown(comparison);
  assert.match(markdown, /declarativeNetRequest/);
  assert.match(markdown, /does not prove exploitability/);
  assert.match(markdown, /\| Analysis SHA-256 \| `[a-f0-9]{64}` \| `[a-f0-9]{64}` \|/);
  assert.match(markdown, /\| Package SHA-256 \| `[a-f0-9]{64}` \| `[a-f0-9]{64}` \|/);
});

test('text output includes score, evidence, and remediation', async () => {
  const audit = await auditExtension(path.join(ROOT, 'cookie-access/mv3'));
  const text = auditToText(audit);
  assert.match(text, /Risk: high \(61\/100\)/);
  assert.match(text, /Package \(mvx-package-v1\): 2 file\(s\), 246 bytes, SHA-256: [a-f0-9]{64}/);
  assert.match(text, /Analysis \(mvx-static-v2\) SHA-256: [a-f0-9]{64}/);
  assert.match(text, /at fixture\.js:2/);
  assert.match(text, /Fix: Avoid reading cookie values/);
});

test('reporters remain compatible with schema-v1 results that predate package and analysis provenance', async () => {
  const audit = await auditExtension(path.join(ROOT, 'cookie-access/mv3'));
  const legacyAudit = structuredClone(audit);
  delete legacyAudit.analysis;
  delete legacyAudit.package;
  assert.doesNotMatch(auditToText(legacyAudit), /Analysis .* SHA-256/);
  assert.equal(auditToSarif(legacyAudit).runs[0].properties, undefined);

  const comparison = await compareExtensions(path.join(ROOT, 'request-tampering/mv2'), path.join(ROOT, 'request-tampering/mv3'));
  const legacyComparison = structuredClone(comparison);
  delete legacyComparison.before.analysis;
  delete legacyComparison.after.analysis;
  delete legacyComparison.before.package;
  delete legacyComparison.after.package;
  assert.doesNotMatch(comparisonToMarkdown(legacyComparison), /Analysis SHA-256/);
  assert.doesNotMatch(comparisonToMarkdown(legacyComparison), /Package SHA-256/);
});
