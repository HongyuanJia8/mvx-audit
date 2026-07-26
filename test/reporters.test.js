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
});

test('Markdown comparison includes caveat and permission delta', async () => {
  const comparison = await compareExtensions(path.join(ROOT, 'request-tampering/mv2'), path.join(ROOT, 'request-tampering/mv3'));
  const markdown = comparisonToMarkdown(comparison);
  assert.match(markdown, /declarativeNetRequest/);
  assert.match(markdown, /does not prove exploitability/);
});

test('text output includes score, evidence, and remediation', async () => {
  const audit = await auditExtension(path.join(ROOT, 'cookie-access/mv3'));
  const text = auditToText(audit);
  assert.match(text, /Risk: high \(61\/100\)/);
  assert.match(text, /at fixture\.js:2/);
  assert.match(text, /Fix: Avoid reading cookie values/);
});
