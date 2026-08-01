import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { verifyAuditReport } from '../src/audit-verification.js';
import { compareExtensions } from '../src/compare.js';
import {
  DNR_RULE_LIMITS, DNR_RULE_PROFILE, analyzeStaticDnrRules,
  extractStaticDnrRules, normalizeDnrRuleLimits
} from '../src/dnr-rules.js';
import { auditToSarif, auditToText, comparisonToMarkdown } from '../src/reporters.js';
import { auditExtensionArchive } from '../src/packed-audit.js';
import { makeZip } from '../support/archive-fixture.js';
import { writeExtension } from '../support/helpers.js';

function source(content, overrides = {}) {
  const bytes = Buffer.byteLength(content);
  return {
    path: 'rules.json',
    content,
    validUtf8: true,
    bytes,
    sha256: createHash('sha256').update(content).digest('hex'),
    ...overrides
  };
}

function manifest(pathname = 'rules.json') {
  return {
    manifest_version: 3,
    declarative_net_request: {
      rule_resources: [{ id: 'static_rules', enabled: true, path: pathname }]
    }
  };
}

test('static DNR inventory classifies all action types with stable rule locations', () => {
  const content = JSON.stringify([
    { id: 1, action: { type: 'allow' }, condition: {} },
    { id: 2, action: { type: 'allowAllRequests' }, condition: {} },
    { id: 3, action: { type: 'block' }, condition: {} },
    {
      id: 4,
      action: {
        type: 'modifyHeaders',
        requestHeaders: [{ header: 'x-test', operation: 'set', value: 'safe' }]
      },
      condition: { urlFilter: 'example' }
    },
    {
      id: 5,
      action: { type: 'redirect', redirect: { url: 'https://example.invalid/' } },
      condition: { urlFilter: 'source' }
    },
    { id: 6, action: { type: 'upgradeScheme' }, condition: {} }
  ], null, 2);
  const inventory = extractStaticDnrRules(manifest(), [source(content)]);
  assert.equal(inventory.profile, DNR_RULE_PROFILE);
  assert.deepEqual(inventory.limits, DNR_RULE_LIMITS);
  assert.equal(inventory.totals.rulesets, 1);
  assert.equal(inventory.totals.rules, 6);
  assert.equal(inventory.totals.validRules, 6);
  assert.equal(inventory.totals.invalidRules, 0);
  assert.equal(inventory.totals.invalidRulesets, 0);
  assert.deepEqual(inventory.totals.actionCounts, {
    allow: 1,
    allowAllRequests: 1,
    block: 1,
    modifyHeaders: 1,
    redirect: 1,
    upgradeScheme: 1
  });
  assert.deepEqual(inventory.entries.map(({ ruleId, action }) => ({ ruleId, action })), [
    { ruleId: 4, action: 'modifyHeaders' },
    { ruleId: 5, action: 'redirect' }
  ]);
  assert.ok(inventory.entries.every((entry) => entry.line > 1));
  assert.ok(Object.isFrozen(inventory));
  assert.ok(Object.isFrozen(inventory.rulesets));
  assert.deepEqual(analyzeStaticDnrRules(inventory).map((finding) => finding.id), [
    'MVX113', 'MVX114'
  ]);
});

test('strict DNR JSON rejects duplicate keys instead of trusting overwritten values', () => {
  const content = '[{"id":1,"action":{"type":"redirect","type":"allow"},"condition":{}}]';
  const inventory = extractStaticDnrRules(manifest(), [source(content)]);
  assert.equal(inventory.rulesets[0].status, 'duplicate-json-key');
  assert.equal(inventory.totals.rules, 0);
  assert.equal(inventory.totals.invalidRulesets, 1);
  assert.deepEqual(analyzeStaticDnrRules(inventory).map((finding) => finding.id), ['MVX115']);
  assert.equal(inventory.entries[0].reason, 'duplicate-json-key');
});

test('DNR structural failures are explicit and do not become capability findings', () => {
  const content = JSON.stringify([
    { id: 1, action: { type: 'block' }, condition: {} },
    { id: 1, action: { type: 'redirect', redirect: { url: 'https://example.invalid/' } }, condition: {} },
    { id: 3, action: { type: 'futureAction' }, condition: {} },
    { id: 4, action: { type: 'redirect', redirect: { url: 'javascript:alert(1)' } }, condition: {} },
    { id: 5, action: { type: 'modifyHeaders', requestHeaders: [] }, condition: {} }
  ]);
  const inventory = extractStaticDnrRules(manifest(), [source(content)]);
  assert.equal(inventory.totals.validRules, 1);
  assert.equal(inventory.totals.invalidRules, 4);
  assert.deepEqual(inventory.entries.map((entry) => entry.reason), [
    'duplicate-rule-id',
    'unsupported-action-type',
    'invalid-redirect-action',
    'invalid-header-action'
  ]);
  assert.deepEqual(analyzeStaticDnrRules(inventory).map((finding) => finding.id), ['MVX115']);
});

test('DNR ruleset status distinguishes missing, malformed, non-array, and invalid UTF-8', () => {
  const missing = extractStaticDnrRules(manifest(), []);
  assert.equal(missing.rulesets[0].status, 'missing');
  assert.equal(missing.totals.missingRulesets, 1);
  assert.deepEqual(analyzeStaticDnrRules(missing), []);

  const malformed = extractStaticDnrRules(manifest(), [source('[invalid')]);
  assert.equal(malformed.rulesets[0].status, 'invalid-json');
  const nonArray = extractStaticDnrRules(manifest(), [source('{"id":1}')]);
  assert.equal(nonArray.rulesets[0].status, 'root-not-array');
  const invalidUtf8 = extractStaticDnrRules(manifest(), [source('[]', { validUtf8: false })]);
  assert.equal(invalidUtf8.rulesets[0].status, 'invalid-utf8');
  for (const inventory of [malformed, nonArray, invalidUtf8]) {
    assert.equal(analyzeStaticDnrRules(inventory)[0].id, 'MVX115');
  }
});

test('manifest DNR descriptors use normalized paths and reject unsafe or duplicate identities', () => {
  const rules = source('[]');
  const normalized = extractStaticDnrRules(manifest('./rules.json'), [rules]);
  assert.equal(normalized.rulesets[0].path, 'rules.json');
  assert.equal(normalized.rulesets[0].status, 'parsed');

  const invalidManifest = {
    declarative_net_request: {
      rule_resources: [
        { id: 'same', enabled: true, path: 'rules.json' },
        { id: 'same', enabled: false, path: 'other.json' },
        { id: 'unsafe', enabled: true, path: '../rules.json' },
        { enabled: true, path: 'rules.json' }
      ]
    }
  };
  const inventory = extractStaticDnrRules(invalidManifest, [rules]);
  assert.equal(inventory.totals.invalidRulesets, 3);
  assert.ok(inventory.entries.every((entry) => entry.path === 'manifest.json'));
  assert.equal(analyzeStaticDnrRules(inventory)[0].evidence.length, 3);

  const invalidResources = extractStaticDnrRules({
    declarative_net_request: { rule_resources: { path: 'rules.json' } }
  }, [rules]);
  assert.equal(invalidResources.totals.invalidRulesets, 1);
  assert.equal(invalidResources.rulesets[0].status, 'invalid-rule-resources');
  assert.equal(analyzeStaticDnrRules(invalidResources)[0].id, 'MVX115');
  const invalidContainer = extractStaticDnrRules({ declarative_net_request: null }, [rules]);
  assert.equal(invalidContainer.rulesets[0].status, 'invalid-declarative-net-request');
});

test('DNR resource budgets and option validation fail closed', () => {
  assert.deepEqual(normalizeDnrRuleLimits({ maxRules: 7 }).maxRules, 7);
  for (const options of [null, [], { maxRules: 0 }, { maxRules: null }, { unknown: 1 }]) {
    assert.throws(() => normalizeDnrRuleLimits(options), (error) => error.code === 'INVALID_ARGUMENT');
  }
  assert.throws(
    () => extractStaticDnrRules({ declarative_net_request: { rule_resources: [{}, {}] } }, [], { maxRulesets: 1 }),
    (error) => error.code === 'DNR_RULE_LIMIT'
  );
  assert.throws(
    () => extractStaticDnrRules(manifest(), [source(JSON.stringify([
      { id: 1, action: { type: 'block' }, condition: {} },
      { id: 2, action: { type: 'block' }, condition: {} }
    ]))], { maxRules: 1 }),
    (error) => error.code === 'DNR_RULE_LIMIT'
  );
  assert.throws(
    () => extractStaticDnrRules(manifest(), [source(JSON.stringify([
      { id: 1, action: { type: 'redirect', redirect: { extensionPath: '/a' } }, condition: {} },
      { id: 2, action: { type: 'redirect', redirect: { extensionPath: '/b' } }, condition: {} }
    ]))], { maxTrackedRules: 1 }),
    (error) => error.code === 'DNR_RULE_LIMIT'
  );
  assert.throws(
    () => extractStaticDnrRules(manifest(), [source('[[[]]]')], { maxJsonDepth: 1 }),
    (error) => error.code === 'DNR_RULE_LIMIT'
  );
  assert.throws(
    () => extractStaticDnrRules(manifest(), [source('[{"id":1,"action":{"type":"block"},"condition":{}}]')], { maxJsonValues: 2 }),
    (error) => error.code === 'DNR_RULE_LIMIT'
  );
});

test('DNR identity is path-independent and binds bytes and limits', () => {
  const rules = source('[{"id":1,"action":{"type":"block"},"condition":{}}]');
  const first = extractStaticDnrRules(manifest(), [rules]);
  const second = extractStaticDnrRules(structuredClone(manifest()), [structuredClone(rules)]);
  assert.equal(first.sha256, second.sha256);
  assert.notEqual(
    first.sha256,
    extractStaticDnrRules(manifest(), [source('[{"id":1,"action":{"type":"allow"},"condition":{}}]')]).sha256
  );
  assert.notEqual(first.sha256, extractStaticDnrRules(manifest(), [rules], { maxRules: 299_999 }).sha256);
});

test('audit, SARIF, comparison, and text reports preserve DNR evidence', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-dnr-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const clean = await writeExtension(path.join(root, 'clean'), {
    manifest_version: 3, name: 'Clean', version: '1.0.0'
  });
  const redirected = await writeExtension(path.join(root, 'redirected'), {
    manifest_version: 3,
    name: 'Redirected',
    version: '1.0.0',
    permissions: ['declarativeNetRequest'],
    declarative_net_request: {
      rule_resources: [{ id: 'redirects', enabled: false, path: 'rules.json' }]
    }
  }, {
    'rules.json': JSON.stringify([{
      id: 7,
      action: { type: 'redirect', redirect: { url: 'https://destination.invalid/' } },
      condition: { urlFilter: 'source.invalid' }
    }], null, 2)
  });
  const audit = await auditExtension(redirected);
  const finding = audit.findings.find((entry) => entry.id === 'MVX114');
  assert.equal(finding.evidence[0].ruleId, 7);
  assert.equal(finding.evidence[0].rulesetEnabled, false);
  assert.equal(audit.analysis.dnrRules.sha256, audit.dnrRules.sha256);
  assert.equal(audit.scan.dnrRules, 1);
  assert.match(auditToText(audit), /Static DNR rules \(mvx-dnr-static-v1\): 1 ruleset\(s\), 1 rule\(s\)/);
  const sarif = auditToSarif(audit);
  assert.deepEqual(sarif.runs[0].properties.dnrRules, audit.dnrRules);
  assert.deepEqual(
    sarif.runs[0].results.find((result) => result.ruleId === 'MVX114').properties.dnrRule,
    { rulesetId: 'redirects', rulesetEnabled: false, ruleId: 7, action: 'redirect' }
  );
  const comparison = await compareExtensions(clean, redirected);
  assert.ok(comparison.delta.introducedFindings.some((entry) => entry.id === 'MVX114'));
  assert.match(comparisonToMarkdown(comparison), /\| Static DNR rules \| 0 \| 1 \|/);

  await writeFile(path.join(redirected, 'rules.json'), '[invalid');
  const invalid = await auditExtension(redirected);
  assert.ok(invalid.findings.some((entry) => entry.id === 'MVX115'));
  assert.ok(!invalid.findings.some((entry) => entry.id === 'MVX114'));
});

test('missing declared DNR files remain package-integrity findings', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-dnr-missing-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeExtension(root, {
    manifest_version: 3,
    name: 'Missing rules',
    version: '1.0.0',
    declarative_net_request: {
      rule_resources: [{ id: 'missing', enabled: true, path: 'missing.json' }]
    }
  });
  const audit = await auditExtension(root);
  assert.equal(audit.dnrRules.totals.missingRulesets, 1);
  assert.ok(audit.findings.some((finding) => finding.id === 'MVX002'));
  assert.ok(!audit.findings.some((finding) => finding.id === 'MVX115'));
});

test('manifest-declared DNR files are inspected without relying on a .json suffix', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-dnr-extensionless-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeExtension(root, {
    manifest_version: 3,
    name: 'Extensionless rules',
    version: '1.0.0',
    declarative_net_request: {
      rule_resources: [{ id: 'rules', enabled: true, path: 'static-rules' }]
    }
  }, {
    'static-rules': JSON.stringify([{
      id: 1,
      action: { type: 'redirect', redirect: { extensionPath: '/target.html' } },
      condition: {}
    }])
  });
  const audit = await auditExtension(root);
  assert.equal(audit.dnrRules.rulesets[0].status, 'parsed');
  assert.equal(audit.dnrRules.totals.actionCounts.redirect, 1);
  assert.ok(audit.findings.some((finding) => finding.id === 'MVX114'));
  assert.equal(audit.encodedPayloads.candidates, 0);
});

test('offline verification replays the exact DNR limits and inventory', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-dnr-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(root, 'extension'), {
    manifest_version: 3,
    name: 'DNR verification',
    version: '1.0.0',
    declarative_net_request: {
      rule_resources: [{ id: 'rules', enabled: true, path: 'rules.json' }]
    }
  }, {
    'rules.json': JSON.stringify([
      { id: 1, action: { type: 'block' }, condition: {} },
      { id: 2, action: { type: 'allow' }, condition: {} }
    ])
  });
  const dnrRuleLimits = { maxRules: 2 };
  const audit = await auditExtension(extension, { dnrRuleLimits });
  const report = path.join(root, 'report.json');
  await writeFile(report, `${JSON.stringify(audit, null, 2)}\n`);
  assert.equal((await verifyAuditReport(report, extension, { dnrRuleLimits })).valid, true);
  await assert.rejects(
    () => verifyAuditReport(report, extension),
    (error) => error.code === 'AUDIT_REPORT_MISMATCH'
  );
  await assert.rejects(
    () => verifyAuditReport(report, extension, { dnrRuleLimits: { maxRules: 1 } }),
    (error) => error.code === 'DNR_RULE_LIMIT'
  );
});

test('packed audits apply DNR limits before returning a report and clean extraction', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'mvx-dnr-packed-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const temporaryDirectory = path.join(root, 'temporary');
  await mkdir(temporaryDirectory);
  const archive = path.join(root, 'extension.zip');
  await writeFile(archive, makeZip([
    {
      name: 'manifest.json',
      content: JSON.stringify({
        manifest_version: 3,
        name: 'Packed DNR',
        version: '1.0.0',
        declarative_net_request: {
          rule_resources: [{ id: 'rules', enabled: true, path: 'rules.json' }]
        }
      })
    },
    {
      name: 'rules.json',
      content: JSON.stringify([
        { id: 1, action: { type: 'block' }, condition: {} },
        { id: 2, action: { type: 'allow' }, condition: {} }
      ])
    }
  ]));
  await assert.rejects(
    () => auditExtensionArchive(archive, {
      temporaryDirectory,
      dnrRuleLimits: { maxRules: 1 }
    }),
    (error) => error.code === 'DNR_RULE_LIMIT'
  );
  const audit = await auditExtensionArchive(archive, {
    temporaryDirectory,
    dnrRuleLimits: { maxRules: 2 }
  });
  assert.equal(audit.dnrRules.totals.rules, 2);
  assert.equal(audit.analysis.dnrRules.limits.maxRules, 2);
});
