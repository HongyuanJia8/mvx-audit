import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { runCli } from '../src/cli.js';
import { compareExtensions } from '../src/compare.js';
import {
  applyDispositionPolicies, loadDispositionPolicies, resolveDispositionPolicies
} from '../src/disposition-policy.js';
import { auditExtensionArchive } from '../src/packed-audit.js';
import { auditToSarif, auditToText, comparisonToMarkdown } from '../src/reporters.js';
import { makeCrx, makeSignedCrx2 } from '../support/archive-fixture.js';
import { captureStreams, writeExtension } from '../support/helpers.js';

const ROOT = path.resolve('corpus/fixtures/cookie-access/mv3');
const AT = '2026-07-30T12:00:00.000Z';

function entry(packageSha256, analysisSha256, fingerprint, overrides = {}) {
  return {
    fingerprint,
    packageSha256,
    analysisSha256,
    artifactSha256: null,
    disposition: 'accepted-risk',
    owner: 'security-team@example.invalid',
    justification: 'Reviewed against the exact package and accepted for this test.',
    expiresAt: '2026-08-30T12:00:00.000Z',
    ticketUrl: 'https://example.invalid/reviews/123',
    ...overrides
  };
}

function policy(entries, overrides = {}) {
  return {
    schemaVersion: 1,
    policyId: 'research.review',
    name: 'Research review dispositions',
    version: '2026.07.30',
    entries,
    ...overrides
  };
}

async function writePolicy(filePath, value) {
  const source = `${JSON.stringify(value, null, 2)}\n`;
  await writeFile(filePath, source, 'utf8');
  return Buffer.from(source);
}

test('disposition policies bind exact package and finding identities without hiding raw findings', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-disposition-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const baseline = await auditExtension(ROOT);
  assert.equal('reviewSummary' in baseline, false);
  const input = path.join(temp, 'policy.json');
  const bytes = await writePolicy(input, policy([
    entry(baseline.package.sha256, baseline.analysis.sha256, 'MVX103'),
    entry(baseline.package.sha256, baseline.analysis.sha256, 'MVX101', { expiresAt: AT, disposition: 'false-positive' }),
    entry(baseline.package.sha256, baseline.analysis.sha256, 'MVX999', { disposition: 'compensating-control' }),
    entry('f'.repeat(64), baseline.analysis.sha256, 'MVX103')
  ]));
  const copied = path.join(temp, 'copied.json');
  await writeFile(copied, bytes);
  const prepared = await loadDispositionPolicies([input], { evaluationTime: AT });
  const copiedPrepared = await loadDispositionPolicies([copied], { evaluationTime: AT });
  assert.deepEqual(prepared.provenance, copiedPrepared.provenance);
  assert.equal(prepared.provenance[0].sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(JSON.stringify(prepared.provenance).includes(temp), false);
  assert.equal(Object.isFrozen(prepared.policies[0].entries[0]), true);

  const result = await auditExtension(ROOT, { dispositionPolicies: [input], dispositionAt: AT });
  assert.deepEqual(result.summary, baseline.summary);
  assert.equal(result.findings.length, baseline.findings.length);
  assert.equal(result.findings.find((finding) => finding.fingerprint === 'MVX103').disposition.status, 'active');
  assert.equal(result.findings.find((finding) => finding.fingerprint === 'MVX101').disposition.status, 'expired');
  assert.equal(result.reviewSummary.total, baseline.summary.total - 1);
  assert.equal(result.dispositionEvaluation.identityEntries, 3);
  assert.equal(result.dispositionEvaluation.matchedEntries, 2);
  assert.equal(result.dispositionEvaluation.unusedIdentityEntries, 1);
  assert.equal(result.dispositionEvaluation.activeFindings, 1);
  assert.equal(result.dispositionEvaluation.expiredFindings, 1);
  assert.match(result.assumptions.at(-1), /original findings and raw risk summary remain/);

  const text = auditToText(result);
  assert.match(text, /Unreviewed risk:/);
  assert.match(text, /Disposition: ACTIVE accepted-risk/);
  assert.match(text, /Disposition: EXPIRED false-positive/);
  assert.match(text, new RegExp(`research\\.review@2026\\.07\\.30: ${bytes.length} bytes, SHA-256 ${prepared.provenance[0].sha256}`));
  assert.match(text, new RegExp(`Policy: research\\.review@2026\\.07\\.30 SHA-256: ${prepared.provenance[0].sha256}`));
  assert.match(text, /Ticket: https:\/\/example\.invalid\/reviews\/123/);
  assert.match(text, /Fingerprint: MVX103/);
  const unusedInput = path.join(temp, 'unused.json');
  const unusedBytes = await writePolicy(unusedInput, policy([
    entry('e'.repeat(64), baseline.analysis.sha256, 'MVX103')
  ], { policyId: 'unused.review' }));
  const unusedResult = await auditExtension(ROOT, {
    dispositionPolicies: [unusedInput], dispositionAt: AT
  });
  assert.equal(unusedResult.dispositionEvaluation.identityEntries, 0);
  assert.match(auditToText(unusedResult), new RegExp(
    `unused\\.review@2026\\.07\\.30: ${unusedBytes.length} bytes, SHA-256 ${createHash('sha256').update(unusedBytes).digest('hex')}`
  ));
  const sarif = auditToSarif(result);
  assert.deepEqual(sarif.runs[0].properties.dispositionEvaluation, result.dispositionEvaluation);
  assert.ok(sarif.runs[0].results.some((item) => item.properties.disposition?.status === 'active'));
  assert.ok(sarif.runs[0].results.every((item) => item.suppressions === undefined));
  assert.equal(sarif.runs[0].results.length, result.findings.reduce((count, finding) => count + finding.evidence.length, 0));

  await assert.rejects(
    () => resolveDispositionPolicies({ _preparedDispositionPolicies: structuredClone(prepared) }),
    (error) => error.code === 'INVALID_ARGUMENT'
  );
  assert.throws(() => applyDispositionPolicies(result.findings, 'A'.repeat(64), prepared),
    (error) => error.code === 'INVALID_ARGUMENT');
  const invalidPolicy = path.join(temp, 'invalid.json');
  await writeFile(invalidPolicy, '{}');
  const emptyPrepared = await loadDispositionPolicies([], { evaluationTime: AT });
  await assert.rejects(() => auditExtension(ROOT, {
    _preparedDispositionPolicies: emptyPrepared,
    dispositionPolicies: [invalidPolicy]
  }), (error) => error.code === 'INVALID_ARGUMENT' && /cannot be combined/.test(error.message));
});

test('disposition loader rejects conflicts, unsafe files, duplicate keys, and non-canonical fields', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-disposition-invalid-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const hash = 'a'.repeat(64);
  const analysisHash = 'b'.repeat(64);
  const first = path.join(temp, 'first.json');
  const duplicate = path.join(temp, 'duplicate.json');
  await writePolicy(first, policy([entry(hash, analysisHash, 'MVX103')]));
  await writePolicy(duplicate, policy([entry(hash, analysisHash, 'MVX103')], { policyId: 'other.review' }));
  await assert.rejects(() => loadDispositionPolicies([first, duplicate], { evaluationTime: AT }),
    (error) => error.code === 'INVALID_DISPOSITION_POLICY' && /Conflicting disposition/.test(error.message));

  const linked = path.join(temp, 'linked.json');
  await symlink(first, linked);
  await assert.rejects(() => loadDispositionPolicies([linked]), (error) => error.code === 'UNSAFE_DISPOSITION_POLICY');
  await assert.rejects(() => loadDispositionPolicies(first), (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => loadDispositionPolicies([first], { evaluationTime: '2026-07-30' }),
    (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => loadDispositionPolicies([first], null), (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => loadDispositionPolicies([first], { maxPolicyBytes: 10 }),
    (error) => error.code === 'DISPOSITION_POLICY_LIMIT');
  await assert.rejects(() => loadDispositionPolicies([first], { unknown: 1 }),
    (error) => error.code === 'INVALID_ARGUMENT');

  const duplicateKeys = path.join(temp, 'duplicate-keys.json');
  await writeFile(duplicateKeys, '{"schemaVersion":1,"policyId":"a","policyId":"b","name":"Name","version":"1","entries":[]}');
  await assert.rejects(() => loadDispositionPolicies([duplicateKeys]),
    (error) => error.code === 'INVALID_DISPOSITION_POLICY' && /duplicate JSON field/.test(error.message));

  const invalid = [
    policy([entry(hash, analysisHash, 'bad fingerprint!')]),
    policy([entry(hash.toUpperCase(), analysisHash, 'MVX103')]),
    policy([entry(hash, analysisHash.toUpperCase(), 'MVX103')]),
    policy([entry(hash, analysisHash, 'MVX103', { artifactSha256: 'C'.repeat(64) })]),
    policy([entry(hash, analysisHash, 'MVX103', { justification: 'too short' })]),
    policy([entry(hash, analysisHash, 'MVX103', { owner: 'unsafe\nowner' })]),
    policy([entry(hash, analysisHash, 'MVX103', { owner: 'unsafe\u0085owner' })]),
    policy([entry(hash, analysisHash, 'MVX103', { owner: 'unsafe\u009bowner' })]),
    policy([entry(hash, analysisHash, 'MVX103', { owner: 'unsafe\u2028owner' })]),
    policy([entry(hash, analysisHash, 'MVX103', { owner: 'unsafe\u2029owner' })]),
    policy([entry(hash, analysisHash, 'MVX103', { expiresAt: '2026-08-30T12:00:00Z' })]),
    policy([entry(hash, analysisHash, 'MVX103', { ticketUrl: 'http://example.invalid/ticket' })]),
    policy([entry(hash, analysisHash, 'MVX103', { ticketUrl: 'https://example.invalid/ticket\nnext' })]),
    policy([entry(hash, analysisHash, 'MVX103', { ticketUrl: 'https://example.invalid/ticket\t' })]),
    policy([entry(hash, analysisHash, 'MVX103', { ticketUrl: ' https://example.invalid/ticket' })]),
    policy([entry(hash, analysisHash, 'MVX103', { ticketUrl: 'https://example.invalid/ticket\u202e' })]),
    policy([entry(hash, analysisHash, 'MVX103', { disposition: 'ignored' })]),
    { ...policy([entry(hash, analysisHash, 'MVX103')]), unknown: true }
  ];
  const missingArtifact = policy([entry(hash, analysisHash, 'MVX103')]);
  delete missingArtifact.entries[0].artifactSha256;
  invalid.push(missingArtifact);
  for (let index = 0; index < invalid.length; index += 1) {
    const input = path.join(temp, `invalid-${index}.json`);
    await writePolicy(input, invalid[index]);
    await assert.rejects(() => loadDispositionPolicies([input]),
      (error) => error.code === 'INVALID_DISPOSITION_POLICY');
  }
});

test('CLI validates policies and only explicit unreviewed thresholds honor active dispositions', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-disposition-cli-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const baseline = await auditExtension(ROOT);
  const input = path.join(temp, 'policy.json');
  await writePolicy(input, policy([entry(baseline.package.sha256, baseline.analysis.sha256, 'MVX103')]));

  const validation = captureStreams();
  assert.equal(await runCli(['dispositions', 'validate', input, '--disposition-at', AT, '--format', 'json'], validation.streams), 0);
  assert.equal(JSON.parse(validation.output().stdout).valid, true);
  assert.equal((await loadDispositionPolicies([path.resolve('examples/disposition-policy.json')], {
    evaluationTime: AT
  })).summary.policies, 1);

  const raw = captureStreams();
  assert.equal(await runCli([
    'audit', ROOT, '--disposition-policy', input, '--disposition-at', AT, '--fail-on', 'critical'
  ], raw.streams), 1);
  const unreviewed = captureStreams();
  assert.equal(await runCli([
    'audit', ROOT, '--disposition-policy', input, '--disposition-at', AT,
    '--fail-on-unreviewed', 'critical', '--format', 'json'
  ], unreviewed.streams), 0);
  assert.equal(JSON.parse(unreviewed.output().stdout).dispositionEvaluation.activeFindings, 1);
  const expiredPolicy = path.join(temp, 'expired.json');
  await writePolicy(expiredPolicy, policy([entry(
    baseline.package.sha256, baseline.analysis.sha256, 'MVX103', { expiresAt: AT }
  )], { policyId: 'expired.review' }));
  const expiredThreshold = captureStreams();
  assert.equal(await runCli([
    'audit', ROOT, '--disposition-policy', expiredPolicy, '--disposition-at', AT,
    '--fail-on-unreviewed', 'critical'
  ], expiredThreshold.streams), 1);

  const conflict = captureStreams();
  assert.equal(await runCli([
    'audit', ROOT, '--disposition-policy', input, '--fail-on', 'high', '--fail-on-unreviewed', 'high'
  ], conflict.streams), 2);
  assert.match(conflict.output().stderr, /INVALID_ARGUMENT.*cannot be combined/);
  const ignored = captureStreams();
  assert.equal(await runCli(['intel', 'stats', '--disposition-policy', input], ignored.streams), 2);
  assert.match(ignored.output().stderr, /INVALID_ARGUMENT.*Disposition policy options/);
  const timeOnly = captureStreams();
  assert.equal(await runCli(['audit', ROOT, '--disposition-at', AT], timeOnly.streams), 2);
  assert.match(timeOnly.output().stderr, /INVALID_ARGUMENT.*requires at least one/);

  const comparison = await compareExtensions(ROOT, ROOT, {
    dispositionPolicies: [input], dispositionAt: AT
  });
  assert.equal(comparison.before.dispositionEvaluation.evaluatedAt, AT);
  assert.equal(comparison.after.dispositionEvaluation.evaluatedAt, AT);
  assert.equal(comparison.delta.unreviewedRiskScore, 0);
  assert.match(comparisonToMarkdown(comparison), /Unreviewed risk score/);

  const compareCli = captureStreams();
  assert.equal(await runCli([
    'compare', ROOT, ROOT, '--disposition-policy', input, '--disposition-at', AT, '--format', 'json'
  ], compareCli.streams), 0);
  assert.equal(JSON.parse(compareCli.output().stdout).before.dispositionEvaluation.evaluatedAt, AT);

  const compareFailOn = captureStreams();
  assert.equal(await runCli(['compare', ROOT, ROOT, '--fail-on', 'high'], compareFailOn.streams), 2);
  assert.match(compareFailOn.output().stderr, /--fail-on applies only to audit/);
  const validateFailOn = captureStreams();
  assert.equal(await runCli(['dispositions', 'validate', input, '--fail-on', 'high'], validateFailOn.streams), 2);
  assert.match(validateFailOn.output().stderr, /--fail-on applies only to audit/);
});

test('packed audit applies dispositions to archive-authenticity findings', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-disposition-packed-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const temporaryDirectory = path.join(temp, 'temporary');
  await mkdir(temporaryDirectory);
  const input = path.join(temp, 'invalid.crx');
  await writeFile(input, makeCrx([{
    name: 'manifest.json', content: '{"manifest_version":3,"name":"Disposition packed","version":"1.0.0"}'
  }]));
  const invalidPolicy = path.join(temp, 'invalid-policy.json');
  await writeFile(invalidPolicy, '{}');
  await assert.rejects(() => auditExtensionArchive(input, {
    temporaryDirectory, dispositionPolicies: [invalidPolicy], dispositionAt: AT
  }), (error) => error.code === 'INVALID_DISPOSITION_POLICY');
  assert.deepEqual(await readdir(temporaryDirectory), []);
  const baseline = await auditExtensionArchive(input, { temporaryDirectory });
  assert.deepEqual(baseline.findings.map((finding) => finding.id), ['MVX004']);
  const policyPath = path.join(temp, 'policy.json');
  await writePolicy(policyPath, policy([entry(baseline.package.sha256, baseline.analysis.sha256, 'MVX004', {
    artifactSha256: baseline.artifact.sha256
  })]));
  const result = await auditExtensionArchive(input, {
    temporaryDirectory, dispositionPolicies: [policyPath], dispositionAt: AT
  });
  assert.equal(result.findings[0].disposition.status, 'active');
  assert.equal(result.summary.total, 1);
  assert.equal(result.reviewSummary.total, 0);
  assert.equal(result.dispositionEvaluation.activeFindings, 1);

  const signed = makeSignedCrx2([{
    name: 'manifest.json', content: '{"manifest_version":3,"name":"Same payload","version":"1.0.0"}'
  }]).bytes;
  const keyLength = signed.readUInt32LE(8);
  const signatureOffset = 16 + keyLength;
  const firstBytes = Buffer.from(signed);
  const secondBytes = Buffer.from(signed);
  firstBytes[signatureOffset] ^= 0x01;
  secondBytes[signatureOffset + 1] ^= 0x01;
  const firstArchive = path.join(temp, 'first-invalid.crx');
  const secondArchive = path.join(temp, 'second-invalid.crx');
  await writeFile(firstArchive, firstBytes);
  await writeFile(secondArchive, secondBytes);
  const firstAudit = await auditExtensionArchive(firstArchive, { temporaryDirectory });
  const secondAudit = await auditExtensionArchive(secondArchive, { temporaryDirectory });
  assert.equal(firstAudit.package.sha256, secondAudit.package.sha256);
  assert.equal(firstAudit.analysis.sha256, secondAudit.analysis.sha256);
  assert.notEqual(firstAudit.artifact.sha256, secondAudit.artifact.sha256);
  const wrapperPolicy = path.join(temp, 'wrapper-policy.json');
  await writePolicy(wrapperPolicy, policy([entry(
    firstAudit.package.sha256, firstAudit.analysis.sha256, 'MVX004', {
      artifactSha256: firstAudit.artifact.sha256
    }
  )]));
  const transferred = await auditExtensionArchive(secondArchive, {
    temporaryDirectory, dispositionPolicies: [wrapperPolicy], dispositionAt: AT
  });
  assert.equal(transferred.findings[0].disposition, undefined);
  assert.equal(transferred.dispositionEvaluation.identityEntries, 0);
});

test('rule-pack dispositions use the complete scoped fingerprint and invalidate on any package change', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-disposition-rule-pack-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const extension = await writeExtension(path.join(temp, 'extension'), {
    manifest_version: 3, name: 'Disposition rule pack', version: '1.0.0'
  }, { 'worker.js': "fetch('https://telemetry.campaign.example.invalid/collect');\n" });
  const rulePack = path.join(temp, 'rule-pack.json');
  const rulePackDocument = JSON.parse(await readFile(path.resolve('examples/campaign-rule-pack.json'), 'utf8'));
  await writeFile(rulePack, `${JSON.stringify(rulePackDocument, null, 2)}\n`);
  const baseline = await auditExtension(extension, { rulePacks: [rulePack] });
  const fingerprint = 'RP:example.campaign:NETWORK_MARKER';
  assert.ok(baseline.findings.some((finding) => finding.fingerprint === fingerprint));
  const policyPath = path.join(temp, 'policy.json');
  await writePolicy(policyPath, policy([entry(baseline.package.sha256, baseline.analysis.sha256, fingerprint)]));
  const reviewed = await auditExtension(extension, {
    rulePacks: [rulePack], dispositionPolicies: [policyPath], dispositionAt: AT
  });
  assert.equal(reviewed.findings.find((finding) => finding.fingerprint === fingerprint).disposition.status, 'active');
  assert.match(auditToText(reviewed), /Fingerprint: RP:example\.campaign:NETWORK_MARKER/);

  rulePackDocument.rules[0].indicators[0].scope = 'all-text';
  await writeFile(rulePack, `${JSON.stringify(rulePackDocument, null, 2)}\n`);
  const changedSemantics = await auditExtension(extension, {
    rulePacks: [rulePack], dispositionPolicies: [policyPath], dispositionAt: AT
  });
  assert.equal(changedSemantics.package.sha256, baseline.package.sha256);
  assert.notEqual(changedSemantics.analysis.sha256, baseline.analysis.sha256);
  assert.ok(changedSemantics.findings.some((finding) => finding.fingerprint === fingerprint));
  assert.equal(changedSemantics.findings.find((finding) => finding.fingerprint === fingerprint).disposition, undefined);
  assert.equal(changedSemantics.dispositionEvaluation.identityEntries, 0);

  await writeFile(path.join(extension, 'asset.bin'), 'one changed package byte');
  const changed = await auditExtension(extension, {
    rulePacks: [rulePack], dispositionPolicies: [policyPath], dispositionAt: AT
  });
  assert.notEqual(changed.package.sha256, baseline.package.sha256);
  assert.equal(changed.findings.find((finding) => finding.fingerprint === fingerprint).disposition, undefined);
  assert.equal(changed.dispositionEvaluation.identityEntries, 0);
});

test('public audit APIs reject non-plain, proxy, accessor, and malformed identity options', async () => {
  const invalidOptions = [null, [], 1, 'options', new Date(), new Proxy({}, {})];
  for (const options of invalidOptions) {
    await assert.rejects(() => auditExtension(ROOT, options), (error) => error.code === 'INVALID_ARGUMENT');
  }
  const accessor = {};
  Object.defineProperty(accessor, 'dispositionPolicies', { get() { throw new Error('must not execute'); } });
  await assert.rejects(() => auditExtension(ROOT, accessor),
    (error) => error.code === 'INVALID_ARGUMENT' && /accessor/.test(error.message));
  await assert.rejects(() => compareExtensions(ROOT, ROOT, null),
    (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => auditExtensionArchive('missing.crx', null),
    (error) => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(() => loadDispositionPolicies([], new Date()),
    (error) => error.code === 'INVALID_ARGUMENT');

  const prepared = await loadDispositionPolicies([], { evaluationTime: AT });
  assert.throws(() => applyDispositionPolicies([], {
    packageSha256: { toString: () => 'a'.repeat(64) },
    analysisSha256: 'b'.repeat(64),
    artifactSha256: null
  }, prepared), (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(() => applyDispositionPolicies([], new Proxy({
    packageSha256: 'a'.repeat(64), analysisSha256: 'b'.repeat(64), artifactSha256: null
  }, {}), prepared), (error) => error.code === 'INVALID_ARGUMENT');
});
