import { lstat, mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { auditExtension } from './analyzer.js';
import { unpackCrx } from './archive.js';
import { MvxError } from './errors.js';
import { SEVERITIES, sortFindings, summarizeFindings } from './model.js';
import { resolveRulePacks } from './rule-packs.js';
import { normalizeDnrRuleLimits } from './dnr-rules.js';
import { analyzeArchiveAuthenticity } from './rules/archive-rules.js';

const EXTENSION_ID = /^[a-p]{32}$/;
const SHA256_CRX = /^([a-f0-9]{64})\.crx$/;

async function discoverSamples(root) {
  const absolute = path.resolve(root);
  let rootStat;
  try { rootStat = await lstat(absolute); } catch (error) {
    throw new MvxError(`Cannot inspect quarantine: ${error.message}`, { code: 'QUARANTINE_NOT_FOUND', cause: error });
  }
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new MvxError('Benchmark quarantine root must be a real directory', { code: 'UNSAFE_QUARANTINE' });
  const samples = [];
  for (const directory of (await readdir(absolute, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!directory.isDirectory() || !EXTENSION_ID.test(directory.name)) continue;
    const extensionRoot = path.join(absolute, directory.name);
    const extensionStat = await lstat(extensionRoot);
    if (extensionStat.isSymbolicLink()) throw new MvxError(`Symlink found in quarantine: ${directory.name}`, { code: 'UNSAFE_QUARANTINE' });
    for (const entry of (await readdir(extensionRoot, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const match = SHA256_CRX.exec(entry.name);
      if (!match) continue;
      if (!entry.isFile()) throw new MvxError(`Unsafe CRX entry: ${directory.name}/${entry.name}`, { code: 'UNSAFE_QUARANTINE' });
      samples.push({ extensionId: directory.name, sha256: match[1], crxPath: path.join(extensionRoot, entry.name) });
    }
  }
  return { root: absolute, samples };
}

function thresholdIndex(threshold) {
  const index = SEVERITIES.indexOf(threshold);
  if (index < 0) throw new MvxError(`Invalid benchmark threshold: ${threshold}`, { code: 'INVALID_ARGUMENT' });
  return index;
}

export async function runStaticBenchmark({
  quarantineDir = 'quarantine',
  records = [],
  label,
  limit = 100,
  threshold = 'high',
  acknowledgeRisk = false,
  requireValidSignature = false,
  dnrRuleLimits,
  rulePacks,
  rulePackLimits,
  _preparedRulePacks,
  unpacker = unpackCrx,
  auditor = auditExtension,
  remover = rm
} = {}) {
  if (!acknowledgeRisk) throw new MvxError('Refusing malware extraction without --acknowledge-risk', { code: 'RISK_ACK_REQUIRED' });
  if (!Number.isSafeInteger(limit) || limit <= 0 || limit > 1000) throw new MvxError('Benchmark limit must be between 1 and 1000', { code: 'INVALID_ARGUMENT' });
  const normalizedDnrRuleLimits = normalizeDnrRuleLimits(dnrRuleLimits ?? {});
  const preparedRulePacks = await resolveRulePacks({ rulePacks, rulePackLimits, _preparedRulePacks });
  const severityLimit = thresholdIndex(threshold);
  const catalog = new Map(records.map((record) => [record.extensionId, record]));
  const discovered = await discoverSamples(quarantineDir);
  const selected = discovered.samples
    .filter((sample) => !label || catalog.get(sample.extensionId)?.labels?.includes(label))
    .slice(0, limit);
  const results = [];
  const failures = [];
  for (const sample of selected) {
    let workspace;
    let result;
    let failure;
    let cleanupFailure;
    try {
      workspace = await mkdtemp(path.join(os.tmpdir(), 'mvx-benchmark-'));
      const destination = path.join(workspace, 'extension');
      const archive = await unpacker(sample.crxPath, destination, {
        requireValidSignature,
        expectedArchiveSha256: sample.sha256,
        // Preserve invalid CRX for MVX004 in forensic mode, but reject a verified ID mismatch before extraction.
        ...(requireValidSignature
          ? { expectedExtensionId: sample.extensionId }
          : { _expectedExtensionIdIfVerified: sample.extensionId })
      });
      if (archive.archiveSha256 && archive.archiveSha256 !== sample.sha256) {
        throw new MvxError('Archive SHA-256 does not match its quarantine filename', { code: 'ARCHIVE_IDENTITY_MISMATCH' });
      }
      if (archive.authenticity?.status === 'verified'
        && archive.authenticity.extensionId !== sample.extensionId) {
        throw new MvxError('Verified CRX extension ID does not match its quarantine directory', { code: 'ARCHIVE_IDENTITY_MISMATCH' });
      }
      const audit = await auditor(destination, {
        dnrRuleLimits: normalizedDnrRuleLimits,
        _preparedRulePacks: preparedRulePacks
      });
      const findings = sortFindings([
        ...audit.findings,
        ...analyzeArchiveAuthenticity(archive.authenticity)
      ]);
      const summary = summarizeFindings(findings);
      const triggering = findings.filter((finding) => SEVERITIES.indexOf(finding.severity) <= severityLimit);
      result = {
        extensionId: sample.extensionId,
        sha256: sample.sha256,
        labels: catalog.get(sample.extensionId)?.labels ?? [],
        manifestVersion: audit.target.manifestVersion,
        version: audit.target.version,
        files: archive.files ?? audit.scan?.filesVisited ?? null,
        cachedExtraction: false,
        authenticity: archive.authenticity ?? null,
        findingCount: findings.length,
        reviewTriggered: triggering.length > 0,
        triggeringRules: [...new Set(triggering.map((finding) => finding.id))].sort(),
        severityCounts: summary.counts
      };
    } catch (error) {
      failure = error;
    } finally {
      if (workspace) {
        try {
          await remover(workspace, { recursive: true, force: true });
        } catch (error) {
          cleanupFailure = error;
        }
      }
    }
    if (failure || cleanupFailure) {
      const originalCode = failure?.code ?? null;
      const reported = cleanupFailure ?? failure;
      const rawMessage = cleanupFailure
        ? `Temporary extraction cleanup failed${originalCode ? ` after ${originalCode}` : ''}: ${cleanupFailure.message}`
        : String(failure.message ?? failure);
      const message = workspace
        ? rawMessage.split(workspace).join('<temporary extraction>')
        : rawMessage;
      failures.push({
        extensionId: sample.extensionId,
        sha256: sample.sha256,
        code: cleanupFailure ? 'TEMP_CLEANUP_FAILED' : reported.code ?? 'UNEXPECTED_ERROR',
        message,
        ...(cleanupFailure ? { originalCode } : {})
      });
    } else results.push(result);
  }
  const triggered = results.filter((result) => result.reviewTriggered).length;
  const ruleCounts = {};
  for (const result of results) for (const id of result.triggeringRules) ruleCounts[id] = (ruleCounts[id] ?? 0) + 1;
  return {
    schemaVersion: 1,
    benchmark: 'static-triage',
    label: label ?? null,
    threshold,
    rulePacks: preparedRulePacks.provenance,
    rulePackLimits: preparedRulePacks.limits,
    dnrRuleLimits: normalizedDnrRuleLimits,
    summary: {
      quarantinedArtifacts: discovered.samples.length,
      selected: selected.length,
      analyzed: results.length,
      failures: failures.length,
      reviewTriggered: triggered,
      reviewTriggerRate: results.length === 0 ? null : triggered / results.length
    },
    ruleCounts: Object.fromEntries(Object.entries(ruleCounts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))),
    results,
    failures,
    caveats: [
      'Review-trigger rate is not malware-classification accuracy; static findings measure risky capability and implementation patterns.',
      'Catalog labels can describe a different version under the same extension ID. SHA-256-bound labels are stronger ground truth.',
      'A clean static result does not make an extension benign; dynamic, obfuscated, gated, or remote behavior may be invisible.'
    ]
  };
}

export function staticBenchmarkToText(report) {
  const rate = report.summary.reviewTriggerRate === null ? 'n/a' : `${(report.summary.reviewTriggerRate * 100).toFixed(1)}%`;
  return [
    'MVX real-sample static triage benchmark',
    `Label filter: ${report.label ?? 'none'}`,
    `Threshold: ${report.threshold}`,
    `Rule packs: ${report.rulePacks?.length ?? 0}`,
    `Analyzed: ${report.summary.analyzed}/${report.summary.selected}`,
    `Failures: ${report.summary.failures}`,
    `Review triggered: ${report.summary.reviewTriggered} (${rate})`,
    `Rules: ${Object.entries(report.ruleCounts).map(([id, count]) => `${id}=${count}`).join(', ') || 'none'}`,
    '',
    ...report.caveats.map((caveat) => `Caveat: ${caveat}`)
  ].join('\n') + '\n';
}
