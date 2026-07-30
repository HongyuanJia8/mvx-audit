import { auditExtension } from './analyzer.js';
import { evidenceFingerprint, findingKey } from './fingerprints.js';
import { resolveRulePacks } from './rule-packs.js';
import { resolveDispositionPolicies } from './disposition-policy.js';

function evidenceKey(finding, evidence) {
  return evidenceFingerprint(finding, evidence);
}

function flattenEvidence(findings) {
  return findings.flatMap((finding) => finding.evidence.map((evidence) => ({
    key: evidenceKey(finding, evidence),
    findingId: finding.id,
    fingerprint: findingKey(finding),
    title: finding.title,
    severity: finding.severity,
    evidence
  })));
}

function difference(left, right) {
  const rightSet = new Set(right);
  return left.filter((item) => !rightSet.has(item));
}

export async function compareExtensions(beforePath, afterPath, options = {}) {
  const preparedRulePacks = await resolveRulePacks(options);
  const preparedDispositionPolicies = await resolveDispositionPolicies(options);
  const auditOptions = {
    ...options,
    _preparedRulePacks: preparedRulePacks,
    _preparedDispositionPolicies: preparedDispositionPolicies
  };
  const [before, after] = await Promise.all([
    auditExtension(beforePath, auditOptions),
    auditExtension(afterPath, auditOptions)
  ]);
  const beforeMap = new Map(before.findings.map((finding) => [findingKey(finding), finding]));
  const afterMap = new Map(after.findings.map((finding) => [findingKey(finding), finding]));
  const beforeEvidence = flattenEvidence(before.findings);
  const afterEvidence = flattenEvidence(after.findings);
  const beforeEvidenceKeys = new Set(beforeEvidence.map((item) => item.key));
  const afterEvidenceKeys = new Set(afterEvidence.map((item) => item.key));
  const resolved = [...beforeMap.keys()].filter((key) => !afterMap.has(key)).map((key) => beforeMap.get(key));
  const introduced = [...afterMap.keys()].filter((key) => !beforeMap.has(key)).map((key) => afterMap.get(key));
  const beforePermissions = before.capabilities.permissions;
  const afterPermissions = after.capabilities.permissions;
  return {
    schemaVersion: 1,
    tool: before.tool,
    before,
    after,
    delta: {
      riskScore: after.summary.riskScore - before.summary.riskScore,
      ...(before.reviewSummary && after.reviewSummary ? {
        unreviewedRiskScore: after.reviewSummary.riskScore - before.reviewSummary.riskScore
      } : {}),
      resolvedFindings: resolved,
      introducedFindings: introduced,
      evidenceAdded: afterEvidence.filter((item) => !beforeEvidenceKeys.has(item.key)).map(({ key, ...item }) => item),
      evidenceRemoved: beforeEvidence.filter((item) => !afterEvidenceKeys.has(item.key)).map(({ key, ...item }) => item),
      evidenceCount: { before: beforeEvidence.length, after: afterEvidence.length, delta: afterEvidence.length - beforeEvidence.length },
      permissionsAdded: difference(afterPermissions, beforePermissions),
      permissionsRemoved: difference(beforePermissions, afterPermissions),
      hostsAdded: difference(after.capabilities.hostPermissions, before.capabilities.hostPermissions),
      hostsRemoved: difference(before.capabilities.hostPermissions, after.capabilities.hostPermissions)
    },
    interpretation: [
      'A resolved static finding may reflect an API or syntax migration rather than removal of the underlying user-data capability.',
      'Compare permission scope and source behavior together; manifest version alone is not a security verdict.'
    ]
  };
}
