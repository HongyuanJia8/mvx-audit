import { auditExtension } from './analyzer.js';
import { auditExtensionArchive } from './packed-audit.js';
import { evidenceFingerprint, findingKey } from './fingerprints.js';
import { resolveRulePacks } from './rule-packs.js';
import { resolveDispositionPolicies } from './disposition-policy.js';
import { assertOptionsObject } from './options.js';
import { MvxError } from './errors.js';
import { types as utilTypes } from 'node:util';

export const ARCHIVE_CONTINUITY_PROFILE = 'mvx-archive-continuity-v1';
export const PACKAGE_DELTA_PROFILE = 'mvx-package-delta-v1';

const EXTENSION_ID = /^[a-p]{32}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const PACKED_COMPARISON_OPTIONS = new Set([
  'archiveLimits',
  'dispositionAt',
  'dispositionPolicies',
  'dispositionPolicyLimits',
  'expectedAfterArchiveSha256',
  'expectedBeforeArchiveSha256',
  'expectedExtensionId',
  'limits',
  'requireSameExtensionId',
  'requireValidSignature',
  'rulePackLimits',
  'rulePacks',
  'temporaryDirectory'
]);

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

function compareAuditResults(before, after) {
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

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function ownOption(options, key) {
  return Object.getOwnPropertyDescriptor(options, key)?.value;
}

function packageDelta(before, after) {
  const beforeEntries = new Map(before.entries.map((entry) => [entry.path, entry]));
  const afterEntries = new Map(after.entries.map((entry) => [entry.path, entry]));
  const paths = [...new Set([...beforeEntries.keys(), ...afterEntries.keys()])].sort(compareText);
  const added = [];
  const removed = [];
  const modified = [];
  let unchanged = 0;
  for (const entryPath of paths) {
    const beforeEntry = beforeEntries.get(entryPath);
    const afterEntry = afterEntries.get(entryPath);
    if (!beforeEntry) {
      added.push(afterEntry);
      continue;
    }
    if (!afterEntry) {
      removed.push(beforeEntry);
      continue;
    }
    if (JSON.stringify(beforeEntry) === JSON.stringify(afterEntry)) {
      unchanged += 1;
      continue;
    }
    modified.push({
      path: entryPath,
      change: beforeEntry.type !== afterEntry.type
        ? 'type'
        : beforeEntry.type === 'file' && beforeEntry.sha256 !== afterEntry.sha256
          ? 'content'
          : 'metadata',
      before: beforeEntry,
      after: afterEntry
    });
  }
  const addedFiles = added.filter((entry) => entry.type === 'file').length;
  const removedFiles = removed.filter((entry) => entry.type === 'file').length;
  const modifiedFiles = modified.filter((entry) =>
    entry.before.type === 'file' || entry.after.type === 'file').length;
  return {
    profile: PACKAGE_DELTA_PROFILE,
    summary: {
      entries: {
        before: before.entries.length,
        after: after.entries.length,
        added: added.length,
        removed: removed.length,
        modified: modified.length,
        unchanged
      },
      files: {
        before: before.fileCount,
        after: after.fileCount,
        added: addedFiles,
        removed: removedFiles,
        modified: modifiedFiles
      },
      bytes: {
        before: before.totalBytes,
        after: after.totalBytes,
        delta: after.totalBytes - before.totalBytes
      }
    },
    added,
    removed,
    modified
  };
}

function authenticityIdentity(result) {
  return {
    format: result.artifact.format,
    crxVersion: result.artifact.crxVersion,
    archiveSha256: result.artifact.sha256,
    authenticityStatus: result.artifact.authenticity.status,
    extensionId: result.artifact.authenticity.extensionId,
    developerKeySha256: result.artifact.authenticity.developerKeySha256
  };
}

function archiveContinuity(before, after, required) {
  const beforeIdentity = authenticityIdentity(before);
  const afterIdentity = authenticityIdentity(after);
  const verifiable = beforeIdentity.authenticityStatus === 'verified'
    && afterIdentity.authenticityStatus === 'verified';
  const sameExtensionId = verifiable
    ? beforeIdentity.extensionId === afterIdentity.extensionId
    : null;
  const sameDeveloperKey = verifiable
    ? beforeIdentity.developerKeySha256 === afterIdentity.developerKeySha256
    : null;
  return {
    profile: ARCHIVE_CONTINUITY_PROFILE,
    required,
    status: !verifiable
      ? 'unverifiable'
      : sameExtensionId && sameDeveloperKey ? 'verified-same' : 'verified-different',
    sameExtensionId,
    sameDeveloperKey,
    sameArchiveBytes: beforeIdentity.archiveSha256 === afterIdentity.archiveSha256,
    samePackage: before.package.sha256 === after.package.sha256,
    before: beforeIdentity,
    after: afterIdentity
  };
}

function validatePackedComparisonOptions(options) {
  assertOptionsObject(options, 'Packed comparison');
  const unknown = Object.getOwnPropertyNames(options)
    .filter((key) => !PACKED_COMPARISON_OPTIONS.has(key))
    .sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown packed comparison option(s): ${unknown.join(', ')}`, { code: 'INVALID_ARGUMENT' });
  }
  for (const key of ['requireSameExtensionId', 'requireValidSignature']) {
    const value = ownOption(options, key);
    if (value !== undefined && typeof value !== 'boolean') {
      throw new MvxError(`${key} must be boolean`, { code: 'INVALID_ARGUMENT' });
    }
  }
  for (const key of ['expectedBeforeArchiveSha256', 'expectedAfterArchiveSha256']) {
    const value = ownOption(options, key);
    if (value !== undefined && (typeof value !== 'string' || !SHA256.test(value))) {
      throw new MvxError(`${key} must be a lowercase SHA-256 digest`, { code: 'INVALID_ARGUMENT' });
    }
  }
  const expectedExtensionId = ownOption(options, 'expectedExtensionId');
  if (expectedExtensionId !== undefined
    && (typeof expectedExtensionId !== 'string' || !EXTENSION_ID.test(expectedExtensionId))) {
    throw new MvxError('expectedExtensionId must be a lowercase Chromium extension ID', { code: 'INVALID_ARGUMENT' });
  }
}

function snapshotRecord(value, label) {
  if (value === undefined) return undefined;
  assertOptionsObject(value, label);
  return Object.freeze(Object.fromEntries(Object.getOwnPropertyNames(value)
    .map((key) => [key, Object.getOwnPropertyDescriptor(value, key).value])));
}

function snapshotPaths(value, label) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || Object.getOwnPropertySymbols(value).length > 0) {
    throw new MvxError(`${label} must be a non-proxy array of file paths`, { code: 'INVALID_ARGUMENT' });
  }
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (key !== 'length' && !Object.hasOwn(descriptor, 'value')) {
      throw new MvxError(`${label} may not contain accessor property: ${key}`, { code: 'INVALID_ARGUMENT' });
    }
  }
  const snapshot = [...value];
  if (snapshot.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new MvxError(`${label} must contain only non-empty file paths`, { code: 'INVALID_ARGUMENT' });
  }
  return Object.freeze(snapshot);
}

function snapshotPackedComparisonOptions(options) {
  return Object.freeze({
    archiveLimits: snapshotRecord(
      ownOption(options, 'archiveLimits'),
      'Packed comparison archive limits'
    ),
    dispositionAt: ownOption(options, 'dispositionAt'),
    dispositionPolicies: snapshotPaths(
      ownOption(options, 'dispositionPolicies'),
      'dispositionPolicies'
    ),
    dispositionPolicyLimits: snapshotRecord(
      ownOption(options, 'dispositionPolicyLimits'),
      'Packed comparison disposition-policy limits'
    ),
    expectedAfterArchiveSha256: ownOption(options, 'expectedAfterArchiveSha256'),
    expectedBeforeArchiveSha256: ownOption(options, 'expectedBeforeArchiveSha256'),
    expectedExtensionId: ownOption(options, 'expectedExtensionId'),
    limits: snapshotRecord(ownOption(options, 'limits'), 'Packed comparison scan limits'),
    requireSameExtensionId: ownOption(options, 'requireSameExtensionId'),
    requireValidSignature: ownOption(options, 'requireValidSignature'),
    rulePackLimits: snapshotRecord(
      ownOption(options, 'rulePackLimits'),
      'Packed comparison rule-pack limits'
    ),
    rulePacks: snapshotPaths(ownOption(options, 'rulePacks'), 'rulePacks'),
    temporaryDirectory: ownOption(options, 'temporaryDirectory')
  });
}

async function auditPackedComparisonSide(inputPath, options, implicitSignatureRequirement) {
  try {
    return await auditExtensionArchive(inputPath, options);
  } catch (error) {
    if (implicitSignatureRequirement && error?.code === 'CRX_SIGNATURE_REQUIRED') {
      throw new MvxError(
        'Same-extension comparison requires two cryptographically verified CRX identities',
        { code: 'ARCHIVE_IDENTITY_UNVERIFIABLE', cause: error }
      );
    }
    throw error;
  }
}

export async function compareExtensions(beforePath, afterPath, options = {}) {
  assertOptionsObject(options, 'Comparison');
  const preparedRulePacks = await resolveRulePacks(options);
  const preparedDispositionPolicies = await resolveDispositionPolicies(options);
  const {
    rulePacks: _rulePacks,
    rulePackLimits: _rulePackLimits,
    dispositionPolicies: _dispositionPolicies,
    dispositionPolicyLimits: _dispositionPolicyLimits,
    dispositionAt: _dispositionAt,
    ...auditBaseOptions
  } = options;
  const auditOptions = {
    ...auditBaseOptions,
    _preparedRulePacks: preparedRulePacks,
    _preparedDispositionPolicies: preparedDispositionPolicies
  };
  const [before, after] = await Promise.all([
    auditExtension(beforePath, auditOptions),
    auditExtension(afterPath, auditOptions)
  ]);
  return compareAuditResults(before, after);
}

export async function compareExtensionArchives(beforePath, afterPath, options = {}) {
  validatePackedComparisonOptions(options);
  for (const [label, value] of [['beforePath', beforePath], ['afterPath', afterPath]]) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new MvxError(`${label} must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
    }
  }
  const stableOptions = snapshotPackedComparisonOptions(options);
  const preparedRulePacks = await resolveRulePacks(stableOptions);
  const preparedDispositionPolicies = await resolveDispositionPolicies(stableOptions);
  const strictContinuity = stableOptions.requireSameExtensionId === true;
  const implicitSignatureRequirement = strictContinuity
    && stableOptions.requireValidSignature !== true;
  const shared = {
    archiveLimits: stableOptions.archiveLimits,
    limits: stableOptions.limits,
    requireValidSignature: stableOptions.requireValidSignature || strictContinuity,
    temporaryDirectory: stableOptions.temporaryDirectory,
    _preparedRulePacks: preparedRulePacks,
    _preparedDispositionPolicies: preparedDispositionPolicies
  };
  const before = await auditPackedComparisonSide(beforePath, {
    ...shared,
    expectedArchiveSha256: stableOptions.expectedBeforeArchiveSha256,
    expectedExtensionId: stableOptions.expectedExtensionId
  }, implicitSignatureRequirement);
  const after = await auditPackedComparisonSide(afterPath, {
    ...shared,
    expectedArchiveSha256: stableOptions.expectedAfterArchiveSha256,
    expectedExtensionId: stableOptions.expectedExtensionId,
    ...(strictContinuity ? {
      ...(stableOptions.expectedExtensionId === undefined ? {
        _expectedExtensionIdIfVerified: before.artifact.authenticity.extensionId
      } : {}),
      _expectedDeveloperKeySha256IfVerified: before.artifact.authenticity.developerKeySha256
    } : {})
  }, implicitSignatureRequirement);
  const continuity = archiveContinuity(before, after, strictContinuity);
  if (continuity.required && continuity.status === 'unverifiable') {
    throw new MvxError('Same-extension comparison requires two cryptographically verified CRX identities', {
      code: 'ARCHIVE_IDENTITY_UNVERIFIABLE'
    });
  }
  if (continuity.required && continuity.status === 'verified-different') {
    throw new MvxError('Verified CRX extension or developer-key identities differ across the comparison', {
      code: 'ARCHIVE_IDENTITY_MISMATCH'
    });
  }
  const comparison = compareAuditResults(before, after);
  return {
    ...comparison,
    archiveContinuity: continuity,
    packageDelta: packageDelta(before.package, after.package),
    interpretation: [
      ...comparison.interpretation,
      'Verified matching CRX extension IDs and full developer-key hashes establish key continuity, not publisher identity, Web Store authorization, or benign behavior.',
      'ZIP or invalid-signature comparisons remain useful for forensic byte differences but cannot establish extension identity continuity.'
    ]
  };
}
