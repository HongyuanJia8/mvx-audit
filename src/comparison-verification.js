import { createHash } from 'node:crypto';
import path from 'node:path';
import { isDeepStrictEqual, types as utilTypes } from 'node:util';
import {
  isVerificationDataRecord,
  normalizeVerificationData,
  parseBoundedJsonReport,
  portableAuditReport,
  replayAuditReportData,
  validateAuditReportData
} from './audit-verification.js';
import { compareAuditResults, comparePackedAuditResults } from './compare.js';
import { MvxError } from './errors.js';
import { assertOptionsObject } from './options.js';
import { readBoundedRegularFile } from './safe-file.js';

export const COMPARISON_VERIFICATION_PROFILE = 'mvx-comparison-verification-v1';
export const DEFAULT_COMPARISON_VERIFICATION_LIMITS = Object.freeze({
  maxReportBytes: 50_000_000,
  maxReportValues: 1_000_000
});

const SHA256 = /^[a-f0-9]{64}$/;
const EXTENSION_ID = /^[a-p]{32}$/;
const OPTIONS = new Set([
  'archiveLimits',
  'dispositionPolicies',
  'dispositionPolicyLimits',
  'expectedAfterAnalysisSha256',
  'expectedAfterArchiveSha256',
  'expectedAfterPackageSha256',
  'expectedBeforeAnalysisSha256',
  'expectedBeforeArchiveSha256',
  'expectedBeforePackageSha256',
  'expectedExtensionId',
  'expectedReportSha256',
  'limits',
  'reportLimits',
  'requireValidSignature',
  'rulePackLimits',
  'rulePacks',
  'temporaryDirectory'
]);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function ownValue(object, key) {
  return Object.getOwnPropertyDescriptor(object, key)?.value;
}

function snapshotRecord(value, label) {
  if (value === undefined) return undefined;
  assertOptionsObject(value, label);
  return Object.freeze(Object.assign(
    Object.create(null),
    Object.fromEntries(Object.getOwnPropertyNames(value)
      .map((key) => [key, Object.getOwnPropertyDescriptor(value, key).value]))
  ));
}

function snapshotPaths(value, label) {
  if (value === undefined) return undefined;
  if (utilTypes.isProxy(value) || !Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || Object.getOwnPropertySymbols(value).length > 0) {
    throw new MvxError(`${label} must be a non-proxy array of file paths`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const length = descriptors.length.value;
  const keys = Object.keys(descriptors).filter((key) => key !== 'length');
  if (keys.length !== length || keys.some((key) => {
    const index = Number(key);
    return !Number.isSafeInteger(index) || index < 0 || index >= length || String(index) !== key;
  })) {
    throw new MvxError(`${label} must be a dense array without extra properties`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  for (const key of keys) {
    if (!Object.hasOwn(descriptors[key], 'value')) {
      throw new MvxError(`${label} may not contain accessor property: ${key}`, {
        code: 'INVALID_ARGUMENT'
      });
    }
  }
  const result = keys.map((key) => descriptors[key].value);
  if (result.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new MvxError(`${label} must contain only non-empty file paths`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  return Object.freeze(result);
}

function snapshotOptions(options) {
  assertOptionsObject(options, 'Comparison verification');
  const unknown = Object.getOwnPropertyNames(options)
    .filter((key) => !OPTIONS.has(key))
    .sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown comparison verification option(s): ${unknown.join(', ')}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  const values = Object.assign(Object.create(null), {
    archiveLimits: snapshotRecord(ownValue(options, 'archiveLimits'), 'Archive limits'),
    dispositionPolicies: snapshotPaths(
      ownValue(options, 'dispositionPolicies'),
      'dispositionPolicies'
    ),
    dispositionPolicyLimits: snapshotRecord(
      ownValue(options, 'dispositionPolicyLimits'),
      'Disposition-policy limits'
    ),
    expectedAfterAnalysisSha256: ownValue(options, 'expectedAfterAnalysisSha256'),
    expectedAfterArchiveSha256: ownValue(options, 'expectedAfterArchiveSha256'),
    expectedAfterPackageSha256: ownValue(options, 'expectedAfterPackageSha256'),
    expectedBeforeAnalysisSha256: ownValue(options, 'expectedBeforeAnalysisSha256'),
    expectedBeforeArchiveSha256: ownValue(options, 'expectedBeforeArchiveSha256'),
    expectedBeforePackageSha256: ownValue(options, 'expectedBeforePackageSha256'),
    expectedExtensionId: ownValue(options, 'expectedExtensionId'),
    expectedReportSha256: ownValue(options, 'expectedReportSha256'),
    limits: snapshotRecord(ownValue(options, 'limits'), 'Scan limits'),
    reportLimits: snapshotRecord(ownValue(options, 'reportLimits'), 'Report limits'),
    requireValidSignature: ownValue(options, 'requireValidSignature'),
    rulePackLimits: snapshotRecord(ownValue(options, 'rulePackLimits'), 'Rule-pack limits'),
    rulePacks: snapshotPaths(ownValue(options, 'rulePacks'), 'rulePacks'),
    temporaryDirectory: ownValue(options, 'temporaryDirectory')
  });
  for (const key of [
    'expectedAfterAnalysisSha256',
    'expectedAfterArchiveSha256',
    'expectedAfterPackageSha256',
    'expectedBeforeAnalysisSha256',
    'expectedBeforeArchiveSha256',
    'expectedBeforePackageSha256',
    'expectedReportSha256'
  ]) {
    if (values[key] !== undefined
      && (typeof values[key] !== 'string' || !SHA256.test(values[key]))) {
      throw new MvxError(`${key} must be a lowercase SHA-256 digest`, {
        code: 'INVALID_ARGUMENT'
      });
    }
  }
  if (values.expectedExtensionId !== undefined
    && (typeof values.expectedExtensionId !== 'string'
      || !EXTENSION_ID.test(values.expectedExtensionId))) {
    throw new MvxError('expectedExtensionId must be a lowercase Chromium extension ID', {
      code: 'INVALID_ARGUMENT'
    });
  }
  if (values.requireValidSignature !== undefined
    && typeof values.requireValidSignature !== 'boolean') {
    throw new MvxError('requireValidSignature must be boolean', {
      code: 'INVALID_ARGUMENT'
    });
  }
  if (values.temporaryDirectory !== undefined
    && (typeof values.temporaryDirectory !== 'string'
      || values.temporaryDirectory.length === 0)) {
    throw new MvxError('temporaryDirectory must be a non-empty string', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const reportLimitKeys = Object.keys(values.reportLimits ?? {});
  if (reportLimitKeys.some(
    (key) => !Object.hasOwn(DEFAULT_COMPARISON_VERIFICATION_LIMITS, key)
  )) {
    throw new MvxError('Unknown comparison verification report limit', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const normalizedReportLimits = Object.create(null);
  for (const [key, fallback] of Object.entries(DEFAULT_COMPARISON_VERIFICATION_LIMITS)) {
    const value = values.reportLimits?.[key] ?? fallback;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new MvxError(`${key} must be a positive safe integer`, {
        code: 'INVALID_ARGUMENT'
      });
    }
    normalizedReportLimits[key] = value;
  }
  values.reportLimits = Object.freeze(normalizedReportLimits);
  return Object.freeze(values);
}

function validateEmbeddedAudit(value, side) {
  try {
    return validateAuditReportData(value);
  } catch (error) {
    if (error?.code === 'INVALID_AUDIT_REPORT') {
      throw new MvxError(`Comparison report has an invalid ${side} audit`, {
        code: 'INVALID_COMPARISON_REPORT',
        cause: error
      });
    }
    throw error;
  }
}

function dispositionTime(report) {
  return report.dispositionEvaluation?.evaluatedAt;
}

function validateComparisonReportData(report) {
  if (!isVerificationDataRecord(report)
    || report.schemaVersion !== 1
    || !isVerificationDataRecord(report.before)
    || !isVerificationDataRecord(report.after)
    || !isVerificationDataRecord(report.delta)
    || !Array.isArray(report.interpretation)) {
    throw new MvxError(
      'Comparison report does not have the required schema-v1 comparison structure',
      { code: 'INVALID_COMPARISON_REPORT' }
    );
  }
  validateEmbeddedAudit(report.before, 'before');
  validateEmbeddedAudit(report.after, 'after');
  const beforePacked = report.before.artifact !== undefined;
  const afterPacked = report.after.artifact !== undefined;
  if (beforePacked !== afterPacked) {
    throw new MvxError('Comparison report mixes directory and packed audit inputs', {
      code: 'INVALID_COMPARISON_REPORT'
    });
  }
  if (dispositionTime(report.before) !== dispositionTime(report.after)) {
    throw new MvxError('Comparison report sides use different disposition evaluation times', {
      code: 'INVALID_COMPARISON_REPORT'
    });
  }
  if (beforePacked) {
    if (!isVerificationDataRecord(report.archiveContinuity)
      || typeof report.archiveContinuity.required !== 'boolean'
      || !isVerificationDataRecord(report.packageDelta)) {
      throw new MvxError('Packed comparison report lacks continuity or package-delta data', {
        code: 'INVALID_COMPARISON_REPORT'
      });
    }
    const beforePolicy = report.before.artifact.identityPolicy;
    const afterPolicy = report.after.artifact.identityPolicy;
    if (beforePolicy.requireValidSignature !== afterPolicy.requireValidSignature
      || beforePolicy.expectedExtensionId !== afterPolicy.expectedExtensionId) {
      throw new MvxError('Packed comparison report sides use inconsistent identity policies', {
        code: 'INVALID_COMPARISON_REPORT'
      });
    }
  } else if (report.archiveContinuity !== undefined || report.packageDelta !== undefined) {
    throw new MvxError('Directory comparison report contains packed-only fields', {
      code: 'INVALID_COMPARISON_REPORT'
    });
  }
  return report;
}

function portableComparisonReport(report) {
  const result = Object.assign(Object.create(null), report);
  result.before = portableAuditReport(report.before);
  result.after = portableAuditReport(report.after);
  return result;
}

function assertExpected(actual, expected, label) {
  if (expected !== undefined && actual !== expected) {
    throw new MvxError(`${label} does not match its independently expected identity`, {
      code: 'COMPARISON_IDENTITY_MISMATCH'
    });
  }
}

function canonicalizeLegacySignaturePolicies(report) {
  const legacy = { before: false, after: false };
  const inferredRequirement = report.archiveContinuity?.required === true;
  for (const side of ['before', 'after']) {
    const policy = report[side].artifact?.identityPolicy;
    if (policy !== undefined && !Object.hasOwn(policy, 'requireValidSignature')) {
      policy.requireValidSignature = inferredRequirement;
      legacy[side] = true;
    }
  }
  return legacy;
}

async function replaySide(side, report, inputPath, options) {
  try {
    return await replayAuditReportData(report, inputPath, options);
  } catch (error) {
    const mappings = new Map([
      ['AUDIT_IDENTITY_MISMATCH', 'COMPARISON_IDENTITY_MISMATCH'],
      ['AUDIT_IDENTITY_UNVERIFIABLE', 'COMPARISON_IDENTITY_UNVERIFIABLE'],
      ['AUDIT_REPORT_MISMATCH', 'COMPARISON_REPORT_MISMATCH'],
      ['INVALID_AUDIT_REPORT', 'INVALID_COMPARISON_REPORT']
    ]);
    const code = mappings.get(error?.code);
    if (!code) throw error;
    throw new MvxError(`${side} comparison input failed verification: ${error.message}`, {
      code,
      cause: error
    });
  }
}

function identitySummary(actual) {
  const verified = actual.artifact?.authenticity?.status === 'verified';
  return {
    packageSha256: actual.package.sha256,
    analysisSha256: actual.analysis.sha256,
    artifactSha256: actual.artifact?.sha256 ?? null,
    authenticityStatus: actual.artifact?.authenticity?.status ?? null,
    extensionId: verified ? actual.artifact.authenticity.extensionId : null,
    developerKeySha256: verified
      ? actual.artifact.authenticity.developerKeySha256
      : null
  };
}

function independentChecks(stable, side) {
  const prefix = side === 'before' ? 'Before' : 'After';
  return {
    packageSha256: stable[`expected${prefix}PackageSha256`] === undefined ? null : true,
    analysisSha256: stable[`expected${prefix}AnalysisSha256`] === undefined ? null : true,
    archiveSha256: stable[`expected${prefix}ArchiveSha256`] === undefined ? null : true,
    extensionId: stable.expectedExtensionId === undefined ? null : true,
    validSignature: stable.requireValidSignature === true ? true : null
  };
}

export async function verifyComparisonReport(
  reportPath,
  beforePath,
  afterPath,
  options = {}
) {
  for (const [label, value] of [
    ['reportPath', reportPath],
    ['beforePath', beforePath],
    ['afterPath', afterPath]
  ]) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new MvxError(`${label} must be a non-empty string`, {
        code: 'INVALID_ARGUMENT'
      });
    }
  }
  const stable = snapshotOptions(options);
  const reportBytes = await readBoundedRegularFile(path.resolve(reportPath), {
    maxBytes: stable.reportLimits.maxReportBytes,
    label: 'comparison report',
    limitCode: 'COMPARISON_REPORT_LIMIT',
    missingCode: 'COMPARISON_REPORT_NOT_FOUND',
    unsafeCode: 'UNSAFE_COMPARISON_REPORT'
  });
  const reportSha256 = createHash('sha256').update(reportBytes).digest('hex');
  assertExpected(reportSha256, stable.expectedReportSha256, 'Comparison report SHA-256');
  const report = validateComparisonReportData(parseBoundedJsonReport(
    reportBytes,
    stable.reportLimits,
    {
      label: 'Comparison report',
      invalidCode: 'INVALID_COMPARISON_REPORT',
      limitCode: 'COMPARISON_REPORT_LIMIT'
    }
  ));
  const packed = report.before.artifact !== undefined;
  if (!packed && (
    stable.archiveLimits !== undefined
    || stable.expectedBeforeArchiveSha256 !== undefined
    || stable.expectedAfterArchiveSha256 !== undefined
    || stable.expectedExtensionId !== undefined
    || stable.requireValidSignature !== undefined
  )) {
    throw new MvxError('Archive verification options require a packed comparison report', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const legacySignaturePolicy = canonicalizeLegacySignaturePolicies(report);
  if (packed && report.archiveContinuity.required
    && (report.before.artifact.identityPolicy.requireValidSignature !== true
      || report.after.artifact.identityPolicy.requireValidSignature !== true)) {
    throw new MvxError(
      'Strict packed comparison reports must require valid signatures on both sides',
      { code: 'INVALID_COMPARISON_REPORT' }
    );
  }
  const shared = {
    archiveLimits: stable.archiveLimits,
    dispositionPolicies: stable.dispositionPolicies,
    dispositionPolicyLimits: stable.dispositionPolicyLimits,
    limits: stable.limits,
    rulePackLimits: stable.rulePackLimits,
    rulePacks: stable.rulePacks,
    temporaryDirectory: stable.temporaryDirectory
  };
  const sideOptions = {
    before: {
      ...shared,
      expectedAnalysisSha256: stable.expectedBeforeAnalysisSha256,
      expectedArchiveSha256: stable.expectedBeforeArchiveSha256,
      expectedExtensionId: stable.expectedExtensionId,
      expectedPackageSha256: stable.expectedBeforePackageSha256,
      requireValidSignature: stable.requireValidSignature
    },
    after: {
      ...shared,
      expectedAnalysisSha256: stable.expectedAfterAnalysisSha256,
      expectedArchiveSha256: stable.expectedAfterArchiveSha256,
      expectedExtensionId: stable.expectedExtensionId,
      expectedPackageSha256: stable.expectedAfterPackageSha256,
      requireValidSignature: stable.requireValidSignature
    }
  };
  const replays = await Promise.allSettled([
    replaySide('Before', report.before, beforePath, sideOptions.before),
    replaySide('After', report.after, afterPath, sideOptions.after)
  ]);
  const failed = replays.find((result) => result.status === 'rejected');
  if (failed) throw failed.reason;
  const before = replays[0].value;
  const after = replays[1].value;
  const actual = normalizeVerificationData(packed
    ? comparePackedAuditResults(
      before.actual,
      after.actual,
      report.archiveContinuity.required
    )
    : compareAuditResults(before.actual, after.actual));
  if (!isDeepStrictEqual(
    portableComparisonReport(report),
    portableComparisonReport(actual)
  )) {
    throw new MvxError(
      'Comparison report does not match deterministic analysis of both supplied inputs',
      { code: 'COMPARISON_REPORT_MISMATCH' }
    );
  }
  const beforeIndependent = independentChecks(stable, 'before');
  const afterIndependent = independentChecks(stable, 'after');
  const anyIndependent = stable.expectedReportSha256 !== undefined
    || [...Object.values(beforeIndependent), ...Object.values(afterIndependent)]
      .some((value) => value !== null);
  return {
    schemaVersion: 1,
    profile: COMPARISON_VERIFICATION_PROFILE,
    valid: true,
    inputType: packed ? 'archive' : 'directory',
    report: {
      bytes: reportBytes.length,
      sha256: reportSha256
    },
    identities: {
      before: identitySummary(before.actual),
      after: identitySummary(after.actual)
    },
    checks: {
      deterministicReport: true,
      toolVersion: true,
      rulePackProvenance: true,
      dispositionProvenance: true,
      packageDelta: packed ? true : null,
      archiveContinuity: packed ? true : null,
      locationMetadataMatchesInput: {
        before: before.locationMetadataMatchesInput,
        after: after.locationMetadataMatchesInput
      },
      recordedSignatureRequirement: packed
        ? (legacySignaturePolicy.before || legacySignaturePolicy.after ? null : true)
        : null,
      independent: {
        reportSha256: stable.expectedReportSha256 === undefined ? null : true,
        before: beforeIndependent,
        after: afterIndependent
      }
    },
    caveats: [
      'The nested target.root and packed artifact.path fields are local transport metadata and are excluded from deterministic comparison.',
      ...(!anyIndependent ? [
        'The comparison is reproducible from the supplied inputs, but no independently trusted identity was supplied.'
      ] : []),
      ...(legacySignaturePolicy.before || legacySignaturePolicy.after ? [
        'A legacy packed side did not record whether a valid signature was required; verification inferred true from strict continuity or otherwise replayed the historical default (false).'
      ] : [])
    ]
  };
}

export function comparisonVerificationToText(result) {
  const sideLines = (label, identity) => [
    `${label} package SHA-256: ${identity.packageSha256}`,
    `${label} analysis SHA-256: ${identity.analysisSha256}`,
    ...(identity.artifactSha256 ? [
      `${label} archive SHA-256: ${identity.artifactSha256}`,
      `${label} CRX authenticity: ${identity.authenticityStatus}`,
      ...(identity.authenticityStatus === 'verified' ? [
        `${label} verified extension ID: ${identity.extensionId}`,
        `${label} verified developer key SHA-256: ${identity.developerKeySha256}`
      ] : [])
    ] : [])
  ];
  return [
    `Comparison report valid: ${result.valid ? 'yes' : 'NO'}`,
    `Input type: ${result.inputType}`,
    `Report SHA-256: ${result.report.sha256}`,
    ...sideLines('Before', result.identities.before),
    ...sideLines('After', result.identities.after),
    ...result.caveats.map((caveat) => `Caveat: ${caveat}`)
  ].join('\n') + '\n';
}
