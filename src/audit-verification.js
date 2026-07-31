import { createHash } from 'node:crypto';
import path from 'node:path';
import { isDeepStrictEqual, types as utilTypes } from 'node:util';
import { auditExtension } from './analyzer.js';
import { MvxError } from './errors.js';
import { assertOptionsObject } from './options.js';
import { auditExtensionArchive } from './packed-audit.js';
import { readBoundedRegularFile } from './safe-file.js';

export const AUDIT_VERIFICATION_PROFILE = 'mvx-audit-verification-v1';
export const DEFAULT_AUDIT_VERIFICATION_LIMITS = Object.freeze({
  maxReportBytes: 25_000_000
});

const SHA256 = /^[a-f0-9]{64}$/;
const EXTENSION_ID = /^[a-p]{32}$/;
const UNSAFE_DISPLAY =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u2028-\u202e\u2066-\u2069]/;
const OPTIONS = new Set([
  'archiveLimits',
  'dispositionPolicies',
  'dispositionPolicyLimits',
  'expectedAnalysisSha256',
  'expectedArchiveSha256',
  'expectedExtensionId',
  'expectedPackageSha256',
  'expectedReportSha256',
  'limits',
  'reportLimits',
  'requireValidSignature',
  'rulePackLimits',
  'rulePacks',
  'temporaryDirectory'
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

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
  if (!Array.isArray(value) || utilTypes.isProxy(value)
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
  assertOptionsObject(options, 'Audit verification');
  const unknown = Object.getOwnPropertyNames(options)
    .filter((key) => !OPTIONS.has(key))
    .sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown audit verification option(s): ${unknown.join(', ')}`, {
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
    expectedAnalysisSha256: ownValue(options, 'expectedAnalysisSha256'),
    expectedArchiveSha256: ownValue(options, 'expectedArchiveSha256'),
    expectedExtensionId: ownValue(options, 'expectedExtensionId'),
    expectedPackageSha256: ownValue(options, 'expectedPackageSha256'),
    expectedReportSha256: ownValue(options, 'expectedReportSha256'),
    limits: snapshotRecord(ownValue(options, 'limits'), 'Scan limits'),
    reportLimits: snapshotRecord(ownValue(options, 'reportLimits'), 'Report limits'),
    requireValidSignature: ownValue(options, 'requireValidSignature'),
    rulePackLimits: snapshotRecord(ownValue(options, 'rulePackLimits'), 'Rule-pack limits'),
    rulePacks: snapshotPaths(ownValue(options, 'rulePacks'), 'rulePacks'),
    temporaryDirectory: ownValue(options, 'temporaryDirectory')
  });
  for (const key of [
    'expectedAnalysisSha256',
    'expectedArchiveSha256',
    'expectedPackageSha256',
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
  if (reportLimitKeys.some((key) => !Object.hasOwn(DEFAULT_AUDIT_VERIFICATION_LIMITS, key))) {
    throw new MvxError('Unknown audit verification report limit', { code: 'INVALID_ARGUMENT' });
  }
  const maxReportBytes = values.reportLimits?.maxReportBytes
    ?? DEFAULT_AUDIT_VERIFICATION_LIMITS.maxReportBytes;
  if (!Number.isSafeInteger(maxReportBytes) || maxReportBytes <= 0) {
    throw new MvxError('maxReportBytes must be a positive safe integer', {
      code: 'INVALID_ARGUMENT'
    });
  }
  values.reportLimits = Object.freeze(Object.assign(Object.create(null), { maxReportBytes }));
  return Object.freeze(values);
}

function rejectDuplicateKeys(source) {
  let cursor = 0;
  const whitespace = () => {
    while (/\s/.test(source[cursor] ?? '')) cursor += 1;
  };
  const jsonString = () => {
    const start = cursor++;
    while (cursor < source.length) {
      if (source[cursor] === '\\') cursor += 2;
      else if (source[cursor++] === '"') break;
    }
    return JSON.parse(source.slice(start, cursor));
  };
  const value = (depth) => {
    if (depth > 128) {
      throw new MvxError('Audit report exceeds 128 JSON nesting levels', {
        code: 'AUDIT_REPORT_LIMIT'
      });
    }
    whitespace();
    if (source[cursor] === '{') {
      cursor += 1;
      whitespace();
      const keys = new Set();
      while (source[cursor] !== '}') {
        const key = jsonString();
        if (keys.has(key)) {
          throw new MvxError(`Audit report contains duplicate JSON field: ${key}`, {
            code: 'INVALID_AUDIT_REPORT'
          });
        }
        keys.add(key);
        whitespace();
        cursor += 1;
        value(depth + 1);
        whitespace();
        if (source[cursor] === ',') {
          cursor += 1;
          whitespace();
        }
      }
      cursor += 1;
      return;
    }
    if (source[cursor] === '[') {
      cursor += 1;
      whitespace();
      while (source[cursor] !== ']') {
        value(depth + 1);
        whitespace();
        if (source[cursor] === ',') {
          cursor += 1;
          whitespace();
        }
      }
      cursor += 1;
      return;
    }
    if (source[cursor] === '"') {
      jsonString();
      return;
    }
    while (cursor < source.length && !/[\s,}\]]/.test(source[cursor])) cursor += 1;
  };
  value(0);
}

function parseReport(bytes) {
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    throw new MvxError('Audit report is not valid UTF-8', {
      code: 'INVALID_AUDIT_REPORT',
      cause: error
    });
  }
  let report;
  try {
    report = JSON.parse(source);
  } catch (error) {
    throw new MvxError(`Audit report is not valid JSON: ${error.message}`, {
      code: 'INVALID_AUDIT_REPORT',
      cause: error
    });
  }
  rejectDuplicateKeys(source);
  if (!report || Array.isArray(report) || typeof report !== 'object'
    || report.schemaVersion !== 1
    || !report.target || Array.isArray(report.target) || typeof report.target !== 'object'
    || typeof report.target.root !== 'string' || report.target.root.length === 0
    || report.target.root.length > 4_096
    || !report.package || typeof report.package.sha256 !== 'string'
    || !report.analysis || typeof report.analysis.sha256 !== 'string'
    || !Array.isArray(report.rulePacks)
    || !Array.isArray(report.findings)) {
    throw new MvxError('Audit report does not have the required schema-v1 audit structure', {
      code: 'INVALID_AUDIT_REPORT'
    });
  }
  if (report.artifact !== undefined
    && (!report.artifact || Array.isArray(report.artifact)
      || typeof report.artifact !== 'object'
      || typeof report.artifact.path !== 'string'
      || report.artifact.path.length === 0
      || report.artifact.path.length > 4_096)) {
    throw new MvxError('Packed audit report has an invalid artifact path', {
      code: 'INVALID_AUDIT_REPORT'
    });
  }
  for (const [label, value] of [
    ['target.root', report.target.root],
    ...(report.artifact ? [['artifact.path', report.artifact.path]] : [])
  ]) {
    if (UNSAFE_DISPLAY.test(value)) {
      throw new MvxError(`Audit report ${label} contains unsafe display characters`, {
        code: 'INVALID_AUDIT_REPORT'
      });
    }
  }
  return report;
}

function portableReport(report) {
  return {
    ...report,
    target: { ...report.target, root: '<verified input>' },
    ...(report.artifact ? {
      artifact: { ...report.artifact, path: '<verified input>' }
    } : {})
  };
}

function assertExpected(actual, expected, label) {
  if (expected !== undefined && actual !== expected) {
    throw new MvxError(`${label} does not match its independently expected identity`, {
      code: 'AUDIT_IDENTITY_MISMATCH'
    });
  }
}

function assertIndependentIdentities(actual, stable) {
  assertExpected(actual.package.sha256, stable.expectedPackageSha256, 'Package SHA-256');
  assertExpected(actual.analysis.sha256, stable.expectedAnalysisSha256, 'Analysis SHA-256');
  assertExpected(actual.artifact?.sha256, stable.expectedArchiveSha256, 'Archive SHA-256');
  if (stable.expectedExtensionId !== undefined
    && actual.artifact?.authenticity?.status !== 'verified') {
    throw new MvxError('The supplied input does not have a cryptographically verified extension ID', {
      code: 'AUDIT_IDENTITY_UNVERIFIABLE'
    });
  }
  assertExpected(
    actual.artifact?.authenticity?.extensionId,
    stable.expectedExtensionId,
    'Verified extension ID'
  );
  if (stable.requireValidSignature === true
    && actual.artifact?.authenticity?.status !== 'verified') {
    throw new MvxError('A cryptographically verified CRX report is required', {
      code: 'AUDIT_IDENTITY_UNVERIFIABLE'
    });
  }
}

export async function verifyAuditReport(reportPath, inputPath, options = {}) {
  for (const [label, value] of [['reportPath', reportPath], ['inputPath', inputPath]]) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new MvxError(`${label} must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
    }
  }
  const stable = snapshotOptions(options);
  const reportBytes = await readBoundedRegularFile(path.resolve(reportPath), {
    maxBytes: stable.reportLimits.maxReportBytes,
    label: 'audit report',
    limitCode: 'AUDIT_REPORT_LIMIT',
    missingCode: 'AUDIT_REPORT_NOT_FOUND',
    unsafeCode: 'UNSAFE_AUDIT_REPORT'
  });
  const reportSha256 = sha256(reportBytes);
  assertExpected(reportSha256, stable.expectedReportSha256, 'Audit report SHA-256');
  const report = parseReport(reportBytes);
  const dispositionAt = report.dispositionEvaluation?.evaluatedAt;
  const auditOptions = Object.assign(Object.create(null), {
    archiveLimits: stable.archiveLimits,
    limits: stable.limits,
    rulePacks: stable.rulePacks,
    rulePackLimits: stable.rulePackLimits,
    dispositionPolicies: stable.dispositionPolicies,
    dispositionPolicyLimits: stable.dispositionPolicyLimits,
    ...(dispositionAt !== undefined ? { dispositionAt } : {})
  });
  let actual;
  if (report.artifact) {
    actual = await auditExtensionArchive(inputPath, Object.assign(Object.create(null), {
      ...auditOptions,
      temporaryDirectory: stable.temporaryDirectory,
      requireValidSignature:
        report.artifact.identityPolicy?.requireValidSignature ?? undefined,
      expectedArchiveSha256:
        report.artifact.identityPolicy?.expectedArchiveSha256 ?? undefined,
      expectedExtensionId:
        report.artifact.identityPolicy?.expectedExtensionId ?? undefined
    }));
  } else {
    if (stable.expectedArchiveSha256 !== undefined
      || stable.expectedExtensionId !== undefined
      || stable.requireValidSignature !== undefined
      || stable.archiveLimits !== undefined
      || stable.temporaryDirectory !== undefined) {
      throw new MvxError('Archive verification options require a packed audit report', {
        code: 'INVALID_ARGUMENT'
      });
    }
    actual = await auditExtension(inputPath, auditOptions);
  }
  assertIndependentIdentities(actual, stable);
  if (!isDeepStrictEqual(portableReport(report), portableReport(actual))) {
    throw new MvxError(
      'Audit report does not match deterministic analysis of the supplied input and review data',
      { code: 'AUDIT_REPORT_MISMATCH' }
    );
  }
  const locationMetadataMatchesInput = report.target.root === actual.target.root
    && (report.artifact?.path ?? null) === (actual.artifact?.path ?? null);
  const independentChecks = {
    reportSha256: stable.expectedReportSha256 === undefined ? null : true,
    packageSha256: stable.expectedPackageSha256 === undefined ? null : true,
    analysisSha256: stable.expectedAnalysisSha256 === undefined ? null : true,
    archiveSha256: stable.expectedArchiveSha256 === undefined ? null : true,
    extensionId: stable.expectedExtensionId === undefined ? null : true,
    validSignature: stable.requireValidSignature === true ? true : null
  };
  return {
    schemaVersion: 1,
    profile: AUDIT_VERIFICATION_PROFILE,
    valid: true,
    inputType: report.artifact ? 'archive' : 'directory',
    report: { bytes: reportBytes.length, sha256: reportSha256 },
    identities: {
      packageSha256: actual.package.sha256,
      analysisSha256: actual.analysis.sha256,
      artifactSha256: actual.artifact?.sha256 ?? null,
      extensionId: actual.artifact?.authenticity?.extensionId ?? null,
      developerKeySha256:
        actual.artifact?.authenticity?.developerKeySha256 ?? null
    },
    checks: {
      deterministicReport: true,
      toolVersion: true,
      rulePackProvenance: true,
      dispositionProvenance: true,
      locationMetadataMatchesInput,
      independent: independentChecks
    },
    caveats: [
      'The target.root and packed artifact.path fields are local transport metadata and are excluded from deterministic comparison.',
      ...(Object.values(independentChecks).every((value) => value === null) ? [
        'The report is reproducible from the supplied inputs, but no independently trusted identity was supplied.'
      ] : [])
    ]
  };
}

export function auditVerificationToText(result) {
  return [
    `Audit report valid: ${result.valid ? 'yes' : 'NO'}`,
    `Input type: ${result.inputType}`,
    `Report SHA-256: ${result.report.sha256}`,
    `Package SHA-256: ${result.identities.packageSha256}`,
    `Analysis SHA-256: ${result.identities.analysisSha256}`,
    ...(result.identities.artifactSha256 ? [
      `Archive SHA-256: ${result.identities.artifactSha256}`,
      `Verified extension ID: ${result.identities.extensionId ?? 'unverifiable'}`,
      `Developer key SHA-256: ${result.identities.developerKeySha256 ?? 'unverifiable'}`
    ] : []),
    ...result.caveats.map((caveat) => `Caveat: ${caveat}`)
  ].join('\n') + '\n';
}
