import { createHash } from 'node:crypto';
import { fork } from 'node:child_process';
import {
  lstat, realpath
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { isDeepStrictEqual, types as utilTypes } from 'node:util';
import { fileURLToPath } from 'node:url';
import { auditExtension } from './analyzer.js';
import { MvxError } from './errors.js';
import { normalizeScanLimits } from './io.js';
import { assertOptionsObject } from './options.js';
import { auditExtensionArchive } from './packed-audit.js';
import {
  assertPrivateWorkspace, createPrivateWorkspace, removePrivateWorkspace,
  resolvePrivateWorkspaceParent
} from './private-workspace.js';
import { readBoundedRegularFile } from './safe-file.js';

export const AUDIT_VERIFICATION_PROFILE = 'mvx-audit-verification-v1';
export const DEFAULT_AUDIT_VERIFICATION_LIMITS = Object.freeze({
  maxReportBytes: 25_000_000,
  maxReportValues: 500_000
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
  const normalizedReportLimits = Object.create(null);
  for (const [key, fallback] of Object.entries(DEFAULT_AUDIT_VERIFICATION_LIMITS)) {
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
  const value = () => {
    whitespace();
    if (source[cursor] === '{') {
      cursor += 1;
      whitespace();
      const keys = new Set();
      while (source[cursor] !== '}') {
        const key = jsonString();
        if (keys.has(key)) {
          throw new MvxError('Audit report contains duplicate JSON fields', {
            code: 'INVALID_AUDIT_REPORT'
          });
        }
        keys.add(key);
        whitespace();
        cursor += 1;
        value();
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
        value();
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
  value();
}

function assertJsonStructure(source, limits) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  let primitive = false;
  let values = 0;
  const countValue = () => {
    values += 1;
    if (values > limits.maxReportValues) {
      throw new MvxError(
        `Audit report exceeds ${limits.maxReportValues} JSON values`,
        { code: 'AUDIT_REPORT_LIMIT' }
      );
    }
  };
  for (const character of source) {
    if (inString) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      countValue();
      inString = true;
      primitive = false;
      continue;
    }
    if (character === '{' || character === '[') {
      countValue();
      primitive = false;
      depth += 1;
      if (depth > 128) {
        throw new MvxError('Audit report exceeds 128 JSON nesting levels', {
          code: 'AUDIT_REPORT_LIMIT'
        });
      }
    } else if (character === '}' || character === ']') {
      primitive = false;
      depth -= 1;
    } else if (/[\s,:]/.test(character)) {
      primitive = false;
    } else if (!primitive) {
      countValue();
      primitive = true;
    }
  }
}

function normalizeData(value) {
  if (Array.isArray(value)) {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const length = descriptors.length.value;
    const result = [];
    Object.setPrototypeOf(result, null);
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        throw new MvxError('Audit report arrays must contain only own data elements', {
          code: 'INVALID_AUDIT_REPORT'
        });
      }
      Object.defineProperty(result, String(index), {
        value: normalizeData(descriptor.value),
        configurable: true,
        enumerable: true,
        writable: true
      });
    }
    return result;
  }
  if (!value || typeof value !== 'object') return value;
  const result = Object.create(null);
  for (const key of Object.getOwnPropertyNames(value)) {
    result[key] = normalizeData(Object.getOwnPropertyDescriptor(value, key).value);
  }
  return result;
}

function isDataRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseReport(bytes, limits) {
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    throw new MvxError('Audit report is not valid UTF-8', {
      code: 'INVALID_AUDIT_REPORT',
      cause: error
    });
  }
  assertJsonStructure(source, limits);
  let report;
  try {
    report = JSON.parse(source);
  } catch (error) {
    throw new MvxError('Audit report is not valid JSON', {
      code: 'INVALID_AUDIT_REPORT',
      cause: error
    });
  }
  rejectDuplicateKeys(source);
  report = normalizeData(report);
  if (!isDataRecord(report)
    || report.schemaVersion !== 1
    || !isDataRecord(report.target)
    || typeof report.target.root !== 'string' || report.target.root.length === 0
    || report.target.root.length > 4_096
    || !isDataRecord(report.package) || typeof report.package.sha256 !== 'string'
    || !isDataRecord(report.analysis) || typeof report.analysis.sha256 !== 'string'
    || !Array.isArray(report.rulePacks)
    || !Array.isArray(report.findings)) {
    throw new MvxError('Audit report does not have the required schema-v1 audit structure', {
      code: 'INVALID_AUDIT_REPORT'
    });
  }
  if (report.artifact !== undefined
    && (!isDataRecord(report.artifact)
      || typeof report.artifact.path !== 'string'
      || report.artifact.path.length === 0
      || report.artifact.path.length > 4_096
      || !isDataRecord(report.artifact.identityPolicy))) {
    throw new MvxError('Packed audit report has an invalid artifact path', {
      code: 'INVALID_AUDIT_REPORT'
    });
  }
  const identityPolicy = report.artifact?.identityPolicy;
  if (identityPolicy !== undefined
    && ((identityPolicy.requireValidSignature !== undefined
        && typeof identityPolicy.requireValidSignature !== 'boolean')
      || (identityPolicy.expectedArchiveSha256 !== undefined
        && identityPolicy.expectedArchiveSha256 !== null
        && (typeof identityPolicy.expectedArchiveSha256 !== 'string'
          || !SHA256.test(identityPolicy.expectedArchiveSha256)))
      || (identityPolicy.expectedExtensionId !== undefined
        && identityPolicy.expectedExtensionId !== null
        && (typeof identityPolicy.expectedExtensionId !== 'string'
          || !EXTENSION_ID.test(identityPolicy.expectedExtensionId))))) {
    throw new MvxError('Packed audit report has an invalid identity policy', {
      code: 'INVALID_AUDIT_REPORT'
    });
  }
  if (report.dispositionEvaluation !== undefined
    && !isDataRecord(report.dispositionEvaluation)) {
    throw new MvxError('Audit report has an invalid disposition evaluation record', {
      code: 'INVALID_AUDIT_REPORT'
    });
  }
  const evaluatedAt = report.dispositionEvaluation?.evaluatedAt;
  if (evaluatedAt !== undefined
    && (typeof evaluatedAt !== 'string'
      || evaluatedAt.length === 0
      || evaluatedAt.length > 24
      || Number.isNaN(new Date(evaluatedAt).getTime())
      || new Date(evaluatedAt).toISOString() !== evaluatedAt)) {
    throw new MvxError('Audit report has an invalid disposition evaluation time', {
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
  const result = Object.assign(Object.create(null), report);
  result.target = Object.assign(Object.create(null), report.target, {
    root: '<verified input>'
  });
  if (report.artifact !== undefined) {
    result.artifact = Object.assign(Object.create(null), report.artifact, {
      path: '<verified input>'
    });
  }
  return result;
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

function sanitizeSnapshotError(error, workspace) {
  if (!workspace || typeof error?.message !== 'string' || !error.message.includes(workspace)) {
    return error;
  }
  const message = error.message.split(workspace).join('<private audit snapshot>');
  if (error instanceof MvxError) return new MvxError(message, { code: error.code });
  const sanitized = new Error(message);
  sanitized.name = typeof error?.name === 'string' ? error.name : 'Error';
  if (typeof error?.code === 'string') sanitized.code = error.code;
  return sanitized;
}

const SNAPSHOT_WORKER = fileURLToPath(
  new URL('./directory-snapshot-worker.js', import.meta.url)
);

async function copyAuditTree(
  sourceRoot,
  destinationRoot,
  requestedLimits,
  rootStat,
  workspace
) {
  const limits = normalizeScanLimits(requestedLimits ?? {});
  await new Promise((resolve, reject) => {
    const child = fork(SNAPSHOT_WORKER, [
      destinationRoot,
      rootStat.dev.toString(),
      rootStat.ino.toString(),
      JSON.stringify(limits),
      workspace.stat.dev.toString(),
      workspace.stat.ino.toString()
    ], {
      cwd: sourceRoot,
      execArgv: [],
      stdio: ['ignore', 'ignore', 'ignore', 'ipc']
    });
    let response;
    child.once('message', (message) => {
      response = message;
    });
    child.once('error', (error) => {
      reject(new MvxError('Cannot start the private audit snapshot worker', {
        code: 'AUDIT_SNAPSHOT_FAILED',
        cause: error
      }));
    });
    child.once('close', (code) => {
      if (response?.ok === true && code === 0) {
        resolve();
        return;
      }
      reject(new MvxError(
        typeof response?.message === 'string'
          ? response.message
          : 'Private audit snapshot worker failed',
        { code: typeof response?.code === 'string' ? response.code : 'AUDIT_SNAPSHOT_FAILED' }
      ));
    });
  });
}

async function prepareDirectorySnapshot(inputPath, temporaryDirectory, limits) {
  const absolute = path.resolve(inputPath);
  const possibleManifestRoot = path.basename(absolute) === 'manifest.json'
    ? path.dirname(absolute)
    : undefined;
  let possibleManifestRootStat;
  if (possibleManifestRoot !== undefined) {
    possibleManifestRootStat = await lstat(possibleManifestRoot, { bigint: true })
      .catch(() => undefined);
  }
  let inputStat;
  try {
    inputStat = await lstat(absolute, { bigint: true });
  } catch (error) {
    throw new MvxError(`Input does not exist: ${absolute}`, {
      code: 'INPUT_NOT_FOUND',
      cause: error
    });
  }
  if (inputStat.isSymbolicLink()) {
    throw new MvxError('The extension root may not be a symbolic link', {
      code: 'UNSAFE_INPUT'
    });
  }
  let root;
  let expectedRootStat;
  if (inputStat.isFile()) {
    if (path.basename(absolute) !== 'manifest.json') {
      throw new MvxError('A file input must be named manifest.json', {
        code: 'INVALID_INPUT'
      });
    }
    root = path.dirname(absolute);
    expectedRootStat = possibleManifestRootStat;
    if (expectedRootStat === undefined) {
      throw new MvxError('The extension root changed before it could be snapshotted', {
        code: 'UNSAFE_INPUT'
      });
    }
    if (expectedRootStat.isSymbolicLink()) {
      throw new MvxError('The extension root may not be a symbolic link', {
        code: 'UNSAFE_INPUT'
      });
    }
  } else if (inputStat.isDirectory()) {
    root = absolute;
    expectedRootStat = inputStat;
  } else {
    throw new MvxError('Input must be an extension directory or manifest.json', {
      code: 'INVALID_INPUT'
    });
  }
  let sourceRoot;
  try {
    sourceRoot = await realpath(root);
  } catch (error) {
    throw new MvxError('The extension root changed before it could be snapshotted', {
      code: 'UNSAFE_INPUT',
      cause: error
    });
  }
  const temporaryParent = await resolvePrivateWorkspaceParent(
    temporaryDirectory ?? os.tmpdir(),
    {
      missingMessage: 'Audit snapshot temporary directory does not exist',
      unsafeMessage: 'Audit snapshot temporary directory must be a real directory',
      changedMessage: 'Audit snapshot temporary directory changed during resolution'
    }
  );
  let rootStat;
  try {
    rootStat = await lstat(sourceRoot, { bigint: true });
  } catch (error) {
    throw new MvxError('The extension root changed before it could be snapshotted', {
      code: 'UNSAFE_INPUT',
      cause: error
    });
  }
  if (!rootStat.isDirectory()
    || rootStat.dev !== expectedRootStat.dev
    || rootStat.ino !== expectedRootStat.ino) {
    throw new MvxError('The extension root changed before it could be snapshotted', {
      code: 'UNSAFE_INPUT'
    });
  }
  const workspace = await createPrivateWorkspace(
    temporaryParent,
    'mvx-audit-input-',
    {
      changedMessage:
        'Audit snapshot temporary directory changed or is inside the extension root',
      cleanupMessage: 'Untrusted audit snapshot workspace cleanup failed',
      cleanupCode: 'AUDIT_SNAPSHOT_CLEANUP_FAILED',
      forbiddenRoot: sourceRoot
    }
  );
  const workspacePath = workspace.path;
  try {
    const snapshot = path.join(workspacePath, 'extension');
    await copyAuditTree(sourceRoot, snapshot, limits, rootStat, workspace);
    await assertPrivateWorkspace(workspace, {
      changedMessage: 'Private audit snapshot workspace changed before analysis'
    });
    return { input: snapshot, location: sourceRoot, workspace };
  } catch (error) {
    const failure = sanitizeSnapshotError(error, workspacePath);
    try {
      await removePrivateWorkspace(workspace, {
        changedMessage: 'Private audit snapshot workspace changed before cleanup',
        cleanupMessage: 'Private audit snapshot workspace cleanup failed',
        cleanupCode: 'AUDIT_SNAPSHOT_CLEANUP_FAILED'
      });
    } catch (cleanupError) {
      const cleanup = sanitizeSnapshotError(cleanupError, workspacePath);
      throw new MvxError(
        `Private audit snapshot cleanup failed after ${failure.code ?? 'copy failure'}: ${cleanup.message}`,
        { code: 'AUDIT_SNAPSHOT_CLEANUP_FAILED' }
      );
    }
    throw failure;
  }
}

async function auditDirectorySnapshot(inputPath, auditOptions, temporaryDirectory) {
  const snapshot = await prepareDirectorySnapshot(
    inputPath,
    temporaryDirectory,
    auditOptions.limits
  );
  let actual;
  let failure;
  try {
    await assertPrivateWorkspace(snapshot.workspace, {
      changedMessage: 'Private audit snapshot workspace changed before analysis'
    });
    actual = await auditExtension(snapshot.input, auditOptions);
  } catch (error) {
    failure = sanitizeSnapshotError(error, snapshot.workspace.path);
  }
  try {
    await removePrivateWorkspace(snapshot.workspace, {
      changedMessage: 'Private audit snapshot workspace changed before cleanup',
      cleanupMessage: 'Private audit snapshot workspace cleanup failed',
      cleanupCode: 'AUDIT_SNAPSHOT_CLEANUP_FAILED'
    });
  } catch (error) {
    const cleanup = sanitizeSnapshotError(error, snapshot.workspace.path);
    throw new MvxError(
      `Private audit snapshot cleanup failed${failure ? ` after ${failure.code ?? 'analysis failure'}` : ''}: ${cleanup.message}`,
      { code: 'AUDIT_SNAPSHOT_CLEANUP_FAILED' }
    );
  }
  if (failure) throw failure;
  return { actual, location: snapshot.location };
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
  const report = parseReport(reportBytes, stable.reportLimits);
  const packed = report.artifact !== undefined;
  const legacySignaturePolicy = packed
    && report.artifact.identityPolicy
    && typeof report.artifact.identityPolicy === 'object'
    && !Object.hasOwn(report.artifact.identityPolicy, 'requireValidSignature');
  if (legacySignaturePolicy) {
    report.artifact.identityPolicy.requireValidSignature = false;
  }
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
  let inputLocation;
  if (packed) {
    actual = await auditExtensionArchive(inputPath, Object.assign(Object.create(null), {
      ...auditOptions,
      temporaryDirectory: stable.temporaryDirectory,
      requireValidSignature:
        report.artifact.identityPolicy?.requireValidSignature ?? false,
      expectedArchiveSha256:
        report.artifact.identityPolicy?.expectedArchiveSha256 ?? undefined,
      expectedExtensionId:
        report.artifact.identityPolicy?.expectedExtensionId ?? undefined,
      _verificationExpectedArchiveSha256: stable.expectedArchiveSha256,
      _verificationExpectedExtensionId: stable.expectedExtensionId,
      _verificationRequireValidSignature: stable.requireValidSignature
    }));
    inputLocation = actual.target.root;
  } else {
    if (stable.expectedArchiveSha256 !== undefined
      || stable.expectedExtensionId !== undefined
      || stable.requireValidSignature !== undefined
      || stable.archiveLimits !== undefined) {
      throw new MvxError('Archive verification options require a packed audit report', {
        code: 'INVALID_ARGUMENT'
      });
    }
    const snapshotAudit = await auditDirectorySnapshot(
      inputPath,
      auditOptions,
      stable.temporaryDirectory
    );
    actual = snapshotAudit.actual;
    inputLocation = snapshotAudit.location;
  }
  actual = normalizeData(actual);
  assertIndependentIdentities(actual, stable);
  if (!isDeepStrictEqual(portableReport(report), portableReport(actual))) {
    throw new MvxError(
      'Audit report does not match deterministic analysis of the supplied input and review data',
      { code: 'AUDIT_REPORT_MISMATCH' }
    );
  }
  const locationMetadataMatchesInput = report.target.root === inputLocation
    && (report.artifact?.path ?? null) === (packed ? inputLocation : null);
  const verifiedAuthenticity = actual.artifact?.authenticity?.status === 'verified';
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
    inputType: packed ? 'archive' : 'directory',
    report: { bytes: reportBytes.length, sha256: reportSha256 },
    identities: {
      packageSha256: actual.package.sha256,
      analysisSha256: actual.analysis.sha256,
      artifactSha256: actual.artifact?.sha256 ?? null,
      authenticityStatus: actual.artifact?.authenticity?.status ?? null,
      extensionId: verifiedAuthenticity
        ? actual.artifact.authenticity.extensionId
        : null,
      developerKeySha256: verifiedAuthenticity
        ? actual.artifact.authenticity.developerKeySha256
        : null
    },
    checks: {
      deterministicReport: true,
      toolVersion: true,
      rulePackProvenance: true,
      dispositionProvenance: true,
      locationMetadataMatchesInput,
      recordedSignatureRequirement: packed
        ? (legacySignaturePolicy ? null : true)
        : null,
      independent: independentChecks
    },
    caveats: [
      'The target.root and packed artifact.path fields are local transport metadata and are excluded from deterministic comparison.',
      ...(Object.values(independentChecks).every((value) => value === null) ? [
        'The report is reproducible from the supplied inputs, but no independently trusted identity was supplied.'
      ] : []),
      ...(legacySignaturePolicy ? [
        'This legacy packed report did not record whether a valid signature was required; verification replayed the historical default (false).'
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
      `CRX authenticity: ${result.identities.authenticityStatus}`,
      ...(result.identities.authenticityStatus === 'verified' ? [
        `Verified extension ID: ${result.identities.extensionId}`,
        `Verified developer key SHA-256: ${result.identities.developerKeySha256}`
      ] : [])
    ] : []),
    ...result.caveats.map((caveat) => `Caveat: ${caveat}`)
  ].join('\n') + '\n';
}
