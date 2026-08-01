import os from 'node:os';
import path from 'node:path';
import { auditExtension } from './analyzer.js';
import { unpackExtensionArchive } from './archive.js';
import { MvxError } from './errors.js';
import { sortFindings, summarizeFindings } from './model.js';
import { resolveRulePacks } from './rule-packs.js';
import { analyzeArchiveAuthenticity } from './rules/archive-rules.js';
import { applyDispositionPolicies, loadDispositionPolicies, resolveDispositionPolicies } from './disposition-policy.js';
import { assertOptionsObject } from './options.js';
import {
  assertPrivateWorkspace, createPrivateWorkspace, removePrivateWorkspace,
  resolvePrivateWorkspaceParent
} from './private-workspace.js';

function ownDataProperty(value, key) {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
    return undefined;
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

function safeErrorMessage(error) {
  const message = ownDataProperty(error, 'message');
  if (typeof message === 'string') return message;
  if (typeof error === 'string') return error;
  if (error === null) return 'null';
  if (['number', 'boolean', 'bigint', 'undefined', 'symbol'].includes(typeof error)) {
    return String(error);
  }
  return 'Unexpected packed audit failure';
}

function sanitizeTemporaryError(error, workspaces) {
  const rawMessage = safeErrorMessage(error);
  const message = workspaces.reduce(
    (current, workspace) => current.split(workspace).join('<temporary extraction>'),
    rawMessage
  );
  const code = ownDataProperty(error, 'code');
  let mvxError = false;
  try {
    mvxError = error instanceof MvxError;
  } catch {
    mvxError = false;
  }
  if (mvxError) {
    return new MvxError(message, {
      code: typeof code === 'string' ? code : 'MVX_ERROR'
    });
  }
  const sanitized = new Error(message);
  const name = ownDataProperty(error, 'name');
  sanitized.name = typeof name === 'string' ? name : 'Error';
  if (typeof code === 'string') sanitized.code = code;
  return sanitized;
}

export async function auditExtensionArchive(inputPath, options = {}) {
  assertOptionsObject(options, 'Packed audit');
  const expectedExtensionIdIfVerified =
    Object.getOwnPropertyDescriptor(options, '_expectedExtensionIdIfVerified')?.value;
  const expectedDeveloperKeySha256IfVerified =
    Object.getOwnPropertyDescriptor(options, '_expectedDeveloperKeySha256IfVerified')?.value;
  const verificationExpectedArchiveSha256 =
    Object.getOwnPropertyDescriptor(options, '_verificationExpectedArchiveSha256')?.value;
  const verificationExpectedExtensionId =
    Object.getOwnPropertyDescriptor(options, '_verificationExpectedExtensionId')?.value;
  const verificationRequireValidSignature =
    Object.getOwnPropertyDescriptor(options, '_verificationRequireValidSignature')?.value;
  const preparedRulePacks = await resolveRulePacks(options);
  const preparedDispositionPolicies = await resolveDispositionPolicies(options);
  const emptyDispositionPolicies = await loadDispositionPolicies([], {
    evaluationTime: preparedDispositionPolicies.evaluationTime
  });
  const requestedTemporaryParent = path.resolve(options.temporaryDirectory ?? os.tmpdir());
  const temporaryParent = await resolvePrivateWorkspaceParent(
    options.temporaryDirectory ?? os.tmpdir(),
    {
      missingMessage: `Temporary directory does not exist: ${requestedTemporaryParent}`,
      unsafeMessage: 'Temporary directory must be a real directory',
      changedMessage: 'Temporary directory changed during resolution'
    }
  );
  const workspaceRecord = await createPrivateWorkspace(
    temporaryParent,
    'mvx-packed-audit-',
    {
      changedMessage: 'Temporary directory changed during workspace creation',
      cleanupMessage: 'Temporary workspace cleanup failed during creation'
    }
  );
  const workspace = workspaceRecord.path;
  const workspaceAliases = [
    workspace,
    path.join(requestedTemporaryParent, path.basename(workspace))
  ];
  let result;
  let failure;
  let failed = false;
  try {
    await assertPrivateWorkspace(workspaceRecord, {
      changedMessage: 'Temporary workspace changed before packed audit'
    });
    const extracted = path.join(workspace, 'extension');
    const archive = await unpackExtensionArchive(inputPath, extracted, {
      limits: options.archiveLimits,
      requireValidSignature: options.requireValidSignature,
      expectedArchiveSha256: options.expectedArchiveSha256,
      expectedExtensionId: options.expectedExtensionId,
      _expectedExtensionIdIfVerified: expectedExtensionIdIfVerified,
      _expectedDeveloperKeySha256IfVerified: expectedDeveloperKeySha256IfVerified,
      _verificationExpectedArchiveSha256: verificationExpectedArchiveSha256,
      _verificationExpectedExtensionId: verificationExpectedExtensionId,
      _verificationRequireValidSignature: verificationRequireValidSignature
    });
    await assertPrivateWorkspace(workspaceRecord, {
      changedMessage: 'Temporary workspace changed after archive extraction'
    });
    const audit = await auditExtension(extracted, {
      limits: options.limits,
      dnrRuleLimits: options.dnrRuleLimits,
      _preparedRulePacks: preparedRulePacks,
      _preparedDispositionPolicies: emptyDispositionPolicies
    });
    const findings = sortFindings([
      ...audit.findings,
      ...analyzeArchiveAuthenticity(archive.authenticity, archive.archiveFormat)
    ]);
    const dispositions = applyDispositionPolicies(findings, {
      packageSha256: audit.package.sha256,
      analysisSha256: audit.analysis.sha256,
      artifactSha256: archive.archiveSha256
    }, preparedDispositionPolicies);
    const dispositionPoliciesApplied = preparedDispositionPolicies.summary.policies > 0;
    result = {
      ...audit,
      summary: summarizeFindings(findings),
      ...(dispositionPoliciesApplied ? {
        dispositionPolicies: preparedDispositionPolicies.provenance,
        dispositionEvaluation: dispositions.evaluation,
        reviewSummary: dispositions.reviewSummary
      } : {}),
      findings: dispositionPoliciesApplied ? dispositions.findings : findings,
      scan: {
        ...audit.scan,
        ...(dispositionPoliciesApplied ? {
          dispositionPoliciesApplied: preparedDispositionPolicies.summary.policies
        } : {})
      },
      target: { ...audit.target, root: archive.input, inputType: 'archive' },
      artifact: {
        kind: 'extension-archive',
        path: archive.input,
        format: archive.archiveFormat,
        crxVersion: archive.crxVersion,
        bytes: archive.archiveBytes,
        sha256: archive.archiveSha256,
        authenticity: archive.authenticity,
        identityPolicy: archive.identityPolicy,
        extraction: {
          entries: archive.entries,
          files: archive.files,
          uncompressedBytes: archive.uncompressedBytes
        }
      },
      assumptions: [
        ...audit.assumptions,
        ...(dispositionPoliciesApplied ? [
          'Disposition policies are analyst-supplied review metadata: original findings and raw risk summary remain authoritative and visible.'
        ] : []),
        ...(archive.identityPolicy.matched ? [
          'All analyst-supplied archive identity expectations matched before extraction; their trust still depends on the external source that supplied them.'
        ] : []),
        ...(archive.authenticity.status === 'verified' ? [
          'CRX signature verification proves archive integrity under the embedded developer key and extension ID; it does not prove publisher identity, Web Store authorization, or benign behavior.'
        ] : archive.archiveFormat === 'crx' ? [
          'CRX authenticity was not established; analysis continued only for forensic inspection of the contained files.'
        ] : [
          'ZIP packages do not carry a CRX developer signature, so CRX authenticity verification is not applicable.'
        ]),
        'The archive was defensively extracted into a private temporary directory, statically audited, and removed without executing extension code.'
      ]
    };
  } catch (error) {
    failed = true;
    failure = error;
  }
  try {
    await removePrivateWorkspace(workspaceRecord, {
      changedMessage: 'Temporary workspace changed before cleanup',
      cleanupMessage: 'Temporary workspace cleanup failed'
    });
  } catch (error) {
    const cleanupFailure = sanitizeTemporaryError(error, workspaceAliases);
    const sanitizedFailure = failed
      ? sanitizeTemporaryError(failure, workspaceAliases)
      : null;
    const originalCode = sanitizedFailure?.code ?? null;
    const reported = new MvxError(
      `Temporary extraction cleanup failed${originalCode ? ` after ${originalCode}` : ''}: ${cleanupFailure.message}`,
      { code: 'TEMP_CLEANUP_FAILED', cause: cleanupFailure }
    );
    if (originalCode) reported.originalCode = originalCode;
    throw reported;
  }
  if (failed) throw sanitizeTemporaryError(failure, workspaceAliases);
  return result;
}
