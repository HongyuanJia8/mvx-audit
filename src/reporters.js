import path from 'node:path';
import { evidenceFingerprint, findingFingerprint, findingKey } from './fingerprints.js';

const UNSAFE_DISPLAY = /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u2028-\u202e\u2066-\u2069]/g;

function escapeText(value) {
  return String(value).replace(UNSAFE_DISPLAY, (character) => {
    return `\\u${character.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
  });
}

function escapeMarkdown(value) {
  return escapeText(value).replace(/\\/g, '\\\\').replace(/([`*_[\]<>])/g, '\\$1');
}

function escapeMarkdownCell(value) {
  return escapeMarkdown(value).replace(/\|/g, '\\|');
}

function sarifUri(value) {
  const unreserved = (byte) => (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
    || (byte >= 48 && byte <= 57) || [45, 46, 95, 126].includes(byte);
  return String(value).split('/').map((segment) => [...Buffer.from(segment, 'utf8')]
    .map((byte) => unreserved(byte) ? String.fromCharCode(byte) : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`)
    .join('')).join('/');
}

export function auditToText(result) {
  const lines = [
    `${escapeText(result.target.name ?? path.basename(result.target.root))} (Manifest V${result.target.manifestVersion ?? '?'})`,
    `Risk: ${result.summary.rating} (${result.summary.riskScore}/100), ${result.summary.total} finding(s)`,
    ...(result.reviewSummary ? [
      `Unreviewed risk: ${result.reviewSummary.rating} (${result.reviewSummary.riskScore}/100), ${result.reviewSummary.total} finding(s)`,
      `Disposition policies: ${result.dispositionEvaluation.policies}; matched entries: ${result.dispositionEvaluation.matchedEntries}/${result.dispositionEvaluation.identityEntries}; unused: ${result.dispositionEvaluation.unusedIdentityEntries}; active: ${result.dispositionEvaluation.activeFindings}; expired: ${result.dispositionEvaluation.expiredFindings}; evaluated: ${result.dispositionEvaluation.evaluatedAt}`
    ] : []),
    `Scanned: ${result.scan.sourceFilesScanned} source file(s), ${result.scan.sourceBytesScanned} bytes`,
    ...(result.package ? [
      `Package (${result.package.profile}): ${result.package.fileCount} file(s), ${result.package.totalBytes} bytes, SHA-256: ${result.package.sha256}`
    ] : []),
    ...(result.encodedPayloads ? [
      `Encoded payloads (${result.encodedPayloads.profile}): ${result.encodedPayloads.decodedCount} decoded, ${result.encodedPayloads.totalDecodedBytes} bytes, SHA-256: ${result.encodedPayloads.sha256}`
    ] : []),
    ...(result.dnrRules ? [
      `Static DNR rules (${result.dnrRules.profile}): ${result.dnrRules.totals.rulesets} ruleset(s), ${result.dnrRules.totals.rules} rule(s), ${result.dnrRules.totals.invalidRulesets} invalid ruleset(s), ${result.dnrRules.totals.invalidRules} invalid rule(s), SHA-256: ${result.dnrRules.sha256}`
    ] : []),
    ...(result.rulePacks?.length ? [`Rule packs: ${result.rulePacks.length} (${result.rulePacks.map((pack) => `${escapeText(pack.namespace)}@${escapeText(pack.version)}`).join(', ')})`] : []),
    ...(result.dispositionPolicies?.length ? [
      `Disposition policy provenance: ${result.dispositionPolicies.length}`,
      ...result.dispositionPolicies.map((policy) => `  ${escapeText(policy.policyId)}@${escapeText(policy.version)}: ${policy.bytes} bytes, SHA-256 ${policy.sha256}, ${policy.entries} entry/entries`)
    ] : []),
    ...(result.artifact ? [
      `Archive (${result.artifact.format === 'crx' ? `CRX${result.artifact.crxVersion}` : result.artifact.format.toUpperCase()}) SHA-256: ${result.artifact.sha256}`,
      ...(result.artifact.authenticity?.status === 'verified' ? [
        `Authenticity: VERIFIED (${escapeText(result.artifact.authenticity.extensionId)}, ${result.artifact.authenticity.proofs.length} proof(s))`
      ] : result.artifact.authenticity?.status === 'invalid' ? [
        `Authenticity: INVALID (${escapeText(result.artifact.authenticity.error)})`
      ] : result.artifact.authenticity?.status === 'not-applicable' ? [
        'Authenticity: not applicable (ZIP has no CRX signature)'
      ] : []),
      ...(result.artifact.identityPolicy?.matched ? [
        `Identity policy: MATCHED (${[
          ...(result.artifact.identityPolicy.archiveSha256Match ? ['archive SHA-256'] : []),
          ...(result.artifact.identityPolicy.extensionIdMatch ? ['extension ID'] : [])
        ].join(', ')})`
      ] : [])
    ] : []),
    ...(result.analysis ? [`Analysis (${result.analysis.profile}) SHA-256: ${result.analysis.sha256}`] : []),
    ''
  ];
  if (result.findings.length === 0) lines.push('No supported risk patterns were detected. This is not a guarantee of safety.');
  for (const finding of result.findings) {
    lines.push(`[${finding.severity.toUpperCase()}] ${escapeText(finding.id)} ${escapeText(finding.title)}`);
    lines.push(`  Fingerprint: ${escapeText(findingKey(finding))}`);
    lines.push(`  ${escapeText(finding.description)}`);
    for (const item of finding.evidence) {
      const location = escapeText(item.file ?? item.scope ?? 'package');
      const decodedDetail = item.decodedFrom
        ? ` [decoded depth ${item.decodedFrom.depth}, encoded line ${item.decodedFrom.encodedLine}, decoded line ${item.decodedLine}, SHA-256 ${item.decodedFrom.sha256}]`
        : item.decodedSha256
          ? ` [${escapeText(item.encoding)} depth ${item.depth}, encoded line ${item.encodedLine}, ${item.decodedBytes} bytes, SHA-256 ${item.decodedSha256}]`
          : '';
      lines.push(`  at ${location}${item.line ? `:${item.line}` : ''}${item.field ? ` (${escapeText(item.field)})` : ''}${decodedDetail}`);
    }
    if (finding.disposition) {
      lines.push(`  Disposition: ${finding.disposition.status.toUpperCase()} ${escapeText(finding.disposition.disposition)} by ${escapeText(finding.disposition.owner)} until ${finding.disposition.expiresAt}`);
      lines.push(`  Justification: ${escapeText(finding.disposition.justification)}`);
      lines.push(`  Policy: ${escapeText(finding.disposition.policyId)}@${escapeText(finding.disposition.policyVersion)} SHA-256: ${finding.disposition.policySha256}`);
      if (finding.disposition.ticketUrl) lines.push(`  Ticket: ${escapeText(finding.disposition.ticketUrl)}`);
    }
    lines.push(`  Fix: ${escapeText(finding.remediation)}`, '');
  }
  for (const warning of result.scan.warnings) lines.push(`Warning: ${escapeText(warning)}`);
  return `${lines.join('\n').trimEnd()}\n`;
}

export function auditToSarif(result) {
  const uniqueRules = [...new Map(result.findings.map((finding) => [finding.id, finding])).values()];
  const runProperties = {
    ...(result.analysis ? { analysis: result.analysis } : {}),
    ...(result.package ? { package: result.package } : {}),
    ...(result.encodedPayloads ? { encodedPayloads: result.encodedPayloads } : {}),
    ...(result.dnrRules ? { dnrRules: result.dnrRules } : {}),
    ...(result.rulePacks?.length ? { rulePacks: result.rulePacks } : {}),
    ...(result.dispositionPolicies?.length ? {
      dispositionPolicies: result.dispositionPolicies,
      dispositionEvaluation: result.dispositionEvaluation,
      reviewSummary: result.reviewSummary
    } : {}),
    ...(result.artifact ? { artifact: result.artifact } : {})
  };
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: result.tool.name,
        version: result.tool.version,
        informationUri: 'https://github.com/hyj28/mvx-audit',
        rules: uniqueRules.map((finding) => ({
          id: finding.id,
          name: finding.title.replace(/[^A-Za-z0-9]+/g, '') || finding.id.replace(/[^A-Za-z0-9]+/g, '') || 'Rule',
          shortDescription: { text: finding.title },
          fullDescription: { text: finding.description },
          help: { text: finding.remediation, markdown: `${escapeMarkdown(finding.remediation)}\n\n${finding.references.map((url) => `- ${escapeMarkdown(url)}`).join('\n')}` },
          defaultConfiguration: { level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : finding.severity === 'medium' ? 'warning' : 'note' }
        }))
      } },
      results: result.findings.flatMap((finding) => finding.evidence.map((item) => ({
        ruleId: finding.id,
        level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : finding.severity === 'medium' ? 'warning' : 'note',
        message: { text: finding.description },
        partialFingerprints: {
          'mvxFinding/v1': findingFingerprint(finding),
          'mvxEvidence/v1': evidenceFingerprint(finding, item)
        },
        ...(item.file ? { locations: [{ physicalLocation: {
          artifactLocation: { uri: sarifUri(item.file) },
          ...(item.line ? { region: { startLine: item.line } } : {})
        } }] } : {}),
        properties: {
          severity: finding.severity,
          confidence: finding.confidence,
          category: finding.category,
          fingerprint: findingKey(finding),
          ...(finding.disposition ? { disposition: finding.disposition } : {}),
          ...(finding.rulePack ? { rulePack: finding.rulePack } : {}),
          ...(finding.condition ? { condition: finding.condition } : {}),
          ...(item.decodedFrom ? {
            decodedFrom: item.decodedFrom,
            decodedLine: item.decodedLine
          } : {}),
          ...(item.decodedSha256 ? {
            decodedSha256: item.decodedSha256,
            decodedBytes: item.decodedBytes,
            encodedLine: item.encodedLine,
            encoding: item.encoding,
            depth: item.depth,
            utf8: item.utf8
          } : {}),
          ...(item.rulesetId ? {
            dnrRule: {
              rulesetId: item.rulesetId,
              rulesetEnabled: item.rulesetEnabled,
              ...(item.ruleId !== undefined ? { ruleId: item.ruleId } : {}),
              ...(item.action ? { action: item.action } : {}),
              ...(item.reason ? { reason: item.reason } : {})
            }
          } : {})
        }
      }))),
      ...(Object.keys(runProperties).length > 0 ? { properties: runProperties } : {})
    }]
  };
}

function comparisonFindingToMarkdown(finding) {
  const disposition = finding.disposition;
  return `- \`${escapeMarkdown(findingKey(finding))}\`: ${escapeMarkdown(finding.title)}${disposition
    ? ` — disposition **${disposition.status.toUpperCase()} ${escapeMarkdown(disposition.disposition)}** via ${escapeMarkdown(disposition.policyId)}@${escapeMarkdown(disposition.policyVersion)} (SHA-256 \`${disposition.policySha256}\`)`
    : ''}`;
}

function policyProvenanceToMarkdown(label, result) {
  return [
    `### ${label}`, '',
    `- Evaluated at: \`${result.dispositionEvaluation.evaluatedAt}\``,
    `- Matched entries: ${result.dispositionEvaluation.matchedEntries}/${result.dispositionEvaluation.identityEntries}`,
    `- Active findings: ${result.dispositionEvaluation.activeFindings}`,
    `- Expired findings: ${result.dispositionEvaluation.expiredFindings}`,
    `- Unused identity entries: ${result.dispositionEvaluation.unusedIdentityEntries}`,
    '- Policies:',
    ...result.dispositionPolicies.map((policy) =>
      `  - ${escapeMarkdown(policy.policyId)}@${escapeMarkdown(policy.version)}: ${policy.bytes} bytes, SHA-256 \`${policy.sha256}\`, ${policy.entries} entry/entries`)
  ];
}

function archiveIdentityToMarkdown(artifact) {
  const authenticity = artifact.authenticity;
  if (authenticity.status === 'verified') {
    return `VERIFIED ${escapeMarkdown(authenticity.extensionId)}`;
  }
  if (authenticity.status === 'invalid') return `INVALID ${escapeMarkdown(authenticity.error)}`;
  return 'not applicable';
}

function developerKeyToMarkdown(artifact) {
  const digest = artifact.authenticity.developerKeySha256;
  return digest ? `\`${digest}\`` : 'not verified';
}

function packageEntryToMarkdown(entry) {
  return `${escapeMarkdown(entry.path)} — ${escapeMarkdown(entry.type)}${entry.type === 'file'
    ? `, ${entry.bytes} bytes, SHA-256 \`${entry.sha256}\``
    : ''}`;
}

function modifiedEntryToMarkdown(entry) {
  const before = entry.before.type === 'file' ? `${entry.before.bytes} bytes, ${entry.before.sha256}` : entry.before.type;
  const after = entry.after.type === 'file' ? `${entry.after.bytes} bytes, ${entry.after.sha256}` : entry.after.type;
  return `${escapeMarkdown(entry.path)} — ${entry.change}: ${escapeMarkdown(before)} → ${escapeMarkdown(after)}`;
}

export function comparisonToMarkdown(comparison) {
  const { before, after, delta } = comparison;
  const lines = [
    '# Extension security comparison', '',
    `| Metric | Before (MV${escapeMarkdownCell(before.target.manifestVersion)}) | After (MV${escapeMarkdownCell(after.target.manifestVersion)}) |`,
    '|---|---:|---:|',
    `| Extension version | ${escapeMarkdownCell(before.target.version ?? 'unknown')} | ${escapeMarkdownCell(after.target.version ?? 'unknown')} |`,
    `| Risk score | ${before.summary.riskScore} | ${after.summary.riskScore} |`,
    ...(before.reviewSummary && after.reviewSummary ? [
      `| Unreviewed risk score | ${before.reviewSummary.riskScore} | ${after.reviewSummary.riskScore} |`,
      `| Unreviewed findings | ${before.reviewSummary.total} | ${after.reviewSummary.total} |`
    ] : []),
    `| Critical | ${before.summary.counts.critical} | ${after.summary.counts.critical} |`,
    `| High | ${before.summary.counts.high} | ${after.summary.counts.high} |`,
    `| Total findings | ${before.summary.total} | ${after.summary.total} |`,
    ...(before.rulePacks && after.rulePacks ? [`| Rule packs | ${before.rulePacks.length} | ${after.rulePacks.length} |`] : []),
    ...(before.package && after.package ? [`| Package SHA-256 | \`${before.package.sha256}\` | \`${after.package.sha256}\` |`] : []),
    ...(before.encodedPayloads && after.encodedPayloads ? [
      `| Encoded payloads decoded | ${before.encodedPayloads.decodedCount} | ${after.encodedPayloads.decodedCount} |`
    ] : []),
    ...(before.dnrRules && after.dnrRules ? [
      `| Static DNR rules | ${before.dnrRules.totals.rules} | ${after.dnrRules.totals.rules} |`,
      `| Invalid DNR rulesets/rules | ${before.dnrRules.totals.invalidRulesets}/${before.dnrRules.totals.invalidRules} | ${after.dnrRules.totals.invalidRulesets}/${after.dnrRules.totals.invalidRules} |`
    ] : []),
    ...(before.analysis && after.analysis ? [`| Analysis SHA-256 | \`${before.analysis.sha256}\` | \`${after.analysis.sha256}\` |`] : []),
    ...(before.artifact && after.artifact ? [
      `| Archive SHA-256 | \`${before.artifact.sha256}\` | \`${after.artifact.sha256}\` |`,
      `| Archive format | ${before.artifact.format === 'crx' ? `CRX${before.artifact.crxVersion}` : 'ZIP'} | ${after.artifact.format === 'crx' ? `CRX${after.artifact.crxVersion}` : 'ZIP'} |`,
      `| Archive authenticity | ${archiveIdentityToMarkdown(before.artifact)} | ${archiveIdentityToMarkdown(after.artifact)} |`,
      `| Developer key SHA-256 | ${developerKeyToMarkdown(before.artifact)} | ${developerKeyToMarkdown(after.artifact)} |`
    ] : []), '',
    ...(comparison.archiveContinuity ? [
      '## Archive identity continuity', '',
      `- Status: **${comparison.archiveContinuity.status.toUpperCase()}**`,
      `- Strict same-extension requirement: ${comparison.archiveContinuity.required ? 'yes' : 'no'}`,
      `- Same verified extension ID: ${comparison.archiveContinuity.sameExtensionId === null ? 'unverifiable' : comparison.archiveContinuity.sameExtensionId ? 'yes' : 'no'}`,
      `- Same verified developer key: ${comparison.archiveContinuity.sameDeveloperKey === null ? 'unverifiable' : comparison.archiveContinuity.sameDeveloperKey ? 'yes' : 'no'}`,
      `- Same archive bytes: ${comparison.archiveContinuity.sameArchiveBytes ? 'yes' : 'no'}`,
      `- Same extracted package: ${comparison.archiveContinuity.samePackage ? 'yes' : 'no'}`, ''
    ] : []),
    ...(comparison.packageDelta ? [
      '## Package entry changes', '',
      `- Added entries: ${comparison.packageDelta.summary.entries.added}`,
      `- Removed entries: ${comparison.packageDelta.summary.entries.removed}`,
      `- Modified entries: ${comparison.packageDelta.summary.entries.modified}`,
      `- Unchanged entries: ${comparison.packageDelta.summary.entries.unchanged}`,
      `- Regular files: ${comparison.packageDelta.summary.files.before} → ${comparison.packageDelta.summary.files.after}`,
      `- Package bytes: ${comparison.packageDelta.summary.bytes.before} → ${comparison.packageDelta.summary.bytes.after} (${comparison.packageDelta.summary.bytes.delta >= 0 ? '+' : ''}${comparison.packageDelta.summary.bytes.delta})`,
      ...(comparison.packageDelta.added.length ? [
        '', 'Added:', ...comparison.packageDelta.added.map((entry) => `- ${packageEntryToMarkdown(entry)}`)
      ] : []),
      ...(comparison.packageDelta.removed.length ? [
        '', 'Removed:', ...comparison.packageDelta.removed.map((entry) => `- ${packageEntryToMarkdown(entry)}`)
      ] : []),
      ...(comparison.packageDelta.modified.length ? [
        '', 'Modified:', ...comparison.packageDelta.modified.map((entry) => `- ${modifiedEntryToMarkdown(entry)}`)
      ] : []), ''
    ] : []),
    ...(before.dispositionEvaluation && after.dispositionEvaluation ? [
      '## Disposition policy provenance', '',
      ...policyProvenanceToMarkdown('Before', before), '',
      ...policyProvenanceToMarkdown('After', after), ''
    ] : []),
    `Risk score delta: ${delta.riskScore >= 0 ? '+' : ''}${delta.riskScore}`, '',
    ...(delta.unreviewedRiskScore !== undefined ? [
      `Unreviewed risk score delta: ${delta.unreviewedRiskScore >= 0 ? '+' : ''}${delta.unreviewedRiskScore}`, ''
    ] : []),
    '## Resolved findings', '',
    ...(delta.resolvedFindings.length ? delta.resolvedFindings.map(comparisonFindingToMarkdown) : ['- None']), '',
    '## Introduced findings', '',
    ...(delta.introducedFindings.length ? delta.introducedFindings.map(comparisonFindingToMarkdown) : ['- None']), '',
    '## Evidence changes', '',
    `- Added locations: ${delta.evidenceAdded.length}`,
    `- Removed locations: ${delta.evidenceRemoved.length}`,
    `- Total occurrence delta: ${delta.evidenceCount.delta >= 0 ? '+' : ''}${delta.evidenceCount.delta}`,
    ...(delta.evidenceAdded.length ? ['', 'New evidence:', ...delta.evidenceAdded.map((item) => {
      const location = item.evidence.file ?? item.evidence.scope ?? 'package';
      return `- ${escapeMarkdown(item.findingId)}: ${escapeMarkdown(location)}${item.evidence.line ? `:${item.evidence.line}` : ''}`;
    })] : []), '',
    '## Permission changes', '',
    `- Added: ${delta.permissionsAdded.map(escapeMarkdown).join(', ') || 'none'}`,
    `- Removed: ${delta.permissionsRemoved.map(escapeMarkdown).join(', ') || 'none'}`,
    `- Hosts added: ${delta.hostsAdded.map(escapeMarkdown).join(', ') || 'none'}`,
    `- Hosts removed: ${delta.hostsRemoved.map(escapeMarkdown).join(', ') || 'none'}`, '',
    ...(comparison.archiveContinuity ? [
      '> Verified key continuity does not prove publisher identity, Web Store authorization, or benign behavior.', ''
    ] : []),
    '> Static comparison measures declared capability and supported code patterns. It does not prove exploitability or benign intent.', ''
  ];
  return lines.join('\n');
}
