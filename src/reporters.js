import path from 'node:path';

function escapeMarkdown(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/([`*_[\]<>])/g, '\\$1');
}

export function auditToText(result) {
  const lines = [
    `${result.target.name ?? path.basename(result.target.root)} (Manifest V${result.target.manifestVersion ?? '?'})`,
    `Risk: ${result.summary.rating} (${result.summary.riskScore}/100), ${result.summary.total} finding(s)`,
    `Scanned: ${result.scan.sourceFilesScanned} source file(s), ${result.scan.sourceBytesScanned} bytes`,
    ...(result.package ? [
      `Package (${result.package.profile}): ${result.package.fileCount} file(s), ${result.package.totalBytes} bytes, SHA-256: ${result.package.sha256}`
    ] : []),
    ...(result.rulePacks?.length ? [`Rule packs: ${result.rulePacks.length} (${result.rulePacks.map((pack) => `${pack.namespace}@${pack.version}`).join(', ')})`] : []),
    ...(result.artifact ? [
      `Archive (${result.artifact.format === 'crx' ? `CRX${result.artifact.crxVersion}` : result.artifact.format.toUpperCase()}) SHA-256: ${result.artifact.sha256}`
    ] : []),
    ...(result.analysis ? [`Analysis (${result.analysis.profile}) SHA-256: ${result.analysis.sha256}`] : []),
    ''
  ];
  if (result.findings.length === 0) lines.push('No supported risk patterns were detected. This is not a guarantee of safety.');
  for (const finding of result.findings) {
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.id} ${finding.title}`);
    lines.push(`  ${finding.description}`);
    for (const item of finding.evidence) {
      lines.push(`  at ${item.file ?? item.scope ?? 'package'}${item.line ? `:${item.line}` : ''}${item.field ? ` (${item.field})` : ''}`);
    }
    lines.push(`  Fix: ${finding.remediation}`, '');
  }
  for (const warning of result.scan.warnings) lines.push(`Warning: ${warning}`);
  return `${lines.join('\n').trimEnd()}\n`;
}

export function auditToSarif(result) {
  const uniqueRules = [...new Map(result.findings.map((finding) => [finding.id, finding])).values()];
  const runProperties = {
    ...(result.analysis ? { analysis: result.analysis } : {}),
    ...(result.package ? { package: result.package } : {}),
    ...(result.rulePacks?.length ? { rulePacks: result.rulePacks } : {}),
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
          name: finding.title.replace(/[^A-Za-z0-9]+/g, ''),
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
        ...(item.file ? { locations: [{ physicalLocation: {
          artifactLocation: { uri: item.file },
          ...(item.line ? { region: { startLine: item.line } } : {})
        } }] } : {}),
        properties: {
          severity: finding.severity,
          confidence: finding.confidence,
          category: finding.category,
          ...(finding.rulePack ? { rulePack: finding.rulePack } : {}),
          ...(finding.condition ? { condition: finding.condition } : {})
        }
      }))),
      ...(Object.keys(runProperties).length > 0 ? { properties: runProperties } : {})
    }]
  };
}

export function comparisonToMarkdown(comparison) {
  const { before, after, delta } = comparison;
  const lines = [
    '# Extension security comparison', '',
    `| Metric | Before (MV${before.target.manifestVersion}) | After (MV${after.target.manifestVersion}) |`,
    '|---|---:|---:|',
    `| Risk score | ${before.summary.riskScore} | ${after.summary.riskScore} |`,
    `| Critical | ${before.summary.counts.critical} | ${after.summary.counts.critical} |`,
    `| High | ${before.summary.counts.high} | ${after.summary.counts.high} |`,
    `| Total findings | ${before.summary.total} | ${after.summary.total} |`,
    ...(before.rulePacks && after.rulePacks ? [`| Rule packs | ${before.rulePacks.length} | ${after.rulePacks.length} |`] : []),
    ...(before.package && after.package ? [`| Package SHA-256 | \`${before.package.sha256}\` | \`${after.package.sha256}\` |`] : []),
    ...(before.analysis && after.analysis ? [`| Analysis SHA-256 | \`${before.analysis.sha256}\` | \`${after.analysis.sha256}\` |`] : []), '',
    `Risk score delta: ${delta.riskScore >= 0 ? '+' : ''}${delta.riskScore}`, '',
    '## Resolved findings', '',
    ...(delta.resolvedFindings.length ? delta.resolvedFindings.map((finding) => `- ${escapeMarkdown(finding.id)}: ${escapeMarkdown(finding.title)}`) : ['- None']), '',
    '## Introduced findings', '',
    ...(delta.introducedFindings.length ? delta.introducedFindings.map((finding) => `- ${escapeMarkdown(finding.id)}: ${escapeMarkdown(finding.title)}`) : ['- None']), '',
    '## Evidence changes', '',
    `- Added locations: ${delta.evidenceAdded.length}`,
    `- Removed locations: ${delta.evidenceRemoved.length}`,
    `- Total occurrence delta: ${delta.evidenceCount.delta >= 0 ? '+' : ''}${delta.evidenceCount.delta}`,
    ...(delta.evidenceAdded.length ? ['', 'New evidence:', ...delta.evidenceAdded.map((item) => {
      const location = item.evidence.file ?? item.evidence.scope ?? 'package';
      return `- ${escapeMarkdown(item.findingId)}: ${escapeMarkdown(location)}${item.evidence.line ? `:${item.evidence.line}` : ''}`;
    })] : []), '',
    '## Permission changes', '',
    `- Added: ${delta.permissionsAdded.join(', ') || 'none'}`,
    `- Removed: ${delta.permissionsRemoved.join(', ') || 'none'}`,
    `- Hosts added: ${delta.hostsAdded.join(', ') || 'none'}`,
    `- Hosts removed: ${delta.hostsRemoved.join(', ') || 'none'}`, '',
    '> Static comparison measures declared capability and supported code patterns. It does not prove exploitability or benign intent.', ''
  ];
  return lines.join('\n');
}
