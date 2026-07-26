import { loadExtension } from './io.js';
import { sortFindings, summarizeFindings } from './model.js';
import { analyzeManifest, hostPermissions } from './rules/manifest-rules.js';
import { analyzeSources } from './rules/source-rules.js';

export async function auditExtension(inputPath, options = {}) {
  const snapshot = await loadExtension(inputPath, options.limits);
  const declaredPermissions = [
    ...(Array.isArray(snapshot.manifest.permissions) ? snapshot.manifest.permissions : []),
    ...(Array.isArray(snapshot.manifest.optional_permissions) ? snapshot.manifest.optional_permissions : [])
  ].filter((permission) => typeof permission === 'string' && permission !== '<all_urls>' && !permission.includes('://'));
  const findings = sortFindings([
    ...analyzeManifest(snapshot.manifest, snapshot.sources),
    ...analyzeSources(snapshot.sources)
  ]);
  return {
    schemaVersion: 1,
    tool: { name: 'mvx-audit', version: '2.0.0' },
    target: {
      root: snapshot.root,
      name: snapshot.manifest.name ?? null,
      version: snapshot.manifest.version ?? null,
      manifestVersion: snapshot.manifest.manifest_version ?? null
    },
    summary: summarizeFindings(findings),
    capabilities: {
      permissions: [...new Set(declaredPermissions)].sort(),
      hostPermissions: hostPermissions(snapshot.manifest)
    },
    findings,
    scan: snapshot.metadata,
    assumptions: [
      'Static findings describe capability and suspicious implementation patterns, not proof of malicious intent.',
      'Absence of a finding is not proof that an extension is safe.',
      'Manifest V3 reduces selected attack surfaces but does not make granted privileges harmless.'
    ]
  };
}
