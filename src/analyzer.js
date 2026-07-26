import { loadExtension } from './io.js';
import { sortFindings, summarizeFindings } from './model.js';
import { analyzeManifest, hostPermissions } from './rules/manifest-rules.js';
import { analyzeSources } from './rules/source-rules.js';
import { createFinding } from './model.js';

function manifestReferences(manifest) {
  const references = [];
  const array = (value) => Array.isArray(value) ? value : [];
  const add = (value, field) => {
    if (typeof value === 'string' && value.length > 0) references.push({ value: value.replace(/^\.?\//, ''), field });
  };
  array(manifest.background?.scripts).forEach((value, index) => add(value, `background.scripts[${index}]`));
  add(manifest.background?.service_worker, 'background.service_worker');
  array(manifest.content_scripts).forEach((script, scriptIndex) => {
    array(script?.js).forEach((value, index) => add(value, `content_scripts[${scriptIndex}].js[${index}]`));
    array(script?.css).forEach((value, index) => add(value, `content_scripts[${scriptIndex}].css[${index}]`));
  });
  for (const [key, action] of Object.entries({ action: manifest.action, browser_action: manifest.browser_action, page_action: manifest.page_action })) {
    add(action?.default_popup, `${key}.default_popup`);
  }
  add(manifest.options_page, 'options_page');
  add(manifest.options_ui?.page, 'options_ui.page');
  add(manifest.devtools_page, 'devtools_page');
  add(manifest.side_panel?.default_path, 'side_panel.default_path');
  Object.entries(manifest.chrome_url_overrides ?? {}).forEach(([key, value]) => add(value, `chrome_url_overrides.${key}`));
  array(manifest.sandbox?.pages).forEach((value, index) => add(value, `sandbox.pages[${index}]`));
  array(manifest.declarative_net_request?.rule_resources).forEach((resource, index) => add(resource?.path, `declarative_net_request.rule_resources[${index}].path`));
  return references;
}

function analyzeIntegrity(manifest, files) {
  const available = new Set(files);
  const missing = manifestReferences(manifest).filter(({ value }) => {
    const segments = value.split('/');
    return segments.includes('..') || !available.has(value);
  });
  if (missing.length === 0) return [];
  return [createFinding({
    id: 'MVX002', title: 'Referenced extension file is missing or unsafe', severity: 'high', confidence: 'high',
    category: 'integrity',
    description: 'The manifest references a file that is absent from the package or escapes the extension root.',
    remediation: 'Add the intended packaged file and use a normalized extension-relative path without parent traversal.',
    references: ['https://developer.chrome.com/docs/extensions/reference/manifest']
  }, missing.map(({ value, field }) => ({ file: 'manifest.json', field, snippet: JSON.stringify(value) })) )];
}

export async function auditExtension(inputPath, options = {}) {
  const snapshot = await loadExtension(inputPath, options.limits);
  const declaredPermissions = [
    ...(Array.isArray(snapshot.manifest.permissions) ? snapshot.manifest.permissions : []),
    ...(Array.isArray(snapshot.manifest.optional_permissions) ? snapshot.manifest.optional_permissions : [])
  ].filter((permission) => typeof permission === 'string' && permission !== '<all_urls>' && !permission.includes('://'));
  const findings = sortFindings([
    ...analyzeIntegrity(snapshot.manifest, snapshot.files),
    ...analyzeManifest(snapshot.manifest, snapshot.sources),
    ...analyzeSources(snapshot.sources)
  ]);
  return {
    schemaVersion: 1,
    tool: { name: 'mvx-audit', version: '3.0.0' },
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
