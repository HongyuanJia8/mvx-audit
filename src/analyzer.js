import { loadExtension } from './io.js';
import { sortFindings, summarizeFindings } from './model.js';
import { analyzeManifest, hostPermissions } from './rules/manifest-rules.js';
import { analyzeSources } from './rules/source-rules.js';
import { analyzePackage } from './rules/package-rules.js';
import { analyzeCustomRules } from './rules/custom-rules.js';
import { resolveRulePacks } from './rule-packs.js';
import { createFinding } from './model.js';
import { applyDispositionPolicies, resolveDispositionPolicies } from './disposition-policy.js';
import { analyzeEncodedPayloads } from './encoded-payloads.js';
import { assertOptionsObject } from './options.js';
import { VERSION } from './version.js';

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
  assertOptionsObject(options, 'Audit');
  const preparedRulePacks = await resolveRulePacks(options);
  const preparedDispositionPolicies = await resolveDispositionPolicies(options);
  const snapshot = await loadExtension(inputPath, options.limits, {
    rulePacks: preparedRulePacks.provenance,
    rulePackLimits: preparedRulePacks.limits
  });
  const declaredPermissions = [
    ...(Array.isArray(snapshot.manifest.permissions) ? snapshot.manifest.permissions : []),
    ...(Array.isArray(snapshot.manifest.optional_permissions) ? snapshot.manifest.optional_permissions : [])
  ].filter((permission) => typeof permission === 'string' && permission !== '<all_urls>' && !permission.includes('://'));
  const findings = sortFindings([
    ...analyzeIntegrity(snapshot.manifest, snapshot.files),
    ...analyzePackage(snapshot.executableFiles),
    ...analyzeManifest(snapshot.manifest, snapshot.sources),
    ...analyzeSources([...snapshot.sources, ...snapshot.decodedSources]),
    ...analyzeEncodedPayloads(snapshot.encodedPayloads),
    ...analyzeCustomRules(snapshot, preparedRulePacks)
  ]);
  const dispositions = applyDispositionPolicies(findings, {
    packageSha256: snapshot.inventory.sha256,
    analysisSha256: snapshot.provenance.sha256,
    artifactSha256: null
  }, preparedDispositionPolicies);
  const dispositionPoliciesApplied = preparedDispositionPolicies.summary.policies > 0;
  return {
    schemaVersion: 1,
    tool: { name: 'mvx-audit', version: VERSION },
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
    analysis: snapshot.provenance,
    package: snapshot.inventory,
    encodedPayloads: {
      profile: snapshot.encodedPayloads.profile,
      parserProfiles: snapshot.encodedPayloads.parserProfiles,
      browserEventHandlerProfile: snapshot.encodedPayloads.browserEventHandlerProfile,
      limits: snapshot.encodedPayloads.limits,
      candidates: snapshot.encodedPayloads.candidates,
      candidateEncodedChars: snapshot.encodedPayloads.candidateEncodedChars,
      parserTokens: snapshot.encodedPayloads.parserTokens,
      astNodes: snapshot.encodedPayloads.astNodes,
      htmlTokens: snapshot.encodedPayloads.htmlTokens,
      htmlAttributes: snapshot.encodedPayloads.htmlAttributes,
      htmlNodes: snapshot.encodedPayloads.htmlNodes,
      htmlTreeWork: snapshot.encodedPayloads.htmlTreeWork,
      htmlMaxDepth: snapshot.encodedPayloads.htmlMaxDepth,
      htmlMaxDocumentDepth: snapshot.encodedPayloads.htmlMaxDocumentDepth,
      htmlNestedChars: snapshot.encodedPayloads.htmlNestedChars,
      xmlEntityDeclarations: snapshot.encodedPayloads.xmlEntityDeclarations,
      xmlExpandedChars: snapshot.encodedPayloads.xmlExpandedChars,
      decodedCount: snapshot.encodedPayloads.decodedCount,
      utf8Count: snapshot.encodedPayloads.utf8Count,
      totalDecodedBytes: snapshot.encodedPayloads.totalDecodedBytes,
      entries: snapshot.encodedPayloads.entries,
      sha256: snapshot.encodedPayloads.sha256
    },
    rulePacks: preparedRulePacks.provenance,
    ...(dispositionPoliciesApplied ? {
      dispositionPolicies: preparedDispositionPolicies.provenance,
      dispositionEvaluation: dispositions.evaluation,
      reviewSummary: dispositions.reviewSummary
    } : {}),
    findings: dispositionPoliciesApplied ? dispositions.findings : findings,
    scan: {
      ...snapshot.metadata,
      rulePacksApplied: preparedRulePacks.summary.packs,
      customRulesApplied: preparedRulePacks.summary.rules,
      customIndicatorsApplied: preparedRulePacks.summary.indicators,
      ...(dispositionPoliciesApplied ? { dispositionPoliciesApplied: preparedDispositionPolicies.summary.policies } : {})
    },
    assumptions: [
      'Static findings describe capability and suspicious implementation patterns, not proof of malicious intent.',
      'Absence of a finding is not proof that an extension is safe.',
      'Manifest V3 reduces selected attack surfaces but does not make granted privileges harmless.',
      'Literal Base64 decoding is bounded static evidence; it does not execute code or fully deobfuscate dynamic behavior.',
      ...(preparedRulePacks.packs.length > 0 ? [
        'Analyst-supplied declarative rule-pack matches are review indicators, not proof of malicious intent.'
      ] : []),
      ...(dispositionPoliciesApplied ? [
        'Disposition policies are analyst-supplied review metadata: original findings and raw risk summary remain authoritative and visible.'
      ] : [])
    ]
  };
}
