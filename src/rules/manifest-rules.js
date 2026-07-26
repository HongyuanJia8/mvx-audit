import { CONFIDENCE, REFERENCES, createFinding } from '../model.js';

const URL_PATTERN = /^(?:\*|https?|file|ftp):\/\//;
const BROAD_HOST_PATTERNS = new Set(['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']);

const SENSITIVE_PERMISSIONS = Object.freeze({
  debugger: ['critical', 'Control the Chrome DevTools Protocol'],
  nativeMessaging: ['high', 'Communicate with native applications'],
  proxy: ['high', 'Control browser proxy settings'],
  management: ['high', 'Manage other installed extensions'],
  history: ['high', 'Read or modify browsing history'],
  clipboardRead: ['high', 'Read clipboard contents'],
  cookies: ['high', 'Read or modify cookies for granted hosts'],
  downloads: ['medium', 'Create and inspect downloads'],
  privacy: ['medium', 'Change privacy-related browser settings'],
  tabs: ['medium', 'Read sensitive tab metadata when host access is available'],
  webNavigation: ['medium', 'Observe navigation across granted hosts']
});

function evidence(field, value) {
  return { file: 'manifest.json', field, snippet: JSON.stringify(value) };
}

function isBroadExternalMatch(match) {
  return match === '<all_urls>' || match.startsWith('*://') || /^[a-z]+:\/\/\*\./.test(match) || /^[a-z]+:\/\/\*\//.test(match);
}

function hasUnsafeExtensionCsp(csp) {
  const directives = new Map();
  for (const rawDirective of csp.split(';')) {
    const [rawName, ...rawTokens] = rawDirective.trim().split(/\s+/);
    if (!rawName) continue;
    const name = rawName.toLowerCase();
    if (!directives.has(name)) directives.set(name, rawTokens.map((token) => token.toLowerCase()));
  }
  const fallback = directives.get('default-src') ?? [];
  const script = directives.get('script-src') ?? fallback;
  const object = directives.get('object-src') ?? fallback;
  const worker = directives.get('worker-src') ?? directives.get('child-src') ?? script;
  const isUnsafe = (tokens) => tokens.some((token) =>
    token === "'unsafe-eval'" || token === "'unsafe-inline'" || token === '*' || /^(?:https?:|data:|blob:|filesystem:)/.test(token)
  );
  return [script, object, worker].some(isUnsafe);
}

function permissionLists(manifest) {
  const permissions = Array.isArray(manifest.permissions) ? manifest.permissions : [];
  const optional = Array.isArray(manifest.optional_permissions) ? manifest.optional_permissions : [];
  return [...new Set([...permissions, ...optional].filter((item) => typeof item === 'string'))];
}

export function hostPermissions(manifest) {
  const explicit = [
    ...(Array.isArray(manifest.host_permissions) ? manifest.host_permissions : []),
    ...(Array.isArray(manifest.optional_host_permissions) ? manifest.optional_host_permissions : [])
  ];
  const legacy = permissionLists(manifest).filter((permission) => URL_PATTERN.test(permission) || permission === '<all_urls>');
  return [...new Set([...explicit, ...legacy].filter((item) => typeof item === 'string'))].sort();
}

function rule(id, title, severity, category, description, remediation, references, confidence) {
  return { id, title, severity, category, description, remediation, references, confidence };
}

export function analyzeManifest(manifest, sources = []) {
  const findings = [];
  const version = manifest.manifest_version;
  const permissions = permissionLists(manifest);
  const hosts = hostPermissions(manifest);
  const broadHosts = hosts.filter((host) => BROAD_HOST_PATTERNS.has(host));

  if (![2, 3].includes(version)) {
    findings.push(createFinding(rule(
      'MVX001', 'Unsupported or missing manifest version', 'critical', 'compatibility',
      'Chrome extension manifests must declare a supported manifest version.',
      'Declare manifest_version 3. Use MV2 only in an isolated historical test environment.', [REFERENCES.mv3]
    ), evidence('manifest_version', version)));
  }

  if (broadHosts.length > 0) {
    findings.push(createFinding(rule(
      'MVX101', 'Broad host access', 'high', 'permissions',
      'The extension can access data on every site covered by a broad match pattern.',
      'Use exact HTTPS origins, activeTab, or optional host permissions.', [REFERENCES.permissions, REFERENCES.privacy]
    ), evidence('host_permissions', broadHosts)));
  }

  for (const permission of permissions) {
    const descriptor = SENSITIVE_PERMISSIONS[permission];
    if (!descriptor) continue;
    findings.push(createFinding(rule(
      'MVX102', `Sensitive permission: ${permission}`, descriptor[0], 'permissions', descriptor[1],
      'Remove the permission if it is not essential; otherwise request it at the narrowest possible scope and document the trust boundary.',
      [REFERENCES.permissions, REFERENCES.privacy]
    ), evidence('permissions', permission), { fingerprint: `MVX102:${permission}` }));
  }

  if (permissions.includes('cookies') && broadHosts.length > 0) {
    findings.push(createFinding(rule(
      'MVX103', 'Broad cookie access', 'critical', 'capability-chain',
      'The cookies permission combined with global host access can expose authentication material across many sites.',
      'Limit host access to the minimum set of origins and avoid transmitting cookie values.', [REFERENCES.privacy]
    ), [evidence('permissions', 'cookies'), evidence('host_permissions', broadHosts)]));
  }

  const contentScripts = Array.isArray(manifest.content_scripts) ? manifest.content_scripts : [];
  contentScripts.forEach((script, index) => {
    const matches = Array.isArray(script.matches) ? script.matches : [];
    if (matches.some((match) => BROAD_HOST_PATTERNS.has(match))) {
      findings.push(createFinding(rule(
        'MVX104', 'Content script injected broadly', 'high', 'content-scripts',
        'A content script runs in pages across a global set of origins, increasing exposure to hostile page content.',
        'Narrow matches and exclude sensitive origins. Keep privileged operations in the service worker.', [REFERENCES.security]
      ), evidence(`content_scripts[${index}].matches`, matches), { fingerprint: `MVX104:${index}` }));
    }
    if (script.all_frames === true) {
      findings.push(createFinding(rule(
        'MVX105', 'Content script runs in every frame', 'medium', 'content-scripts',
        'all_frames expands execution into matching subframes and increases the number of untrusted contexts.',
        'Use top-frame execution unless subframe access is required and tested.', [REFERENCES.security]
      ), evidence(`content_scripts[${index}].all_frames`, true), { fingerprint: `MVX105:${index}` }));
    }
    if (script.world === 'MAIN') {
      findings.push(createFinding(rule(
        'MVX106', 'Content script uses the page main world', 'high', 'content-scripts',
        'MAIN-world scripts share the JavaScript environment with untrusted page code.',
        'Prefer the default isolated world and use narrowly validated messaging when page interaction is unavoidable.', [REFERENCES.security]
      ), evidence(`content_scripts[${index}].world`, 'MAIN'), { fingerprint: `MVX106:${index}` }));
    }
  });

  const csp = typeof manifest.content_security_policy === 'string'
    ? manifest.content_security_policy
    : manifest.content_security_policy?.extension_pages;
  if (typeof csp === 'string' && hasUnsafeExtensionCsp(csp)) {
    findings.push(createFinding(rule(
      'MVX107', 'Extension CSP permits unsafe code sources', 'critical', 'code-execution',
      'The extension page CSP contains a dynamic or remote code source.',
      "Restrict extension pages to script-src 'self'; object-src 'self' and bundle all executable code.", [REFERENCES.csp, REFERENCES.remoteCode]
    ), evidence('content_security_policy', csp)));
  }

  const external = manifest.externally_connectable;
  const externalIds = Array.isArray(external?.ids) ? external.ids : [];
  const externalMatches = Array.isArray(external?.matches) ? external.matches : [];
  if (external && (externalIds.includes('*') || externalMatches.some(isBroadExternalMatch))) {
    findings.push(createFinding(rule(
      'MVX108', 'Broad external messaging surface', 'high', 'messaging',
      'A wide set of websites or extensions can initiate messages to this extension.',
      'Allowlist exact senders and validate sender.id, sender.origin, message shape, and requested action.', [REFERENCES.messaging]
    ), evidence('externally_connectable', external)));
  }

  const resources = Array.isArray(manifest.web_accessible_resources) ? manifest.web_accessible_resources : [];
  const broadResource = version === 2
    ? resources.some((resource) => typeof resource === 'string' && resource.includes('*'))
    : resources.some((entry) => entry?.resources?.some((resource) => resource.includes('*')) || entry?.matches?.some((match) => BROAD_HOST_PATTERNS.has(match)));
  if (broadResource) {
    findings.push(createFinding(rule(
      'MVX109', 'Broad web-accessible resources', 'medium', 'exposure',
      'Wildcard resource exposure can aid extension fingerprinting or expose attackable extension pages.',
      'Expose only required files to exact origins and enable use_dynamic_url where appropriate.', [REFERENCES.webResources]
    ), evidence('web_accessible_resources', resources)));
  }

  if (permissions.includes('webRequestBlocking')) {
    findings.push(createFinding(rule(
      'MVX110', 'Blocking webRequest capability', version === 3 ? 'critical' : 'high', 'network-control',
      version === 3 ? 'webRequestBlocking is unavailable to most MV3 extensions.' : 'Blocking webRequest handlers can observe and modify traffic synchronously.',
      'Use narrowly scoped declarativeNetRequest rules; policy-installed enterprise extensions are a documented exception.', [REFERENCES.webRequest, REFERENCES.dnr]
    ), evidence('permissions', 'webRequestBlocking')));
  }

  const insecureHosts = hosts.filter((host) => host.startsWith('http://'));
  if (insecureHosts.length > 0) {
    findings.push(createFinding(rule(
      'MVX111', 'Unencrypted host permission', 'medium', 'transport',
      'HTTP host access permits data exchange over a transport vulnerable to network modification.',
      'Use HTTPS-only host permissions outside an explicitly isolated localhost lab.', [REFERENCES.security]
    ), evidence('host_permissions', insecureHosts)));
  }

  if (version === 3 && manifest.background?.scripts) {
    findings.push(createFinding(rule(
      'MVX112', 'MV2 background scripts declared in MV3', 'high', 'compatibility',
      'MV3 uses a single extension service worker and does not accept background.scripts.',
      'Migrate background logic to background.service_worker and make state event-driven.', [REFERENCES.mv3]
    ), evidence('background.scripts', manifest.background.scripts)));
  }

  const ruleResources = Array.isArray(manifest.declarative_net_request?.rule_resources) ? manifest.declarative_net_request.rule_resources : [];
  const dnrPaths = new Set(ruleResources.map((resource) => resource?.path).filter(Boolean));
  const dnrEvidence = sources
    .filter((source) => dnrPaths.has(source.path) && /"type"\s*:\s*"modifyHeaders"/.test(source.content))
    .map((source) => ({ file: source.path, line: source.content.slice(0, source.content.search(/"type"\s*:\s*"modifyHeaders"/)).split('\n').length, snippet: '"type": "modifyHeaders"' }));
  if (dnrEvidence.length > 0) {
    findings.push(createFinding(rule(
      'MVX113', 'Declarative header modification rules', 'high', 'network-control',
      'Declarative Net Request rules can add, remove, or set selected request and response headers.',
      'Constrain urlFilter, resourceTypes, initiatorDomains, and header operations to the minimum required scope.', [REFERENCES.dnr]
    ), dnrEvidence));
  }

  return findings;
}
