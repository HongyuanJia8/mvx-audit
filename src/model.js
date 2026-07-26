export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_WEIGHT = Object.freeze({
  critical: 25,
  high: 12,
  medium: 6,
  low: 2,
  info: 0
});

export const CONFIDENCE = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low' });

export const REFERENCES = Object.freeze({
  mv3: 'https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3',
  permissions: 'https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions',
  privacy: 'https://developer.chrome.com/docs/extensions/develop/security-privacy/user-privacy',
  security: 'https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure',
  messaging: 'https://developer.chrome.com/docs/extensions/develop/concepts/messaging',
  csp: 'https://developer.chrome.com/docs/extensions/develop/migrate/improve-security',
  webRequest: 'https://developer.chrome.com/docs/extensions/reference/api/webRequest',
  dnr: 'https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest',
  webResources: 'https://developer.chrome.com/docs/extensions/reference/manifest/web-accessible-resources',
  remoteCode: 'https://developer.chrome.com/docs/extensions/develop/migrate/remote-hosted-code',
  mv2Timeline: 'https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline'
});

export function createFinding(rule, evidence, overrides = {}) {
  return Object.freeze({
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    confidence: rule.confidence ?? CONFIDENCE.HIGH,
    category: rule.category,
    description: rule.description,
    remediation: rule.remediation,
    references: rule.references ?? [],
    evidence: Array.isArray(evidence) ? evidence : [evidence],
    ...overrides
  });
}

export function sortFindings(findings) {
  const order = new Map(SEVERITIES.map((severity, index) => [severity, index]));
  return [...findings].sort((left, right) => {
    const severity = order.get(left.severity) - order.get(right.severity);
    if (severity !== 0) return severity;
    const id = left.id.localeCompare(right.id);
    if (id !== 0) return id;
    const leftEvidence = left.evidence[0] ?? {};
    const rightEvidence = right.evidence[0] ?? {};
    return `${leftEvidence.file}:${leftEvidence.line ?? 0}`.localeCompare(
      `${rightEvidence.file}:${rightEvidence.line ?? 0}`
    );
  });
}

export function summarizeFindings(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  let score = 0;
  for (const finding of findings) {
    counts[finding.severity] += 1;
    score += SEVERITY_WEIGHT[finding.severity];
  }
  score = Math.min(100, score);
  const rating = score >= 70 ? 'critical' : score >= 40 ? 'high' : score >= 20 ? 'medium' : score > 0 ? 'low' : 'clean';
  return { total: findings.length, counts, riskScore: score, rating };
}

