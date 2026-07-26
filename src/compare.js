import { auditExtension } from './analyzer.js';

function findingKey(finding) {
  return finding.fingerprint ?? finding.id;
}

function difference(left, right) {
  const rightSet = new Set(right);
  return left.filter((item) => !rightSet.has(item));
}

export async function compareExtensions(beforePath, afterPath, options = {}) {
  const [before, after] = await Promise.all([
    auditExtension(beforePath, options),
    auditExtension(afterPath, options)
  ]);
  const beforeMap = new Map(before.findings.map((finding) => [findingKey(finding), finding]));
  const afterMap = new Map(after.findings.map((finding) => [findingKey(finding), finding]));
  const resolved = [...beforeMap.keys()].filter((key) => !afterMap.has(key)).map((key) => beforeMap.get(key));
  const introduced = [...afterMap.keys()].filter((key) => !beforeMap.has(key)).map((key) => afterMap.get(key));
  const beforePermissions = before.capabilities.permissions;
  const afterPermissions = after.capabilities.permissions;
  return {
    schemaVersion: 1,
    tool: before.tool,
    before,
    after,
    delta: {
      riskScore: after.summary.riskScore - before.summary.riskScore,
      resolvedFindings: resolved,
      introducedFindings: introduced,
      permissionsAdded: difference(afterPermissions, beforePermissions),
      permissionsRemoved: difference(beforePermissions, afterPermissions),
      hostsAdded: difference(after.capabilities.hostPermissions, before.capabilities.hostPermissions),
      hostsRemoved: difference(before.capabilities.hostPermissions, after.capabilities.hostPermissions)
    },
    interpretation: [
      'A resolved static finding may reflect an API or syntax migration rather than removal of the underlying user-data capability.',
      'Compare permission scope and source behavior together; manifest version alone is not a security verdict.'
    ]
  };
}

