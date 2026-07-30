import { createHash } from 'node:crypto';

export const FINDING_FINGERPRINT_PROFILE = 'mvx-finding-v1';
export const EVIDENCE_FINGERPRINT_PROFILE = 'mvx-evidence-v1';

function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry ?? null)).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return 'null';
}

function digest(profile, value) {
  return createHash('sha256').update(profile).update('\0').update(canonicalJson(value)).digest('hex');
}

export function findingKey(finding) {
  const key = finding?.fingerprint ?? finding?.id;
  if (typeof key !== 'string' || key.length === 0) throw new TypeError('Finding requires a non-empty fingerprint or rule ID');
  return key;
}

export function findingFingerprint(finding) {
  return digest(FINDING_FINGERPRINT_PROFILE, { fingerprint: findingKey(finding) });
}

export function evidenceFingerprint(finding, evidence) {
  return digest(EVIDENCE_FINGERPRINT_PROFILE, {
    fingerprint: findingKey(finding),
    evidence
  });
}
