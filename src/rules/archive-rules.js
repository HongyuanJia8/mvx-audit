import { createFinding } from '../model.js';

const INVALID_CRX_SIGNATURE = Object.freeze({
  id: 'MVX004',
  title: 'CRX signature verification failed',
  severity: 'high',
  confidence: 'high',
  category: 'integrity',
  description: 'The CRX cannot establish archive integrity under its embedded developer key and declared extension ID.',
  remediation: 'Obtain the CRX again from a trusted source, verify its expected extension ID and digest, and do not deploy it unless signature verification succeeds.',
  references: [
    'https://chromium.googlesource.com/chromium/src/+/HEAD/components/crx_file/crx3.proto',
    'https://chromium.googlesource.com/chromium/src/+/HEAD/components/crx_file/crx_verifier.cc'
  ]
});

export function analyzeArchiveAuthenticity(authenticity, format = 'crx') {
  if (format !== 'crx' || !authenticity || authenticity.status === 'verified') return [];
  return [createFinding(INVALID_CRX_SIGNATURE, {
    scope: 'archive',
    field: 'authenticity',
    snippet: authenticity.error ?? authenticity.status
  })];
}
