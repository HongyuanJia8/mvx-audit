export { auditExtension } from './analyzer.js';
export {
  AUDIT_VERIFICATION_PROFILE, DEFAULT_AUDIT_VERIFICATION_LIMITS,
  auditVerificationToText, verifyAuditReport
} from './audit-verification.js';
export { auditExtensionArchive } from './packed-audit.js';
export { unpackCrx, unpackExtensionArchive } from './archive.js';
export { runStaticBenchmark, staticBenchmarkToText } from './benchmark.js';
export {
  ARCHIVE_CONTINUITY_PROFILE, PACKAGE_DELTA_PROFILE,
  compareExtensionArchives, compareExtensions
} from './compare.js';
export {
  COMPARISON_VERIFICATION_PROFILE, DEFAULT_COMPARISON_VERIFICATION_LIMITS,
  comparisonVerificationToText, verifyComparisonReport
} from './comparison-verification.js';
export {
  DEFAULT_DISPOSITION_POLICY_LIMITS, applyDispositionPolicies, dispositionPoliciesToText,
  loadDispositionPolicies
} from './disposition-policy.js';
export { loadCatalog, validateCatalog } from './catalog.js';
export { loadIntelCatalog, lookupIntel, validateIntelCatalog } from './intelligence.js';
export {
  DEFAULT_LAB_EVIDENCE_LIMITS, LAB_EVALUATION_PROFILE, LAB_EVIDENCE_PROFILE,
  LAB_EXECUTION_PROFILE, LAB_VERIFICATION_PROFILE, evaluateLabFiles, evaluateLabRun,
  labReportToText, labVerificationToText, loadLabScenario, parseLabEvents,
  verifyLabReport, VERDICTS
} from './lab.js';
export {
  EVIDENCE_FINGERPRINT_PROFILE, FINDING_FINGERPRINT_PROFILE, FINGERPRINT_LIMITS,
  evidenceFingerprint, findingFingerprint, findingKey
} from './fingerprints.js';
export { fetchSample, fetchSampleBatch, planSample, planSampleBatch } from './quarantine.js';
export { loadRulePacks, rulePacksToText } from './rule-packs.js';
export { auditToSarif, auditToText, comparisonToMarkdown } from './reporters.js';
export { MvxError } from './errors.js';
export {
  ENCODED_PAYLOAD_LIMITS, ENCODED_PAYLOAD_PARSER_PROFILES,
  ENCODED_PAYLOAD_PROFILE
} from './encoded-payloads.js';
export {
  BROWSER_EVENT_HANDLER_PROFILE, BROWSER_EVENT_HANDLER_PROVENANCE,
  BODY_EVENT_HANDLER_ATTRIBUTES, FRAMESET_EVENT_HANDLER_ATTRIBUTES,
  HTML_EVENT_HANDLER_ATTRIBUTES, SVG_EVENT_HANDLER_ATTRIBUTES
} from './browser-event-handlers.js';
