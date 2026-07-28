import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateLabRun, parseLabEvents } from '../src/lab.js';

const scenario = {
  schemaVersion: 1,
  id: 'credential-test',
  targetUrl: 'https://accounts.example.test/login',
  canaries: {
    credentialPassword: 'mvx-password-123456',
    sessionCookie: 'mvx-session-12345678'
  }
};
const event = (type, data = {}) => ({ schemaVersion: 1, timestamp: '2026-01-02T03:04:05.000Z', type, data });

test('canary in a blocked external request is a confirmed contained attack', () => {
  const report = evaluateLabRun(scenario, [
    event('lab.started', { canaries: scenario.canaries }),
    event('network.request', {
      url: 'https://collector.evil.invalid/ingest',
      method: 'POST',
      postData: `password=${scenario.canaries.credentialPassword}`,
      headers: {},
      disposition: 'blocked-external'
    }),
    event('lab.completed')
  ]);
  assert.equal(report.verdict, 'confirmed_attack');
  assert.equal(report.contained, true);
  assert.equal(report.objectives.credentialPassword.status, 'confirmed');
  assert.equal(report.summary.blockedExternalRequests, 1);
});

test('external request without a canary is suspicious rather than confirmed', () => {
  const report = evaluateLabRun(scenario, [
    event('network.request', { url: 'https://telemetry.evil.invalid/ping', method: 'GET', headers: {}, disposition: 'blocked-external' }),
    event('lab.completed')
  ]);
  assert.equal(report.verdict, 'suspicious_activity');
  assert.equal(report.summary.confirmedObjectives, 0);
});

test('extension-initiated same-origin canary exfiltration is still confirmed', () => {
  const report = evaluateLabRun(scenario, [
    event('network.request', {
      url: 'https://accounts.example.test/extension-collector',
      method: 'POST',
      postData: scenario.canaries.credentialPassword,
      headers: {},
      initiator: 'extension',
      disposition: 'blocked-external'
    }),
    event('lab.completed')
  ]);
  assert.equal(report.verdict, 'confirmed_attack');
  assert.equal(report.contained, true);
  assert.equal(report.objectives.credentialPassword.status, 'confirmed');
});

test('setup events containing canaries cannot create false attack evidence', () => {
  const report = evaluateLabRun(scenario, [
    event('lab.started', { canaries: scenario.canaries }),
    event('extension.loaded', { extensionId: 'abcdefghijklmnopabcdefghijklmnop', targetType: 'service_worker' }),
    event('lab.completed')
  ]);
  assert.equal(report.verdict, 'no_trigger_observed');
});

test('protected DOM changes and extension navigation are confirmed objectives', () => {
  const report = evaluateLabRun(scenario, [
    event('dom.mutation', { protectedCanaryChanged: true, details: 'login form replaced' }),
    event('navigation.attempt', { from: scenario.targetUrl, to: 'https://search-hijack.invalid/', initiator: 'extension' }),
    event('lab.completed')
  ]);
  assert.equal(report.verdict, 'confirmed_attack');
  assert.equal(report.objectives.contentManipulation.status, 'confirmed');
  assert.equal(report.objectives.navigationHijack.status, 'confirmed');
});

test('collection errors without completion are inconclusive', () => {
  const report = evaluateLabRun(scenario, [event('lab.error', { message: 'browser terminated' })]);
  assert.equal(report.verdict, 'inconclusive');
  assert.equal(report.summary.errors, 1);
});

test('event parser rejects malformed schemas and scenario rejects weak canaries', () => {
  assert.throws(() => parseLabEvents('{bad\n'), (error) => error.code === 'INVALID_LAB_EVENTS');
  assert.throws(() => evaluateLabRun({ ...scenario, canaries: { weak: 'short' } }, [event('lab.completed')]),
    (error) => error.code === 'INVALID_LAB_SCENARIO');
});

test('uncontained canary delivery and unauthorized downloads are confirmed', () => {
  const report = evaluateLabRun(scenario, [
    event('network.request', { url: `https://evil.invalid/?token=${scenario.canaries.sessionCookie}`, disposition: 'fulfilled' }),
    event('download.attempt', { url: 'https://evil.invalid/dropper', userGesture: false }),
    event('lab.completed')
  ]);
  assert.equal(report.verdict, 'confirmed_attack');
  assert.equal(report.contained, false);
  assert.equal(report.objectives.unauthorizedDownload.status, 'confirmed');
});

test('user-initiated-looking downloads remain suspicious instead of confirmed', () => {
  const report = evaluateLabRun(scenario, [event('download.attempt', { url: 'https://example.test/file', userGesture: true }), event('lab.completed')]);
  assert.equal(report.verdict, 'suspicious_activity');
  assert.equal(report.objectives.unauthorizedDownload.status, 'observed');
});

test('scenario and event structural errors fail closed', () => {
  for (const invalid of [null, [], { ...scenario, schemaVersion: 2 }, { ...scenario, id: 'Bad ID' }, { ...scenario, targetUrl: 'http://example.test' }, { ...scenario, canaries: [] }]) {
    assert.throws(() => evaluateLabRun(invalid, []), (error) => error.code === 'INVALID_LAB_SCENARIO');
  }
  for (const invalidEvent of [
    null,
    { ...event('lab.completed'), schemaVersion: 2 },
    { ...event('lab.completed'), type: 'unknown' },
    { ...event('lab.completed'), timestamp: 'never' },
    { ...event('lab.completed'), data: [] }
  ]) assert.throws(() => evaluateLabRun(scenario, [invalidEvent]), (error) => error.code === 'INVALID_LAB_EVENTS');
});
