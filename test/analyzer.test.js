import assert from 'node:assert/strict';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { MvxError } from '../src/errors.js';
import { writeExtension } from '../support/helpers.js';

const ROOT = path.resolve('corpus/fixtures');

test('a minimal MV3 manifest produces no supported findings', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-clean-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Clean fixture', version: '1.0.0' });
  const result = await auditExtension(temp);
  assert.equal(result.summary.total, 0);
  assert.equal(result.summary.riskScore, 0);
  assert.equal(result.summary.rating, 'clean');
});

test('cookie capability chain is detected in both manifest and source', async () => {
  const result = await auditExtension(path.join(ROOT, 'cookie-access/mv3'));
  assert.deepEqual(result.findings.map((finding) => finding.id), ['MVX103', 'MVX101', 'MVX102', 'MVX206']);
  assert.equal(result.findings.find((finding) => finding.id === 'MVX206').evidence[0].line, 2);
  assert.deepEqual(result.capabilities.hostPermissions, ['<all_urls>']);
});

test('multiple source patterns retain deterministic evidence locations', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-source-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Source fixture', version: '1.0.0' }, {
    'a.js': "const node = document.body;\nnode.innerHTML = value;\n",
    'b.js': "window.postMessage({ ready: true }, '*');\n"
  });
  const result = await auditExtension(temp);
  assert.equal(result.findings.find((finding) => finding.id === 'MVX203').evidence[0].line, 2);
  assert.equal(result.findings.find((finding) => finding.id === 'MVX204').evidence[0].file, 'b.js');
});

test('invalid manifest JSON returns a typed error', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-json-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeFile(path.join(temp, 'manifest.json'), '{broken', 'utf8');
  await assert.rejects(() => auditExtension(temp), (error) => error instanceof MvxError && error.code === 'INVALID_MANIFEST');
});

test('symbolic links are skipped and reported', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-link-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Link fixture', version: '1.0.0' });
  await symlink('/etc/hosts', path.join(temp, 'linked.js'));
  const result = await auditExtension(temp);
  assert.match(result.scan.warnings[0], /Skipped symbolic link/);
  assert.equal(result.scan.sourceFilesScanned, 0);
});

test('scan byte limits fail closed', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-limit-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Limit fixture', version: '1.0.0' }, { 'large.js': 'x'.repeat(20) });
  await assert.rejects(() => auditExtension(temp, { limits: { maxFileBytes: 10 } }), (error) => error.code === 'SCAN_LIMIT');
});

test('oversized supported source fails closed instead of returning clean', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-source-limit-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Large source fixture', version: '1.0.0' }, {
    'evil.js': `eval(payload);\n${'x'.repeat(1_000)}`
  });
  await assert.rejects(
    () => auditExtension(temp, { limits: { maxFileBytes: 512 } }),
    (error) => error.code === 'SCAN_LIMIT' && /evil\.js/.test(error.message)
  );
});

test('loopback HTTP does not trigger the public insecure endpoint source rule', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-loopback-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Loopback fixture', version: '1.0.0' }, { 'fixture.js': "fetch('http://127.0.0.1:8080/test');\n" });
  const result = await auditExtension(temp);
  assert.equal(result.findings.some((finding) => finding.id === 'MVX207'), false);
});

test('MV3 compatibility and exposure rules are reported together', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-manifest-rules-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Manifest rules fixture',
    version: '1.0.0',
    permissions: ['webRequestBlocking'],
    host_permissions: ['http://insecure.example.invalid/*'],
    background: { scripts: ['legacy.js'] },
    externally_connectable: { ids: ['*'] },
    content_scripts: [{ matches: ['https://example.invalid/*'], js: ['content.js'], world: 'MAIN' }],
    web_accessible_resources: [{ resources: ['assets/*'], matches: ['<all_urls>'] }]
  }, { 'legacy.js': '', 'content.js': '' });
  const result = await auditExtension(temp);
  const ids = new Set(result.findings.map((finding) => finding.id));
  for (const id of ['MVX106', 'MVX108', 'MVX109', 'MVX110', 'MVX111', 'MVX112']) assert.ok(ids.has(id), id);
  assert.equal(result.findings.find((finding) => finding.id === 'MVX110').severity, 'critical');
});

test('unsupported manifest versions produce a critical finding instead of a crash', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-version-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 4, name: 'Future fixture', version: '1.0.0' });
  const result = await auditExtension(temp);
  assert.equal(result.findings[0].id, 'MVX001');
  assert.equal(result.findings[0].severity, 'critical');
});

test('a direct manifest.json path is accepted', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-file-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'File fixture', version: '1.0.0' });
  const result = await auditExtension(path.join(temp, 'manifest.json'));
  assert.equal(result.target.name, 'File fixture');
});

test('missing manifest file references produce an integrity finding', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-missing-ref-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Missing reference fixture',
    version: '1.0.0',
    background: { service_worker: 'missing.js' }
  });
  const result = await auditExtension(temp);
  assert.equal(result.findings[0].id, 'MVX002');
  assert.equal(result.findings[0].evidence[0].field, 'background.service_worker');
});

test('data-only CSP origins, exact external matches, and image sources avoid code-execution findings', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-negative-rules-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Negative fixture',
    version: '1.0.0',
    content_security_policy: { extension_pages: "default-src https://api.example.invalid; script-src 'self'; object-src 'none'; connect-src https://api.example.invalid" },
    externally_connectable: { matches: ['https://app.example.invalid/*'] }
  }, {
    'image.js': "const image = document.createElement('img');\nimage.src = 'https://cdn.example.invalid/image.png';\n",
    'unused.json': '{"type":"modifyHeaders"}\n'
  });
  const ids = new Set((await auditExtension(temp)).findings.map((finding) => finding.id));
  assert.equal(ids.has('MVX107'), false);
  assert.equal(ids.has('MVX108'), false);
  assert.equal(ids.has('MVX113'), false);
  assert.equal(ids.has('MVX202'), false);
});

test('effective worker CSP sources are checked after directive fallback', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-worker-csp-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Worker CSP fixture',
    version: '1.0.0',
    content_security_policy: { extension_pages: "default-src 'self'; script-src 'self'; object-src 'none'; worker-src https://worker.example.invalid" }
  });
  const result = await auditExtension(temp);
  assert.ok(result.findings.some((finding) => finding.id === 'MVX107'));
});

test('packaged source inside vendor directories is not skipped', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-vendor-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Vendor fixture', version: '1.0.0' }, {
    'vendor/dynamic.js': 'new Function(sourceText);\n'
  });
  const result = await auditExtension(temp);
  assert.ok(result.findings.some((finding) => finding.id === 'MVX201'));
});
