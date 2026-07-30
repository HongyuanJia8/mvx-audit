import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
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
  assert.match(result.analysis.sha256, /^[a-f0-9]{64}$/);
  assert.match(result.analysis.manifest.sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.analysis.profile, 'mvx-static-v3');
  assert.deepEqual(result.analysis.sources, []);
  assert.equal(result.package.profile, 'mvx-package-v1');
  assert.equal(result.package.fileCount, 1);
  assert.equal(result.package.entries[0].path, 'manifest.json');
  assert.equal(result.analysis.packageSha256, result.package.sha256);
  assert.equal(result.scan.limits.maxFiles, 5_000);
  assert.equal(result.scan.limits.maxPackageBytes, 250_000_000);
});

test('analysis provenance is path-independent and changes with analyzed bytes or package layout', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-provenance-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const first = await writeExtension(path.join(temp, 'first'), {
    manifest_version: 3, name: 'Provenance fixture', version: '1.0.0'
  }, { 'worker.js': 'eval(payload);\n', 'a.js': '', 'a/nested.js': '', 'asset.bin': 'first' });
  const second = path.join(temp, 'second');
  await cp(first, second, { recursive: true });

  const firstAudit = await auditExtension(first);
  const copiedAudit = await auditExtension(second);
  assert.equal(firstAudit.analysis.sha256, copiedAudit.analysis.sha256);
  assert.equal(firstAudit.package.sha256, copiedAudit.package.sha256);
  assert.deepEqual(firstAudit.package.entries.map((entry) => entry.path), [
    'a', 'a.js', 'a/nested.js', 'asset.bin', 'manifest.json', 'worker.js'
  ]);
  assert.equal(firstAudit.package.fileCount, 5);
  assert.equal(firstAudit.scan.packageFilesHashed, 5);
  assert.equal(firstAudit.scan.packageBytesHashed, firstAudit.package.totalBytes);
  assert.deepEqual(firstAudit.analysis.sources.map((source) => source.path), ['a.js', 'a/nested.js', 'worker.js']);
  const worker = firstAudit.analysis.sources.find((source) => source.path === 'worker.js');
  assert.equal(worker.bytes, 15);
  assert.equal(worker.sha256, 'f00a3e7d1e2d4a745f37410abd100285afa2dca484d071f080745274b7a8aeab');

  await writeFile(path.join(second, 'asset.bin'), 'different unparsed bytes', 'utf8');
  const changedBinary = await auditExtension(second);
  assert.notEqual(changedBinary.package.sha256, firstAudit.package.sha256);
  assert.notEqual(changedBinary.analysis.sha256, firstAudit.analysis.sha256);
  assert.equal(changedBinary.analysis.sources.find((source) => source.path === 'worker.js').sha256, worker.sha256);

  const differentLimits = await auditExtension(second, { limits: { maxFiles: 4_999 } });
  assert.notEqual(differentLimits.analysis.sha256, changedBinary.analysis.sha256);
  const orderedLimits = await auditExtension(second, { limits: { maxFiles: 4_999, maxEntries: 9_999 } });
  const reversedLimits = await auditExtension(second, { limits: { maxEntries: 9_999, maxFiles: 4_999 } });
  assert.equal(orderedLimits.analysis.sha256, reversedLimits.analysis.sha256);
  await assert.rejects(
    () => auditExtension(second, { limits: { ignoredLimit: 1 } }),
    (error) => error.code === 'INVALID_ARGUMENT' && /Unknown scan limit/.test(error.message)
  );
  await assert.rejects(
    () => auditExtension(second, { limits: { maxFiles: '5000' } }),
    (error) => error.code === 'INVALID_ARGUMENT' && /positive safe integer/.test(error.message)
  );

  await writeFile(path.join(second, 'worker.js'), 'eval(changedPayload);\n', 'utf8');
  const changedSource = await auditExtension(second);
  assert.notEqual(changedSource.analysis.sha256, firstAudit.analysis.sha256);
  assert.notEqual(changedSource.analysis.sources.find((source) => source.path === 'worker.js').sha256, worker.sha256);

  await writeFile(path.join(second, 'worker.js'), 'eval(payload);\n', 'utf8');
  await mkdir(path.join(second, 'empty-directory'));
  const changedLayout = await auditExtension(second);
  assert.notEqual(changedLayout.analysis.packageLayoutSha256, firstAudit.analysis.packageLayoutSha256);
  assert.notEqual(changedLayout.analysis.sha256, firstAudit.analysis.sha256);

  await writeFile(path.join(second, 'manifest.json'), JSON.stringify({
    manifest_version: 3, name: 'Changed manifest', version: '1.0.0'
  }), 'utf8');
  const changedManifest = await auditExtension(second);
  assert.notEqual(changedManifest.analysis.manifest.sha256, firstAudit.analysis.manifest.sha256);
  assert.notEqual(changedManifest.analysis.sha256, changedLayout.analysis.sha256);
});

test('cookie capability chain is detected in both manifest and source', async () => {
  const result = await auditExtension(path.join(ROOT, 'cookie-access/mv3'));
  assert.deepEqual(result.findings.map((finding) => finding.id), ['MVX103', 'MVX101', 'MVX102', 'MVX206']);
  assert.equal(result.findings.find((finding) => finding.id === 'MVX206').evidence[0].line, 2);
  assert.deepEqual(result.capabilities.hostPermissions, ['<all_urls>']);
  assert.equal(result.analysis.manifest.sha256, '3a9e7868763f271ead5caefe274ea72c63cfa19d1b197511dcbf28a0ef7a8fff');
  assert.equal(result.analysis.packageLayoutSha256, 'b0261980aa905c75bd30450d2ffc1af5fa27454eb9923d75f1c4d25bec134744');
  assert.equal(result.analysis.sha256, '0f1c266447fd38b37b56241733c11534d5ba9277e40ff9da7982ea018212b5a5');
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
  const linked = result.package.entries.find((entry) => entry.path === 'linked.js');
  assert.equal(linked.type, 'symlink');
  assert.match(linked.targetSha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(result).includes('/etc/hosts'), false);
});

test('package identity and source analysis do not hide .git subtrees', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-git-inventory-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Git inventory fixture', version: '1.0.0' });
  await mkdir(path.join(temp, '.git'));
  await writeFile(path.join(temp, '.git', 'hidden.js'), 'eval(hiddenPayload);\n', 'utf8');
  const result = await auditExtension(temp);
  assert.deepEqual(result.package.entries.filter((entry) => entry.path.startsWith('.git')), [
    { path: '.git', type: 'directory' },
    {
      path: '.git/hidden.js',
      type: 'file',
      bytes: 21,
      sha256: 'e3a2774c7ebbeaa0925486cd5b20070e6ef2594c692aa06871c1afeff328b3fb'
    }
  ]);
  assert.equal(result.package.fileCount, 2);
  assert.ok(result.findings.some((finding) => finding.id === 'MVX201'
    && finding.evidence.some((evidence) => evidence.file === '.git/hidden.js')));
  const before = result.package.sha256;
  await writeFile(path.join(temp, '.git', 'hidden.js'), 'eval(changedPayload);\n', 'utf8');
  assert.notEqual((await auditExtension(temp)).package.sha256, before);
});

test('a symlinked manifest is rejected instead of hashed and parsed outside the root', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-manifest-link-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const root = path.join(temp, 'extension');
  await mkdir(root);
  const outside = path.join(temp, 'outside.json');
  await writeFile(outside, '{"manifest_version":3,"name":"Outside","version":"1.0.0"}\n', 'utf8');
  await symlink(outside, path.join(root, 'manifest.json'));
  await assert.rejects(
    () => auditExtension(root),
    (error) => error.code === 'UNSAFE_INPUT' && /manifest\.json/.test(error.message)
  );
});

test('scan byte limits fail closed', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-limit-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Limit fixture', version: '1.0.0' }, { 'large.js': 'x'.repeat(20) });
  await assert.rejects(() => auditExtension(temp, { limits: { maxFileBytes: 10 } }), (error) => error.code === 'SCAN_LIMIT');
});

test('package byte limits hash unparsed files or fail closed', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-package-limit-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Package limit fixture', version: '1.0.0' }, {
    'large.bin': 'x'.repeat(400)
  });
  await assert.rejects(
    () => auditExtension(temp, { limits: { maxPackageFileBytes: 200 } }),
    (error) => error.code === 'SCAN_LIMIT' && /large\.bin/.test(error.message)
  );
  await assert.rejects(
    () => auditExtension(temp, { limits: { maxPackageBytes: 50 } }),
    (error) => error.code === 'SCAN_LIMIT' && /Package content/.test(error.message)
  );
});

test('opaque executable signatures are inventoried and reported without trusting extensions', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-executable-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Executable fixture', version: '1.0.0' }, {
    'module.data': Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    'helper.bin': Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]),
    'portable.dat': Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
    'universal.payload': Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00]),
    'named-only.wasm': 'not actually WebAssembly'
  });
  const result = await auditExtension(temp);
  const finding = result.findings.find((item) => item.id === 'MVX003');
  assert.ok(finding);
  assert.equal(finding.severity, 'medium');
  assert.deepEqual(finding.evidence.map((item) => [item.file, item.format]), [
    ['helper.bin', 'elf'],
    ['module.data', 'webassembly'],
    ['portable.dat', 'windows-executable'],
    ['universal.payload', 'mach-o']
  ]);
  assert.equal(finding.evidence.some((item) => item.file === 'named-only.wasm'), false);
  assert.equal(result.scan.sourceFilesScanned, 0);
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

test('default limits scan realistic multi-megabyte bundles', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-large-bundle-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Large bundle', version: '1.0.0' }, {
    'bundle.js': `eval(payload);\n${'x'.repeat(2_100_000)}`
  });
  const result = await auditExtension(temp);
  assert.ok(result.findings.some((finding) => finding.id === 'MVX201'));
  assert.ok(result.scan.sourceBytesScanned > 2_000_000);
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

test('manifest path input cannot bypass a symlinked extension root', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-root-link-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const realRoot = path.join(temp, 'real');
  await writeExtension(realRoot, { manifest_version: 3, name: 'Real fixture', version: '1.0.0' });
  const linkedRoot = path.join(temp, 'linked');
  await symlink(realRoot, linkedRoot);
  await assert.rejects(
    () => auditExtension(path.join(linkedRoot, 'manifest.json')),
    (error) => error.code === 'UNSAFE_INPUT'
  );
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

test('remote framed UI and sensitive iframe delegation are detected', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-remote-frame-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Remote sidebar fixture',
    version: '1.0.0',
    side_panel: { default_path: 'sidepanel.html' }
  }, {
    'sidepanel.html': '<iframe src="https://remote.example.invalid/chat" allow="clipboard-read; clipboard-write"></iframe>\n'
  });
  const result = await auditExtension(temp);
  assert.deepEqual(result.findings.map((finding) => finding.id), ['MVX211', 'MVX212']);
  assert.equal(result.findings[0].evidence[0].file, 'sidepanel.html');
});

test('packaged iframe and ordinary remote image do not trigger remote UI rules', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-local-frame-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Local frame fixture', version: '1.0.0' }, {
    'page.html': '<iframe src="local.html" sandbox="allow-scripts"></iframe><img src="https://cdn.example.invalid/logo.png">\n',
    'local.html': '<p>packaged</p>\n'
  });
  const ids = new Set((await auditExtension(temp)).findings.map((finding) => finding.id));
  assert.equal(ids.has('MVX211'), false);
  assert.equal(ids.has('MVX212'), false);
});
