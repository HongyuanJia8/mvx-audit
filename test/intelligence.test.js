import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadIntelCatalog, lookupIntel, validateIntelCatalog } from '../src/intelligence.js';
import { buildIntelCatalog, serializeCatalog } from '../scripts/update-intelligence.mjs';

const ID_A = 'abcdefghijklmnopabcdefghijklmnop';
const ID_B = 'ponmlkjihgfedcbaponmlkjihgfedcba';
const HASH = 'a'.repeat(64);

function fixtureCatalog() {
  const config = {
    schemaVersion: 1,
    snapshotDate: '2026-01-02',
    sources: [
      { id: 'malext-sentry', name: 'MalExt', repository: 'https://example.invalid/a', license: 'MIT', ref: '1'.repeat(40) },
      { id: 'tpci-chrome-mal-ids', name: 'TPCI', repository: 'https://example.invalid/b', license: 'CC-BY-4.0', ref: '2'.repeat(40) },
      { id: 'mthcht-browser-extensions', name: 'Community', repository: 'https://example.invalid/d', license: 'MIT', ref: '4'.repeat(40) },
      { id: 'gherardo-crx', name: 'CRX', repository: 'https://example.invalid/c', license: 'MIT', ref: '3'.repeat(40) }
    ]
  };
  return buildIntelCatalog(config, {
    malextCsv: `extension_id,name,reason,source,insert_date_fmt,blocklist,store\n${ID_A},Alpha,Malware,https://example.invalid/report,2026-01-01,,Google Chrome\n`,
    tpciCsv: `EXTID,EXTID-NAME,DATE-DIS,SOURCE,ARTICLE,CONFIRM-MAL,REPORTED-MAL,THREAT-TYPE,OWNERSHIP-TRANSFER,BROWSER,STILL-ACTIVE,TPCI-VERIFY,TPCI-CRX-HASH,TPCI-BEHAVIORAL\n${ID_A},Alpha,2025-12-31,https://example.invalid/source,,3,1,credential-theft,0,chrome,0,5,${HASH},malicious\n`,
    mthchtCsv: `browser_extension,browser_extension_id_wildcard,browser_extension_id,metadata_category,metadata_type,metadata_link,metadata_comment,crx_file_sha256\nCommunity Alpha,*${ID_A}*,${ID_A},malware,malicious,https://example.invalid/community,reported credential theft,${HASH}\n`,
    gherardoJson: JSON.stringify({ extensions: [{ extension_id: ID_B, source_url: 'https://example.invalid/report', date_reported: '2026-01-01', date_added: '2026-01-02', crx_sha256: HASH }] }),
    gherardoTree: JSON.stringify({ tree: [{ type: 'blob', path: `AutomatedExtensions/${ID_B}.crx`, size: 1234, sha: 'b'.repeat(40) }] })
  });
}

test('intelligence builder merges providers without double-counting extension IDs', () => {
  const catalog = fixtureCatalog();
  assert.equal(catalog.meta.summary.records, 2);
  assert.equal(catalog.meta.summary.confirmedMalware, 1);
  assert.equal(catalog.meta.summary.artifacts, 1);
  assert.equal(catalog.meta.summary.recordsWithSha256, 2);
  const first = catalog.records.find((record) => record.extensionId === ID_A);
  assert.ok(first.labels.includes('google-confirmed-malware'));
  assert.ok(first.labels.includes('community-reported-malicious'));
  assert.equal(first.verification.communityReported, true);
  assert.ok(first.threatTypes.includes('credential-theft'));
});

test('checked-in real-world intelligence is internally consistent and searchable', async () => {
  const validation = await validateIntelCatalog();
  assert.equal(validation.valid, true, validation.errors.join('\n'));
  assert.ok(validation.summary.records >= 4_000);
  assert.ok(validation.summary.artifacts >= 400);
  const { records } = await loadIntelCatalog();
  const withHash = records.find((record) => record.sha256.length > 0);
  assert.ok(withHash);
  assert.ok((await lookupIntel(withHash.extensionId)).length >= 1);
  assert.ok((await lookupIntel(withHash.sha256[0])).length >= 1);
});

test('intelligence validator reports malformed records instead of trusting metadata', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-intel-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const metaPath = path.join(temp, 'meta.json');
  const recordsPath = path.join(temp, 'records.jsonl');
  await writeFile(metaPath, JSON.stringify({ schemaVersion: 1, sources: [{}], summary: { records: 1, artifacts: 0 } }));
  await writeFile(recordsPath, '{"extensionId":"bad"}\n');
  const validation = await validateIntelCatalog({ metaPath, recordsPath });
  assert.equal(validation.valid, false);
  assert.match(validation.errors.join('\n'), /invalid extensionId/);
});

test('serialized intelligence output is deterministic', () => {
  const first = serializeCatalog(fixtureCatalog());
  const second = serializeCatalog(fixtureCatalog());
  assert.deepEqual(first, second);
});
