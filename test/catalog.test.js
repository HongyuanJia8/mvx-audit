import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadCatalog, validateCatalog } from '../src/catalog.js';

test('catalog contains a diverse paired corpus and validates against analyzer output', async () => {
  const validation = await validateCatalog();
  assert.deepEqual(validation.errors, []);
  assert.equal(validation.valid, true);
  assert.equal(validation.scenarios, 17);
  assert.equal(validation.fixturePairs, 17);
});

test('catalog identifiers and fixture paths are unique', async () => {
  const { catalog } = await loadCatalog();
  const ids = catalog.scenarios.map((scenario) => scenario.id);
  const fixturePaths = catalog.scenarios.flatMap((scenario) => Object.values(scenario.fixtures));
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(new Set(fixturePaths).size, fixturePaths.length);
  assert.ok(new Set(catalog.scenarios.map((scenario) => scenario.category)).size >= 7);
});

test('malformed catalog structure returns validation errors instead of throwing', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-catalog-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const catalogPath = path.join(temp, 'catalog.json');
  await writeFile(catalogPath, 'null\n', 'utf8');
  let validation = await validateCatalog(catalogPath);
  assert.equal(validation.valid, false);
  assert.match(validation.errors[0], /JSON object/);
  await writeFile(catalogPath, '{"schemaVersion":1,"scenarios":{}}\n', 'utf8');
  validation = await validateCatalog(catalogPath);
  assert.equal(validation.valid, false);
  assert.match(validation.errors[0], /non-empty array/);
});

test('malformed nested catalog values are accumulated as validation errors', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-nested-catalog-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const catalogPath = path.join(temp, 'catalog.json');
  for (const scenario of [
    null,
    { id: 'bad-reference', title: 'x', category: 'x', description: 'x', mv3Effect: 'unchanged', references: [null], fixtures: {} },
    { id: 'bad-fixture', title: 'x', category: 'x', description: 'x', mv3Effect: 'unchanged', references: ['https://example.invalid'], fixtures: { mv2: 7, mv3: 8 } }
  ]) {
    await writeFile(catalogPath, `${JSON.stringify({ schemaVersion: 1, scenarios: [scenario] })}\n`, 'utf8');
    const validation = await validateCatalog(catalogPath);
    assert.equal(validation.valid, false);
    assert.ok(validation.errors.length > 0);
  }
});
