import assert from 'node:assert/strict';
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

