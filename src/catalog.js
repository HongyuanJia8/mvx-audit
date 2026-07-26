import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditExtension } from './analyzer.js';
import { MvxError } from './errors.js';

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_CATALOG_PATH = path.join(PROJECT_ROOT, 'corpus/catalog.json');
const EFFECTS = new Set(['blocked', 'constrained', 'changed', 'unchanged', 'policy-dependent']);

export async function loadCatalog(catalogPath = DEFAULT_CATALOG_PATH) {
  const absolute = path.resolve(catalogPath);
  let source;
  try {
    source = await readFile(absolute, 'utf8');
  } catch (error) {
    throw new MvxError(`Cannot read corpus catalog: ${absolute}`, { code: 'CATALOG_NOT_FOUND', cause: error });
  }
  try {
    const catalog = JSON.parse(source);
    return { catalog, path: absolute, root: path.dirname(absolute) };
  } catch (error) {
    throw new MvxError(`Invalid corpus catalog JSON: ${error.message}`, { code: 'INVALID_CATALOG', cause: error });
  }
}

export async function validateCatalog(catalogPath = DEFAULT_CATALOG_PATH) {
  const { catalog, path: absolute, root } = await loadCatalog(catalogPath);
  const errors = [];
  const result = () => ({
    valid: errors.length === 0,
    errors,
    path: absolute,
    scenarios: Array.isArray(catalog?.scenarios) ? catalog.scenarios.length : 0,
    fixturePairs: Array.isArray(catalog?.scenarios) ? catalog.scenarios.length : 0
  });
  if (!catalog || Array.isArray(catalog) || typeof catalog !== 'object') {
    errors.push('catalog must be a JSON object');
    return result();
  }
  if (catalog.schemaVersion !== 1) errors.push('schemaVersion must equal 1');
  if (!Array.isArray(catalog.scenarios)) {
    errors.push('scenarios must be a non-empty array');
    return result();
  }
  if (catalog.scenarios.length === 0) errors.push('scenarios must be a non-empty array');
  const ids = new Set();

  for (const [index, scenario] of (catalog.scenarios ?? []).entries()) {
    const fallbackLabel = `scenario[${index}]`;
    if (!scenario || Array.isArray(scenario) || typeof scenario !== 'object') {
      errors.push(`${fallbackLabel}: must be a JSON object`);
      continue;
    }
    const label = typeof scenario.id === 'string' && scenario.id ? scenario.id : fallbackLabel;
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(scenario.id ?? '')) errors.push(`${label}: invalid id`);
    if (ids.has(scenario.id)) errors.push(`${label}: duplicate id`);
    ids.add(scenario.id);
    if (![scenario.title, scenario.category, scenario.description].every((value) => typeof value === 'string' && value.length > 0)) {
      errors.push(`${label}: missing descriptive metadata`);
    }
    if (!EFFECTS.has(scenario.mv3Effect)) errors.push(`${label}: invalid mv3Effect`);
    if (!Array.isArray(scenario.references) || scenario.references.length === 0 || scenario.references.some((url) => typeof url !== 'string' || !url.startsWith('https://'))) {
      errors.push(`${label}: references must contain HTTPS primary sources`);
    }
    for (const mode of ['mv2', 'mv3']) {
      const fixture = scenario.fixtures?.[mode];
      if (typeof fixture !== 'string' || fixture.length === 0) {
        errors.push(`${label}: missing ${mode} fixture`);
        continue;
      }
      try {
        const fixturePath = path.resolve(root, fixture);
        const result = await auditExtension(fixturePath);
        const expectedVersion = mode === 'mv2' ? 2 : 3;
        if (result.target.manifestVersion !== expectedVersion) errors.push(`${label}: ${mode} fixture has wrong manifest version`);
        const actual = new Set(result.findings.map((finding) => finding.id));
        const expectedFindings = Array.isArray(scenario.expectedFindings?.[mode]) ? scenario.expectedFindings[mode] : [];
        if (scenario.expectedFindings?.[mode] !== undefined && !Array.isArray(scenario.expectedFindings[mode])) {
          errors.push(`${label}: expectedFindings.${mode} must be an array`);
        }
        for (const expected of expectedFindings) {
          if (!actual.has(expected)) errors.push(`${label}: ${mode} fixture did not produce ${expected}`);
        }
      } catch (error) {
        errors.push(`${label}: cannot audit ${mode} fixture (${error.message})`);
      }
    }
  }

  return result();
}

export function catalogToText(catalog) {
  const rows = catalog.scenarios.map((scenario) => [scenario.id, scenario.category, scenario.mv3Effect, scenario.title]);
  const widths = [0, 1, 2, 3].map((index) => Math.max(...rows.map((row) => row[index].length), ['ID', 'CATEGORY', 'MV3 EFFECT', 'TITLE'][index].length));
  const line = (row) => row.map((value, index) => value.padEnd(widths[index])).join('  ').trimEnd();
  return `${line(['ID', 'CATEGORY', 'MV3 EFFECT', 'TITLE'])}\n${line(widths.map((width) => '-'.repeat(width)))}\n${rows.map(line).join('\n')}\n`;
}
