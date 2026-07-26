#!/usr/bin/env node
import { readFile, readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ROOTS = ['bin', 'lab', 'src', 'scripts', 'support', 'test'];
const checked = [];
const errors = [];

async function visit(relative) {
  const absolute = path.join(ROOT, relative);
  let entries;
  try {
    entries = await readdir(absolute, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const child = path.join(relative, entry.name);
    if (entry.isDirectory()) await visit(child);
    else if (/\.(?:js|mjs|cjs)$/.test(entry.name)) {
      const result = spawnSync(process.execPath, ['--check', child], { cwd: ROOT, encoding: 'utf8' });
      if (result.status !== 0) errors.push(result.stderr.trim());
      const content = await readFile(path.join(ROOT, child), 'utf8');
      if (!content.endsWith('\n')) errors.push(`${child}: missing final newline`);
      if (content.split('\n').some((line) => /[ \t]+$/.test(line))) errors.push(`${child}: trailing whitespace`);
      checked.push(child);
    }
  }
}

for (const root of ROOTS) await visit(root);
if (errors.length > 0) {
  process.stderr.write(`${errors.join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Lint passed: ${checked.length} JavaScript files\n`);
}
