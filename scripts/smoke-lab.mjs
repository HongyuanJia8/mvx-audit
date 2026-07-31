#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { verifyLabReport } from '../src/lab.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
if (process.argv.length !== 3 || process.argv[2] !== '--acknowledge-risk') {
  throw new Error('Refusing live extension smoke tests without --acknowledge-risk');
}

function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(ROOT, 'scripts', 'run-lab.mjs'), ...args], { stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? resolve() : reject(new Error(`Lab child exited with ${code ?? signal}`)));
  });
}

const outputRoot = await mkdtemp(path.join(os.tmpdir(), 'mvx-lab-smoke-'));
const scenario = path.join(ROOT, 'lab', 'scenarios', 'credential-exfiltration.json');

async function runFixture(name, expectedVerdict) {
  const output = path.join(outputRoot, name);
  await run([
    '--extension', path.join(ROOT, 'lab', 'fixtures', name),
    '--scenario', scenario,
    '--output', output,
    '--acknowledge-risk'
  ]);
  const report = JSON.parse(await readFile(path.join(output, 'report.json'), 'utf8'));
  assert.equal(report.verdict, expectedVerdict, `${name} verdict`);
  assert.equal(report.contained, true, `${name} containment`);
  assert.equal(report.summary.errors, 0, `${name} collection errors`);
  const verification = await verifyLabReport(
    path.join(output, 'report.json'),
    path.join(ROOT, 'lab', 'fixtures', name),
    path.join(output, 'scenario.json'),
    path.join(output, 'events.jsonl'),
    { expectedImageId: report.execution.container.imageId }
  );
  assert.equal(verification.valid, true, `${name} evidence verification`);
  return report;
}

await runFixture('benign', 'no_trigger_observed');
const attack = await runFixture('credential-exfiltration', 'confirmed_attack');
assert.equal(attack.objectives.credentialPassword.status, 'confirmed');
process.stdout.write(`Dynamic smoke tests passed; evidence: ${outputRoot}\n`);
