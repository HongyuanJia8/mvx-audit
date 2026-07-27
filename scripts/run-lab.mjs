#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { lstat, mkdir, readdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { evaluateLabFiles } from '../src/lab.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SECCOMP_PROFILE = path.join(ROOT, 'lab', 'seccomp-chromium.json');

function parse(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--acknowledge-risk') options.acknowledgeRisk = true;
    else if (['--extension', '--scenario', '--output', '--image'].includes(token)) options[token.slice(2)] = argv[++index];
    else throw new Error(`Unknown lab option: ${token}`);
  }
  if (!options.acknowledgeRisk) throw new Error('Refusing live extension execution without --acknowledge-risk');
  for (const key of ['extension', 'scenario', 'output']) if (!options[key]) throw new Error(`--${key} is required`);
  return options;
}

async function assertTreeHasNoLinks(root) {
  let visited = 0;
  async function visit(directory, depth) {
    if (depth > 64) throw new Error('Extension tree exceeds 64 directory levels');
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      visited += 1;
      if (visited > 10_000) throw new Error('Extension tree exceeds 10000 entries');
      const child = path.join(directory, entry.name);
      const childStat = await lstat(child);
      if (childStat.isSymbolicLink()) throw new Error(`Extension tree contains a symbolic link: ${child}`);
      if (childStat.isDirectory()) await visit(child, depth + 1);
      else if (!childStat.isFile()) throw new Error(`Extension tree contains a special file: ${child}`);
    }
  }
  await visit(root, 0);
}

function capture(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'inherit'] });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? resolve(output.trim()) : reject(new Error(`${command} exited with ${code ?? signal}`)));
  });
}

async function captureToFile(command, args, destination) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'inherit'] });
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? resolve() : reject(new Error(`${command} exited with ${code ?? signal}`)));
  });
  try {
    await Promise.all([
      exited,
      pipeline(child.stdout, createWriteStream(destination, { flags: 'wx', mode: 0o600 }))
    ]);
  } catch (error) {
    if (child.exitCode === null) child.kill('SIGKILL');
    throw error;
  }
}

const options = parse(process.argv.slice(2));
const extension = await realpath(path.resolve(options.extension));
const scenario = await realpath(path.resolve(options.scenario));
const extensionStat = await lstat(extension);
const scenarioStat = await lstat(scenario);
if (!extensionStat.isDirectory() || !scenarioStat.isFile()) throw new Error('Extension must be a directory and scenario must be a file');
await assertTreeHasNoLinks(extension);
const requestedOutput = path.resolve(options.output);
await mkdir(requestedOutput, { recursive: true, mode: 0o700 });
const output = await realpath(requestedOutput);
const outputStat = await lstat(output);
if (outputStat.isSymbolicLink() || !outputStat.isDirectory()) throw new Error('Output must be a real directory');
if ((await readdir(output)).length > 0) throw new Error('Output directory must be empty');
if ([extension, scenario, output, SECCOMP_PROFILE].some((value) => value.includes(','))) {
  throw new Error('Docker bind-mount paths cannot contain commas');
}
const image = options.image ?? 'mvx-lab:local';
const imageId = await capture('docker', ['image', 'inspect', '--format', '{{.Id}}', image]);

const eventsPath = path.join(output, 'events.jsonl');
await captureToFile('docker', [
  'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
  '--security-opt', 'no-new-privileges', '--security-opt', `seccomp=${SECCOMP_PROFILE}`,
  '--pids-limit', '256', '--memory', '1g', '--cpus', '2', '--tmpfs', '/tmp:rw,noexec,nosuid,size=512m',
  '--env', `MVX_LAB_IMAGE_ID=${imageId}`,
  '--mount', `type=bind,src=${extension},dst=/sample,readonly`,
  '--mount', `type=bind,src=${scenario},dst=/scenario.json,readonly`,
  image, '--acknowledge-risk'
], eventsPath);

const report = await evaluateLabFiles(scenario, eventsPath);
await writeFile(path.join(output, 'report.json'), `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
process.stdout.write(`Lab verdict: ${report.verdict}; contained: ${report.contained ? 'yes' : 'NO'}\n`);
if (!report.contained) process.exitCode = 1;

export { assertTreeHasNoLinks, parse };
