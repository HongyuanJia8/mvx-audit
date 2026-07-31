#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { chmod, lstat, mkdir, readdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { LAB_EXECUTION_PROFILE, evaluateLabFiles } from '../src/lab.js';
import { prepareLabInputSnapshot, removeLabInputSnapshot } from '../src/lab-snapshot.js';
import { readBoundedRegularFile } from '../src/safe-file.js';
import { VERSION } from '../src/version.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SECCOMP_PROFILE = path.join(ROOT, 'lab', 'seccomp-chromium.json');
const IMAGE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$/;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function overlaps(left, right) {
  const relative = path.relative(left, right);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

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

function capture(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'inherit'] });
    let output = '';
    child.stdout.on('data', (chunk) => {
      output += chunk;
      if (Buffer.byteLength(output) > 4_096 && child.exitCode === null) child.kill('SIGKILL');
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? resolve(output.trim()) : reject(new Error(`${command} exited with ${code ?? signal}`)));
  });
}

async function captureToFile(command, args, destination, maxBytes = 20_000_000, runtimeMs = 60_000) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'inherit'] });
  let bytes = 0;
  let timedOut = false;
  let killTimer;
  const runtimeTimer = setTimeout(() => {
    timedOut = true;
    child.kill('SIGTERM');
    killTimer = setTimeout(() => child.kill('SIGKILL'), 2_000);
  }, runtimeMs);
  const bounded = new Transform({
    transform(chunk, encoding, callback) {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        const error = new Error(`Lab event stream exceeds ${maxBytes} bytes`);
        error.code = 'LAB_LIMIT';
        callback(error);
      } else callback(null, chunk);
    }
  });
  const exited = new Promise((resolve, reject) => {
    child.once('error', (error) => {
      clearTimeout(runtimeTimer);
      clearTimeout(killTimer);
      reject(error);
    });
    child.once('exit', (code, signal) => {
      clearTimeout(runtimeTimer);
      clearTimeout(killTimer);
      if (timedOut) {
        const error = new Error(`Lab container exceeded the ${runtimeMs}-millisecond host runtime limit`);
        error.code = 'LAB_TIMEOUT';
        reject(error);
      } else if (code === 0) resolve();
      else reject(new Error(`${command} exited with ${code ?? signal}`));
    });
  });
  try {
    await Promise.all([
      exited,
      pipeline(child.stdout, bounded, createWriteStream(destination, { flags: 'wx', mode: 0o600 }))
    ]);
  } catch (error) {
    if (child.exitCode === null) child.kill('SIGKILL');
    throw error;
  }
}

const options = parse(process.argv.slice(2));
const extension = path.resolve(options.extension);
const scenario = path.resolve(options.scenario);
const extensionStat = await lstat(extension);
const scenarioStat = await lstat(scenario);
if (extensionStat.isSymbolicLink() || !extensionStat.isDirectory()) throw new Error('Extension must be a real directory');
if (scenarioStat.isSymbolicLink() || !scenarioStat.isFile()) throw new Error('Scenario must be a real regular file');
const canonicalExtension = await realpath(extension);
const requestedOutput = path.resolve(options.output);
if (overlaps(canonicalExtension, requestedOutput) || overlaps(requestedOutput, canonicalExtension)) {
  throw new Error('Output directory must not overlap the extension tree');
}
await mkdir(requestedOutput, { recursive: true, mode: 0o700 });
const requestedOutputStat = await lstat(requestedOutput);
if (requestedOutputStat.isSymbolicLink() || !requestedOutputStat.isDirectory()) throw new Error('Output must be a real directory');
const output = await realpath(requestedOutput);
if (overlaps(canonicalExtension, output) || overlaps(output, canonicalExtension)) {
  throw new Error('Output directory must not overlap the extension tree');
}
await chmod(output, 0o700);
if ((await readdir(output)).length > 0) throw new Error('Output directory must be empty');
if ([extension, scenario, output, SECCOMP_PROFILE].some((value) => value.includes(','))) {
  throw new Error('Docker bind-mount paths cannot contain commas');
}
const image = options.image ?? 'mvx-lab:local';
if (!IMAGE_REFERENCE.test(image)) throw new Error('Container image reference is invalid');
const snapshot = await prepareLabInputSnapshot(extension, scenario);
let labError;
try {
  const seccompBytes = await readBoundedRegularFile(SECCOMP_PROFILE, {
      maxBytes: 1_000_000, label: 'Lab seccomp profile', limitCode: 'LAB_LIMIT',
      missingCode: 'LAB_INPUT_NOT_FOUND', unsafeCode: 'UNSAFE_LAB_INPUT'
    });
  const scenarioSha256 = sha256(snapshot.scenarioBytes);
  const seccompSha256 = sha256(seccompBytes);
  const seccompSnapshot = path.join(snapshot.workspace, 'seccomp.json');
  const retainedScenario = path.join(output, 'scenario.json');
  await writeFile(seccompSnapshot, seccompBytes, { flag: 'wx', mode: 0o400 });
  await writeFile(retainedScenario, snapshot.scenarioBytes, { flag: 'wx', mode: 0o600 });
  const imageId = await capture('docker', ['image', 'inspect', '--format', '{{.Id}}', image]);
  if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) throw new Error('Docker returned a non-canonical image ID');

  const eventsPath = path.join(output, 'events.jsonl');
  await captureToFile('docker', [
    'run', '--rm', '--pull', 'never', '--stop-timeout', '2', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--security-opt', `seccomp=${seccompSnapshot}`,
    '--pids-limit', '256', '--memory', '1g', '--cpus', '2', '--tmpfs', '/tmp:rw,noexec,nosuid,size=512m',
    '--env', `MVX_LAB_PROFILE=${LAB_EXECUTION_PROFILE}`,
    '--env', `MVX_LAB_TOOL_VERSION=${VERSION}`,
    '--env', `MVX_LAB_IMAGE_ID=${imageId}`,
    '--env', `MVX_LAB_IMAGE_REFERENCE=${image}`,
    '--env', `MVX_LAB_PACKAGE_SHA256=${snapshot.package.sha256}`,
    '--env', `MVX_LAB_ANALYSIS_SHA256=${snapshot.analysis.sha256}`,
    '--env', `MVX_LAB_SCENARIO_SHA256=${scenarioSha256}`,
    '--env', `MVX_LAB_SECCOMP_SHA256=${seccompSha256}`,
    '--mount', `type=bind,src=${snapshot.extension},dst=/sample,readonly`,
    '--mount', `type=bind,src=${snapshot.scenario},dst=/scenario.json,readonly`,
    imageId, '--acknowledge-risk'
  ], eventsPath);

  const report = await evaluateLabFiles(retainedScenario, eventsPath);
  if (!report.execution
    || report.execution.extension.packageSha256 !== snapshot.package.sha256
    || report.execution.extension.analysisSha256 !== snapshot.analysis.sha256
    || report.execution.scenarioSha256 !== scenarioSha256
    || report.execution.isolation.seccompSha256 !== seccompSha256
    || report.execution.container.imageId !== imageId) {
    throw new Error('Container evidence did not preserve the host-bound execution identity');
  }
  await writeFile(path.join(output, 'report.json'), `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8', flag: 'wx', mode: 0o600
  });
  process.stdout.write(`Lab verdict: ${report.verdict}; contained: ${report.contained ? 'yes' : 'NO'}\n`);
  if (!report.contained) process.exitCode = 1;
} catch (error) {
  labError = error;
}
try {
  await removeLabInputSnapshot(snapshot);
} catch (cleanupError) {
  const combined = new Error(`Private lab snapshot cleanup failed${labError ? ` after ${labError.code ?? labError.name ?? 'run failure'}` : ''}`);
  combined.code = 'LAB_TEMP_CLEANUP_FAILED';
  if (labError) combined.originalCode = labError.code ?? labError.name ?? 'ERROR';
  combined.cause = cleanupError;
  throw combined;
}
if (labError) throw labError;

export { parse };
