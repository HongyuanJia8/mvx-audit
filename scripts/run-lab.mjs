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

function captureResult(command, args, { maxBytes = 4_096, runtimeMs = 10_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    let errorOutput = '';
    let failure;
    let killTimer;
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(runtimeTimer);
      clearTimeout(killTimer);
      resolve({ ...outcome, output: output.trim(), errorOutput: errorOutput.trim(), failure });
    };
    const stop = (error) => {
      if (!failure) failure = error;
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
      if (!killTimer) killTimer = setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      }, 2_000);
    };
    const runtimeTimer = setTimeout(() => {
      const error = new Error(`${command} exceeded the ${runtimeMs}-millisecond runtime limit`);
      error.code = 'LAB_TIMEOUT';
      stop(error);
    }, runtimeMs);
    child.stdout.on('data', (chunk) => {
      if (failure) return;
      if (Buffer.byteLength(output) + Buffer.byteLength(errorOutput) + chunk.length > maxBytes) {
        const error = new Error(`${command} output exceeds ${maxBytes} bytes`);
        error.code = 'LAB_LIMIT';
        stop(error);
      } else output += chunk;
    });
    child.stderr.on('data', (chunk) => {
      if (failure) return;
      if (Buffer.byteLength(output) + Buffer.byteLength(errorOutput) + chunk.length > maxBytes) {
        const error = new Error(`${command} output exceeds ${maxBytes} bytes`);
        error.code = 'LAB_LIMIT';
        stop(error);
      } else errorOutput += chunk;
    });
    child.once('error', (error) => finish({ error }));
    child.once('exit', (code, signal) => finish({ code, signal }));
  });
}

async function capture(command, args) {
  const result = await captureResult(command, args);
  if (result.error) throw result.error;
  if (result.failure) throw result.failure;
  if (result.code !== 0) {
    throw new Error(`${command} exited with ${result.code ?? result.signal}${result.errorOutput ? `: ${result.errorOutput}` : ''}`);
  }
  return result.output;
}

async function captureToFile(command, args, destination, maxBytes = 20_000_000, runtimeMs = 60_000) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'inherit'] });
  let bytes = 0;
  let runtimeError;
  let killTimer;
  const requestStop = () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    if (!killTimer) killTimer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }, 2_000);
  };
  const runtimeTimer = setTimeout(() => {
    runtimeError = new Error(`Lab container exceeded the ${runtimeMs}-millisecond host runtime limit`);
    runtimeError.code = 'LAB_TIMEOUT';
    requestStop();
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
  const exited = new Promise((resolve) => {
    child.once('error', (error) => {
      resolve({ error });
    });
    child.once('exit', (code, signal) => {
      resolve({ code, signal });
    });
  });
  const streamError = await pipeline(
    child.stdout, bounded, createWriteStream(destination, { flags: 'wx', mode: 0o600 })
  ).then(() => null, (error) => {
    requestStop();
    return error;
  });
  const outcome = await exited;
  clearTimeout(runtimeTimer);
  clearTimeout(killTimer);
  if (runtimeError) throw runtimeError;
  if (streamError) throw streamError;
  if (outcome.error) throw outcome.error;
  if (outcome.code !== 0) throw new Error(`${command} exited with ${outcome.code ?? outcome.signal}`);
}

async function forceRemoveContainer(cidFile) {
  let cidBytes;
  try {
    cidBytes = await readBoundedRegularFile(cidFile, {
      maxBytes: 128, label: 'Lab container ID file', limitCode: 'LAB_CONTAINER_CLEANUP_FAILED',
      missingCode: 'LAB_CONTAINER_NOT_CREATED', unsafeCode: 'LAB_CONTAINER_CLEANUP_FAILED'
    });
  } catch (error) {
    if (error.code === 'LAB_CONTAINER_NOT_CREATED') return;
    throw error;
  }
  const containerId = cidBytes.toString('utf8').trim();
  if (!/^[a-f0-9]{64}$/.test(containerId)) {
    const error = new Error('Docker wrote a non-canonical container ID');
    error.code = 'LAB_CONTAINER_CLEANUP_FAILED';
    throw error;
  }
  const result = await captureResult('docker', ['rm', '--force', containerId]);
  if (result.error) throw result.error;
  if (result.failure) throw result.failure;
  if (result.code === 0) return;
  if (new RegExp(`(?:No such container|No such object):?\\s+${containerId}`, 'i').test(result.errorOutput)) return;
  const error = new Error(`Unable to confirm removal of lab container ${containerId}`);
  error.code = 'LAB_CONTAINER_CLEANUP_FAILED';
  throw error;
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
let containerIdFile;
let retainSnapshot = false;
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
  containerIdFile = path.join(snapshot.workspace, 'container.cid');
  await captureToFile('docker', [
    'run', '--rm', '--cidfile', containerIdFile, '--pull', 'never', '--stop-timeout', '2', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
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
  if (containerIdFile) {
    try {
      await forceRemoveContainer(containerIdFile);
    } catch (cleanupError) {
      retainSnapshot = true;
      const combined = new Error(`Lab container cleanup failed after ${labError.code ?? labError.name ?? 'run failure'}; private snapshot retained at ${snapshot.workspace}`);
      combined.code = 'LAB_CONTAINER_CLEANUP_FAILED';
      combined.originalCode = labError.code ?? labError.name ?? 'ERROR';
      combined.snapshotPath = snapshot.workspace;
      combined.cause = cleanupError;
      labError = combined;
    }
  }
}
if (!retainSnapshot) {
  try {
    await removeLabInputSnapshot(snapshot);
  } catch (cleanupError) {
    const combined = new Error(`Private lab snapshot cleanup failed${labError ? ` after ${labError.code ?? labError.name ?? 'run failure'}` : ''}`);
    combined.code = 'LAB_TEMP_CLEANUP_FAILED';
    if (labError) combined.originalCode = labError.code ?? labError.name ?? 'ERROR';
    combined.cause = cleanupError;
    throw combined;
  }
}
if (labError) throw labError;

export { parse };
