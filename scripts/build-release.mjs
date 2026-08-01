#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile, mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST = path.join(ROOT, 'dist');
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

function fail(message) {
  process.stderr.write(`Release build failed: ${message}\n`);
  process.exit(1);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function deterministicUuid(hex) {
  const bytes = Buffer.from(hex.slice(0, 32), 'hex');
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const value = bytes.toString('hex');
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

function pack(destination) {
  const output = execFileSync(NPM, ['pack', '--json', '--pack-destination', destination], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024
  });
  const result = JSON.parse(output);
  if (!Array.isArray(result) || result.length !== 1 || typeof result[0].filename !== 'string') {
    fail('npm pack returned an unexpected result');
  }
  return result[0].filename;
}

const args = process.argv.slice(2);
let expectedTag = null;
for (let index = 0; index < args.length; index += 1) {
  if (args[index] !== '--expected-tag' || expectedTag !== null || index + 1 >= args.length) {
    fail('usage: npm run release:build -- [--expected-tag vX.Y.Z]');
  }
  expectedTag = args[index + 1];
  index += 1;
}

const packageJson = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8'));
const shrinkwrap = JSON.parse(await readFile(path.join(ROOT, 'npm-shrinkwrap.json'), 'utf8'));
const versionSource = await readFile(path.join(ROOT, 'src/version.js'), 'utf8');
const citation = await readFile(path.join(ROOT, 'CITATION.cff'), 'utf8');
const version = packageJson.version;

if (!SEMVER.test(version)) fail(`invalid package version ${JSON.stringify(version)}`);
if (shrinkwrap.version !== version || shrinkwrap.packages?.['']?.version !== version) {
  fail('package.json and npm-shrinkwrap.json versions differ');
}
if (!versionSource.includes(`export const VERSION = '${version}';`)) {
  fail('package.json and src/version.js versions differ');
}
if (!citation.split('\n').includes(`version: ${version}`)) {
  fail('package.json and CITATION.cff versions differ');
}
if (expectedTag !== null && expectedTag !== `v${version}`) {
  fail(`tag ${expectedTag} does not match package version v${version}`);
}

await rm(DIST, { recursive: true, force: true });
await mkdir(DIST, { recursive: true });
const temporary = await mkdtemp(path.join(os.tmpdir(), 'mvx-release-'));

try {
  const first = path.join(temporary, 'first');
  const second = path.join(temporary, 'second');
  await mkdir(first);
  await mkdir(second);
  const firstName = pack(first);
  const secondName = pack(second);
  if (firstName !== secondName) fail('repeated npm pack filenames differ');

  const firstBytes = await readFile(path.join(first, firstName));
  const secondBytes = await readFile(path.join(second, secondName));
  if (!firstBytes.equals(secondBytes)) fail('repeated npm pack archives are not byte-identical');
  await rename(path.join(first, firstName), path.join(DIST, firstName));

  const rawSbom = execFileSync(NPM, ['sbom', '--sbom-format', 'cyclonedx'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024
  });
  const sbom = JSON.parse(rawSbom);
  delete sbom.serialNumber;
  if (sbom.metadata && typeof sbom.metadata === 'object') delete sbom.metadata.timestamp;
  const sbomSeed = JSON.stringify(stable(sbom));
  sbom.serialNumber = `urn:uuid:${deterministicUuid(sha256(sbomSeed))}`;
  const sbomName = `${packageJson.name}-${version}.cdx.json`;
  const sbomBytes = `${JSON.stringify(stable(sbom), null, 2)}\n`;
  await writeFile(path.join(DIST, sbomName), sbomBytes, 'utf8');

  const checksums = [
    `${sha256(firstBytes)}  ${firstName}`,
    `${sha256(sbomBytes)}  ${sbomName}`
  ].sort().join('\n');
  await writeFile(path.join(DIST, 'SHA256SUMS'), `${checksums}\n`, 'utf8');
  process.stdout.write(`Built reproducible release assets for ${packageJson.name}@${version}:\n${checksums}\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
