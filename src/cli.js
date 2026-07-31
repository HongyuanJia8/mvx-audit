import { lstat, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { auditExtension } from './analyzer.js';
import { unpackExtensionArchive } from './archive.js';
import { runStaticBenchmark, staticBenchmarkToText } from './benchmark.js';
import { loadCatalog, validateCatalog, catalogToText } from './catalog.js';
import { compareExtensions } from './compare.js';
import { dispositionPoliciesToText, loadDispositionPolicies } from './disposition-policy.js';
import { MvxError } from './errors.js';
import { auditExtensionArchive } from './packed-audit.js';
import { intelRecordToText, intelStatsToText, loadIntelCatalog, lookupIntel, validateIntelCatalog } from './intelligence.js';
import { evaluateLabFiles, labReportToText, labVerificationToText, verifyLabReport } from './lab.js';
import { SEVERITIES } from './model.js';
import { fetchSample, fetchSampleBatch, planSample, planSampleBatch, sampleBatchPlanToText, samplePlanToText } from './quarantine.js';
import { auditToSarif, auditToText, comparisonToMarkdown } from './reporters.js';
import { loadRulePacks, rulePacksToText } from './rule-packs.js';
import { VERSION } from './version.js';

const HELP = `mvx-audit ${VERSION}

Usage:
  mvx audit <extension|file.crx|file.zip> [--format text|json|sarif]
            [--output file] [--fail-on severity|--fail-on-unreviewed severity]
            [--rule-pack file ...] [--disposition-policy file ...]
            [--disposition-at timestamp]
            [--acknowledge-risk] [--require-valid-signature]
            [--expected-archive-sha256 digest] [--expected-extension-id id]
  mvx compare <before> <after> [--format markdown|json] [--output file]
              [--rule-pack file ...] [--disposition-policy file ...]
              [--disposition-at timestamp]
  mvx rules validate <file> [file ...] [--format text|json]
  mvx dispositions validate <file> [file ...] [--disposition-at timestamp]
                           [--format text|json]
  mvx corpus [list|validate] [--format text|json] [--catalog file]
  mvx intel stats|validate [--format text|json]
  mvx intel lookup <extension-id|sha256> [--format text|json]
  mvx sample plan <extension-id> [--format text|json]
  mvx sample fetch <extension-id> --acknowledge-risk [--artifact index]
                   [--quarantine directory] [--max-bytes number]
  mvx sample plan-many [--limit number] [--label label] [--max-total-bytes number]
  mvx sample fetch-many --acknowledge-risk [--limit number] [--label label]
                        [--quarantine directory] [--max-bytes number]
                        [--max-total-bytes number]
  mvx sample unpack <file.crx-or-zip> --acknowledge-risk [--destination directory]
                    [--require-valid-signature]
                    [--expected-archive-sha256 digest] [--expected-extension-id id]
  mvx lab evaluate <scenario.json> <events.jsonl> [--format text|json]
  mvx lab verify <report.json> <extension> <scenario.json> <events.jsonl>
                 [--expected-image-id sha256:digest] [--format text|json]
  mvx benchmark static <quarantine> --acknowledge-risk [--label label]
                       [--limit number] [--threshold severity] [--format text|json]
                       [--rule-pack file ...] [--require-valid-signature]
  mvx --help

Exit codes:
  0  completed successfully (and no configured threshold was met)
  1  findings met a configured threshold, or corpus validation failed
  2  invalid arguments or unreadable input
`;

function parseArgs(argv) {
  const positionals = [];
  const options = {};
  const valueOptions = new Set(['--format', '--output', '--fail-on', '--fail-on-unreviewed', '--disposition-at', '--catalog', '--artifact', '--quarantine', '--max-bytes', '--max-total-bytes', '--limit', '--label', '--threshold', '--destination', '--expected-archive-sha256', '--expected-extension-id', '--expected-image-id']);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--help' || token === '-h') options.help = true;
    else if (token === '--version' || token === '-v') options.version = true;
    else if (token === '--acknowledge-risk') options.acknowledgeRisk = true;
    else if (token === '--require-valid-signature') options.requireValidSignature = true;
    else if (token === '--rule-pack') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new MvxError('--rule-pack requires a value', { code: 'INVALID_ARGUMENT' });
      options.rulePacks ??= [];
      options.rulePacks.push(value);
      index += 1;
    }
    else if (token === '--disposition-policy') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new MvxError('--disposition-policy requires a value', { code: 'INVALID_ARGUMENT' });
      options.dispositionPolicies ??= [];
      options.dispositionPolicies.push(value);
      index += 1;
    }
    else if (valueOptions.has(token)) {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new MvxError(`${token} requires a value`, { code: 'INVALID_ARGUMENT' });
      options[token.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
      index += 1;
    } else if (token.startsWith('--')) throw new MvxError(`Unknown option: ${token}`, { code: 'INVALID_ARGUMENT' });
    else positionals.push(token);
  }
  return { positionals, options };
}

async function emit(content, output, stdout) {
  if (!output) {
    stdout.write(content);
    return;
  }
  const absolute = path.resolve(output);
  await mkdir(path.dirname(absolute), { recursive: true });
  await writeFile(absolute, content, 'utf8');
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function thresholdMet(result, threshold, unreviewed = false) {
  if (!threshold || threshold === 'none') return false;
  const thresholdIndex = SEVERITIES.indexOf(threshold);
  if (thresholdIndex === -1) throw new MvxError(`Invalid severity: ${threshold}`, { code: 'INVALID_ARGUMENT' });
  return result.findings.some((finding) => (!unreviewed || finding.disposition?.status !== 'active')
    && SEVERITIES.indexOf(finding.severity) <= thresholdIndex);
}

async function isPackedAuditInput(inputPath) {
  if (!['.crx', '.zip'].includes(path.extname(inputPath).toLowerCase())) return false;
  try {
    return (await lstat(path.resolve(inputPath))).isFile();
  } catch {
    return false;
  }
}

export async function runCli(argv, streams = process) {
  try {
    const { positionals, options } = parseArgs(argv);
    if (options.version) {
      streams.stdout.write(`${VERSION}\n`);
      return 0;
    }
    if (options.help || positionals.length === 0) {
      streams.stdout.write(HELP);
      return 0;
    }
    const [command, ...args] = positionals;
    const archiveIdentityRequested = options.expectedArchiveSha256 !== undefined
      || options.expectedExtensionId !== undefined;
    const signatureVerificationRequested = options.requireValidSignature === true;
    const labImageIdentityRequested = options.expectedImageId !== undefined;
    const dispositionPolicyOptionsRequested = options.dispositionPolicies !== undefined
      || options.dispositionAt !== undefined;
    if (archiveIdentityRequested && !['audit', 'sample'].includes(command)) {
      throw new MvxError('Archive identity options apply only to audit or sample unpack', { code: 'INVALID_ARGUMENT' });
    }
    if (signatureVerificationRequested && !['audit', 'sample', 'benchmark'].includes(command)) {
      throw new MvxError('Archive signature verification applies only to packed audit, sample unpack, or static benchmark', { code: 'INVALID_ARGUMENT' });
    }
    if (labImageIdentityRequested && command !== 'lab') {
      throw new MvxError('--expected-image-id applies only to lab verify', { code: 'INVALID_ARGUMENT' });
    }
    if (dispositionPolicyOptionsRequested && !['audit', 'compare', 'dispositions'].includes(command)) {
      throw new MvxError('Disposition policy options apply only to audit, compare, or dispositions validate', { code: 'INVALID_ARGUMENT' });
    }
    if (options.failOnUnreviewed !== undefined && command !== 'audit') {
      throw new MvxError('--fail-on-unreviewed applies only to audit', { code: 'INVALID_ARGUMENT' });
    }
    if (options.failOn !== undefined && command !== 'audit') {
      throw new MvxError('--fail-on applies only to audit', { code: 'INVALID_ARGUMENT' });
    }

    if (command === 'audit') {
      if (args.length !== 1) throw new MvxError('audit requires exactly one extension or archive path', { code: 'INVALID_ARGUMENT' });
      const format = options.format ?? 'text';
      if (options.dispositionAt !== undefined && options.dispositionPolicies === undefined) {
        throw new MvxError('--disposition-at requires at least one --disposition-policy', { code: 'INVALID_ARGUMENT' });
      }
      if (options.failOn !== undefined && options.failOnUnreviewed !== undefined) {
        throw new MvxError('--fail-on and --fail-on-unreviewed cannot be combined', { code: 'INVALID_ARGUMENT' });
      }
      if (!['text', 'json', 'sarif'].includes(format)) throw new MvxError(`Unsupported audit format: ${format}`, { code: 'INVALID_ARGUMENT' });
      const packed = await isPackedAuditInput(args[0]);
      if (!packed && (options.requireValidSignature || options.expectedArchiveSha256 || options.expectedExtensionId)) {
        throw new MvxError('Archive signature and identity options apply only to packed CRX/ZIP audit input', { code: 'INVALID_ARGUMENT' });
      }
      if (packed && !options.acknowledgeRisk) {
        throw new MvxError('Refusing packed extension extraction without --acknowledge-risk', { code: 'RISK_ACK_REQUIRED' });
      }
      const auditOptions = {
        rulePacks: options.rulePacks,
        requireValidSignature: options.requireValidSignature || options.expectedExtensionId !== undefined,
        expectedArchiveSha256: options.expectedArchiveSha256,
        expectedExtensionId: options.expectedExtensionId,
        dispositionPolicies: options.dispositionPolicies,
        dispositionAt: options.dispositionAt
      };
      const result = packed ? await auditExtensionArchive(args[0], auditOptions) : await auditExtension(args[0], auditOptions);
      const content = format === 'text' ? auditToText(result) : format === 'sarif' ? json(auditToSarif(result)) : json(result);
      await emit(content, options.output, streams.stdout);
      return thresholdMet(result, options.failOn ?? options.failOnUnreviewed, options.failOnUnreviewed !== undefined) ? 1 : 0;
    }

    if (command === 'compare') {
      if (args.length !== 2) throw new MvxError('compare requires before and after extension paths', { code: 'INVALID_ARGUMENT' });
      if (options.dispositionAt !== undefined && options.dispositionPolicies === undefined) {
        throw new MvxError('--disposition-at requires at least one --disposition-policy', { code: 'INVALID_ARGUMENT' });
      }
      const format = options.format ?? 'markdown';
      if (!['markdown', 'json'].includes(format)) throw new MvxError(`Unsupported comparison format: ${format}`, { code: 'INVALID_ARGUMENT' });
      const result = await compareExtensions(args[0], args[1], {
        rulePacks: options.rulePacks,
        dispositionPolicies: options.dispositionPolicies,
        dispositionAt: options.dispositionAt
      });
      await emit(format === 'json' ? json(result) : comparisonToMarkdown(result), options.output, streams.stdout);
      return 0;
    }

    if (command === 'corpus') {
      const action = args[0] ?? 'list';
      if (args.length > 1 || !['list', 'validate'].includes(action)) throw new MvxError('corpus action must be list or validate', { code: 'INVALID_ARGUMENT' });
      if (options.format && !['text', 'json'].includes(options.format)) throw new MvxError(`Unsupported corpus format: ${options.format}`, { code: 'INVALID_ARGUMENT' });
      if (action === 'validate') {
        const validation = await validateCatalog(options.catalog);
        await emit(options.format === 'json' ? json(validation) : validation.valid
          ? `Corpus valid: ${validation.scenarios} scenarios / ${validation.fixturePairs} MV2-MV3 pairs\n`
          : `Corpus invalid:\n${validation.errors.map((error) => `- ${error}`).join('\n')}\n`, options.output, streams.stdout);
        return validation.valid ? 0 : 1;
      }
      const { catalog } = await loadCatalog(options.catalog);
      await emit(options.format === 'json' ? json(catalog) : catalogToText(catalog), options.output, streams.stdout);
      return 0;
    }

    if (command === 'rules') {
      if (args.length < 2 || args[0] !== 'validate') {
        throw new MvxError('rules action must be validate <file> [file ...]', { code: 'INVALID_ARGUMENT' });
      }
      const format = options.format ?? 'text';
      if (!['text', 'json'].includes(format)) throw new MvxError(`Unsupported rules format: ${format}`, { code: 'INVALID_ARGUMENT' });
      const prepared = await loadRulePacks(args.slice(1));
      const validation = { valid: true, rulePacks: prepared.provenance, limits: prepared.limits, summary: prepared.summary };
      await emit(format === 'json' ? json(validation) : rulePacksToText(prepared), options.output, streams.stdout);
      return 0;
    }

    if (command === 'dispositions') {
      if (args.length < 2 || args[0] !== 'validate') {
        throw new MvxError('dispositions action must be validate <file> [file ...]', { code: 'INVALID_ARGUMENT' });
      }
      if (options.dispositionPolicies !== undefined || options.failOnUnreviewed !== undefined) {
        throw new MvxError('dispositions validate accepts policy paths as positional arguments', { code: 'INVALID_ARGUMENT' });
      }
      const format = options.format ?? 'text';
      if (!['text', 'json'].includes(format)) throw new MvxError(`Unsupported dispositions format: ${format}`, { code: 'INVALID_ARGUMENT' });
      const prepared = await loadDispositionPolicies(args.slice(1), {
        ...(options.dispositionAt !== undefined ? { evaluationTime: options.dispositionAt } : {})
      });
      const validation = {
        valid: true, dispositionPolicies: prepared.provenance,
        evaluationTime: prepared.evaluationTime, limits: prepared.limits, summary: prepared.summary
      };
      await emit(format === 'json' ? json(validation) : dispositionPoliciesToText(prepared), options.output, streams.stdout);
      return 0;
    }

    if (command === 'intel') {
      const action = args[0] ?? 'stats';
      const format = options.format ?? 'text';
      if (!['text', 'json'].includes(format)) throw new MvxError(`Unsupported intel format: ${format}`, { code: 'INVALID_ARGUMENT' });
      if (action === 'stats' && args.length <= 1) {
        const { meta } = await loadIntelCatalog();
        await emit(format === 'json' ? json(meta) : intelStatsToText(meta), options.output, streams.stdout);
        return 0;
      }
      if (action === 'validate' && args.length === 1) {
        const validation = await validateIntelCatalog();
        await emit(format === 'json' ? json(validation) : validation.valid
          ? `Intelligence valid: ${validation.summary.records} IDs / ${validation.summary.artifacts} CRX artifacts indexed\n`
          : `Intelligence invalid:\n${validation.errors.map((error) => `- ${error}`).join('\n')}\n`, options.output, streams.stdout);
        return validation.valid ? 0 : 1;
      }
      if (action === 'lookup' && args.length === 2) {
        const records = await lookupIntel(args[1]);
        await emit(format === 'json' ? json(records) : intelRecordToText(records, args[1]), options.output, streams.stdout);
        return 0;
      }
      throw new MvxError('intel action must be stats, validate, or lookup <extension-id|sha256>', { code: 'INVALID_ARGUMENT' });
    }

    if (command === 'sample') {
      const [action, target] = args;
      if (archiveIdentityRequested && action !== 'unpack') {
        throw new MvxError('Archive identity options apply only to sample unpack', { code: 'INVALID_ARGUMENT' });
      }
      if (signatureVerificationRequested && action !== 'unpack') {
        throw new MvxError('Archive signature verification applies only to sample unpack', { code: 'INVALID_ARGUMENT' });
      }
      if (['plan-many', 'fetch-many'].includes(action)) {
        if (args.length !== 1) throw new MvxError(`sample ${action} does not accept a target`, { code: 'INVALID_ARGUMENT' });
        const format = options.format ?? 'text';
        if (!['text', 'json'].includes(format)) throw new MvxError(`Unsupported sample format: ${format}`, { code: 'INVALID_ARGUMENT' });
        const parseInteger = (value, name) => {
          if (value === undefined) return undefined;
          const parsed = Number.parseInt(value, 10);
          if (!Number.isSafeInteger(parsed) || String(parsed) !== value || parsed <= 0) throw new MvxError(`${name} must be a positive integer`, { code: 'INVALID_ARGUMENT' });
          return parsed;
        };
        const { meta, records } = await loadIntelCatalog();
        const batchOptions = {
          limit: parseInteger(options.limit, '--limit'),
          maxBytes: parseInteger(options.maxBytes, '--max-bytes'),
          maxTotalBytes: parseInteger(options.maxTotalBytes, '--max-total-bytes'),
          label: options.label
        };
        if (action === 'plan-many') {
          const plan = planSampleBatch(records, meta.sources, batchOptions);
          await emit(format === 'json' ? json(plan) : sampleBatchPlanToText(plan), options.output, streams.stdout);
          return 0;
        }
        const result = await fetchSampleBatch({
          records,
          sources: meta.sources,
          quarantineDir: options.quarantine,
          acknowledgeRisk: options.acknowledgeRisk,
          ...batchOptions
        });
        await emit(format === 'json' ? json(result) : [
          `Batch fetched: ${result.fetched.length}/${result.plan.selected}`,
          `Failures: ${result.failures.length}`,
          `Pinned bytes: ${result.plan.totalBytes}`,
          'Samples remain packed in the ignored quarantine directory and were not executed.'
        ].join('\n') + '\n', options.output, streams.stdout);
        return result.complete ? 0 : 1;
      }
      if (!['plan', 'fetch', 'unpack'].includes(action) || args.length !== 2) {
        throw new MvxError('sample action must be plan/fetch <extension-id>, plan-many/fetch-many, or unpack <file.crx-or-zip>', { code: 'INVALID_ARGUMENT' });
      }
      const format = options.format ?? 'text';
      if (!['text', 'json'].includes(format)) throw new MvxError(`Unsupported sample format: ${format}`, { code: 'INVALID_ARGUMENT' });
      if (action === 'unpack') {
        if (!options.acknowledgeRisk) throw new MvxError('Refusing live malware extraction without --acknowledge-risk', { code: 'RISK_ACK_REQUIRED' });
        const input = path.resolve(target);
        const destination = options.destination
          ? path.resolve(options.destination)
          : path.join(path.dirname(input), 'unpacked', path.basename(input, path.extname(input)));
        const result = await unpackExtensionArchive(input, destination, {
          requireValidSignature: options.requireValidSignature || options.expectedExtensionId !== undefined,
          expectedArchiveSha256: options.expectedArchiveSha256,
          expectedExtensionId: options.expectedExtensionId
        });
        await emit(format === 'json' ? json(result) : [
          `Unpacked quarantined ${result.archiveFormat.toUpperCase()}: ${result.destination}`,
          ...(result.crxVersion === null ? [] : [`CRX version: ${result.crxVersion}`]),
          `Archive SHA-256: ${result.archiveSha256}`,
          ...(result.authenticity.status === 'verified'
            ? [`Authenticity: VERIFIED (${result.authenticity.extensionId})`]
            : result.authenticity.status === 'invalid'
              ? [`Authenticity: INVALID (${result.authenticity.error})`]
              : ['Authenticity: not applicable']),
          ...(result.identityPolicy.matched ? [`Identity policy: MATCHED (${[
            ...(result.identityPolicy.archiveSha256Match ? ['archive SHA-256'] : []),
            ...(result.identityPolicy.extensionIdMatch ? ['extension ID'] : [])
          ].join(', ')})`] : []),
          `Archive bytes: ${result.archiveBytes}`,
          `Files: ${result.files}`,
          `Uncompressed bytes: ${result.uncompressedBytes}`,
          'No extension code was executed.'
        ].join('\n') + '\n', options.output, streams.stdout);
        return 0;
      }
      const { meta } = await loadIntelCatalog();
      const matches = await lookupIntel(target);
      if (matches.length === 0) throw new MvxError(`No intelligence record for ${target}`, { code: 'SAMPLE_NOT_AVAILABLE' });
      const record = matches.find((entry) => entry.extensionId === target.toLowerCase()) ?? matches[0];
      const plan = planSample(record, meta.sources);
      if (action === 'plan') {
        await emit(format === 'json' ? json(plan) : samplePlanToText(plan), options.output, streams.stdout);
        return 0;
      }
      const artifactIndex = options.artifact === undefined ? 0 : Number.parseInt(options.artifact, 10);
      const maxBytes = options.maxBytes === undefined ? undefined : Number.parseInt(options.maxBytes, 10);
      if (!Number.isSafeInteger(artifactIndex) || String(artifactIndex) !== String(options.artifact ?? '0')) {
        throw new MvxError('--artifact must be a non-negative integer', { code: 'INVALID_ARGUMENT' });
      }
      if (artifactIndex < 0) throw new MvxError('--artifact must be a non-negative integer', { code: 'INVALID_ARGUMENT' });
      if (options.maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || String(maxBytes) !== options.maxBytes)) {
        throw new MvxError('--max-bytes must be a positive integer', { code: 'INVALID_ARGUMENT' });
      }
      const result = await fetchSample({
        record,
        sources: meta.sources,
        artifactIndex,
        quarantineDir: options.quarantine,
        ...(maxBytes === undefined ? {} : { maxBytes }),
        acknowledgeRisk: options.acknowledgeRisk
      });
      await emit(format === 'json' ? json(result) : [
        `${result.cached ? 'Verified cached' : 'Fetched'} quarantined sample: ${result.path}`,
        `SHA-256: ${result.sha256}`,
        ...(result.reportedSha256 ? [`Reported SHA-256: ${result.reportedSha256} (${result.reportedSha256Match ? 'match' : 'VERSION MISMATCH'})`] : []),
        `Bytes: ${result.bytes}`,
        'The sample was not unpacked, loaded, or executed.'
      ].join('\n') + '\n', options.output, streams.stdout);
      return 0;
    }

    if (command === 'lab') {
      const format = options.format ?? 'text';
      if (!['text', 'json'].includes(format)) throw new MvxError(`Unsupported lab format: ${format}`, { code: 'INVALID_ARGUMENT' });
      if (args[0] === 'evaluate' && args.length === 3) {
        if (options.expectedImageId !== undefined) throw new MvxError('--expected-image-id applies only to lab verify', { code: 'INVALID_ARGUMENT' });
        const report = await evaluateLabFiles(args[1], args[2]);
        await emit(format === 'json' ? json(report) : labReportToText(report), options.output, streams.stdout);
        return report.contained ? 0 : 1;
      }
      if (args[0] === 'verify' && args.length === 5) {
        const verification = await verifyLabReport(args[1], args[2], args[3], args[4], {
          ...(options.expectedImageId !== undefined ? { expectedImageId: options.expectedImageId } : {})
        });
        await emit(format === 'json' ? json(verification) : labVerificationToText(verification), options.output, streams.stdout);
        return 0;
      }
      throw new MvxError('lab action must be evaluate <scenario.json> <events.jsonl> or verify <report.json> <extension> <scenario.json> <events.jsonl>', { code: 'INVALID_ARGUMENT' });
    }

    if (command === 'benchmark') {
      if (args.length !== 2 || args[0] !== 'static') throw new MvxError('benchmark action must be static <quarantine>', { code: 'INVALID_ARGUMENT' });
      const format = options.format ?? 'text';
      if (!['text', 'json'].includes(format)) throw new MvxError(`Unsupported benchmark format: ${format}`, { code: 'INVALID_ARGUMENT' });
      let limit;
      if (options.limit !== undefined) {
        limit = Number.parseInt(options.limit, 10);
        if (!Number.isSafeInteger(limit) || String(limit) !== options.limit || limit <= 0) throw new MvxError('--limit must be a positive integer', { code: 'INVALID_ARGUMENT' });
      }
      const { records } = await loadIntelCatalog();
      const report = await runStaticBenchmark({
        quarantineDir: args[1], records, label: options.label, limit,
        threshold: options.threshold, acknowledgeRisk: options.acknowledgeRisk,
        requireValidSignature: options.requireValidSignature,
        rulePacks: options.rulePacks
      });
      await emit(format === 'json' ? json(report) : staticBenchmarkToText(report), options.output, streams.stdout);
      return report.summary.failures === 0 ? 0 : 1;
    }

    throw new MvxError(`Unknown command: ${command}`, { code: 'INVALID_ARGUMENT' });
  } catch (error) {
    const message = error instanceof MvxError ? `${error.code}: ${error.message}` : `UNEXPECTED_ERROR: ${error.message}`;
    streams.stderr.write(`${message}\n`);
    return 2;
  }
}

export { HELP, VERSION };
