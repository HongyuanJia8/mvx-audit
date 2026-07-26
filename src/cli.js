import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { auditExtension } from './analyzer.js';
import { loadCatalog, validateCatalog, catalogToText } from './catalog.js';
import { compareExtensions } from './compare.js';
import { MvxError } from './errors.js';
import { intelRecordToText, intelStatsToText, loadIntelCatalog, lookupIntel, validateIntelCatalog } from './intelligence.js';
import { SEVERITIES } from './model.js';
import { auditToSarif, auditToText, comparisonToMarkdown } from './reporters.js';

const VERSION = '2.0.0';
const HELP = `mvx-audit ${VERSION}

Usage:
  mvx audit <extension> [--format text|json|sarif] [--output file] [--fail-on severity]
  mvx compare <before> <after> [--format markdown|json] [--output file]
  mvx corpus [list|validate] [--format text|json] [--catalog file]
  mvx intel stats|validate [--format text|json]
  mvx intel lookup <extension-id|sha256> [--format text|json]
  mvx --help

Exit codes:
  0  completed successfully (and no configured threshold was met)
  1  findings met --fail-on, or corpus validation failed
  2  invalid arguments or unreadable input
`;

function parseArgs(argv) {
  const positionals = [];
  const options = {};
  const valueOptions = new Set(['--format', '--output', '--fail-on', '--catalog']);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--help' || token === '-h') options.help = true;
    else if (token === '--version' || token === '-v') options.version = true;
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

function thresholdMet(result, threshold) {
  if (!threshold || threshold === 'none') return false;
  const thresholdIndex = SEVERITIES.indexOf(threshold);
  if (thresholdIndex === -1) throw new MvxError(`Invalid severity: ${threshold}`, { code: 'INVALID_ARGUMENT' });
  return result.findings.some((finding) => SEVERITIES.indexOf(finding.severity) <= thresholdIndex);
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

    if (command === 'audit') {
      if (args.length !== 1) throw new MvxError('audit requires exactly one extension path', { code: 'INVALID_ARGUMENT' });
      const format = options.format ?? 'text';
      if (!['text', 'json', 'sarif'].includes(format)) throw new MvxError(`Unsupported audit format: ${format}`, { code: 'INVALID_ARGUMENT' });
      const result = await auditExtension(args[0]);
      const content = format === 'text' ? auditToText(result) : format === 'sarif' ? json(auditToSarif(result)) : json(result);
      await emit(content, options.output, streams.stdout);
      return thresholdMet(result, options.failOn) ? 1 : 0;
    }

    if (command === 'compare') {
      if (args.length !== 2) throw new MvxError('compare requires before and after extension paths', { code: 'INVALID_ARGUMENT' });
      const format = options.format ?? 'markdown';
      if (!['markdown', 'json'].includes(format)) throw new MvxError(`Unsupported comparison format: ${format}`, { code: 'INVALID_ARGUMENT' });
      const result = await compareExtensions(args[0], args[1]);
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

    throw new MvxError(`Unknown command: ${command}`, { code: 'INVALID_ARGUMENT' });
  } catch (error) {
    const message = error instanceof MvxError ? `${error.code}: ${error.message}` : `UNEXPECTED_ERROR: ${error.message}`;
    streams.stderr.write(`${message}\n`);
    return 2;
  }
}

export { HELP, VERSION };
