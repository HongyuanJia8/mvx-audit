import path from 'node:path';
import { MvxError } from '../errors.js';
import { createFinding } from '../model.js';

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function buildAutomaton(patterns, foldAscii) {
  if (patterns.length === 0) return null;
  const nodes = [{ next: new Map(), fail: 0, outputLink: -1, outputs: [] }];
  for (const pattern of patterns) {
    let state = 0;
    const value = foldAscii ? pattern.value.toLowerCase() : pattern.value;
    for (let index = 0; index < value.length; index += 1) {
      const character = value[index];
      if (!nodes[state].next.has(character)) {
        nodes[state].next.set(character, nodes.length);
        nodes.push({ next: new Map(), fail: 0, outputLink: -1, outputs: [] });
      }
      state = nodes[state].next.get(character);
    }
    nodes[state].outputs.push({ ...pattern, length: value.length });
  }
  const queue = [...nodes[0].next.values()];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const state = queue[cursor];
    for (const [character, next] of nodes[state].next) {
      queue.push(next);
      let failure = nodes[state].fail;
      while (failure !== 0 && !nodes[failure].next.has(character)) failure = nodes[failure].fail;
      if (nodes[failure].next.has(character) && nodes[failure].next.get(character) !== next) {
        failure = nodes[failure].next.get(character);
      }
      nodes[next].fail = failure;
      nodes[next].outputLink = nodes[failure].outputs.length > 0
        ? failure
        : nodes[failure].outputLink;
    }
  }
  const kinds = new Set();
  for (const pattern of patterns) {
    if (pattern.scope === 'all-text') {
      kinds.add('manifest');
      kinds.add('source');
    } else kinds.add(pattern.scope);
  }
  return { nodes, foldAscii, kinds };
}

function characterAt(content, index, foldAscii) {
  const code = content.charCodeAt(index);
  return foldAscii && code >= 65 && code <= 90 ? String.fromCharCode(code + 32) : content[index];
}

function lineStarts(content) {
  const starts = [0];
  for (let index = 0; index < content.length; index += 1) if (content[index] === '\n') starts.push(index + 1);
  return starts;
}

function lineAt(starts, offset) {
  let low = 0;
  let high = starts.length;
  while (low + 1 < high) {
    const middle = Math.floor((low + high) / 2);
    if (starts[middle] <= offset) low = middle;
    else high = middle;
  }
  return low + 1;
}

function lineSnippet(content, starts, line) {
  const start = starts[line - 1];
  const end = content.indexOf('\n', start);
  return content.slice(start, end === -1 ? content.length : end).trim().slice(0, 240);
}

const UNSAFE_SNIPPET = /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u2028-\u202e\u2066-\u2069]/g;

function safeDecodedSnippet(value) {
  return value.replace(UNSAFE_SNIPPET, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function textScopeMatches(scope, kind) {
  return scope === 'all-text' || scope === kind;
}

export function analyzeCustomRules(snapshot, prepared) {
  if (prepared.packs.length === 0) return [];
  const states = prepared.packs.flatMap((pack) => pack.rules.map((rule) => ({
    pack,
    rule,
    matches: rule.indicators.map(() => []),
    seen: rule.indicators.map(() => new Set())
  })));
  const textPatterns = states.flatMap((state, stateIndex) => state.rule.indicators
    .map((indicator, indicatorIndex) => ({ indicator, indicatorIndex }))
    .filter(({ indicator }) => indicator.type === 'text')
    .map(({ indicator, indicatorIndex }) => ({
      value: indicator.value,
      scope: indicator.scope,
      stateIndex,
      indicatorIndex,
      caseSensitive: indicator.caseSensitive
    })));
  const sensitive = buildAutomaton(textPatterns.filter((pattern) => pattern.caseSensitive), false);
  const insensitive = buildAutomaton(textPatterns.filter((pattern) => !pattern.caseSensitive), true);
  let matchCount = 0;
  const record = (stateIndex, indicatorIndex, evidence, identity) => {
    const state = states[stateIndex];
    matchCount += 1;
    if (matchCount > prepared.limits.maxMatches) {
      throw new MvxError(`Custom rule matches exceed ${prepared.limits.maxMatches}`, { code: 'RULE_PACK_LIMIT' });
    }
    if (state.seen[indicatorIndex].has(identity)) return;
    state.seen[indicatorIndex].add(identity);
    state.matches[indicatorIndex].push(evidence);
  };
  const scan = (textFile, automaton) => {
    if (!automaton?.kinds.has(textFile.kind)) return;
    let state = 0;
    let starts;
    for (let index = 0; index < textFile.content.length; index += 1) {
      const character = characterAt(textFile.content, index, automaton.foldAscii);
      while (state !== 0 && !automaton.nodes[state].next.has(character)) state = automaton.nodes[state].fail;
      if (automaton.nodes[state].next.has(character)) state = automaton.nodes[state].next.get(character);
      for (let outputState = state; outputState !== -1; outputState = automaton.nodes[outputState].outputLink) {
        for (const output of automaton.nodes[outputState].outputs) {
          if (!textScopeMatches(output.scope, textFile.kind)) continue;
          const offset = index - output.length + 1;
          starts ??= lineStarts(textFile.content);
          const decodedLine = lineAt(starts, offset);
          const evidence = {
            file: textFile.file,
            line: textFile.decodedFrom?.line ?? decodedLine,
            indicator: output.indicatorIndex,
            indicatorType: 'text',
            snippet: lineSnippet(textFile.content, starts, decodedLine)
          };
          if (textFile.decodedFrom) {
            evidence.decodedLine = decodedLine;
            evidence.decodedFrom = textFile.decodedFrom;
            evidence.snippet = safeDecodedSnippet(evidence.snippet);
          }
          record(output.stateIndex, output.indicatorIndex, evidence,
            `${textFile.file}\0${textFile.decodedFrom?.line ?? ''}`
            + `\0${textFile.decodedFrom?.encodedLine ?? ''}`
            + `\0${textFile.decodedFrom?.depth ?? ''}`
            + `\0${textFile.decodedFrom?.sha256 ?? ''}\0${decodedLine}`);
        }
      }
    }
  };
  const textFiles = [
    { file: 'manifest.json', content: snapshot.manifestSource, kind: 'manifest' },
    ...snapshot.sources.map((source) => ({ file: source.path, content: source.content, kind: 'source' })),
    ...snapshot.decodedSources.map((source) => ({
      file: source.path,
      content: source.content,
      kind: 'source',
      decodedFrom: source.decodedFrom
    }))
  ];
  for (const textFile of textFiles) {
    scan(textFile, sensitive);
    scan(textFile, insensitive);
  }

  const files = snapshot.inventory.entries.filter((entry) => entry.type === 'file');
  const exactPaths = new Map(files.map((file) => [file.path, file]));
  const basenames = new Map();
  const hashes = new Map();
  for (const file of files) {
    const basename = path.posix.basename(file.path);
    if (!basenames.has(basename)) basenames.set(basename, []);
    basenames.get(basename).push(file);
    if (!hashes.has(file.sha256)) hashes.set(file.sha256, []);
    hashes.get(file.sha256).push(file);
  }
  for (let stateIndex = 0; stateIndex < states.length; stateIndex += 1) {
    const state = states[stateIndex];
    for (let indicatorIndex = 0; indicatorIndex < state.rule.indicators.length; indicatorIndex += 1) {
      const indicator = state.rule.indicators[indicatorIndex];
      if (indicator.type === 'path') {
        const exact = exactPaths.get(indicator.value);
        const matched = indicator.match === 'exact' ? (exact ? [exact] : []) : (basenames.get(indicator.value) ?? []);
        for (const file of matched) record(stateIndex, indicatorIndex, {
          file: file.path,
          indicator: indicatorIndex,
          indicatorType: indicator.type,
          snippet: `${indicator.match} path match: ${indicator.value}`
        }, file.path);
      } else if (indicator.type === 'file-sha256') {
        for (const file of hashes.get(indicator.value) ?? []) record(stateIndex, indicatorIndex, {
          file: file.path,
          indicator: indicatorIndex,
          indicatorType: indicator.type,
          sha256: file.sha256,
          snippet: `SHA-256 ${file.sha256}`
        }, file.path);
      } else if (indicator.type === 'package-sha256' && snapshot.inventory.sha256 === indicator.value) {
        record(stateIndex, indicatorIndex, {
          scope: 'package',
          indicator: indicatorIndex,
          indicatorType: indicator.type,
          sha256: snapshot.inventory.sha256,
          snippet: `Package SHA-256 ${snapshot.inventory.sha256}`
        }, snapshot.inventory.sha256);
      }
    }
  }

  const findings = [];
  for (const state of states) {
    const matched = state.matches.map((matches) => matches.length > 0);
    const triggered = state.rule.condition === 'all' ? matched.every(Boolean) : matched.some(Boolean);
    if (!triggered) continue;
    const evidence = state.matches.flat().sort((left, right) => compareText(left.file ?? '', right.file ?? '')
      || (left.line ?? 0) - (right.line ?? 0)
      || left.indicator - right.indicator);
    findings.push(createFinding({
      id: `RP:${state.pack.namespace}:${state.rule.id}`,
      title: state.rule.title,
      severity: state.rule.severity,
      confidence: state.rule.confidence,
      category: state.rule.category,
      description: state.rule.description,
      remediation: state.rule.remediation,
      references: state.rule.references
    }, evidence, {
      fingerprint: `RP:${state.pack.namespace}:${state.rule.id}`,
      rulePack: { namespace: state.pack.namespace, version: state.pack.version, ruleId: state.rule.id },
      condition: state.rule.condition
    }));
  }
  return findings;
}
