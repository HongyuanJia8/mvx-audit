import { CONFIDENCE, createFinding } from '../model.js';

const FORMAT_LABELS = Object.freeze({
  webassembly: 'WebAssembly',
  elf: 'ELF',
  'windows-executable': 'Windows executable',
  'mach-o': 'Mach-O'
});

export function analyzePackage(executableFiles) {
  if (executableFiles.length === 0) return [];
  return [createFinding({
    id: 'MVX003',
    title: 'Opaque executable payload packaged',
    severity: 'medium',
    confidence: CONFIDENCE.HIGH,
    category: 'code-execution',
    description: 'The package contains executable-format bytes that MVX records but does not parse as source code.',
    remediation: 'Review the identified payload with a format-specific static analyzer and verify how extension code reaches or instantiates it.',
    references: ['https://developer.mozilla.org/docs/WebAssembly/Guides/Concepts']
  }, executableFiles.map((entry) => ({
    file: entry.path,
    format: entry.format,
    sha256: entry.sha256,
    snippet: `${FORMAT_LABELS[entry.format]} signature; ${entry.bytes} bytes; SHA-256 ${entry.sha256}`
  })) )];
}
