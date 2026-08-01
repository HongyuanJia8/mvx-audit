import { CONFIDENCE, REFERENCES, createFinding } from '../model.js';

const RULES = [
  {
    id: 'MVX201', title: 'Dynamic JavaScript evaluation', severity: 'critical', category: 'code-execution',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(/,
    description: 'A JavaScript string can be interpreted as executable code.',
    remediation: 'Replace dynamic evaluation with explicit data parsing and packaged, reviewable code.', references: [REFERENCES.remoteCode, REFERENCES.security]
  },
  {
    id: 'MVX202', title: 'Remote script source assignment', severity: 'critical', category: 'code-execution',
    pattern: /createElement\s*\(\s*[`'"]script[`'"]\s*\)[\s\S]{0,500}\.src\s*=\s*[`'"]https?:\/\//,
    description: 'Code assigns an HTTP(S) URL to a resource source, which may load remotely controlled script.',
    remediation: 'Bundle executable code with the extension and treat remote responses as data only.', references: [REFERENCES.remoteCode]
  },
  {
    id: 'MVX203', title: 'Potential DOM injection sink', severity: 'high', category: 'injection',
    pattern: /\.innerHTML\s*=|\bdocument\.write\s*\(|\.insertAdjacentHTML\s*\(/,
    description: 'A DOM API capable of interpreting HTML is used. Risk depends on whether the value is attacker-controlled.',
    remediation: 'Use textContent or construct DOM nodes explicitly; sanitize unavoidable HTML with a reviewed policy.', references: [REFERENCES.security], confidence: CONFIDENCE.MEDIUM
  },
  {
    id: 'MVX204', title: 'Wildcard window messaging', severity: 'high', category: 'messaging',
    pattern: /\.postMessage\s*\([^;\n]+,\s*[`'"]\*[`'"]\s*\)/,
    description: 'A message is sent to any origin, allowing unintended recipients to observe it.',
    remediation: 'Use an exact target origin and validate the origin and schema of every received message.', references: [REFERENCES.messaging]
  },
  {
    id: 'MVX205', title: 'Keystroke capture behavior', severity: 'high', category: 'surveillance',
    pattern: /addEventListener\s*\(\s*[`'"]key(?:down|up|press)[`'"]|\.onkey(?:down|up|press)\s*=/,
    description: 'The source observes user keystrokes. This can expose credentials and private text when broadly injected.',
    remediation: 'Avoid global key capture. Limit collection to an explicit, user-visible control and never retain sensitive input.', references: [REFERENCES.privacy]
  },
  {
    id: 'MVX206', title: 'Cookie enumeration', severity: 'high', category: 'sensitive-data',
    pattern: /chrome\.cookies\.(?:getAll|getAllCookieStores)\s*\(/,
    description: 'The extension enumerates cookie data accessible under its granted host permissions.',
    remediation: 'Avoid reading cookie values; narrow host permissions and process only the minimum metadata locally.', references: [REFERENCES.privacy]
  },
  {
    id: 'MVX207', title: 'Unencrypted network endpoint', severity: 'high', category: 'transport',
    pattern: /(?:fetch\s*\(\s*|\.open\s*\([^,]+,\s*)[`'"]http:\/\/(?!localhost(?::|\/)|127\.0\.0\.1(?::|\/))/,
    description: 'Source code communicates with a non-loopback endpoint over unencrypted HTTP.',
    remediation: 'Use authenticated HTTPS and avoid transmitting browsing or user data.', references: [REFERENCES.security]
  },
  {
    id: 'MVX208', title: 'Programmatic download creation', severity: 'medium', category: 'browser-control',
    pattern: /chrome\.downloads\.download\s*\(/,
    description: 'The extension can initiate a browser download.',
    remediation: 'Require an explicit user gesture, validate fixed HTTPS destinations, and use conflictAction safely.', references: [REFERENCES.permissions]
  },
  {
    id: 'MVX209', title: 'Clipboard read operation', severity: 'high', category: 'sensitive-data',
    pattern: /navigator\.clipboard\.read(?:Text)?\s*\(|document\.execCommand\s*\(\s*[`'"]paste/,
    description: 'The source reads clipboard content, which may contain secrets.',
    remediation: 'Read only after an explicit user action and avoid storage or transmission of clipboard data.', references: [REFERENCES.privacy]
  },
  {
    id: 'MVX211', title: 'Remote origin embedded in extension UI', severity: 'high', category: 'remote-content',
    pattern: /<iframe\b(?=[^>]{0,2000}\bsrc\s*=\s*["']https?:\/\/)[^>]*>/i,
    description: 'An extension page embeds a remotely controlled origin. That origin can present trusted-looking UI and observe interactions inside its frame.',
    remediation: 'Use packaged UI and treat remote responses as data. If framing is essential, allowlist one reviewed origin and apply a restrictive iframe sandbox.',
    references: [REFERENCES.security], confidence: CONFIDENCE.MEDIUM
  },
  {
    id: 'MVX212', title: 'Sensitive capability delegated to iframe', severity: 'high', category: 'sensitive-data',
    pattern: /<iframe\b(?=[^>]{0,2000}\ballow\s*=\s*["'][^"']*\b(?:clipboard-read|camera|microphone|geolocation)\b)[^>]*>/i,
    description: 'An iframe receives a sensitive browser capability through its Permissions Policy allowlist.',
    remediation: 'Remove sensitive iframe delegation or restrict it to the minimum trusted origin and a user-initiated workflow.',
    references: [REFERENCES.permissionsPolicy, REFERENCES.privacy], confidence: CONFIDENCE.HIGH
  }
];

function locate(content, pattern) {
  const match = content.match(pattern);
  if (!match) return null;
  const prefix = content.slice(0, match.index);
  const line = prefix.split('\n').length;
  const lineText = content.split('\n')[line - 1]?.trim() ?? match[0];
  return { line, snippet: lineText.slice(0, 240) };
}

function locateAll(content, pattern) {
  const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`;
  const globalPattern = new RegExp(pattern.source, flags);
  const matches = [];
  for (const match of content.matchAll(globalPattern)) {
    const prefix = content.slice(0, match.index);
    const line = prefix.split('\n').length;
    const lineText = content.split('\n')[line - 1]?.trim() ?? match[0];
    matches.push({ line, snippet: lineText.slice(0, 240) });
    if (matches.length >= 20) break;
  }
  return matches;
}

const UNSAFE_SNIPPET = /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u2028-\u202e\u2066-\u2069]/g;

function safeDecodedSnippet(value) {
  return value.replace(UNSAFE_SNIPPET, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function sourceEvidence(source, location) {
  if (!source.decodedFrom) return { file: source.path, ...location };
  return {
    file: source.path,
    line: source.decodedFrom.line,
    decodedLine: location.line,
    decodedFrom: source.decodedFrom,
    snippet: safeDecodedSnippet(location.snippet)
  };
}

export function analyzeSources(sources) {
  const findings = [];
  const executableSources = sources.filter((source) => !/\.json$/i.test(source.path));
  for (const rule of RULES) {
    const matches = [];
    for (const source of executableSources) {
      const locations = locateAll(source.content, rule.pattern);
      matches.push(...locations.map((location) => sourceEvidence(source, location)));
      if (matches.length >= 20) break;
    }
    if (matches.length > 0) findings.push(createFinding(rule, matches.slice(0, 20)));
  }

  for (const source of executableSources) {
    const listens = /chrome\.runtime\.onMessage(?:External)?\.addListener/.test(source.content);
    const privileged = /chrome\.(?:cookies|debugger|downloads|history|management|nativeMessaging|proxy|tabs)\./.test(source.content);
    const validatesSender = /sender\.(?:id|origin|url)/.test(source.content);
    if (listens && privileged && !validatesSender) {
      const location = locate(source.content, /chrome\.runtime\.onMessage(?:External)?\.addListener/);
      findings.push(createFinding({
        id: 'MVX210', title: 'Unvalidated privileged message bridge', severity: 'critical', confidence: CONFIDENCE.MEDIUM,
        category: 'capability-chain',
        description: 'A message handler invokes privileged Chrome APIs without an apparent sender check in the same file.',
        remediation: 'Allowlist senders, validate a strict message schema, and map messages to fixed least-privilege actions.',
        references: [REFERENCES.messaging, REFERENCES.security]
      }, sourceEvidence(source, location)));
    }
  }
  return findings;
}
