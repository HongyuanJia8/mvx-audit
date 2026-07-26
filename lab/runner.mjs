#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import process from 'node:process';

const OUTPUT = '/output/events.jsonl';
const CHROME = '/usr/bin/chromium';
const MAX_EVENT_STRING = 16_384;

function bounded(value, depth = 0) {
  if (depth > 5) return '[depth-limit]';
  if (typeof value === 'string') return value.slice(0, MAX_EVENT_STRING);
  if (Array.isArray(value)) return value.slice(0, 100).map((entry) => bounded(entry, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 100).map(([key, entry]) => [key, bounded(entry, depth + 1)]));
  return value;
}

let writeChain = Promise.resolve();
function emit(type, data = {}, target) {
  const event = bounded({ schemaVersion: 1, timestamp: new Date().toISOString(), type, ...(target ? { target } : {}), data });
  writeChain = writeChain.then(() => appendFile(OUTPUT, `${JSON.stringify(event)}\n`, 'utf8'));
  return writeChain;
}

class Cdp {
  constructor(input, output) {
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = [];
    this.input = input;
    this.output = output;
    this.buffer = '';
    this.ready = Promise.resolve();
    output.setEncoding('utf8');
    output.on('data', (chunk) => {
      this.buffer += chunk;
      let boundary;
      while ((boundary = this.buffer.indexOf('\0')) >= 0) {
        const data = this.buffer.slice(0, boundary);
        this.buffer = this.buffer.slice(boundary + 1);
        if (data.length > 0) this.receive(JSON.parse(data));
      }
    });
    output.once('close', () => this.rejectPending(new Error('Chromium DevTools pipe closed')));
    output.once('error', (error) => this.rejectPending(error));
  }

  rejectPending(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  receive(message) {
    if (message.id) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
      return;
    }
    for (const listener of this.listeners) listener(message);
  }

  async send(method, params = {}, sessionId) {
    await this.ready;
    const id = this.nextId++;
    const result = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Chromium DevTools command timed out: ${method}`));
      }, 5_000);
      this.pending.set(id, { resolve, reject, timer });
    });
    this.input.write(`${JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })}\0`);
    return result;
  }

  on(listener) { this.listeners.push(listener); }
  close() { this.input.end(); }
}

function canaryPage(scenario) {
  const entries = Object.entries(scenario.canaries);
  const escapeHtml = (value) => String(value).replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
  const fields = entries.map(([name, value]) => `<input name="${escapeHtml(name)}" value="${escapeHtml(value)}">`).join('');
  const storage = JSON.stringify(scenario.canaries).replaceAll('<', '\\u003c');
  return `<!doctype html><meta charset="utf-8"><title>MVX Canary</title><form id="mvx-protected" data-canary="intact">${fields}</form><script>const c=${storage};for(const [k,v] of Object.entries(c))localStorage.setItem(k,v);document.cookie='mvx_session='+encodeURIComponent(c.sessionCookie||Object.values(c)[0])+'; Secure; SameSite=Strict';</script>`;
}

function isExtensionInitiator(initiator) {
  return JSON.stringify(initiator ?? {}).includes('chrome-extension://');
}

async function main() {
  if (process.env.MVX_LAB_CONTAINER !== '1' || process.argv[2] !== '--acknowledge-risk') {
    throw new Error('Runner is container-only and requires --acknowledge-risk');
  }
  const scenario = JSON.parse(await readFile('/scenario.json', 'utf8'));
  const target = new URL(scenario.targetUrl);
  const canaries = Object.entries(scenario.canaries ?? {});
  if (scenario.schemaVersion !== 1 || target.protocol !== 'https:' || canaries.length === 0 || canaries.some(([, value]) => typeof value !== 'string' || value.length < 16)) {
    throw new Error('Invalid scenario');
  }
  const durationMs = Math.min(30_000, Math.max(1_000, scenario.durationMs ?? 8_000));
  await writeFile(OUTPUT, '', { encoding: 'utf8', mode: 0o600 });
  const browserVersion = spawnSync(CHROME, ['--version'], { encoding: 'utf8' }).stdout.trim();
  await emit('lab.started', { browser: browserVersion, image: process.env.MVX_LAB_IMAGE_ID ?? 'unreported', network: 'none', durationMs });

  const chrome = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check',
    '--remote-debugging-pipe', '--user-data-dir=/tmp/chrome-profile',
    '--disable-extensions-except=/sample', '--load-extension=/sample', 'about:blank'
  ], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
  let chromeError = '';
  chrome.stderr.on('data', (chunk) => { chromeError = `${chromeError}${chunk}`.slice(-8_192); });
  let cdp;
  try {
    cdp = new Cdp(chrome.stdio[3], chrome.stdio[4]);
    const sessions = new Map();
    const initialized = new Set();
    const requestInitiators = new Map();
    const pageReady = new Promise((resolve) => {
      cdp.on((message) => {
        if (message.method === 'Target.attachedToTarget') {
          const { sessionId, targetInfo } = message.params;
          sessions.set(sessionId, targetInfo);
          void (async () => {
            if (initialized.has(sessionId)) return;
            initialized.add(sessionId);
            await Promise.all([
              cdp.send('Runtime.enable', {}, sessionId),
              cdp.send('Network.enable', {}, sessionId),
              cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] }, sessionId),
              targetInfo.type === 'page' ? cdp.send('Page.enable', {}, sessionId) : Promise.resolve()
            ]);
            await cdp.send('Runtime.runIfWaitingForDebugger', {}, sessionId).catch(() => {});
            if (targetInfo.type === 'page') resolve(sessionId);
          })().catch((error) => emit('lab.error', { message: `target setup: ${error.message}` }, targetInfo.url));
        }
        if (message.method === 'Network.requestWillBeSent') {
          requestInitiators.set(message.params.requestId, message.params.initiator);
          if (message.params.type === 'Document' && isExtensionInitiator(message.params.initiator)) {
            void emit('navigation.attempt', { from: message.params.documentURL, to: message.params.request.url, initiator: 'extension' }, message.params.request.url);
          }
        }
        if (message.method === 'Fetch.requestPaused') {
          const request = message.params.request;
          const url = new URL(request.url);
          const target = new URL(scenario.targetUrl);
          if (url.href === target.href) {
            const body = Buffer.from(canaryPage(scenario)).toString('base64');
            void cdp.send('Fetch.fulfillRequest', { requestId: message.params.requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' }], body }, message.sessionId);
          } else if (['http:', 'https:'].includes(url.protocol)) {
            void emit('network.request', {
              url: request.url, method: request.method, headers: request.headers, postData: request.postData ?? null,
              initiator: isExtensionInitiator(requestInitiators.get(message.params.networkId)) ? 'extension' : 'unknown',
              disposition: 'blocked-external'
            }, request.url);
            void cdp.send('Fetch.failRequest', { requestId: message.params.requestId, errorReason: 'Aborted' }, message.sessionId);
          } else {
            void cdp.send('Fetch.continueRequest', { requestId: message.params.requestId }, message.sessionId);
          }
        }
        if (message.method === 'Browser.downloadWillBegin') {
          void emit('download.attempt', { url: message.params.url, suggestedFilename: message.params.suggestedFilename, userGesture: false }, message.params.url);
        }
      });
    });
    await cdp.send('Target.setDiscoverTargets', { discover: true });
    await cdp.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
    await cdp.send('Browser.setDownloadBehavior', { behavior: 'deny', eventsEnabled: true });
    const pageSession = await Promise.race([
      pageReady,
      new Promise((_, reject) => setTimeout(() => reject(new Error('page target was not attached')), 5_000))
    ]);
    await cdp.send('Page.navigate', { url: scenario.targetUrl }, pageSession);
    await new Promise((resolve) => setTimeout(resolve, durationMs));
    const state = await cdp.send('Runtime.evaluate', {
      expression: `(() => { const node=document.querySelector('#mvx-protected'); return {url:location.href, exists:!!node, marker:node?.getAttribute('data-canary'), html:node?.innerHTML?.slice(0,4096)} })()`,
      returnByValue: true
    }, pageSession);
    const value = state.result?.value;
    if (!value?.exists || value.marker !== 'intact') await emit('dom.mutation', { protectedCanaryChanged: true, details: value ?? null }, scenario.targetUrl);
    await emit('lab.completed', { sessionsObserved: sessions.size });
  } catch (error) {
    await emit('lab.error', { message: error.message, browserStderr: chromeError });
  } finally {
    if (cdp) cdp.close();
    chrome.kill('SIGTERM');
    await Promise.race([new Promise((resolve) => chrome.once('exit', resolve)), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    if (chrome.exitCode === null) chrome.kill('SIGKILL');
    await writeChain;
  }
}

await main().catch(async (error) => {
  await emit('lab.error', { message: error.message });
  await writeChain;
  process.exitCode = 2;
});
