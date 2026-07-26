import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

export async function writeExtension(root, manifest, files = {}) {
  await mkdir(root, { recursive: true });
  await writeFile(path.join(root, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, content, 'utf8');
  }
  return root;
}

export function captureStreams() {
  let stdout = '';
  let stderr = '';
  return {
    streams: {
      stdout: { write(value) { stdout += value; } },
      stderr: { write(value) { stderr += value; } }
    },
    output() { return { stdout, stderr }; }
  };
}
