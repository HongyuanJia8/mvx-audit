import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { MvxError } from './errors.js';

export async function readBoundedRegularFile(filePath, {
  maxBytes,
  label,
  limitCode = 'SCAN_LIMIT',
  missingCode = 'INPUT_NOT_FOUND',
  unsafeCode = 'UNSAFE_INPUT'
}) {
  let handle;
  try {
    handle = await open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  } catch (error) {
    if (error.code === 'ELOOP') {
      throw new MvxError(`${label} may not be a symbolic link`, { code: unsafeCode, cause: error });
    }
    throw new MvxError(`Cannot read ${label}: ${filePath}`, { code: missingCode, cause: error });
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new MvxError(`${label} must be a regular file`, { code: unsafeCode });
    if (stat.size > maxBytes) throw new MvxError(`${label} exceeds ${maxBytes} bytes`, { code: limitCode });
    const chunks = [];
    let total = 0;
    while (total <= maxBytes) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1 - total));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      total += bytesRead;
    }
    if (total > maxBytes) throw new MvxError(`${label} exceeds ${maxBytes} bytes`, { code: limitCode });
    return Buffer.concat(chunks, total);
  } finally {
    await handle.close();
  }
}
