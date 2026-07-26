import assert from 'node:assert/strict';
import test from 'node:test';
import { parseCsv } from '../src/csv.js';

test('CSV parser handles BOM, quoted commas, escaped quotes, and CRLF', () => {
  const rows = parseCsv('\uFEFFid,name,notes\r\na,"quoted, name","a ""quote"""\r\n');
  assert.deepEqual(rows, [{ id: 'a', name: 'quoted, name', notes: 'a "quote"' }]);
});

test('CSV parser rejects malformed and resource-exhausting input', () => {
  assert.throws(() => parseCsv('a,b\n"unterminated,b\n'), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => parseCsv('a,b\n1,2\n3,4\n', { maxRows: 1 }), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => parseCsv('a,a\n1,2\n'), (error) => error.code === 'INVALID_CSV');
});
