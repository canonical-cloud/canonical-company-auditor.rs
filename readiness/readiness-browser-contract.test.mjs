import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('native evidence pattern compiles under HTML Unicode-set rules and rejects URLs', async () => {
  const source = await readFile(new URL('./browser.mjs', import.meta.url), 'utf8');
  const match = source.match(/input\.pattern = String\.raw`([^`]+)`/);
  assert.ok(match, 'browser must declare the explicit native evidence pattern');
  const pattern = new RegExp(`^(?:${match[1]})$`, 'v');
  for (const value of ['vault:e-001', 'repo.commit_12', 'a']) assert.equal(pattern.test(value), true);
  for (const value of ['https://example.invalid/private', '../file', 'a b', 'x'.repeat(129)]) assert.equal(pattern.test(value), false);
});
