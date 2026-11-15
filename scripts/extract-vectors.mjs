// Converts the downloaded DOMPurify fixtures (ESM) into plain JSON the test
// suite can import without executing third-party code.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const src = join(root, 'data/vectors/dompurify-expect.mjs');
const mod = await import('file://' + src);
const cases = mod.default;

const clean = cases.map((c) => ({
  title: String(c.title ?? ''),
  payload: String(c.payload ?? ''),
  expected: c.expected == null ? null : String(c.expected),
}));

const out = join(root, 'data/build/dompurify-vectors.json');
writeFileSync(out, JSON.stringify(clean, null, 0));
console.log(`extracted ${clean.length} vectors -> ${out}`);
