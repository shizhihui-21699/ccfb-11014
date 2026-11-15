import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { purify, purifyDetailed } from '../src/index.ts';
import { findExecutionPrimitives } from './oracle.ts';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

interface Vector {
  title: string;
  payload: string;
  expected?: string | null;
}

const dompurify = JSON.parse(
  readFileSync(join(root, 'data/build/dompurify-vectors.json'), 'utf8')
) as Vector[];
const manual = JSON.parse(
  readFileSync(join(root, 'data/vectors/manual-vectors.json'), 'utf8')
) as Vector[];

function assertSecureVector(v: Vector): void {
  const once = purify(v.payload);

  // Core security property: no executable primitive survives.
  const findings = findExecutionPrimitives(once);
  assert.deepEqual(
    findings,
    [],
    `[${v.title}] unsafe output for payload ${JSON.stringify(v.payload)}\n  output: ${once}\n  findings: ${findings.join('; ')}`
  );

  // mXSS guard: re-parsing and re-serializing the clean output is a fixed
  // point. If it changed, parse/serialize disagree — the classic mXSS shape.
  const twice = purify(once);
  assert.equal(
    twice,
    once,
    `[${v.title}] not idempotent\n  first:  ${once}\n  second: ${twice}`
  );

  // The clean output must itself be safe under the oracle even when fed back
  // through the parser (covered by idempotence + oracle above, asserted again
  // explicitly so a regression message names the property).
  assert.deepEqual(findExecutionPrimitives(twice), []);
}

test('DOMPurify official fixture vectors (223): all neutralized and idempotent', () => {
  let withAlert = 0;
  for (const v of dompurify) {
    if (/alert|script|onerror|onload|javascript|vbscript/i.test(v.payload)) withAlert++;
    assertSecureVector(v);
  }
  assert.ok(withAlert > 50, `expected many attack vectors, saw ${withAlert}`);
});

test('manual high-risk vector list: all neutralized and idempotent', () => {
  for (const v of manual) assertSecureVector(v);
  assert.ok(manual.length >= 50);
});

test('sanitized output preserves intended safe content', () => {
  // A representative benign document must survive structurally.
  const input =
    '<p>Hello <strong>world</strong>, <a href="https://example.com">link</a></p>' +
    '<ul><li>one</li><li>two</li></ul>' +
    '<img src="/img/a.png" alt="a">';
  const out = purify(input);
  assert.ok(out.includes('<strong>world</strong>'), out);
  assert.ok(out.includes('href="https://example.com"'), out);
  assert.ok(out.includes('<li>one</li>'), out);
  assert.ok(out.includes('src="/img/a.png"'), out);
});

test('every attack payload containing alert() emits no executable residue', () => {
  for (const v of [...dompurify, ...manual]) {
    if (!/alert/i.test(v.payload)) continue;
    const { html } = purifyDetailed(v.payload);
    // The oracle parses real attributes (ignoring entity-escaped text), so an
    // `onerror` that survives only as `&lt;img onerror=...` text is correctly
    // treated as inert. Any real surviving handler/scheme fails here.
    const findings = findExecutionPrimitives(html);
    assert.deepEqual(findings, [], `[${v.title}] residual executable:\n${html}`);
  }
});
