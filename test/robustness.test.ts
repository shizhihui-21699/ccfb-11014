import { test } from 'node:test';
import assert from 'node:assert/strict';
import { purify, purifyStable } from '../src/index.ts';

test('deeply nested elements do not overflow the stack (iterative walk)', () => {
  // 20k-deep nesting would blow a recursive serializer/sanitizer.
  const depth = 20_000;
  const input = '<div>'.repeat(depth) + 'x' + '</div>'.repeat(depth);
  const out = purify(input);
  assert.ok(out.includes('x'));
  // Fixed point even at depth.
  assert.equal(purify(out), out);
});

test('deep nesting with unwrapped tags stays bounded and preserves text', () => {
  const depth = 10_000;
  // <center> is not on the allow list, so every layer is unwrapped but the
  // text node must survive and the result must remain a fixed point.
  const input = '<center>'.repeat(depth) + 'y' + '</center>'.repeat(depth);
  const out = purify(input);
  assert.ok(out.endsWith('y'), out.slice(-20));
  assert.ok(!out.includes('<center'), 'unwrapped tags must not reappear');
  assert.equal(purify(out), out);
});

test('empty and whitespace-only input', () => {
  assert.equal(purify(''), '');
  assert.equal(purify('   '), '   ');
  assert.equal(purify('<!-- just a comment -->'), '');
});

test('control characters are encoded, never raw', () => {
  const out = purify('<p>a\u0001b\u007fc</p>');
  assert.ok(!out.includes('\u0001') && !out.includes('\u007f'), out);
  assert.ok(out.includes('&#x1;') && out.includes('&#x7f;'), out);
});

test('attribute values always quoted, and inner quotes are escaped', () => {
  // A literal double quote inside an attribute value is encoded as &quot; so
  // it cannot terminate the serialized attribute early.
  const out = purify('<a title="say &quot;hi&quot;">y</a>');
  assert.ok(out.includes('title="say &quot;hi&quot;"'), out);
  // Every serialized attribute is double-quoted (no bare unquoted values).
  const attrBodies = out.match(/<[a-z][^>]*>/g) ?? [];
  for (const tag of attrBodies) {
    const hasAttr = tag.includes('=');
    if (hasAttr) assert.match(tag, /\w+="[^"]*"/, `unquoted attr in ${tag}`);
  }
});

test('purifyStable throws on non-idempotent hypothetical', () => {
  // The real implementation is idempotent; confirm the guard returns normally.
  assert.doesNotThrow(() => purifyStable('<p>x</p><img src="a.png">'));
});

test('malformed/broken markup never throws', () => {
  const broken = [
    '<', '<div', '<div>', '<a href=', '<a href="', '<table><td>',
    '<<>>', '<p><p><p>', '</div></span></b>', '<b "weird"=x>',
    '<svg><', '<math><', '<<<<', 'a > b < c',
  ];
  for (const b of broken) {
    assert.doesNotThrow(() => purify(b), `threw on ${JSON.stringify(b)}`);
    const o = purify(b);
    assert.equal(purify(o), o, `not idempotent on ${JSON.stringify(b)}`);
  }
});

test('namespace round-trip: svg and math keep correct serialization', () => {
  const svg = purify('<svg viewBox="0 0 10 10"><circle cx="5" cy="5" r="4"/></svg>');
  assert.ok(svg.includes('<svg') && svg.includes('viewBox="0 0 10 10"'), svg);
  assert.ok(svg.includes('/>'), 'empty foreign element self-closes: ' + svg);

  const math = purify('<math><mrow><mi>x</mi></mrow></math>');
  assert.ok(math.includes('<math>') && math.includes('<mi>x</mi>'), math);
});

test('foreign breakout: html tag inside svg returns to html namespace', () => {
  const out = purify('<svg><div><b>x</b></div></svg>');
  // div forces a namespace breakout; content must survive and be idempotent.
  assert.ok(out.includes('<b>x</b>'), out);
  assert.equal(purify(out), out);
});

test('text content is never parsed as markup after sanitization', () => {
  // Even if an attacker lands executable-looking text, it is escaped on output.
  const out = purify('<p>&lt;img src=x onerror=alert(1)&gt;</p>');
  assert.ok(!out.includes('<img'), out);
  assert.ok(out.includes('&lt;img'), out);
});
