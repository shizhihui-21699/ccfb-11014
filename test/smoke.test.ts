import { test } from 'node:test';
import assert from 'node:assert/strict';
import { purify, purifyStable, purifyDetailed, TreeBuilder, serialize } from '../src/index.ts';

test('smoke: basic tag and text round-trip', () => {
  assert.equal(purify('<p>hello <b>world</b></p>'), '<p>hello <b>world</b></p>');
});

test('smoke: event handler removed', () => {
  const out = purify('<img src="x" onerror="alert(1)">');
  assert.ok(!/onerror/i.test(out), out);
  assert.ok(/src="x"/.test(out), out);
});

test('smoke: script element subtree dropped', () => {
  assert.equal(purify('<p>a</p><script>alert(1)</script><p>b</p>'), '<p>a</p><p>b</p>');
});

test('smoke: javascript: URL blocked', () => {
  const out = purify('<a href="javascript:alert(1)">x</a>');
  assert.ok(!/javascript/i.test(out), out);
});

test('smoke: idempotent', () => {
  const samples = [
    '<p>hello <b>world</b></p>',
    '<img src="x" onerror="alert(1)">',
    '<a href="javascript:alert(1)">x</a>',
    '<svg><script>1</script></svg>',
    '<table><tr><td>x</td></tr></table>',
    '<math><mi>x</mi></math>',
  ];
  for (const s of samples) {
    const once = purify(s);
    assert.equal(purify(once), once, `not idempotent: ${s} -> ${once}`);
  }
});

test('debug: parse tree', () => {
  const { tree, html } = purifyDetailed('<div><b>bold</b><i>italic</i>');
  function walk(n: any, d = 0): string {
    const pad = '  '.repeat(d);
    if (n.type === 'text') return pad + 'TEXT ' + JSON.stringify(n.data) + '\n';
    let s = pad + '<' + n.tag + '>\n';
    for (const c of n.children) s += walk(c, d + 1);
    return s;
  }
  console.log(walk(tree));
  console.log(html);
});
