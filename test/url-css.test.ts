import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeUrl, sanitizeSrcset } from '../src/url.ts';
import { sanitizeStyle } from '../src/css.ts';

test('safe schemes pass', () => {
  assert.equal(sanitizeUrl('https://example.com/a'), 'https://example.com/a');
  assert.equal(sanitizeUrl('http://example.com'), 'http://example.com');
  assert.equal(sanitizeUrl('mailto:a@b.com'), 'mailto:a@b.com');
  assert.equal(sanitizeUrl('/relative/path'), '/relative/path');
  assert.equal(sanitizeUrl('#fragment'), '#fragment');
  assert.equal(sanitizeUrl('?query=1'), '?query=1');
  assert.equal(sanitizeUrl('//cdn.example.com/x'), '//cdn.example.com/x');
});

test('dangerous schemes are blocked', () => {
  assert.equal(sanitizeUrl('javascript:alert(1)'), null);
  assert.equal(sanitizeUrl('vbscript:msgbox(1)'), null);
  assert.equal(sanitizeUrl('data:text/html,<script>alert(1)</script>'), null);
  assert.equal(sanitizeUrl('file:///etc/passwd'), null);
});

test('scheme obfuscation via control chars is normalized then blocked', () => {
  assert.equal(sanitizeUrl('java\u0000script:alert(1)'), null);
  assert.equal(sanitizeUrl('  javascript:alert(1)  '), null);
  assert.equal(sanitizeUrl('java\tscript:alert(1)'), null);
});

test('backslash confusion is handled', () => {
  // Backslash before ':' breaks the scheme token, so it cannot classify as
  // javascript:; the value survives only as a non-executable relative path.
  const js = sanitizeUrl('javascript\\:alert(1)');
  assert.ok(js !== null && !/^javascript:/i.test(js), String(js));
  // Leading /\ normalizes to protocol-relative.
  assert.equal(sanitizeUrl('/\\evil.com'), '//evil.com');
});

test('entity-newline tricks are already decoded upstream, scheme still caught', () => {
  // The tokenizer turns jav&#x0A;ascript into "javascript\n:..." — controls
  // stripped here, so the scheme must classify as javascript.
  assert.equal(sanitizeUrl('javascript\n:alert(1)'), null);
});

test('data URL MIME restriction', () => {
  assert.equal(sanitizeUrl('data:image/png;base64,AAAA'), 'data:image/png;base64,AAAA');
  assert.equal(sanitizeUrl('data:,hello'), 'data:,hello'); // defaults to text/plain
  assert.equal(sanitizeUrl('data:text/plain;base64,AAAA'), 'data:text/plain;base64,AAAA');
  // SVG can carry script and must be rejected even under image/.
  assert.equal(sanitizeUrl('data:image/svg+xml,<svg onload=alert(1)>'), null);
  assert.equal(sanitizeUrl('data:text/html,<script>alert(1)</script>'), null);
});

test('srcset validates every candidate and drops on any unsafe one', () => {
  assert.equal(
    sanitizeSrcset('a.png 1x, https://x.com/b.png 2x'),
    'a.png 1x, https://x.com/b.png 2x'
  );
  assert.equal(sanitizeSrcset('safe.png 1x, javascript:alert(1) 2x'), null);
});

test('CSS: benign declarations pass and are canonical', () => {
  assert.equal(sanitizeStyle('color: red; font-size: 12px'), 'color: red; font-size: 12px');
});

test('CSS: expression() is removed', () => {
  assert.equal(sanitizeStyle('width: expression(alert(1))'), '');
  assert.equal(sanitizeStyle('width: -ms-expression(alert(1))'), '');
});

test('CSS: javascript url() is removed, image url kept', () => {
  assert.equal(sanitizeStyle('background: url(javascript:alert(1))'), '');
  const ok = sanitizeStyle('background: url(https://x.com/a.png)');
  assert.ok(ok.includes('url("https://x.com/a.png")'), ok);
});

test('CSS: escape obfuscation is decoded and caught', () => {
  assert.equal(sanitizeStyle('width: expr\\65 ssion(alert(1))'), '');
  assert.equal(sanitizeStyle('background: url("j\\61 vascript:alert(1)")'), '');
});

test('CSS: behavior and -moz-binding blocked', () => {
  assert.equal(sanitizeStyle('behavior: url(x.htc)'), '');
  assert.equal(sanitizeStyle('-moz-binding: url(x.xml#x)'), '');
});

test('CSS: at-rules and comments are rejected/stripped', () => {
  assert.equal(sanitizeStyle('@import url(evil.css)'), '');
  assert.equal(sanitizeStyle('color: /* secret */ red'), 'color: red');
});

test('CSS: custom properties dropped by default', () => {
  assert.equal(sanitizeStyle('--evil: x; color: red'), 'color: red');
});

test('CSS: idempotent canonical output', () => {
  const once = sanitizeStyle('color:red;;  font-weight : bold ;');
  assert.equal(sanitizeStyle(once), once);
});
