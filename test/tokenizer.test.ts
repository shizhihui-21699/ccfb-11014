import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Tokenizer } from '../src/tokenizer.ts';
import type { Token } from '../src/types.ts';

function tokenize(input: string, foreign = false): Token[] {
  const out: Token[] = [];
  let last: string | null = null;
  const t = new Tokenizer({
    onToken: (tok) => {
      out.push(tok);
      if (tok.kind === 'startTag') last = tok.tag;
      if (tok.kind === 'endTag') last = null;
    },
    isForeign: () => foreign,
    getLastStartTag: () => last,
  });
  t.parse(input);
  return out.filter((t) => t.kind !== 'eof');
}

test('tags and attributes are lower-cased, duplicates keep first', () => {
  const toks = tokenize('<DIV CLASS="a" class="b" id=z>');
  const tag = toks[0]!;
  assert.equal(tag.kind, 'startTag');
  if (tag.kind !== 'startTag') return;
  assert.equal(tag.tag, 'div');
  assert.deepEqual(
    tag.attrs.map((a) => [a.name, a.value]),
    [['class', 'a'], ['id', 'z']]
  );
});

test('quoted attribute values including entities', () => {
  const toks = tokenize('<a href="?x=1&amp;y=2" title=\'q\'>');
  const tag = toks[0];
  assert.ok(tag && tag.kind === 'startTag');
  if (tag.kind !== 'startTag') return;
  assert.equal(tag.attrs[0]!.value, '?x=1&y=2');
  assert.equal(tag.attrs[1]!.value, 'q');
});

test('unquoted attribute terminates on whitespace', () => {
  const toks = tokenize('<input value=hello world>');
  const tag = toks[0];
  assert.ok(tag && tag.kind === 'startTag');
  if (tag.kind !== 'startTag') return;
  assert.equal(tag.attrs[0]!.name, 'value');
  assert.equal(tag.attrs[0]!.value, 'hello');
  assert.equal(tag.attrs[1]!.name, 'world');
});

test('named and numeric character references in text', () => {
  const text = tokenize('&amp;&#65;&#x42;&nbsp;').filter((t) => t.kind === 'character').map((t) => t.kind === 'character' && t.data).join('');
  assert.equal(text, '&AB ');
});

test('numeric reference null -> replacement char, win-1252 mapping', () => {
  const a = tokenize('&#0;').find((t) => t.kind === 'character');
  assert.equal(a && a.kind === 'character' && a.data, '�');
  const euro = tokenize('&#128;').find((t) => t.kind === 'character');
  assert.equal(euro && euro.kind === 'character' && euro.data, '€');
});

test('legacy entity needs trailing boundary in data state', () => {
  // &notit; should NOT decode &not; because 'i' follows.
  const text = tokenize('&notit;').filter((t) => t.kind === 'character').map((t) => t.kind === 'character' && t.data).join('');
  assert.equal(text, '&notit;');
  const ok = tokenize('&not;').filter((t) => t.kind === 'character').map((t) => t.kind === 'character' && t.data).join('');
  assert.equal(ok, '¬');
});

test('raw text element content is not parsed as tags', () => {
  const toks = tokenize('<style>.a{color:red}</style><p>x</p>');
  // The style text must survive verbatim and the </style> end tag must fire.
  assert.ok(toks.some((t) => t.kind === 'endTag' && t.kind === 'endTag' && t.tag === 'style'));
  const p = toks.find((t) => t.kind === 'startTag' && t.kind === 'startTag' && t.tag === 'p');
  assert.ok(p);
});

test('script escape states: </script> inside <!-- ... --> does not end the script', () => {
  // Per spec, once a <script> sees <!-- it enters the escaped states; a
  // </script> there is ignored until a --> restores normal script data.
  const toks = tokenize('<script><!-- </script> still inside --></script><p>after</p>');
  const ends = toks.filter((t) => t.kind === 'endTag' && t.kind === 'endTag' && t.tag === 'script');
  assert.equal(ends.length, 1);
  const p = toks.find((t) => t.kind === 'startTag' && t.kind === 'startTag' && t.tag === 'p');
  assert.ok(p, 'content after the real </script> must still parse');
});

test('script without escape marker ends at first </script>', () => {
  const toks = tokenize('<script>alert(1)</script><p>after</p>');
  const ends = toks.filter((t) => t.kind === 'endTag' && t.kind === 'endTag' && t.tag === 'script');
  assert.equal(ends.length, 1);
  assert.ok(toks.some((t) => t.kind === 'startTag' && t.kind === 'startTag' && t.tag === 'p'));
});

test('self-closing flag is captured', () => {
  const toks = tokenize('<svg/>');
  assert.equal(toks[0]!.kind, 'startTag');
  if (toks[0]!.kind !== 'startTag') return;
  assert.equal(toks[0]!.selfClosing, true);
});

test('comments and doctypes are tokenized but carry no content we keep', () => {
  const toks = tokenize('<!-- c --><!DOCTYPE html>x');
  assert.ok(toks.some((t) => t.kind === 'comment'));
  assert.ok(toks.some((t) => t.kind === 'doctype'));
  assert.ok(toks.some((t) => t.kind === 'character'));
});

test('CDATA only recognized in foreign content', () => {
  const foreign = tokenize('<![CDATA[x<y]]>', true).filter((t) => t.kind === 'character').map((t) => t.kind === 'character' && t.data).join('');
  assert.equal(foreign, 'x<y');
  const html = tokenize('<![CDATA[x<y]]>', false);
  assert.ok(html.some((t) => t.kind === 'comment')); // bogus comment in HTML
});

test('null bytes become replacement characters', () => {
  const toks = tokenize('<a title="a\u0000b">x\u0000y</a>');
  const tag = toks[0];
  assert.ok(tag && tag.kind === 'startTag');
  if (tag.kind !== 'startTag') return;
  assert.equal(tag.attrs[0]!.value, 'a�b');
});
