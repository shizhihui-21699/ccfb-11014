/**
 * mXSS-safe HTML serializer (WHATWG §13.2.6 "serializing HTML fragments",
 * tightened where the spec's loose escaping has caused mutation XSS).
 *
 * mXSS happens when parse(serialize(x)) !== x in a security-relevant way. The
 * defenses here:
 *   1. Text and attribute values are escaped from *decoded* tree data, so
 *      entity-encoding tricks can't round-trip into markup.
 *   2. `>` is always escaped in text (the spec allows it unescaped; escaping
 *      it removes an entire class of `</style`-boundary confusion bugs).
 *   3. Attribute values are always double-quoted; ambiguous unquoted syntax
 *      is never emitted.
 *   4. Control characters that browsers strip on parse are emitted as
 *      numeric character references, so they cannot alter tokenization after
 *      a re-parse.
 *   5. Namespace decides tag casing and self-closing: SVG/MathML foreign
 *      elements always get an explicit end tag (or self-close when empty),
 *      HTML void elements never get one.
 *   6. No comments, DOCTYPE or processing instructions are ever emitted —
 *      the sanitizer discarded them and they carry no content.
 *
 * The walk is iterative (explicit stack) so deeply nested input cannot
 * overflow the call stack.
 */

import { NS_HTML, NS_MATHML, NS_SVG, type ElementNode, type Node } from './types.ts';

const HTML_VOID = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr',
]);

const RAWTEXT_TAGS = new Set(['style', 'script', 'xmp', 'iframe', 'noembed', 'noframes']);
const RCDATA_TAGS = new Set(['title', 'textarea']);

interface CloseMarker {
  close: ElementNode;
}

export function serialize(root: ElementNode): string {
  const out: string[] = [];
  const stack: (Node | CloseMarker)[] = [];
  for (let i = root.children.length - 1; i >= 0; i--) stack.push(root.children[i]!);

  while (stack.length) {
    const item = stack.pop()!;

    if ('close' in item) {
      out.push('</' + item.close.tag + '>');
      continue;
    }
    if (item.type === 'text') {
      out.push(escapeText(item.data));
      continue;
    }

    const el = item;
    out.push(openTag(el));

    if (el.namespace === NS_HTML && HTML_VOID.has(el.tag)) continue;

    if (el.children.length === 0) {
      if (el.namespace === NS_SVG || el.namespace === NS_MATHML) {
        out[out.length - 1] = out[out.length - 1]!.replace(/>$/, '/>');
      } else {
        out.push('</' + el.tag + '>');
      }
      continue;
    }

    const rawText =
      el.namespace === NS_HTML && (RAWTEXT_TAGS.has(el.tag) || RCDATA_TAGS.has(el.tag));
    if (rawText) {
      for (const child of el.children) {
        if (child.type === 'text') out.push(child.data.replace(/\u0000/g, '�'));
      }
      out.push('</' + el.tag + '>');
      continue;
    }

    stack.push({ close: el });
    for (let i = el.children.length - 1; i >= 0; i--) stack.push(el.children[i]!);
  }

  return out.join('');
}

function openTag(el: ElementNode): string {
  let s = '<' + el.tag;
  for (const attr of el.attrs) {
    s += ' ' + attr.name + '="' + escapeAttr(attr.value) + '"';
  }
  return s + '>';
}

// ------------------------------------------------------------- escaping

function escapeText(s: string): string {
  let out = '';
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    switch (ch) {
      case '&': out += '&amp;'; break;
      case '<': out += '&lt;'; break;
      case '>': out += '&gt;'; break;
      case ' ':
        out += '&nbsp;';
        break;
      default:
        out += needsNumericRef(code) ? '&#x' + code.toString(16) + ';' : ch;
    }
  }
  return out;
}

function escapeAttr(s: string): string {
  let out = '';
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    switch (ch) {
      case '&': out += '&amp;'; break;
      case '"': out += '&quot;'; break;
      case '<': out += '&lt;'; break;
      case '>': out += '&gt;'; break;
      case ' ': out += '&nbsp;'; break;
      case '`': out += '&#96;'; break;
      default:
        out += needsNumericRef(code) ? '&#x' + code.toString(16) + ';' : ch;
    }
  }
  return out;
}

/**
 * Non-whitespace C0 controls and U+007F: browsers either replace or strip
 * these during tokenization, so leaving them raw would make re-parse output
 * differ. Encoding them preserves the byte visibly and stably. U+2028/U+2029
 * inside attributes are treated as whitespace by HTML parsers.
 */
function needsNumericRef(code: number): boolean {
  if (code <= 0x1f && code !== 0x09 && code !== 0x0a && code !== 0x0d) return true;
  if (code === 0x7f) return true;
  if (code === 0x2028 || code === 0x2029) return true;
  return false;
}
