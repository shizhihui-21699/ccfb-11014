/**
 * Shared security oracle: decide whether a serialized HTML fragment could
 * still execute script when parsed by a browser.
 *
 * The oracle parses each tag's attribute *names* properly (skipping quoted
 * values) so that an `onerror` sitting inside a quoted attribute *value* is
 * not mistaken for a real handler. It inspects the serialized output, so any
 * entity-encoded payload has already been collapsed by the sanitizer's parser
 * and appears here in its decoded form if it survived.
 */

const URL_ATTRS = new Set([
  'href', 'src', 'action', 'cite', 'poster', 'background', 'longdesc',
  'xlink:href', 'xml:base', 'usemap', 'data', 'formaction', 'srcset', 'imagesrcset',
]);

interface ParsedAttr {
  name: string;
  value: string;
  quoted: boolean;
}

const isSpace = (ch: string | undefined): boolean =>
  ch === ' ' || ch === '\t' || ch === '\n' || ch === '\f' || ch === '\r';

/** Parse the attributes of one serialized tag string (without the <>). */
function parseAttrs(tagInner: string): ParsedAttr[] {
  const attrs: ParsedAttr[] = [];
  const n = tagInner.length;
  let i = 0;
  // Skip element name.
  while (i < n && !isSpace(tagInner[i])) i++;

  while (i < n) {
    while (i < n && isSpace(tagInner[i])) i++;
    if (i >= n) break;
    // Read attribute name up to whitespace, '=' or '/'.
    const nameStart = i;
    while (i < n && !isSpace(tagInner[i]) && tagInner[i] !== '=' && tagInner[i] !== '/') i++;
    const name = tagInner.slice(nameStart, i);
    let value = '';
    let quoted = false;

    // Skip spaces before a possible '='.
    while (i < n && isSpace(tagInner[i])) i++;
    if (tagInner[i] === '=') {
      i++;
      while (i < n && isSpace(tagInner[i])) i++;
      const q = tagInner[i];
      if (q === '"' || q === "'") {
        quoted = true;
        i++;
        const valStart = i;
        while (i < n && tagInner[i] !== q) i++;
        value = tagInner.slice(valStart, i);
        if (i < n) i++; // closing quote
      } else {
        const valStart = i;
        while (i < n && !isSpace(tagInner[i])) i++;
        value = tagInner.slice(valStart, i);
      }
    } else if (tagInner[i] === '/') {
      i++; // self-closing slash, not part of any attribute
    }

    if (name) attrs.push({ name: name.toLowerCase(), value, quoted });
  }
  return attrs;
}

/** Returns human-readable reasons the HTML is unsafe; empty means safe. */
export function findExecutionPrimitives(html: string): string[] {
  const findings: string[] = [];
  const lower = html.toLowerCase();

  if (/<\s*(script|iframe|object|embed|applet|frame|frameset)\b/.test(lower)) {
    findings.push('script-capable element present');
  }

  const tags = html.match(/<[^>]*>/g) ?? [];
  for (const tag of tags) {
    if (!/^<\/?[a-zA-Z]/.test(tag)) continue; // skip comments / doctypes / text
    const inner = tag.slice(1, -1).replace(/\/$/, '');
    const attrs = parseAttrs(inner);

    for (const a of attrs) {
      // 1. Real event handler attribute (name only — values are ignored).
      if (a.name.startsWith('on') && a.name.length > 2) {
        findings.push(`event handler attribute: ${a.name}`);
      }
      // 2. Executable scheme only in attributes that actually navigate/fetch.
      if (URL_ATTRS.has(a.name) && /(?:javascript|vbscript|livescript)\s*:/i.test(a.value)) {
        findings.push(`script scheme in URL attribute ${a.name}`);
      }
      // 3. Active data: documents in URL-bearing attributes.
      if (URL_ATTRS.has(a.name) && /data:\s*(text\/html|image\/svg)/i.test(a.value)) {
        findings.push(`active data: URL in ${a.name}`);
      }
      // 4. Script-capable CSS only inside an actual style attribute. The
      //    same tokens in escaped text content are inert and must not count.
      if (a.name === 'style' && /expression\s*\(|-ms-expression|behavior\s*:|-moz-binding\s*:/i.test(a.value)) {
        findings.push('script-capable CSS in style attribute');
      }
    }
  }

  // SVG <set>/<animate> driving an event handler attribute.
  if (/<\s*(set|animate)\b[^>]*attributename\s*=\s*["']?\s*on/i.test(lower)) {
    findings.push('SVG animation targeting an event attribute');
  }

  return findings;
}

export function isSafe(html: string): boolean {
  return findExecutionPrimitives(html).length === 0;
}
