/**
 * URL attribute validation.
 *
 * The goal is not full URL parsing but *scheme classification* that cannot
 * be tricked by the obfuscations that make naive regex checks fail:
 * embedded C0 controls / U+0000, backslash-as-slash confusion, leading
 * whitespace / control prefixes, and `jav&#x0A;ascript:`-style entity tricks
 * (entities are already decoded by the tokenizer before we get here).
 */

export interface UrlPolicy {
  /** Lower-case schemes without ':', e.g. ['http', 'https', 'mailto']. */
  allowedSchemes: ReadonlySet<string>;
  /**
   * data: URLs are restricted separately because `data:text/html` is script
   * execution even though `data:image/png` is safe.
   */
  allowedDataMimePrefixes: ReadonlySet<string>;
  /** Allow protocol-relative URLs (`//host/path`). */
  allowProtocolRelative: boolean;
  /** Allow bare fragments/queries/relative paths (no scheme at all). */
  allowRelative: boolean;
}

export const DEFAULT_URL_POLICY: UrlPolicy = {
  allowedSchemes: new Set(['http', 'https', 'mailto', 'tel', 'ftp', 'data', 'news', 'irc', 'ircs']),
  // image/svg+xml is deliberately excluded: SVG is XML and can carry
  // <script> / onload, so a data: SVG executes in the document's origin.
  allowedDataMimePrefixes: new Set(['image/png', 'image/gif', 'image/jpeg', 'image/webp', 'image/avif', 'text/plain']),
  allowProtocolRelative: true,
  allowRelative: true,
};

// C0 controls + DEL.
const C0_AND_FF = /[\u0000-\u001f\u007f]/g;

// WHATWG "C0 control or space" plus the full Unicode whitespace set that
// browsers strip/ignore around URLs. Includes the Ogham space mark, the
// Mongolian vowel separator, the general-punctuation spaces and the
// ideographic space — all observed in real filter-bypass vectors.
const UNICODE_WS = new RegExp("[\u0009-\u000d\u0020\u00a0\u1680\u180e\u2000-\u200d\u2028\u2029\u202f\u205f\u3000\ufeff]", "g");
/**
 * @returns the (possibly trimmed/cleaned) safe URL string, or null to drop
 * the attribute entirely.
 */
export function sanitizeUrl(raw: string, policy: UrlPolicy = DEFAULT_URL_POLICY): string | null {
  if (raw === '') return '';


  // 1. Strip every C0 control and DEL. Browsers ignore these when
  //    classifying schemes, so `java\x00script:` must look like `javascript:`.
  let s = raw.replace(C0_AND_FF, '');

  // 2. Remove ALL whitespace browsers ignore in URLs — ASCII and Unicode
  //    (U+00A0, U+2000.., U+3000, …). Removing them everywhere, not just at
  //    the ends, defeats `&#x2000;javascript:` and zero-width/feff prefixes.
  s = s.replace(UNICODE_WS, '');
  if (s === '') return '';

  // 3. Normalize backslashes: IE/old-Edge treated '\' as '/'; modern Chrome
  //    treats `\\evil.com` as protocol-relative. Converting up front makes
  //    scheme extraction unambiguous and defeats `/\javascript:` tricks.
  const probe = s.replace(/\\/g, '/');

  // 4. Protocol-relative. Return the normalized form so backslashes cannot
  //    survive into the serialized output.
  if (probe.startsWith('//')) {
    return policy.allowProtocolRelative ? probe : null;
  }

  // 5. Scheme extraction per RFC 3986-ish rule: ALPHA *( ALPHA/DIGIT/+/-/. ) ':'
  const colon = probe.indexOf(':');
  if (colon > 0) {
    let schemeOk = true;
    for (let i = 0; i < colon; i++) {
      const c = probe.charCodeAt(i);
      const isAlpha = (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
      const isDigit = c >= 0x30 && c <= 0x39;
      const isSym = c === 0x2b /* + */ || c === 0x2d /* - */ || c === 0x2e /* . */;
      if (!(isAlpha || isDigit || isSym)) {
        schemeOk = false;
        break;
      }
    }
    if (schemeOk) {
      const scheme = probe.slice(0, colon).toLowerCase();

      if (scheme === 'data') {
        if (!policy.allowedSchemes.has('data')) return null;
        // data:[<mediatype>][;base64],<data>
        const rest = probe.slice(colon + 1).replace(/^\/+/, '');
        const comma = rest.indexOf(',');
        const mimePart = (comma >= 0 ? rest.slice(0, comma) : rest).toLowerCase();
        const mime = mimePart.split(';')[0]!.trim();
        const allowed =
          mime === '' || // data:,… defaults to text/plain
          [...policy.allowedDataMimePrefixes].some((p) => mime.startsWith(p));
        return allowed ? probe : null;
      }

      return policy.allowedSchemes.has(scheme) ? probe : null;
    }
  }

  // 6. No usable scheme: relative URL, fragment or query. Emit the
  //    backslash-normalized form for stable round-tripping.
  if (policy.allowRelative) return probe;
  return null;
}

/**
 * srcset parsing (§4.8.4.3.6): comma-separated candidate descriptors.
 * Each candidate's URL part is validated; a single unsafe candidate drops
 * the whole attribute (browsers reject malformed srcset wholesale).
 */
export function sanitizeSrcset(raw: string, policy: UrlPolicy = DEFAULT_URL_POLICY): string | null {
  const candidates = splitSrcset(raw);
  const out: string[] = [];
  for (const candidate of candidates) {
    const trimmed = candidate.trim();
    if (trimmed === '') continue;
    const space = trimmed.search(/[\s,]/);
    const url = space >= 0 ? trimmed.slice(0, space) : trimmed;
    const rest = space >= 0 ? trimmed.slice(space).trim() : '';
    const clean = sanitizeUrl(url, policy);
    if (clean === null) return null;
    out.push(rest ? `${clean} ${rest}` : clean);
  }
  return out.join(', ');
}

function splitSrcset(input: string): string[] {
  // Commas inside data: URLs must not split candidates.
  const parts: string[] = [];
  let depth = 0;
  let buf = '';
  for (const ch of input) {
    if (ch === ':' ) depth++;
    if (ch === ',') {
      if (depth > 0 && /^data:/i.test(buf.trim())) {
        buf += ch;
        continue;
      }
      parts.push(buf);
      buf = '';
      continue;
    }
    buf += ch;
  }
  parts.push(buf);
  return parts;
}
