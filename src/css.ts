/**
 * Sanitizer for inline `style` attributes.
 *
 * Inline CSS cannot load external scripts directly, but it has a long history
 * of script-execution and data-exfiltration vectors:
 *   - expression(...) / -ms-expression (old IE JScript in CSS)
 *   - url(javascript:…), url(vbscript:…)
 *   - behavior: url(htc) and -moz-binding (legacy script loading)
 *   - @import / @supports rule smuggling inside a declaration block
 *   - CSS escape obfuscation (`j\61 vascript`, `\00006a…`)
 *   - control characters / nulls / unterminated strings confusing serializers
 *
 * We parse the value as a declaration list (the only grammar legal in a style
 * attribute), validate property names and every function token, and re-serialize
 * canonically so the output is stable under repeated sanitization.
 */

import { sanitizeUrl, DEFAULT_URL_POLICY, type UrlPolicy } from './url.ts';

const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000e-\u001f\u007f]/g;

/**
 * Properties whose values can pull in external resources or script.
 * Everything else is kept as long as the value tokens are benign.
 */
const PROPERTY_BLOCKLIST = new Set([
  // Legacy script binding.
  'behavior',
  '-moz-binding',
  '-webkit-binding',
  // Positioning tricks used for UI redress / overlay attacks.
  'position',
  // Obsolete IE filter / transition filter engines (can load HTC/scripts).
  'filter',
  '-ms-filter',
]);

/** Functions that must never appear in a sanitized value. */
const FORBIDDEN_FUNCTIONS = new Set([
  'expression',
  '-ms-expression',
  'javascript',
  'vbscript',
  'livescript',
]);

export interface CssPolicy {
  /** Keep custom properties (`--foo`). They are inert without JS reading them. */
  allowCustomProperties: boolean;
  urlPolicy: UrlPolicy;
}

export const DEFAULT_CSS_POLICY: CssPolicy = {
  allowCustomProperties: false,
  urlPolicy: DEFAULT_URL_POLICY,
};

export function sanitizeStyle(raw: string, policy: CssPolicy = DEFAULT_CSS_POLICY): string {
  if (raw.trim() === '') return '';

  let s = raw.replace(CONTROL_CHARS, '');
  // Strip comments — they can't survive in a style attribute usefully and are
  // a classic place to hide tokens from naive scanners.
  s = removeComments(s);
  // Reject any at-rule smuggled into the declaration block.
  if (/@?import\b/i.test(s) || /@(?!media\b|supports\b|layer\b|container\b)/.test(s) || /@(media|supports|layer|container)\b/i.test(s)) {
    // @media etc. are statements, not declarations; none are legal inside
    // an HTML style attribute, so any at-rule disqualifies the whole value.
    return '';
  }

  const declarations = splitDeclarations(s);
  const kept: string[] = [];

  for (const decl of declarations) {
    const ci = decl.indexOf(':');
    if (ci <= 0) continue;
    const prop = decl.slice(0, ci).trim().toLowerCase();
    let value = decl.slice(ci + 1).trim();
    if (prop === '' || value === '') continue;

    if (prop.startsWith('--')) {
      if (!policy.allowCustomProperties) continue;
    } else if (!isValidPropertyName(prop) || PROPERTY_BLOCKLIST.has(prop)) {
      continue;
    }

    // Decode CSS escape sequences before pattern checks so `j\61 vascript`
    // is visible in plain form, then re-validate the decoded text too.
    const decoded = decodeCssEscapes(value);
    if (hasForbiddenFunction(decoded)) continue;

    // Validate every url(...) token against the URL policy.
    const urlCheck = checkUrls(decoded, policy.urlPolicy);
    if (urlCheck === null) continue;
    value = urlCheck;

    // Reject backslash escape tricks that survived decoding suspiciously,
    // and angle brackets (never legal in declaration values).
    if (/[<>]/.test(value)) continue;
    if (/\\[0-9a-fA-F]/.test(value) && /expression|script|behavior|binding/i.test(decoded)) continue;

    kept.push(`${prop}: ${canonicalValue(value)}`);
  }

  return kept.join('; ');
}

// --------------------------------------------------------------- parsing

function removeComments(s: string): string {
  let out = '';
  let inStr: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (inStr) {
      out += c;
      if (c === '\\' && i + 1 < s.length) {
        out += s[i + 1];
        i++;
      } else if (c === inStr) {
        inStr = null;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = c;
      out += c;
      continue;
    }
    if (c === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      i = end < 0 ? s.length : end + 1;
      continue;
    }
    out += c;
  }
  return out;
}

/** Split on top-level semicolons (respecting strings and parens). */
function splitDeclarations(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let inStr: string | null = null;
  let buf = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (inStr) {
      buf += c;
      if (c === '\\' && i + 1 < s.length) {
        buf += s[i + 1];
        i++;
      } else if (c === inStr) {
        inStr = null;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = c;
      buf += c;
      continue;
    }
    if (c === '(') depth++;
    if (c === ')') depth = Math.max(0, depth - 1);
    if (c === ';' && depth === 0) {
      if (buf.trim()) out.push(buf.trim());
      buf = '';
      continue;
    }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function isValidPropertyName(prop: string): boolean {
  // Vendor-prefixed and standard identifiers; no escapes, quotes, spaces.
  return /^-?[a-z][a-z0-9-]*$/i.test(prop) && !prop.endsWith('-');
}

function hasForbiddenFunction(value: string): boolean {
  const lower = value.toLowerCase();
  for (const fn of FORBIDDEN_FUNCTIONS) {
    const re = new RegExp(`(^|[^a-z0-9_-])${fn}\\s*\\(`, 'i');
    if (re.test(lower)) return true;
  }
  // Catch bare protocol labels too: url("javascript:...") is checked in
  // checkUrls, but `javascript:...` without url() appears in some legacy
  // shorthand contexts.
  if (/(^|[\s;,])\s*(javascript|vbscript|livescript)\s*:/i.test(lower)) return true;
  return false;
}

/** Decode `\XX ` hex and `\c` identity escapes inside a CSS value. */
function decodeCssEscapes(value: string): string {
  return value.replace(/\\(?:([0-9a-fA-F]{1,6})\s?|(.))/g, (_m, hex: string | undefined, ident: string | undefined) => {
    if (hex !== undefined) {
      const code = parseInt(hex, 16);
      if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return '�';
      return String.fromCodePoint(code);
    }
    return ident ?? '';
  });
}

/** Validate each url(...) / bare string URL token. Returns cleaned value. */
function checkUrls(value: string, urlPolicy: UrlPolicy): string | null {
  let result = '';
  let i = 0;
  while (i < value.length) {
    const rest = value.slice(i);
    const m = /^url\s*\(/i.exec(rest);
    if (m) {
      const closeIdx = findMatchingParen(rest, m[0].length - 1);
      if (closeIdx < 0) return null;
      const inner = rest.slice(m[0].length, closeIdx).trim();
      const unquoted = unquote(inner);
      if (unquoted === null) return null;
      const safe = sanitizeUrl(unquoted, urlPolicy);
      if (safe === null) return null;
      result += `url("${safe.replace(/"/g, '%22')}")`;
      i += closeIdx + 1;
      continue;
    }
    result += value[i];
    i++;
  }
  return result;
}

function findMatchingParen(s: string, openIdx: number): number {
  let depth = 0;
  let inStr: string | null = null;
  for (let i = openIdx; i < s.length; i++) {
    const c = s[i]!;
    if (inStr) {
      if (c === '\\' && i + 1 < s.length) {
        i++;
        continue;
      }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = c;
      continue;
    }
    if (c === '(') depth++;
    if (c === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function unquote(s: string): string | null {
  if (s.length >= 2 && (s[0] === '"' || s[0] === "'")) {
    if (s[s.length - 1] !== s[0]) return null;
    return s.slice(1, -1);
  }
  // Unquoted url tokens may not contain quotes/parens/whitespace sequences.
  if (/["'()]/.test(s)) return null;
  return s;
}

function canonicalValue(value: string): string {
  return value.replace(/\s+/g, ' ').trim().replace(/;$/, '');
}
