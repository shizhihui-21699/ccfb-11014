/**
 * Public entry point.
 *
 * Pipeline:  string -> Tokenizer (§13.25) -> TreeBuilder (§13.2.6, with SVG /
 * MathML namespace semantics) -> policy tree filter -> mXSS-safe serializer.
 */

import { TreeBuilder } from './tree-builder.ts';
import { sanitizeTree, type SanitizeOptions } from './sanitizer.ts';
import { serialize } from './serializer.ts';
import { DEFAULT_POLICY, type SanitizePolicy } from './policy.ts';
import { DEFAULT_URL_POLICY, type UrlPolicy } from './url.ts';
import { DEFAULT_CSS_POLICY, type CssPolicy } from './css.ts';

export { DEFAULT_POLICY } from './policy.ts';
export type { SanitizePolicy } from './policy.ts';
export { DEFAULT_URL_POLICY, sanitizeUrl, sanitizeSrcset } from './url.ts';
export type { UrlPolicy } from './url.ts';
export { DEFAULT_CSS_POLICY, sanitizeStyle } from './css.ts';
export type { CssPolicy } from './css.ts';
export { TreeBuilder } from './tree-builder.ts';
export { serialize } from './serializer.ts';
export * from './types.ts';

export interface PurifyResult {
  /** Serialized safe HTML. */
  html: string;
  /** The parsed-and-sanitized tree (fragment root is a synthetic <div>). */
  tree: import('./types.ts').ElementNode;
}

/**
 * Sanitize an untrusted HTML fragment.
 *
 * @example
 *   purify('<img src=x onerror=alert(1)>') // '<img src="x">'
 */
export function purify(input: string, options: SanitizeOptions = {}): string {
  return purifyDetailed(input, options).html;
}

export function purifyDetailed(input: string, options: SanitizeOptions = {}): PurifyResult {
  const builder = new TreeBuilder();
  const parsed = builder.parseFragment(input);
  const tree = sanitizeTree(parsed, options);
  return { html: serialize(tree), tree };
}

/**
 * Idempotence self-check: sanitizing the output again must produce byte-
 * identical HTML. Throws if it does not (indicates a serializer/parser
 * divergence that would be an mXSS candidate).
 */
export function purifyStable(input: string, options: SanitizeOptions = {}): string {
  const once = purify(input, options);
  const twice = purify(once, options);
  if (once !== twice) {
    throw new Error(
      `sanitizer not idempotent:\n--- first ---\n${once}\n--- second ---\n${twice}`
    );
  }
  return once;
}

export function createSanitizer(defaults: SanitizeOptions): (input: string) => string {
  return (input: string) => purify(input, defaults);
}

export type { SanitizeOptions };
