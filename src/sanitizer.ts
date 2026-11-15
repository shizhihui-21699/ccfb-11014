/**
 * Policy-driven tree sanitizer.
 *
 * The parser has already done the security-critical work: the tree reflects
 * exactly what a browser would construct, namespaces are resolved, entities
 * decoded and formatting reconstructed. This stage only needs to make
 * allow/deny decisions on the stable tree, which keeps the policy layer
 * small and auditable.
 *
 * Two removal modes, matching browser semantics:
 *  - unwrap (default): element goes away, children are kept and hoisted.
 *  - drop subtree: element and every descendant are removed, used for
 *    script/style/frame elements whose text content is itself executable.
 */

import {
  NS_HTML,
  NS_SVG,
  NS_MATHML,
  makeElement,
  type Attr,
  type ElementNode,
  type Node,
  type Namespace,
} from './types.ts';
import { DEFAULT_POLICY, type SanitizePolicy } from './policy.ts';
import { DEFAULT_URL_POLICY, sanitizeUrl, sanitizeSrcset, type UrlPolicy } from './url.ts';
import { DEFAULT_CSS_POLICY, sanitizeStyle, type CssPolicy } from './css.ts';

export interface SanitizeOptions {
  policy?: SanitizePolicy;
  urlPolicy?: UrlPolicy;
  cssPolicy?: CssPolicy;
}

/** Attribute names that are dangerous regardless of the allow list. */
const GLOBAL_DENY_ATTRS = new Set([
  // Event handlers (on*) — checked by prefix, but explicit names are belt
  // and braces.
  'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur',
  'onanimationstart', 'onanimationend', 'onanimationiteration',
  'onbeforeinput', 'onbeforeprint', 'onbeforeunload', 'onchange',
  'oncontextmenu', 'oncopy', 'oncut', 'ondblclick', 'ondrag', 'ondragend',
  'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop',
  'oninput', 'onkeydown', 'onkeypress', 'onkeyup', 'onloadstart',
  'onmessage', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseup',
  'onmousewheel', 'onoffline', 'ononline', 'onpagehide', 'onpageshow',
  'onpaste', 'onpointerdown', 'onpointermove', 'onpointerup', 'onpopstate',
  'onprogress', 'onreset', 'onresize', 'onscroll', 'onsearch', 'onselect',
  'onstorage', 'onsubmit', 'ontoggle', 'ontouchstart', 'ontouchend',
  'ontouchmove', 'ontransitionend', 'onunload', 'onwheel',
  // Legacy script-bearing attributes.
  'srcdoc',
  // SVG <set> can animate arbitrary attributes incl. event handlers; the
  // attributeName value is validated elsewhere, but keeping these off plain
  // HTML elements is required.
  'data',
]);

const DANGEROUS_NAME_PATTERNS: RegExp[] = [
  /^on/i, // every event handler, including vendor-prefixed ones
];

// Whitespace (incl. Unicode spaces) and C0 controls that could pad an
// animation target name to evade a prefix check.
const WS_OR_CONTROL = new RegExp(
  "[" +
    "\\u0000-\\u0020\\u007f" +
    "\\u00a0\\u1680\\u180e" +
    "\\u2000-\\u200a" +
    "\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff" +
  "]", "g"
);

// Attribute names that, when used as an SVG animation target, can execute
// script or load an active document.
const DANGEROUS_ANIMATION_TARGETS = new Set([
  'href', 'xlink:href', 'src', 'action', 'formaction', 'background',
  'poster', 'data', 'style',
]);

export function sanitizeTree(
  root: ElementNode,
  options: SanitizeOptions = {}
): ElementNode {
  const policy = options.policy ?? DEFAULT_POLICY;
  const urlPolicy = options.urlPolicy ?? DEFAULT_URL_POLICY;
  const cssPolicy = options.cssPolicy ?? DEFAULT_CSS_POLICY;
  const ctx: Ctx = { policy, urlPolicy, cssPolicy };

  const clean = makeElement(root.tag, root.namespace);

  // Iterative DFS with an explicit stack so arbitrarily deep input cannot
  // blow the call stack. Each frame sanitizes src.children into dst and
  // tracks the next child index. An unwrapped/dropped element is handled by
  // redirecting where its children land, without descending into a call.
  type Frame = { src: ElementNode; dst: ElementNode; index: number };
  const frames: Frame[] = [{ src: root, dst: clean, index: 0 }];

  while (frames.length) {
    const frame = frames[frames.length - 1]!;
    if (frame.index >= frame.src.children.length) {
      frames.pop();
      continue;
    }
    const child = frame.src.children[frame.index++]!;

    if (child.type === 'text') {
      frame.dst.children.push(child); // safe; serializer re-escapes it
      continue;
    }
    const decision = decideElement(child, ctx);
    if (decision === 'drop-subtree') continue;
    if (decision === 'unwrap') {
      // Process the element's children into the same destination next.
      frames.push({ src: child, dst: frame.dst, index: 0 });
      continue;
    }
    const kept = makeElement(child.tag, child.namespace, filterAttrs(child, ctx));
    frame.dst.children.push(kept);
    frames.push({ src: child, dst: kept, index: 0 });
  }

  return clean;
}

interface Ctx {
  policy: SanitizePolicy;
  urlPolicy: UrlPolicy;
  cssPolicy: CssPolicy;
}

type ElementDecision = 'keep' | 'unwrap' | 'drop-subtree';

function decideElement(el: ElementNode, ctx: Ctx): ElementDecision {
  if (el.namespace === NS_HTML) {
    if (ctx.policy.dropContentTags.has(el.tag)) return 'drop-subtree';
    if (ctx.policy.allowedTags.has(el.tag)) return 'keep';
    return 'unwrap';
  }
  if (el.namespace === NS_SVG) {
    // No drop-content foreign tags in the default set; an unknown foreign
    // element is unwrapped so its contents stay visible but cannot carry
    // foreign semantics.
    return ctx.policy.allowedSvgTags.has(el.tag) ? 'keep' : 'unwrap';
  }
  return ctx.policy.allowedMathTags.has(el.tag) ? 'keep' : 'unwrap';
}

function allowedAttrSet(namespace: Namespace, ctx: Ctx): ReadonlySet<string> {
  if (namespace === NS_SVG) return ctx.policy.allowedSvgAttrs;
  if (namespace === NS_MATHML) return ctx.policy.allowedMathAttrs;
  return ctx.policy.allowedAttrs;
}

function filterAttrs(el: ElementNode, ctx: Ctx): Attr[] {
  const allowed = allowedAttrSet(el.namespace, ctx);
  const kept: Attr[] = [];
  const seen = new Set<string>();

  for (const attr of el.attrs) {
    const name = attr.name;
    if (seen.has(name)) continue; // parser already de-dupes; defensive

    if (!isAttrAllowed(name, el.namespace, allowed, ctx.policy)) continue;
    if (GLOBAL_DENY_ATTRS.has(name)) continue;
    if (DANGEROUS_NAME_PATTERNS.some((re) => re.test(name))) continue;

    let value = attr.value;

    if (name === 'style') {
      value = sanitizeStyle(value, ctx.cssPolicy);
      if (value === '') continue;
    } else if (ctx.policy.srcsetAttrs.has(name)) {
      const checked = sanitizeSrcset(value, ctx.urlPolicy);
      if (checked === null) continue;
      value = checked;
    } else if (ctx.policy.urlAttrs.has(name)) {
      const checked = sanitizeUrl(value, ctx.urlPolicy);
      if (checked === null) continue;
      value = checked;
    } else if (el.namespace === NS_SVG && (name === 'attributename' || name === 'attributeName')) {
      // <set>/<animate attributeName=...> can animate ANY attribute, including
      // event handlers. Normalize the target name (strip whitespace incl.
      // Unicode) and reject event handlers and other script-bearing targets.
      const target = value.replace(WS_OR_CONTROL, '').toLowerCase();
      if (DANGEROUS_ANIMATION_TARGETS.has(target) || target.startsWith('on')) continue;
    }

    seen.add(name);
    kept.push({ name, value, prefix: attr.prefix });
  }
  return kept;
}

function isAttrAllowed(
  name: string,
  namespace: Namespace,
  allowed: ReadonlySet<string>,
  policy: SanitizePolicy
): boolean {
  if (allowed.has(name)) {
    if (name === 'class' && !policy.allowClass) return false;
    return true;
  }
  if (policy.allowAria && (name === 'role' || name.startsWith('aria-'))) return true;
  if (policy.allowDataAttrs && name.startsWith('data-')) {
    // data-attributes must be well-formed and must not smuggle a namespace.
    return /^data-[^=\s"'>/\\]+$/.test(name) && !name.includes(':');
  }
  void namespace;
  return false;
}
