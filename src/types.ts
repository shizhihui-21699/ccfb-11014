/**
 * Core DOM-like data structures produced by the tree builder and consumed by
 * the sanitizer / serializer. This is a deliberately minimal subset: the only
 * information retained is what sanitization needs.
 */

export const NS_HTML = 'http://www.w3.org/1999/xhtml' as const;
export const NS_SVG = 'http://www.w3.org/2000/svg' as const;
export const NS_MATHML = 'http://www.w3.org/1998/Math/MathML' as const;

export type Namespace = typeof NS_HTML | typeof NS_SVG | typeof NS_MATHML;

/**
 * A parsed attribute. Name is always lower-case for HTML elements. For foreign
 * content, names follow the "adjust SVG/MathML attributes" tables in the spec
 * (e.g. `viewBox`, `xlink:href`).
 */
export interface Attr {
  name: string;
  /** Decoded attribute value, never null (missing => ''). */
  value: string;
  /**
   * Namespace prefix for namespaced attributes (xlink / xml / xmlns),
   * already baked into `name` as `prefix:local`; kept for serialization.
   */
  prefix: string | null;
}

export type NodeType = 'element' | 'text';

export interface ElementNode {
  type: 'element';
  tag: string;
  namespace: Namespace;
  attrs: Attr[];
  children: Node[];
  /** Parent element; null only on the fragment root. */
  parent: ElementNode | null;
  /**
   * Index of this element in the builder's active formatting element list,
   * or -1. Used only during parsing.
   */
  afeIndex: number;
}

export interface TextNode {
  type: 'text';
  data: string;
  parent: ElementNode | null;
}

export type Node = ElementNode | TextNode;

export function makeElement(
  tag: string,
  namespace: Namespace,
  attrs: Attr[] = []
): ElementNode {
  return { type: 'element', tag, namespace, attrs, children: [], parent: null, afeIndex: -1 };
}

export function makeText(data: string): TextNode {
  return { type: 'text', data, parent: null };
}

/** Token types emitted by the tokenizer. */
export type Token =
  | { kind: 'doctype' } // DOCTYPEs carry no info we keep
  | { kind: 'startTag'; tag: string; attrs: Attr[]; selfClosing: boolean }
  | { kind: 'endTag'; tag: string; selfClosing: boolean }
  | { kind: 'comment'; data: string }
  | { kind: 'character'; data: string }
  | { kind: 'eof' };
