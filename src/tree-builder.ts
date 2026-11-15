/**
 * HTML tree construction (fragment case) — WHATWG HTML Standard §13.2.6.
 *
 * Implements the insertion modes, open-element stack, active formatting
 * element (AFE) list with the adoption agency algorithm, foster parenting,
 * and full foreign-content (SVG / MathML) semantics including namespace
 * switches, integration points and the tag/attribute name adjustment tables.
 *
 * The output is a plain tree of ElementNode/TextNode rooted at a synthetic
 * <div> (the fragment context), which the sanitizer walks separately.
 */

import { Tokenizer } from './tokenizer.ts';
import type { ContentModel } from './tokenizer.ts';
import {
  NS_HTML,
  NS_SVG,
  NS_MATHML,
  makeElement,
  makeText,
  type Attr,
  type ElementNode,
  type Namespace,
  type Node,
  type Token,
} from './types.ts';

type InsertionMode =
  | 'initial'
  | 'before-html'
  | 'before-head'
  | 'in-head'
  | 'after-head'
  | 'in-body'
  | 'text'
  | 'in-table'
  | 'in-table-text'
  | 'in-caption'
  | 'in-column-group'
  | 'in-table-body'
  | 'in-row'
  | 'in-cell'
  | 'in-select'
  | 'in-select-in-table'
  | 'template'
  | 'after-body'
  | 'after-after-body';

// ------------------------------------------------------------------- tables

const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr',
]);

const RCDATA_ELEMENTS = new Set(['title', 'textarea']);
const RAWTEXT_ELEMENTS = new Set(['style', 'xmp', 'iframe', 'noembed', 'noframes']);

/** Elements whose content model makes the tokenizer switch states. */
function contentModelFor(tag: string): ContentModel {
  if (RCDATA_ELEMENTS.has(tag)) return 'rcdata';
  if (RAWTEXT_ELEMENTS.has(tag)) return 'rawtext';
  if (tag === 'script') return 'script';
  if (tag === 'plaintext') return 'plaintext';
  return 'data';
}

const FORMATTING_ELEMENTS = new Set([
  'a', 'b', 'big', 'code', 'em', 'font', 'i', 'nobr', 's', 'small',
  'strike', 'strong', 'tt', 'u',
]);

const HEAD_ELEMENTS = new Set([
  'base', 'basefont', 'bgsound', 'link', 'meta', 'title', 'style', 'noscript', 'noframes',
]);

const SCOPE_STOPPERS: Record<string, ReadonlySet<string>> = {
  [NS_HTML]: new Set([
    'applet', 'caption', 'html', 'table', 'td', 'th', 'marquee', 'object', 'template',
  ]),
  [NS_SVG]: new Set(['foreignObject', 'desc', 'title']),
  [NS_MATHML]: new Set(['mi', 'mo', 'mn', 'ms', 'mtext', 'annotation-xml']),
};
const LIST_SCOPE_STOPPERS: Record<string, ReadonlySet<string>> = {
  [NS_HTML]: new Set(['applet', 'caption', 'html', 'table', 'td', 'th', 'marquee', 'object', 'template', 'ol', 'ul']),
  [NS_SVG]: SCOPE_STOPPERS[NS_SVG]!,
  [NS_MATHML]: SCOPE_STOPPERS[NS_MATHML]!,
};
const BUTTON_SCOPE_STOPPERS: Record<string, ReadonlySet<string>> = {
  [NS_HTML]: new Set(['applet', 'caption', 'html', 'table', 'td', 'th', 'marquee', 'object', 'template', 'button']),
  [NS_SVG]: SCOPE_STOPPERS[NS_SVG]!,
  [NS_MATHML]: SCOPE_STOPPERS[NS_MATHML]!,
};

// In-body start-tag special handling groups.
const CLOSE_P_ELEMENTS = new Set([
  'address', 'article', 'aside', 'blockquote', 'center', 'details', 'dialog',
  'dir', 'div', 'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'header',
  'hgroup', 'main', 'menu', 'nav', 'ol', 'p', 'search', 'section', 'summary', 'ul',
]);
const HEADINGS = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
const LIST_ELEMENTS = new Set(['ul', 'ol']);
const DL_PARTICIPANTS = new Set(['dt', 'dd']);
const TABLE_ELEMENTS = new Set(['table', 'tbody', 'tfoot', 'thead', 'tr']);
const TABLE_CELLS = new Set(['td', 'th']);
const TABLE_SCOPE_STOPPERS = new Set(['table', 'html', 'template']);
const BODY_END_CANDIDATES = new Set(['dd', 'dt', 'li', 'optgroup', 'option', 'p', 'rb', 'rp', 'rt', 'rtc']);
const BLOCKED_IN_P = new Set([...CLOSE_P_ELEMENTS, ...HEADINGS, ...TABLE_ELEMENTS, ...TABLE_CELLS, 'pre', 'listing']);

// Foreign content tag-name adjustment (§13.2.6.4.7 / .8).
const SVG_TAG_ADJUST: Record<string, string> = {
  altglyph: 'altGlyph', altglyphdef: 'altGlyphDef', altglyphitem: 'altGlyphItem',
  animatecolor: 'animateColor', animatemotion: 'animateMotion', animatetransform: 'animateTransform',
  clippath: 'clipPath', feblend: 'feBlend', fecolormatrix: 'feColorMatrix',
  fecomponenttransfer: 'feComponentTransfer', fecomposite: 'feComposite',
  feconvolvematrix: 'feConvolveMatrix', fediffuselighting: 'feDiffuseLighting',
  fedisplacementmap: 'feDisplacementMap', fedistantlight: 'feDistantLight',
  fedropshadow: 'feDropShadow', feflood: 'feFlood', fefunca: 'feFuncA',
  fefuncb: 'feFuncB', fefuncg: 'feFuncG', fefuncr: 'feFuncR',
  fegaussianblur: 'feGaussianBlur', feimage: 'feImage', femerge: 'feMerge',
  femergenode: 'feMergeNode', femorphology: 'feMorphology', feoffset: 'feOffset',
  fepointlight: 'fePointLight', fespecularlighting: 'feSpecularLighting',
  fespotlight: 'feSpotLight', fetile: 'feTile', feturbulence: 'feTurbulence',
  foreignobject: 'foreignObject', glyphref: 'glyphRef', lineargradient: 'linearGradient',
  radialgradient: 'radialGradient', textpath: 'textPath',
};
const SVG_BREAKOUT = new Set([
  'b', 'big', 'blockquote', 'body', 'br', 'center', 'code', 'dd', 'div', 'dl',
  'dt', 'em', 'embed', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'hr', 'i',
  'img', 'li', 'listing', 'menu', 'meta', 'nobr', 'ol', 'p', 'pre', 'ruby',
  's', 'small', 'span', 'strong', 'strike', 'sub', 'sup', 'table', 'u', 'ul', 'var',
]);
const MATHML_TEXT_INTEGRATION = new Set(['mi', 'mo', 'mn', 'ms', 'mtext']);
const HTML_INTEGRATION = new Set(['foreignObject', 'desc', 'title']); // SVG
const MATHML_HTML_INTEGRATION = new Set(['annotation-xml']);

// Attribute name adjustment tables.
const SVG_ATTR_ADJUST: Record<string, string> = {
  attributename: 'attributeName', attributetype: 'attributeType', basefrequency: 'baseFrequency',
  baseprofile: 'baseProfile', calcmode: 'calcMode', clippathunits: 'clipPathUnits',
  contenteditable: 'contenteditable', diffuseconstant: 'diffuseConstant',
  edgemode: 'edgeMode', externalresourcesrequired: 'externalResourcesRequired',
  filterres: 'filterRes', filterunits: 'filterUnits', glyphref: 'glyphRef',
  gradienttransform: 'gradientTransform', gradientunits: 'gradientUnits',
  kernelmatrix: 'kernelMatrix', kernelunitlength: 'kernelUnitLength',
  keypoints: 'keyPoints', keypointspline: 'keySplines', keytimes: 'keyTimes',
  lengthadjust: 'lengthAdjust', limitingconeangle: 'limitingConeAngle',
  markerheight: 'markerHeight', markerunits: 'markerUnits', markerwidth: 'markerWidth',
  maskcontentunits: 'maskContentUnits', maskunits: 'maskUnits',
  numoctaves: 'numOctaves', pathlength: 'pathLength', patterncontentunits: 'patternContentUnits',
  patterntransform: 'patternTransform', patternunits: 'patternUnits',
  pointsatx: 'pointsAtX', pointsaty: 'pointsAtY', pointsatz: 'pointsAtZ',
  preservealpha: 'preserveAlpha', preserveaspectratio: 'preserveAspectRatio',
  primitiveunits: 'primitiveUnits', refx: 'refX', refy: 'refY',
  repeatcount: 'repeatCount', repeatdur: 'repeatDur', requiredextensions: 'requiredExtensions',
  requiredfeatures: 'requiredFeatures', specularconstant: 'specularConstant',
  specularexponent: 'specularExponent', spreadmethod: 'spreadMethod',
  startoffset: 'startOffset', stddeviation: 'stdDeviation', stitchtiles: 'stitchTiles',
  surfacescale: 'surfaceScale', systemlanguage: 'systemLanguage', tablevalues: 'tableValues',
  targetx: 'targetX', targety: 'targetY', textlength: 'textLength',
  viewbox: 'viewBox', viewtarget: 'viewTarget', xchannelselector: 'xChannelSelector',
  ychannelselector: 'yChannelSelector', zoomandpan: 'zoomAndPan',
};
const FOREIGN_ATTR_ADJUST: Record<string, string> = {
  'xlink:actuate': 'xlink:actuate', 'xlink:arcrole': 'xlink:arcrole',
  'xlink:href': 'xlink:href', 'xlink:role': 'xlink:role',
  'xlink:show': 'xlink:show', 'xlink:title': 'xlink:title', 'xlink:type': 'xlink:type',
  'xml:lang': 'xml:lang', 'xml:space': 'xml:space', 'xmlns:xlink': 'xmlns:xlink',
};

const MARKER = Symbol('afe-marker');
type AfeEntry = ElementNode | typeof MARKER;

export class TreeBuilder {
  private tokenizer: Tokenizer;
  private root: ElementNode; // synthetic fragment <div> in HTML namespace
  private stack: ElementNode[] = [];
  private afe: AfeEntry[] = [];
  private modes: InsertionMode[] = ['in-body'];
  private mode: InsertionMode = 'in-body';
  private framesetOk = true;
  private pendingTableText = '';
  private pendingTableTextPendingTable = false;
  private foster = false;
  private head: ElementNode | null = null;
  private formPointer: ElementNode | null = null;
  private selectDepth = 0;
  private tableDepth = 0;
  private inTemplate = 0;

  constructor() {
    this.root = makeElement('div', NS_HTML);
    this.stack.push(this.root);
    this.tokenizer = new Tokenizer({
      onToken: (t) => this.handleToken(t),
      isForeign: () => this.currentNode().namespace !== NS_HTML,
      getLastStartTag: () => {
        for (let i = this.stack.length - 1; i >= 0; i--) {
          const el = this.stack[i]!;
          if (el.namespace === NS_HTML) return el.tag;
        }
        return null;
      },
    });
  }

  parseFragment(input: string): ElementNode {
    this.tokenizer.parse(input);
    return this.root;
  }

  // ------------------------------------------------------------ utilities

  private currentNode(): ElementNode {
    return this.stack[this.stack.length - 1]!;
  }

  private pushMode(m: InsertionMode): void {
    this.modes.push(m);
    this.mode = m;
  }
  private popMode(): void {
    this.modes.pop();
    this.mode = this.modes[this.modes.length - 1]!;
  }

  /** §13.2.6.4.1 "has an element in scope" with per-namespace stopper lists. */
  private inScope(tag: string, table: Record<string, ReadonlySet<string>> = SCOPE_STOPPERS): boolean {
    for (let i = this.stack.length - 1; i >= 0; i--) {
      const el = this.stack[i]!;
      if (el.namespace === NS_HTML && el.tag === tag) return true;
      if (table[el.namespace]!.has(el.tag)) return false;
    }
    return false;
  }
  private inListScope(tag: string): boolean {
    return this.inScope(tag, LIST_SCOPE_STOPPERS);
  }
  private inButtonScope(tag: string): boolean {
    return this.inScope(tag, BUTTON_SCOPE_STOPPERS);
  }
  private inTableScope(tag: string): boolean {
    for (let i = this.stack.length - 1; i >= 0; i--) {
      const el = this.stack[i]!;
      if (el.namespace === NS_HTML && el.tag === tag) return true;
      if (TABLE_SCOPE_STOPPERS.has(el.tag)) return false;
    }
    return false;
  }

  private popUntil(predicate: (el: ElementNode) => boolean): ElementNode {
    for (;;) {
      if (this.stack.length <= 1) return this.stack[0]!; // never pop the fragment root
      const el = this.stack.pop()!;
      if (predicate(el)) return el;
    }
  }

  private insertElement(tag: string, namespace: Namespace, attrs: Attr[]): ElementNode {
    const el = makeElement(tag, namespace, attrs.map((a) => ({ ...a })));
    if (this.foster) this.fosterParent(el);
    else this.appendChild(this.currentNode(), el);
    this.stack.push(el);
    return el;
  }

  private appendChild(parent: ElementNode, node: Node): void {
    node.parent = parent;
    parent.children.push(node);
  }

  private insertChildAt(parent: ElementNode, index: number, node: Node): void {
    node.parent = parent;
    parent.children.splice(index, 0, node);
  }

  private insertText(data: string): void {
    if (data === '') return;
    let parent: ElementNode;
    let index: number;
    if (this.foster) {
      const loc = this.fosterLocation();
      parent = loc.parent;
      index = loc.index;
    } else {
      parent = this.currentNode();
      index = parent.children.length;
    }
    const prev = parent.children[index - 1];
    if (prev && prev.type === 'text') {
      prev.data += data;
      return;
    }
    const node = makeText(data);
    this.insertChildAt(parent, index, node);
  }

  // §13.2.6.4.5 foster parenting: insert before the nearest table.
  private fosterLocation(): { parent: ElementNode; index: number } {
    for (let i = this.stack.length - 1; i >= 0; i--) {
      const el = this.stack[i]!;
      if (el.namespace === NS_HTML && (el.tag === 'table' || el.tag === 'template')) {
        const host = this.stack[i - 1] ?? this.root;
        return { parent: host, index: host.children.indexOf(el) };
      }
    }
    return { parent: this.root, index: this.root.children.length };
  }
  private fosterParent(node: Node): void {
    const { parent, index } = this.fosterLocation();
    this.insertChildAt(parent, index, node);
  }

  private reconstructAFE(): void {
    if (this.afe.length === 0 || this.afe[this.afe.length - 1] === MARKER) return;
    if (this.afe[this.afe.length - 1] === this.currentNode()) return;

    // Collect the trailing entries that are not in the stack / not current.
    let i = this.afe.length - 1;
    const toReopen: ElementNode[] = [];
    while (i >= 0 && this.afe[i] !== MARKER) {
      const entry = this.afe[i]! as ElementNode;
      if (this.stack.includes(entry) || entry === this.currentNode()) break;
      toReopen.unshift(entry);
      i--;
    }
    for (const formatting of toReopen) {
      const fresh = makeElement(formatting.tag, formatting.namespace, formatting.attrs.map((a) => ({ ...a })));
      this.appendChild(this.currentNode(), fresh);
      this.stack.push(fresh);
      this.afe[this.afe.indexOf(formatting)] = fresh;
    }
  }

  // §13.2.6.4.7 adoption agency algorithm.
  //
  // Faithful implementation of the spec's furthest-block reconstruction,
  // using real subtree moves (nodes carry parent pointers). Producing the
  // same DOM a browser would is what makes the later serialization a fixed
  // point, which is the property that defeats mXSS.
  private adoptionAgency(tokenTag: string, preInserted: ElementNode | null): void {
    for (let outer = 0; outer < 8; outer++) {
      const afeIndex = this.findAfe(tokenTag);
      if (afeIndex < 0) {
        if (preInserted) this.afe.push(preInserted);
        return;
      }
      const formattingElement = this.afe[afeIndex] as ElementNode;

      // Not in the open-element stack: drop stale AFE entry, retry.
      if (!this.stack.includes(formattingElement)) {
        this.afe.splice(afeIndex, 1);
        continue;
      }

      // Well-nested close: formatting element is the current node.
      if (this.currentNode() === formattingElement) {
        this.stack.pop();
        this.afe.splice(afeIndex, 1);
        if (preInserted) this.afe.push(preInserted);
        return;
      }

      const formattingIndex = this.stack.indexOf(formattingElement);

      // Collect formatting elements open between the target and current.
      let inner = 0;
      const lastElements: ElementNode[] = [];
      for (let i = formattingIndex + 1; i < this.stack.length && inner < 3; i++) {
        const el = this.stack[i]!;
        if (this.afe.includes(el)) {
          lastElements.push(el);
          inner++;
        }
      }

      // Find the furthest block: deepest block-level element below the
      // formatting element in the open-element stack.
      let furthestBlock: ElementNode | null = null;
      for (let i = formattingIndex + 1; i < this.stack.length; i++) {
        const el = this.stack[i]!;
        if (this.isBlockBoundary(el)) furthestBlock = el;
      }

      if (!furthestBlock) {
        // No block boundary: common-ancestor reconstruction. Pop to the
        // formatting element and reopen a fresh copy of it.
        this.stack.length = formattingIndex;
        this.afe.splice(afeIndex, 1);
        const fresh = this.cloneElement(formattingElement);
        this.appendChild(formattingElement.parent ?? this.root, fresh);
        this.stack.push(fresh);
        this.afe.push(fresh);
        if (preInserted) this.afe.push(preInserted);
        return;
      }

      // --- Spec steps 7–11: rebuild around the furthest block. ---
      const commonAncestor = this.stack[formattingIndex - 1]!;

      // Bookmark the AFE slot; remove the old formatting entry.
      this.afe.splice(afeIndex, 1);

      // Move the furthest block out to be a sibling right after the
      // formatting element (taking its subtree with it).
      detach(furthestBlock);
      insertAfter(furthestBlock, formattingElement);

      // Clone the furthest block. Everything that followed it as a sibling
      // inside the formatting element moves into the clone.
      const clone = this.cloneElement(furthestBlock);
      const fbParent = furthestBlock.parent!;
      const fbIndex = fbParent.children.indexOf(furthestBlock);
      const trailing = fbParent.children.splice(fbIndex + 1);
      for (const t of trailing) clone.children.push(t);
      insertAfter(clone, furthestBlock);

      // Rebuild the open-element stack: replace furthestBlock with clone and
      // drop the formatting element from it.
      const fbStackIndex = this.stack.indexOf(furthestBlock);
      const above = this.stack.splice(fbStackIndex + 1);
      this.stack[fbStackIndex] = clone;
      this.stack.length = formattingIndex; // pop formatting element
      this.stack.push(clone);

      // Recreate the intervening formatting elements inside the block.
      let wrapNode: ElementNode = clone;
      for (const last of lastElements) {
        const lastClone = this.cloneElement(last);
        wrapNode.children.push(lastClone);
        wrapNode = lastClone;
        const lastAfe = this.afe.indexOf(last);
        if (lastAfe >= 0) this.afe[lastAfe] = lastClone;
      }

      // Re-attach non-formatting stack elements beneath the wrapper.
      for (const popped of above) {
        if (!this.afe.includes(popped)) wrapNode.children.push(popped);
        this.stack.push(popped);
      }

      // Fresh formatting element: sibling after the furthest block, and the
      // new AFE entry at the bookmarked position.
      const fresh = this.cloneElement(formattingElement);
      insertAfter(fresh, clone);
      if (afeIndex < this.afe.length) this.afe.splice(afeIndex, 0, fresh);
      else this.afe.push(fresh);
      this.stack.push(fresh);
      if (preInserted) this.afe.push(preInserted);

      void commonAncestor;
      return;
    }
    // Outer budget exhausted: nothing further; filter stage handles residue.
  }

  private cloneElement(el: ElementNode): ElementNode {
    return makeElement(
      el.tag,
      el.namespace,
      el.attrs.map((a) => ({ ...a }))
    );
  }

  private isBlockBoundary(el: ElementNode): boolean {
    if (el.namespace !== NS_HTML) return false;
    return (
      BLOCKED_IN_P.has(el.tag) ||
      el.tag === 'table' || el.tag === 'ul' || el.tag === 'ol' ||
      el.tag === 'dl' || el.tag === 'blockquote' || el.tag === 'pre' ||
      HEADINGS.has(el.tag)
    );
  }

  private findAfe(tag: string): number {
    for (let i = this.afe.length - 1; i >= 0; i--) {
      const entry = this.afe[i];
      if (entry === undefined || entry === MARKER) return -1;
      if (entry.namespace === NS_HTML && entry.tag === tag) return i;
    }
    return -1;
  }

  private stackTopIs(el: ElementNode): boolean {
    return this.currentNode() === el;
  }

  // ------------------------------------------------------------- dispatch

  private handleToken(token: Token): void {
    switch (token.kind) {
      case 'doctype':
      case 'comment':
        return; // sanitizer never retains these
      case 'eof':
        return;
      case 'character':
        this.handleCharacters(token.data);
        return;
      case 'startTag':
        this.handleStartTag(token.tag, token.attrs, token.selfClosing);
        return;
      case 'endTag':
        this.handleEndTag(token.tag, token.selfClosing);
        return;
    }
  }

  private handleCharacters(data: string): void {
    const cur = this.currentNode();
    if (cur.namespace === NS_HTML && (cur.tag === 'table' || cur.tag === 'tbody' || cur.tag === 'thead' || cur.tag === 'tfoot')) {
      // in-table text: whitespace passes, the rest triggers foster parenting.
      if (data.trim() === '') {
        this.insertText(data);
        return;
      }
      this.pendingTableText += data;
      this.pendingTableTextPendingTable = true;
      this.foster = true;
      this.insertText(data);
      this.foster = false;
      return;
    }
    if (this.mode === 'in-select' && data.trim() === '') {
      this.insertText(data);
      return;
    }
    if (this.mode === 'text') {
      this.insertText(data);
      return;
    }
    this.reconstructAFE();
    this.insertText(data);
  }

  // --------------------------------------------------------- start tags

  private handleStartTag(tag: string, attrs: Attr[], selfClosing: boolean): void {
    // Foreign content gets first crack (§13.2.6.4.7 / in "in head" etc. too).
    if (this.currentNode().namespace !== NS_HTML) {
      if (this.handleForeignStart(tag, attrs, selfClosing)) return;
      // breakout: pop back to HTML and fall through to HTML handling.
    }

    switch (this.mode) {
      case 'in-head':
        return this.startInHead(tag, attrs, selfClosing);
      case 'in-table':
        return this.startInTable(tag, attrs, selfClosing);
      case 'in-table-body':
      case 'in-row':
      case 'in-cell':
      case 'in-caption':
      case 'in-column-group':
        return this.startInTableish(tag, attrs, selfClosing);
      case 'in-select':
      case 'in-select-in-table':
        return this.startInSelect(tag, attrs, selfClosing);
      case 'template':
        if (tag === 'template') return this.startInBody(tag, attrs, selfClosing);
        if (HEAD_ELEMENTS.has(tag)) return this.startInBody(tag, attrs, selfClosing);
        this.popMode();
        return this.handleStartTag(tag, attrs, selfClosing);
      case 'text':
        // text mode only ends via RCDATA end tag; stray starts are chars.
        this.insertText('<' + tag + '>');
        return;
      default:
        return this.startInBody(tag, attrs, selfClosing);
    }
  }

  private startInHead(tag: string, attrs: Attr[], selfClosing: boolean): void {
    if (tag === 'template') {
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.afe.push(MARKER);
      this.inTemplate++;
      this.pushMode('template');
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }
    if (HEAD_ELEMENTS.has(tag)) {
      const el = this.insertElement(tag, NS_HTML, attrs);
      const model = contentModelFor(tag);
      if (model !== 'data') {
        this.tokenizer.setContentModel(model);
        this.pushMode('text');
      } else if (!VOID_ELEMENTS.has(tag) && !selfClosing) {
        // title/style already handled by model; others stay in head briefly.
      }
      if (selfClosing || VOID_ELEMENTS.has(tag)) this.stack.pop();
      return;
    }
    if (tag === 'noscript') {
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.tokenizer.setContentModel('rawtext');
      this.pushMode('text');
      void el;
      return;
    }
    // Anything else leaves head.
    this.popMode();
    this.startInBody(tag, attrs, selfClosing);
  }

  private startInBody(tag: string, attrs: Attr[], selfClosing: boolean): void {
    // --- raw text / special element handling
    const model = contentModelFor(tag);
    if (model !== 'data') {
      this.reconstructAFE();
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.tokenizer.setContentModel(model);
      this.pushMode('text');
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (VOID_ELEMENTS.has(tag)) {
      this.reconstructAFE();
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.stack.pop(); // void: never stays open
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'input' || tag === 'source') {
      this.reconstructAFE();
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.stack.pop();
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'pre' || tag === 'listing') {
      if (this.inButtonScope('p')) this.closeP();
      this.reconstructAFE();
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.afe.push(MARKER);
      // The spec consumes a leading newline here; our serializer never
      // re-introduces one, so skipping it is lossless for sanitization.
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'form') {
      this.reconstructAFE();
      if (this.formPointer && this.inTemplate === 0) {
        if (selfClosing) return;
        return; // ignore
      }
      if (this.inButtonScope('p')) this.closeP();
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.formPointer = el;
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'a') {
      this.reconstructAFE();
      const existing = this.findAfe('a');
      if (existing >= 0) {
        // Run the adoption agency first, then insert the new element and
        // register it on the AFE (§13.2.6.4.7 "a" start tag).
        this.adoptionAgency('a', null);
      }
      this.insertFormatting(tag, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(this.currentNode());
      return;
    }

    if (FORMATTING_ELEMENTS.has(tag)) {
      this.reconstructAFE();
      this.insertFormatting(tag, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(this.currentNode());
      return;
    }

    if (CLOSE_P_ELEMENTS.has(tag)) {
      if (BLOCKED_IN_P.has(tag) && this.inButtonScope('p')) this.closeP();
      this.reconstructAFE();
      const el = this.insertElement(tag, NS_HTML, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (HEADINGS.has(tag)) {
      if (this.inButtonScope('p')) this.closeP();
      // Spec "in body" heading rule: pop elements until the current node is
      // neither a heading nor one of the elements that may contain one. We
      // pop an open heading even when it sits beneath formatting/anchor
      // elements, so the first parse already yields canonical structure
      // (this is what makes re-serialization a fixed point).
      while (this.stack.length > 1) {
        const el = this.currentNode();
        if (el.namespace !== NS_HTML) break;
        if (HEADINGS.has(el.tag)) this.stack.pop();
        else if (FORMATTING_ELEMENTS.has(el.tag) || el.tag === 'a') this.stack.pop();
        else break;
      }
      const el = this.insertElement(tag, NS_HTML, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (LIST_ELEMENTS.has(tag)) {
      if (this.inListScope(tag)) this.popUntil((e) => e.namespace === NS_HTML && e.tag === tag);
      if (this.inButtonScope('p')) this.closeP();
      const el = this.insertElement(tag, NS_HTML, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'li') {
      for (let i = this.stack.length - 1; i >= 0; i--) {
        const el = this.stack[i]!;
        if (el.namespace !== NS_HTML) continue;
        if (el.tag === 'li') { this.stack.length = i; break; }
        if (SCOPE_STOPPERS[NS_HTML]!.has(el.tag) && el.tag !== 'address' && el.tag !== 'div') break;
      }
      if (this.inButtonScope('p')) this.closeP();
      const el = this.insertElement(tag, NS_HTML, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (DL_PARTICIPANTS.has(tag)) {
      if (this.inButtonScope('p')) this.closeP();
      const cur = this.currentNode();
      if (cur.namespace === NS_HTML && DL_PARTICIPANTS.has(cur.tag)) this.stack.pop();
      const el = this.insertElement(tag, NS_HTML, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'table') {
      if (this.inButtonScope('p')) this.closeP();
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.pushMode('in-table');
      this.tableDepth++;
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'select') {
      this.reconstructAFE();
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.afe.push(MARKER);
      this.selectDepth++;
      this.pushMode(this.tableDepth > 0 ? 'in-select-in-table' : 'in-select');
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'option' || tag === 'optgroup') {
      const cur = this.currentNode();
      if (cur.namespace === NS_HTML && cur.tag === 'option') this.stack.pop();
      const el = this.insertElement(tag, NS_HTML, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'svg') {
      const el = this.insertElement('svg', NS_SVG, this.adjustForeignAttrs(attrs, NS_SVG));
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }
    if (tag === 'math') {
      const el = this.insertElement('math', NS_MATHML, this.adjustForeignAttrs(attrs, NS_MATHML));
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    if (tag === 'br') {
      this.reconstructAFE();
      const el = this.insertElement(tag, NS_HTML, attrs);
      this.stack.pop();
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }

    return this.anyOtherStartTag(tag, attrs, selfClosing);
  }

  private anyOtherStartTag(tag: string, attrs: Attr[], selfClosing = false): void {
    this.reconstructAFE();
    const el = this.insertElement(tag, NS_HTML, attrs);
    if (FORMATTING_ELEMENTS.has(tag)) this.afe.push(el);
    if (selfClosing) this.acknowledgeSelfClosing(el);
  }

  private insertFormatting(tag: string, attrs: Attr[]): void {
    // §13.2.6.4.7 "reconstruct active formatting elements" insertion step.
    const adjusted = attrs;
    if (this.afe.length > 3 && this.hasThreeBlockersBefore(tag)) {
      this.afe.shift();
    }
    const el = this.insertElement(tag, NS_HTML, adjusted);
    el.afeIndex = this.afe.length;
    this.afe.push(el);
  }

  private hasThreeBlockersBefore(tag: string): boolean {
    let blockers = 0;
    for (const entry of this.afe) {
      if (entry === MARKER) blockers++;
      else if (entry.namespace === NS_HTML && entry.tag === tag) return false;
    }
    void tag;
    return blockers >= 3;
  }

  // ----------------------------------------------------------- end tags

  private handleEndTag(tag: string, selfClosing: boolean): void {
    if (selfClosing) {
      // Self-closing end tags are parse errors in HTML; ignore the flag.
    }
    if (this.currentNode().namespace !== NS_HTML) {
      if (this.handleForeignEnd(tag)) return;
    }
    switch (this.mode) {
      case 'text':
        if (RCDATA_ELEMENTS.has(tag) || RAWTEXT_ELEMENTS.has(tag) || tag === 'script' || tag === 'noscript') {
          // The current node is the raw-text/RCDATA element itself.
          this.stack.pop();
          this.popMode();
          return;
        }
        return;
      case 'in-head':
        if (HEAD_ELEMENTS.has(tag) || tag === 'noscript' || tag === 'noframes') {
          this.popUntil((e) => e.namespace === NS_HTML && e.tag === tag);
          return;
        }
        if (tag === 'template') {
          this.stackPopUntilTag('template');
          this.afe.length = 0;
          this.inTemplate--;
          this.popMode();
          return;
        }
        this.popMode();
        return this.handleEndTag(tag, false);
      case 'in-table':
        return this.endInTable(tag);
      case 'in-table-body':
      case 'in-row':
      case 'in-cell':
      case 'in-caption':
      case 'in-column-group':
        return this.endInTableish(tag);
      case 'in-select':
      case 'in-select-in-table':
        return this.endInSelect(tag);
      case 'template':
        if (tag === 'template') {
          this.stackPopUntilTag('template');
          this.afe.length = 0;
          this.inTemplate--;
          this.popMode();
        }
        return;
      default:
        return this.endInBody(tag);
    }
  }

  private endInBody(tag: string): void {
    if (BODY_END_CANDIDATES.has(tag)) {
      if (!this.inScope(tag)) return;
      this.popUntil((e) => e.namespace === NS_HTML && e.tag === tag);
      return;
    }
    if (tag === 'form') {
      const form = this.formPointer;
      this.formPointer = null;
      if (!form || !this.inScope('form')) return;
      this.popUntil((e) => e === form);
      return;
    }
    if (tag === 'p') {
      // Stray </p> with no open paragraph: ignore (no empty element).
      if (!this.inButtonScope('p')) return;
      this.closeP();
      return;
    }
    if (FORMATTING_ELEMENTS.has(tag)) {
      this.adoptionAgency(tag, null);
      return;
    }
    if (tag === 'br') {
      // </br> parse error -> act like <br>.
      this.reconstructAFE();
      const el = this.insertElement('br', NS_HTML, []);
      this.stack.pop();
      return;
    }
    if (tag === 'svg') {
      this.stackPopUntilTag('svg', NS_SVG);
      return;
    }
    if (tag === 'math') {
      this.stackPopUntilTag('math', NS_MATHML);
      return;
    }
    if (tag === 'table') {
      if (!this.inTableScope('table')) return;
      this.stackPopUntilTag('table');
      this.tableDepth--;
      this.popMode();
      return;
    }
    // Generic end tag. Never close the fragment root (index 0).
    for (let i = this.stack.length - 1; i >= 1; i--) {
      const el = this.stack[i]!;
      if (el.namespace === NS_HTML && el.tag === tag) {
        this.stack.length = i;
        return;
      }
      if (SCOPE_STOPPERS[NS_HTML]!.has(el.tag)) return;
    }
  }

  /** Pop the open <p> in button scope. Callers must check scope first. */
  private closeP(): void {
    this.popUntil((e) => e.namespace === NS_HTML && e.tag === 'p');
  }

  private stackPopUntilTag(tag: string, namespace: Namespace = NS_HTML): void {
    // Never remove the fragment root at index 0.
    for (let i = this.stack.length - 1; i >= 1; i--) {
      const el = this.stack[i]!;
      if (el.namespace === namespace && el.tag === tag) {
        this.stack.length = i;
        return;
      }
    }
  }

  // ----------------------------------------------------------- tables

  private startInTable(tag: string, attrs: Attr[], selfClosing: boolean): void {
    switch (tag) {
      case 'caption':
      case 'colgroup':
      case 'col':
      case 'tbody':
      case 'tfoot':
      case 'thead':
      case 'tr':
      case 'td':
      case 'th': {
        if (tag === 'caption') {
          const el = this.insertFosterless(tag, attrs);
          this.afe.push(MARKER);
          this.pushMode('in-caption');
          if (selfClosing) this.acknowledgeSelfClosing(el);
          return;
        }
        if (tag === 'colgroup') {
          const el = this.insertFosterless(tag, attrs);
          this.pushMode('in-column-group');
          if (selfClosing) this.acknowledgeSelfClosing(el);
          return;
        }
        if (tag === 'col') {
          const el = this.insertFosterless(tag, attrs);
          this.stack.pop();
          if (selfClosing) this.acknowledgeSelfClosing(el);
          return;
        }
        if (tag === 'tbody' || tag === 'thead' || tag === 'tfoot') {
          const el = this.insertFosterless(tag, attrs);
          this.pushMode('in-table-body');
          if (selfClosing) this.acknowledgeSelfClosing(el);
          return;
        }
        if (tag === 'tr') {
          const body = this.insertFosterless('tbody', []);
          this.pushMode('in-table-body');
          const row = this.insertElement('tr', NS_HTML, attrs);
          this.pushMode('in-row');
          if (selfClosing) this.acknowledgeSelfClosing(row);
          void body;
          return;
        }
        // td/th directly in table -> fabricate tbody/tr.
        this.insertFosterless('tbody', []);
        this.pushMode('in-table-body');
        this.insertElement('tr', NS_HTML, []);
        this.pushMode('in-row');
        this.startInCell(tag, attrs, selfClosing);
        return;
      }
      case 'style':
      case 'script':
      case 'template':
        return this.startInHead(tag, attrs, selfClosing);
      case 'input': {
        // Only type=hidden inputs are processed in-table; others foster out.
        const typeAttr = attrs.find((a) => a.name === 'type');
        if (typeAttr && typeAttr.value.toLowerCase() === 'hidden') {
          const el = this.insertElement(tag, NS_HTML, attrs);
          this.stack.pop();
          if (selfClosing) this.acknowledgeSelfClosing(el);
          return;
        }
        break;
      }
      case 'form':
        return; // ignored in-table except the pointer bookkeeping, skipped
      default:
        break;
    }
    // Anything else: process in body with foster parenting on.
    this.foster = true;
    this.startInBody(tag, attrs, selfClosing);
    this.foster = false;
  }

  private insertFosterless(tag: string, attrs: Attr[]): ElementNode {
    return this.insertElement(tag, NS_HTML, attrs);
  }

  private startInTableish(tag: string, attrs: Attr[], selfClosing: boolean): void {
    // A new section while one is already open: close the current section
    // (and any open row/cell) then let in-table create the new one.
    if (tag === 'tbody' || tag === 'thead' || tag === 'tfoot') {
      this.closeToTableBody();
      return this.startInTable(tag, attrs, selfClosing);
    }
    if (this.mode === 'in-column-group') {
      if (tag === 'col') {
        const el = this.insertElement(tag, NS_HTML, attrs);
        this.stack.pop();
        if (selfClosing) this.acknowledgeSelfClosing(el);
        return;
      }
      this.stackPopUntilTag('colgroup');
      this.popMode();
      return this.startInTable(tag, attrs, selfClosing);
    }
    if ((this.mode === 'in-table-body' || this.mode === 'in-row') && tag === 'tr') {
      // Implicitly close the previous row (an open cell is already closed by
      // the row transition in practice; in-row is the live mode here).
      if (this.mode === 'in-row') {
        this.stackPopUntilTag('tr');
        this.popMode(); // -> in-table-body
      }
      const el = this.insertElement('tr', NS_HTML, attrs);
      this.pushMode('in-row');
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }
    if (TABLE_CELLS.has(tag)) {
      return this.startInCell(tag, attrs, selfClosing);
    }
    if (TABLE_ELEMENTS.has(tag)) {
      this.closeTableish();
      return this.startInTable(tag, attrs, selfClosing);
    }
    if (tag === 'caption' || tag === 'colgroup') {
      this.closeTableish();
      return this.startInTable(tag, attrs, selfClosing);
    }
    this.foster = true;
    this.startInBody(tag, attrs, selfClosing);
    this.foster = false;
  }

  private startInCell(tag: string, attrs: Attr[], selfClosing: boolean): void {
    // A cell is already open in this row: close it implicitly so the new
    // cell becomes a sibling under the same <tr>.
    if (this.mode === 'in-cell') {
      const openTag = this.currentNode().tag === 'th' ? 'th' : 'td';
      this.stackPopUntilTag(openTag);
      this.afe.length = Math.max(0, this.lastMarkerIndex());
      this.popMode(); // in-cell -> in-row (current node is now <tr>)
    }
    const el = this.insertElement(tag, NS_HTML, attrs);
    this.afe.push(MARKER);
    this.pushMode('in-cell');
    if (selfClosing) this.acknowledgeSelfClosing(el);
  }

  private endInTable(tag: string): void {
    if (tag === 'table') {
      if (!this.inTableScope('table')) return;
      this.stackPopUntilTag('table');
      this.tableDepth--;
      this.popMode();
      return;
    }
    if (tag === 'template') return this.endInBody(tag);
    // Ignore mismatched table end tags.
  }

  private endInTableish(tag: string): void {
    // Cell end tag: pop the cell, clear its AFE markers, return to in-row.
    if ((tag === 'td' || tag === 'th') && this.mode === 'in-cell') {
      if (!this.inTableScope(tag)) return;
      this.stackPopUntilTag(tag);
      this.afe.length = Math.max(0, this.lastMarkerIndex());
      this.popMode(); // in-cell -> in-row
      return;
    }
    if (tag === 'caption' && this.mode === 'in-caption') {
      if (!this.inTableScope('caption')) return;
      this.stackPopUntilTag('caption');
      this.afe.length = Math.max(0, this.lastMarkerIndex());
      this.popMode(); // -> in-table
      return;
    }
    if (tag === 'tr') {
      if (!this.inTableScope('tr')) return;
      // Close any open cell implicitly first.
      if (this.mode === 'in-cell') {
        this.stackPopUntilTag(this.currentNode().tag === 'th' ? 'th' : 'td');
        this.afe.length = Math.max(0, this.lastMarkerIndex());
        this.popMode(); // -> in-row
      }
      this.stackPopUntilTag('tr');
      this.popMode(); // in-row -> in-table-body
      return;
    }
    if (tag === 'tbody' || tag === 'thead' || tag === 'tfoot') {
      if (!this.inTableScope(tag)) return;
      if (this.mode === 'in-cell') {
        this.stackPopUntilTag(this.currentNode().tag === 'th' ? 'th' : 'td');
        this.afe.length = Math.max(0, this.lastMarkerIndex());
        this.popMode();
      }
      if (this.mode === 'in-row') {
        this.stackPopUntilTag('tr');
        this.popMode();
      }
      this.stackPopUntilTag(tag);
      this.popMode(); // section -> in-table
      return;
    }
    if (TABLE_ELEMENTS.has(tag)) {
      this.closeTableish();
      return this.endInTable(tag);
    }
    this.foster = true;
    this.endInBody(tag);
    this.foster = false;
  }

  /** Pop an open cell/row and the current table section, ending in in-table. */
  private closeToTableBody(): void {
    if (this.mode === 'in-cell') {
      const t = this.currentNode().tag === 'th' ? 'th' : 'td';
      this.stackPopUntilTag(t);
      this.afe.length = Math.max(0, this.lastMarkerIndex());
      this.popMode(); // -> in-row
    }
    if (this.mode === 'in-row') {
      this.stackPopUntilTag('tr');
      this.popMode(); // -> in-table-body
    }
    if (this.mode === 'in-table-body') {
      const cur = this.currentNode();
      if (cur.namespace === NS_HTML && (cur.tag === 'tbody' || cur.tag === 'thead' || cur.tag === 'tfoot')) {
        this.stack.pop();
      }
      this.popMode(); // -> in-table
    }
  }

  private closeTableish(): void {
    // Pop back to the nearest table structural element.
    while (this.stack.length) {
      const el = this.currentNode();
      if (el.namespace === NS_HTML && ['table', 'tbody', 'thead', 'tfoot', 'tr', 'td', 'th', 'caption', 'colgroup'].includes(el.tag)) {
        this.stack.pop();
        this.popMode();
        if (el.tag === 'table') break;
        if (this.mode === 'in-table') break;
      } else break;
    }
  }

  private lastMarkerIndex(): number {
    for (let i = this.afe.length - 1; i >= 0; i--) {
      if (this.afe[i] === MARKER) return i;
    }
    return 0;
  }

  // ---------------------------------------------------------- select

  private startInSelect(tag: string, attrs: Attr[], selfClosing: boolean): void {
    if (tag === 'option' || tag === 'optgroup') {
      if (this.currentNode().tag === 'option') this.stack.pop();
      const el = this.insertElement(tag, NS_HTML, attrs);
      if (selfClosing) this.acknowledgeSelfClosing(el);
      return;
    }
    if (tag === 'input') {
      const typeAttr = attrs.find((a) => a.name === 'type');
      if (typeAttr && typeAttr.value.toLowerCase() === 'hidden') {
        const el = this.insertElement(tag, NS_HTML, attrs);
        this.stack.pop();
        if (selfClosing) this.acknowledgeSelfClosing(el);
        return;
      }
      // Non-hidden input: close select, reprocess in body.
      this.stackPopUntilTag('select');
      this.popMode();
      this.selectDepth--;
      return this.startInBody(tag, attrs, selfClosing);
    }
    if (tag === 'select') {
      this.stackPopUntilTag('select');
      this.popMode();
      this.selectDepth--;
      return;
    }
    if (this.mode === 'in-select-in-table' && TABLE_ELEMENTS.has(tag)) {
      this.stackPopUntilTag('select');
      const saved = this.mode;
      this.popMode();
      this.selectDepth--;
      void saved;
      return this.startInTable(tag, attrs, selfClosing);
    }
    // Everything else is ignored inside select.
  }

  private endInSelect(tag: string): void {
    if (tag === 'option' || tag === 'optgroup') {
      for (let i = this.stack.length - 1; i >= 0; i--) {
        const el = this.stack[i]!;
        if (el.namespace === NS_HTML && el.tag === tag) {
          this.stack.length = i;
          return;
        }
        if (el.namespace === NS_HTML && el.tag === 'select') return;
      }
      return;
    }
    if (tag === 'select') {
      if (!this.inScope('select')) return;
      this.stackPopUntilTag('select');
      this.afe.length = Math.max(0, this.lastMarkerIndex());
      this.popMode();
      this.selectDepth--;
      return;
    }
    // Other end tags ignored in select.
  }

  // --------------------------------------------------------- foreign

  /** @returns true if handled inside foreign content. */
  private handleForeignStart(tag: string, attrs: Attr[], selfClosing: boolean): boolean {
    const cur = this.currentNode();

    // Breakout conditions (§13.2.6.4.7).
    if (cur.namespace === NS_SVG && SVG_BREAKOUT.has(tag)) {
      this.popToHtml();
      return false;
    }
    if (tag === 'font' && attrs.some((a) => (a.name === 'color' || a.name === 'face' || a.name === 'size'))) {
      this.popToHtml();
      return false;
    }
    // MathML text integration point: only font/type tags stay foreign.
    if (cur.namespace === NS_MATHML && MATHML_TEXT_INTEGRATION.has(cur.tag)) {
      if (tag !== 'mglyph' && tag !== 'malignmark') {
        this.popToHtml();
        return false;
      }
    }
    // HTML integration points: HTML tags stay, only foreign re-entry switches.
    if ((cur.namespace === NS_SVG && HTML_INTEGRATION.has(cur.tag)) ||
        (cur.namespace === NS_MATHML && MATHML_HTML_INTEGRATION.has(cur.tag) &&
          cur.attrs.some((a) => a.name === 'encoding' && /text\/html/i.test(a.value)))) {
      if (tag === 'svg') {
        const el = this.insertElement('svg', NS_SVG, this.adjustForeignAttrs(attrs, NS_SVG));
        if (selfClosing) this.acknowledgeSelfClosing(el);
        return true;
      }
      if (tag === 'math') {
        const el = this.insertElement('math', NS_MATHML, this.adjustForeignAttrs(attrs, NS_MATHML));
        if (selfClosing) this.acknowledgeSelfClosing(el);
        return true;
      }
      this.popToHtml();
      return false;
    }

    const namespace = cur.namespace;
    const adjustedTag = namespace === NS_SVG ? SVG_TAG_ADJUST[tag] ?? tag : tag;
    const el = this.insertElement(adjustedTag, namespace, this.adjustForeignAttrs(attrs, namespace));
    if (selfClosing || this.isForeignVoid(namespace, adjustedTag)) {
      this.acknowledgeSelfClosing(el);
    }
    return true;
  }

  private handleForeignEnd(tag: string): boolean {
    const adjusted = this.currentNode().namespace === NS_SVG ? SVG_TAG_ADJUST[tag] ?? tag : tag;
    for (let i = this.stack.length - 1; i >= 1; i--) {
      const el = this.stack[i]!;
      if (el.namespace !== NS_HTML && el.tag === adjusted) {
        this.stack.length = i;
        return true;
      }
      if (el.namespace === NS_HTML) break;
    }
    // Parse error: an end tag in foreign content with no matching foreign
    // element is swallowed — it must NOT fall through to the HTML rules
    // (where e.g. </br> would synthesize an HTML <br> and leak namespace).
    return true;
  }

  private popToHtml(): void {
    while (this.currentNode().namespace !== NS_HTML) this.stack.pop();
  }

  private isForeignVoid(namespace: Namespace, tag: string): boolean {
    if (namespace === NS_MATHML) {
      // MathML has no HTML-style void elements in fragment parsing; all stay open.
      return false;
    }
    // SVG: self-closing is driven by the token; nothing is implicitly void.
    void tag;
    return false;
  }

  private adjustForeignAttrs(attrs: Attr[], namespace: Namespace): Attr[] {
    return attrs.map((a) => {
      const name = FOREIGN_ATTR_ADJUST[a.name] ?? (namespace === NS_SVG ? SVG_ATTR_ADJUST[a.name] ?? a.name : a.name);
      return { name, value: a.value, prefix: attrPrefixOf(name) };
    });
  }

  private acknowledgeSelfClosing(el: ElementNode): void {
    // Acknowledged self-closing: pop immediately.
    const idx = this.stack.indexOf(el);
    if (idx >= 0 && this.stack[idx] === el) this.stack.length = idx;
  }
}

function attrPrefixOf(name: string): string | null {
  const colon = name.indexOf(':');
  return colon > 0 ? name.slice(0, colon) : null;
}

// --------------------------------------------- low-level tree manipulation

function detach(node: Node): void {
  const parent = node.parent;
  if (!parent) return;
  const i = parent.children.indexOf(node);
  if (i >= 0) parent.children.splice(i, 1);
  node.parent = null;
}

function insertAfter(node: Node, ref: ElementNode): void {
  const parent = ref.parent;
  if (!parent) return;
  const i = parent.children.indexOf(ref);
  node.parent = parent;
  parent.children.splice(i + 1, 0, node);
}

function parentOf(node: ElementNode): ElementNode {
  return node.parent ?? node;
}
