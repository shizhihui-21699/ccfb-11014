/**
 * HTML tokenizer — WHATWG HTML Standard §13.25 "Tokenization".
 *
 * Character-by-character state machine. Deliberate simplification: DOCTYPE
 * tokens carry no details (a sanitizer always discards them). Everything
 * relevant to security — character references, raw-text elements, CDATA in
 * foreign content, self-closing flags, null replacement, bogus comments,
 * duplicate attributes — follows the spec.
 */

import {
  NAMED_ENTITIES,
  LEGACY_ENTITIES,
  NAMED_ENTITY_KEYS,
  LEGACY_ENTITY_KEYS,
} from './entities.ts';
import type { Attr, Token } from './types.ts';

const S = {
  Data: 1,
  Rcdata: 2,
  Rawtext: 3,
  ScriptData: 4,
  Plaintext: 5,
  TagOpen: 6,
  EndTagOpen: 7,
  TagName: 8,
  RcdataLt: 9,
  RcdataTagOpen: 10,
  RcdataTagName: 11,
  RawtextLt: 12,
  RawtextTagOpen: 13,
  RawtextTagName: 14,
  ScriptDataLt: 15,
  ScriptDataTagOpen: 16,
  ScriptDataTagName: 17,
  ScriptDataEsc: 18,
  ScriptDataEscDash: 19,
  ScriptDataEscDashDash: 20,
  ScriptDataEscLt: 21,
  ScriptDataEscTagName: 22,
  ScriptDataDoubleEsc: 23,
  ScriptDataDoubleEscDash: 24,
  ScriptDataDoubleEscDashDash: 25,
  ScriptDataDoubleEscLt: 26,
  BeforeAttr: 27,
  AttrName: 28,
  AfterAttrName: 29,
  BeforeAttrValue: 30,
  AttrValueDq: 31,
  AttrValueSq: 32,
  AttrValueUnquoted: 33,
  AfterAttrValueQ: 34,
  SelfClosingStart: 35,
  BogusComment: 36,
  MarkupDeclOpen: 37,
  CommentStart: 38,
  CommentStartDash: 39,
  Comment: 40,
  CommentLt: 41,
  CommentDash: 42,
  CommentDashDash: 43,
  CommentEndBang: 44,
  Doctype: 45,
  Cdata: 46,
  CdataBracket: 47,
  CdataEnd: 48,
} as const;
type S = (typeof S)[keyof typeof S];

const REPLACEMENT = '�';
const WS = new Set(['\t', '\n', '\f', ' ']);

/** Windows-1252 override / replacement table for numeric refs (§13.2.5.72). */
const NUMERIC_MAP: ReadonlyMap<number, number> = new Map([
  [0x00, 0xfffd], [0x0d, 0x000d],
  [0x80, 0x20ac], [0x82, 0x201a], [0x83, 0x0192], [0x84, 0x201e],
  [0x85, 0x2026], [0x86, 0x2020], [0x87, 0x2021], [0x88, 0x02c6],
  [0x89, 0x2030], [0x8a, 0x0160], [0x8b, 0x2039], [0x8c, 0x0152],
  [0x8e, 0x017d], [0x91, 0x2018], [0x92, 0x2019], [0x93, 0x201c],
  [0x94, 0x201d], [0x95, 0x2022], [0x96, 0x2013], [0x97, 0x2014],
  [0x98, 0x02dc], [0x99, 0x2122], [0x9a, 0x0161], [0x9b, 0x203a],
  [0x9c, 0x0153], [0x9e, 0x017e], [0x9f, 0x0178],
]);

function decodeNumeric(code: number): string {
  if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return REPLACEMENT;
  const mapped = NUMERIC_MAP.get(code);
  return String.fromCodePoint(mapped ?? code);
}

/**
 * Longest key in the sorted list that is a prefix of `input` at `start`.
 * Keys include the leading '&'.
 */
function longestPrefix(
  keys: readonly string[],
  input: string,
  start: number
): string | null {
  // Lower-bound search on the key list using a correct lexicographic
  // comparison of each key against the input suffix (truncated to key length).
  let lo = 0;
  let hi = keys.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    const key = keys[mid]!;
    if (compareKeyToSuffix(key, input, start) <= 0) lo = mid + 1;
    else hi = mid;
  }
  // lo is the first key strictly greater than the suffix. The longest
  // matching prefix is among the keys immediately before it; walk backwards.
  for (let i = lo - 1; i >= 0; i--) {
    const key = keys[i]!;
    if (suffixStartsWith(input, start, key)) return key;
    // Keys are sorted; once the key no longer even shares the leading '&'
    // region ordering, no earlier key can match.
    if (key[0] !== '&' || input[start] !== '&') break;
  }
  return null;
}

/** Compare key against input[start:], treating the suffix as shorter-or-equal. */
function compareKeyToSuffix(key: string, input: string, start: number): number {
  const n = Math.min(key.length, input.length - start);
  for (let i = 0; i < n; i++) {
    const a = key.charCodeAt(i);
    const b = input.charCodeAt(start + i);
    if (a !== b) return a < b ? -1 : 1;
  }
  // All compared chars equal: shorter suffix sorts first.
  return key.length <= n ? 0 : 1;
}

function suffixStartsWith(input: string, start: number, prefix: string): boolean {
  if (start + prefix.length > input.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (input.charCodeAt(start + i) !== prefix.charCodeAt(i)) return false;
  }
  return true;
}

export interface TokenizerHost {
  onToken(token: Token): void;
  /** Adjusted insertion location in foreign (SVG/MathML) content? */
  isForeign(): boolean;
  /** The start tag the raw-text scanner is looking for (lower-case). */
  getLastStartTag(): string | null;
}

export type ContentModel = 'data' | 'rcdata' | 'rawtext' | 'script' | 'plaintext';

export class Tokenizer {
  private input = '';
  private pos = 0;
  private state: S = S.Data;
  private returnState: S = S.Data;

  private tagName = '';
  private attrs: Attr[] = [];
  private attrName = '';
  private attrValue = '';
  private selfClosing = false;
  private isEndTag = false;

  private comment = '';
  private tmpTag = '';

  private host: TokenizerHost;

  constructor(host: TokenizerHost) {
    this.host = host;
  }

  parse(input: string): void {
    // §13.2.3.1: U+0000 is a parse error -> U+FFFD in every state. Replacing
    // up front gives identical results because numeric-character-reference
    // decoding (the one state with different null handling) happens before
    // the replacement in the data stream.
    this.input = input.includes('\u0000') ? input.replace(/\u0000/g, REPLACEMENT) : input;
    this.pos = 0;
    this.state = S.Data;
    this.returnState = S.Data;
    this.tagName = '';
    this.attrs = [];
    this.comment = '';
    this.isEndTag = false;

    while (this.pos < this.input.length) {
      const c = this.input[this.pos]!;
      this.step(c);
    }
    this.eof();
  }

  /** Reconsume helper: state switch without advancing. */
  private reconsume(state: S, c: string): void {
    this.state = state;
    this.step(c);
  }

  private step(c: string): void {
    switch (this.state) {
      case S.Data: {
        if (c === '&') { this.charRef(false); return; }
        if (c === '<') { this.state = S.TagOpen; this.pos++; return; }
        this.emitChar(c);
        this.pos++;
        return;
      }
      case S.Rcdata: {
        if (c === '&') { this.returnState = S.Rcdata; this.charRef(false); return; }
        if (c === '<') { this.state = S.RcdataLt; this.pos++; return; }
        this.emitChar(c);
        this.pos++;
        return;
      }
      case S.Rawtext: {
        if (c === '<') { this.state = S.RawtextLt; this.pos++; return; }
        this.emitChar(c);
        this.pos++;
        return;
      }
      case S.Plaintext: {
        this.emitChar(c);
        this.pos++;
        return;
      }
      case S.ScriptData: {
        if (c === '<') { this.state = S.ScriptDataLt; this.pos++; return; }
        this.emitChar(c);
        this.pos++;
        return;
      }

      case S.TagOpen: {
        if (c === '!') { this.state = S.MarkupDeclOpen; this.pos++; return; }
        if (c === '/') { this.state = S.EndTagOpen; this.pos++; return; }
        if (isAsciiAlpha(c)) {
          this.tagName = c.toLowerCase();
          this.attrs = [];
          this.selfClosing = false;
          this.isEndTag = false;
          this.state = S.TagName;
          this.pos++;
          return;
        }
        this.emitChar('<');
        this.reconsume(S.Data, c);
        return;
      }
      case S.EndTagOpen: {
        if (isAsciiAlpha(c)) {
          this.tagName = c.toLowerCase();
          this.attrs = [];
          this.selfClosing = false;
          this.isEndTag = true;
          this.state = S.TagName;
          this.pos++;
          return;
        }
        if (c === '>') { this.state = S.Data; this.pos++; return; }
        this.comment = '';
        this.state = S.BogusComment;
        this.pos++;
        return;
      }
      case S.TagName: {
        if (WS.has(c)) { this.state = S.BeforeAttr; this.pos++; return; }
        if (c === '/') { this.state = S.SelfClosingStart; this.pos++; return; }
        if (c === '>') { this.emitTag(); this.pos++; return; }
        if (c === '<') { this.emitChar(c); this.pos++; return; }
        this.tagName += c.toLowerCase();
        this.pos++;
        return;
      }

      // --------------------------------------------- raw text end-tag scan
      case S.RcdataLt:
      case S.RawtextLt: {
        const base = this.state === S.RcdataLt ? S.Rcdata : S.Rawtext;
        if (c === '/') {
          this.tmpTag = '';
          this.state = this.state === S.RcdataLt ? S.RcdataTagOpen : S.RawtextTagOpen;
          this.pos++;
          return;
        }
        this.emitChar('<');
        this.reconsume(base, c);
        return;
      }
      case S.RcdataTagOpen:
      case S.RawtextTagOpen: {
        const base = this.state === S.RcdataTagOpen ? S.Rcdata : S.Rawtext;
        if (isAsciiAlpha(c)) {
          this.tmpTag = c.toLowerCase();
          this.tagName = this.tmpTag;
          this.attrs = [];
          this.isEndTag = true;
          this.state = this.state === S.RcdataTagOpen ? S.RcdataTagName : S.RawtextTagName;
          this.pos++;
          return;
        }
        this.emitChar('<');
        this.emitChar('/');
        this.reconsume(base, c);
        return;
      }
      case S.RcdataTagName:
        return this.textLikeTagName(c, S.Rcdata);
      case S.RawtextTagName:
        return this.textLikeTagName(c, S.Rawtext);

      // ------------------------------------------------------- <script>
      case S.ScriptDataLt: {
        if (c === '/') { this.tmpTag = ''; this.state = S.ScriptDataTagOpen; this.pos++; return; }
        if (c === '!') { this.emitChar('<'); this.emitChar('!'); this.state = S.ScriptDataEsc; this.pos++; return; }
        this.emitChar('<');
        this.reconsume(S.ScriptData, c);
        return;
      }
      case S.ScriptDataTagOpen: {
        if (isAsciiAlpha(c)) {
          this.tmpTag = c.toLowerCase();
          this.tagName = this.tmpTag;
          this.attrs = [];
          this.isEndTag = true;
          this.state = S.ScriptDataTagName;
          this.pos++;
          return;
        }
        this.emitChar('<');
        this.emitChar('/');
        this.reconsume(S.ScriptData, c);
        return;
      }
      case S.ScriptDataTagName:
        return this.textLikeTagName(c, S.ScriptData);
      case S.ScriptDataEsc: {
        if (c === '-') { this.emitChar(c); this.state = S.ScriptDataEscDash; this.pos++; return; }
        if (c === '<') { this.state = S.ScriptDataEscLt; this.pos++; return; }
        this.emitChar(c);
        this.pos++;
        return;
      }
      case S.ScriptDataEscDash: {
        if (c === '-') { this.emitChar(c); this.state = S.ScriptDataEscDashDash; this.pos++; return; }
        this.emitChar(c);
        this.state = S.ScriptDataEsc;
        this.pos++;
        return;
      }
      case S.ScriptDataEscDashDash: {
        if (c === '-') { this.emitChar(c); this.pos++; return; }
        if (c === '<') { this.state = S.ScriptDataEscLt; this.pos++; return; }
        if (c === '>') { this.emitChar(c); this.state = S.ScriptData; this.pos++; return; }
        this.emitChar(c);
        this.state = S.ScriptDataEsc;
        this.pos++;
        return;
      }
      case S.ScriptDataEscLt:
      case S.ScriptDataDoubleEscLt: {
        if (isAsciiAlpha(c)) {
          this.tmpTag = c.toLowerCase();
          this.emitChar('<');
          this.emitChar(c);
          this.state = S.ScriptDataEscTagName;
          this.pos++;
          return;
        }
        this.emitChar('<');
        this.reconsume(S.ScriptDataEsc, c);
        return;
      }
      case S.ScriptDataEscTagName: {
        if (WS.has(c) && this.matchesLast()) { this.tagName = this.tmpTag; this.state = S.BeforeAttr; this.pos++; return; }
        if (c === '/' && this.matchesLast()) { this.tagName = this.tmpTag; this.state = S.SelfClosingStart; this.pos++; return; }
        if (c === '>' && this.matchesLast()) { this.tagName = this.tmpTag; this.emitTag(); this.pos++; return; }
        this.tmpTag += c;
        this.emitChar(c);
        this.pos++;
        return;
      }
      case S.ScriptDataDoubleEsc: {
        if (c === '-') { this.emitChar(c); this.state = S.ScriptDataDoubleEscDash; this.pos++; return; }
        if (c === '<') { this.state = S.ScriptDataDoubleEscLt; this.pos++; return; }
        this.emitChar(c);
        this.pos++;
        return;
      }
      case S.ScriptDataDoubleEscDash: {
        if (c === '-') { this.emitChar(c); this.state = S.ScriptDataDoubleEscDashDash; this.pos++; return; }
        this.emitChar(c);
        this.state = S.ScriptDataDoubleEsc;
        this.pos++;
        return;
      }
      case S.ScriptDataDoubleEscDashDash: {
        if (c === '>') { this.state = S.ScriptData; this.pos++; return; }
        if (c === '-') { this.emitChar(c); this.pos++; return; }
        this.emitChar(c);
        this.state = S.ScriptDataDoubleEsc;
        this.pos++;
        return;
      }

      // --------------------------------------------------------- attributes
      case S.BeforeAttr: {
        if (WS.has(c)) { this.pos++; return; }
        if (c === '/' || c === '>') { this.reconsume(S.SelfClosingStart, c); return; }
        if (c === '=') { this.emitChar(c); this.pos++; return; }
        this.attrName = '';
        this.attrValue = '';
        this.state = S.AttrName;
        return; // reconsume
      }
      case S.AttrName: {
        if (WS.has(c) || c === '/' || c === '>') {
          // Attribute without a value. Commit it now; the value field is ''.
          this.finishAttr();
          this.reconsume(S.AfterAttrName, c);
          return;
        }
        if (c === '=') {
          // Name is complete; value comes after the '=' (BeforeAttrValue).
          // Do NOT finish here — attrValue must survive until the value is read.
          this.state = S.BeforeAttrValue;
          this.pos++;
          return;
        }
        this.attrName += c.toLowerCase();
        this.pos++;
        return;
      }
      case S.AfterAttrName: {
        if (WS.has(c)) { this.pos++; return; }
        if (c === '/') { this.state = S.SelfClosingStart; this.pos++; return; }
        if (c === '>') { this.emitTag(); this.pos++; return; }
        if (c === '=') { this.state = S.BeforeAttrValue; this.pos++; return; }
        this.attrName = '';
        this.attrValue = '';
        this.state = S.AttrName;
        return; // reconsume
      }
      case S.BeforeAttrValue: {
        if (WS.has(c)) { this.pos++; return; }
        if (c === '"') { this.attrValue = ''; this.state = S.AttrValueDq; this.pos++; return; }
        if (c === "'") { this.attrValue = ''; this.state = S.AttrValueSq; this.pos++; return; }
        if (c === '>') { this.emitTag(); this.pos++; return; }
        this.attrValue = '';
        this.state = S.AttrValueUnquoted;
        return; // reconsume
      }
      case S.AttrValueDq: {
        if (c === '"') { this.finishAttr(); this.state = S.AfterAttrValueQ; this.pos++; return; }
        if (c === '&') { this.returnState = S.AttrValueDq; this.charRef(true); return; }
        this.attrValue += c;
        this.pos++;
        return;
      }
      case S.AttrValueSq: {
        if (c === "'") { this.finishAttr(); this.state = S.AfterAttrValueQ; this.pos++; return; }
        if (c === '&') { this.returnState = S.AttrValueSq; this.charRef(true); return; }
        this.attrValue += c;
        this.pos++;
        return;
      }
      case S.AttrValueUnquoted: {
        if (WS.has(c)) { this.finishAttr(); this.state = S.BeforeAttr; this.pos++; return; }
        if (c === '>') { this.finishAttr(); this.emitTag(); this.pos++; return; }
        if (c === '<' || c === '`') { this.emitChar(c); this.pos++; return; }
        if (c === '&') { this.returnState = S.AttrValueUnquoted; this.charRef(true); return; }
        this.attrValue += c;
        this.pos++;
        return;
      }
      case S.AfterAttrValueQ: {
        if (WS.has(c)) { this.state = S.BeforeAttr; this.pos++; return; }
        if (c === '/') { this.state = S.SelfClosingStart; this.pos++; return; }
        if (c === '>') { this.emitTag(); this.pos++; return; }
        if (c === '<') { this.emitChar(c); this.pos++; return; }
        this.reconsume(S.BeforeAttr, c);
        return;
      }
      case S.SelfClosingStart: {
        if (c === '>') { this.selfClosing = true; this.emitTag(); this.pos++; return; }
        // Parse error: the '/' was not followed by '>'. Discard the '/' by
        // moving to BeforeAttr WITHOUT reconsuming (reconsuming would bounce
        // straight back here for '/' and '>' and never advance).
        this.state = S.BeforeAttr;
        this.pos++;
        return;
      }

      // ---------------------------------------------------------- comments
      case S.BogusComment: {
        if (c === '>') { this.emitComment(); this.state = S.Data; this.pos++; return; }
        this.comment += c; // nulls already replaced up front
        this.pos++;
        return;
      }
      case S.MarkupDeclOpen: {
        if (c === '-' && this.input[this.pos + 1] === '-') {
          this.comment = '';
          this.state = S.CommentStart;
          this.pos += 2;
          return;
        }
        if (startsWithCI(this.input, this.pos, 'DOCTYPE')) {
          this.state = S.Doctype;
          this.pos += 7;
          this.host.onToken({ kind: 'doctype' });
          return;
        }
        if (
          c === '[' &&
          this.host.isForeign() &&
          startsWithCI(this.input, this.pos, '[CDATA[')
        ) {
          this.state = S.Cdata;
          this.pos += 7;
          return;
        }
        this.comment = '';
        this.state = S.BogusComment;
        this.pos++;
        return;
      }
      case S.CommentStart: {
        if (c === '-') { this.state = S.CommentStartDash; this.pos++; return; }
        if (c === '>') { this.comment = ''; this.reconsume(S.BogusComment, c); return; }
        this.comment = '';
        this.reconsume(S.Comment, c);
        return;
      }
      case S.CommentStartDash: {
        if (c === '-') { this.state = S.CommentDashDash; this.pos++; return; }
        if (c === '>') { this.emitComment(); this.state = S.Data; this.pos++; return; }
        this.comment += '-';
        this.reconsume(S.Comment, c);
        return;
      }
      case S.Comment: {
        if (c === '<') { this.comment += c; this.state = S.CommentLt; this.pos++; return; }
        if (c === '-') { this.state = S.CommentDash; this.pos++; return; }
        this.comment += c;
        this.pos++;
        return;
      }
      case S.CommentLt: {
        if (c === '!') { this.comment += c; this.state = S.CommentDash; this.pos++; return; }
        if (c !== '<') this.reconsume(S.Comment, c);
        else { this.comment += '<'; this.pos++; }
        return;
      }
      case S.CommentDash: {
        if (c === '-') { this.state = S.CommentDashDash; this.pos++; return; }
        this.comment += '-';
        this.reconsume(S.Comment, c);
        return;
      }
      case S.CommentDashDash: {
        if (c === '>') { this.emitComment(); this.state = S.Data; this.pos++; return; }
        if (c === '!') { this.state = S.CommentEndBang; this.pos++; return; }
        if (c !== '-') { this.comment += '--'; this.reconsume(S.Comment, c); return; }
        this.comment += '-';
        this.pos++;
        return;
      }
      case S.CommentEndBang: {
        if (c === '>') { this.emitComment(); this.state = S.Data; this.pos++; return; }
        if (c !== '-') { this.comment += '--!'; this.reconsume(S.Comment, c); return; }
        this.comment += '--!-';
        this.pos++;
        return;
      }

      // ------------------------------------------------------------ misc
      case S.Doctype: {
        if (c === '>') this.state = S.Data;
        this.pos++;
        return;
      }
      case S.Cdata: {
        if (c === ']') { this.state = S.CdataBracket; this.pos++; return; }
        this.emitChar(c);
        this.pos++;
        return;
      }
      case S.CdataBracket: {
        if (c === ']') { this.state = S.CdataEnd; this.pos++; return; }
        this.emitChar(']');
        this.reconsume(S.Cdata, c);
        return;
      }
      case S.CdataEnd: {
        if (c === '>') { this.state = S.Data; this.pos++; return; }
        if (c === ']') { this.emitChar(']'); this.pos++; return; }
        this.emitChar(']');
        this.emitChar(']');
        this.reconsume(S.Cdata, c);
        return;
      }
    }
  }

  private eof(): void {
    // Flush per-state; partial tags are discarded (spec parse errors), then EOF.
    switch (this.state) {
      case S.Data:
        break;
      case S.Rcdata:
      case S.Rawtext:
      case S.Plaintext:
      case S.ScriptData:
      case S.ScriptDataEsc:
      case S.ScriptDataEscDash:
      case S.ScriptDataEscDashDash:
      case S.ScriptDataDoubleEsc:
      case S.ScriptDataDoubleEscDash:
      case S.ScriptDataDoubleEscDashDash:
        break;
      case S.TagOpen:
        this.emitChar('<');
        break;
      case S.EndTagOpen:
        this.emitChar('<');
        this.emitChar('/');
        break;
      case S.BogusComment:
      case S.Comment:
      case S.CommentLt:
      case S.CommentDash:
      case S.CommentDashDash:
      case S.CommentStart:
      case S.CommentStartDash:
      case S.CommentEndBang:
        this.emitComment();
        break;
      default:
        // Partial attribute/tag/doctype/cdata: drop.
        break;
    }
    this.host.onToken({ kind: 'eof' });
  }

  // ----------------------------------------------------- character refs

  /**
   * Called with this.pos on the '&'. On return this.pos is positioned on the
   * first character after the reference (or on the char after '&' on failure).
   */
  private charRef(inAttribute: boolean): void {
    const start = this.pos;
    let i = start + 1;
    const input = this.input;

    if (input[i] === '#') {
      i++;
      let hex = false;
      if (input[i] === 'x' || input[i] === 'X') {
        hex = true;
        i++;
      }
      const digitStart = i;
      let code = 0;
      if (hex) {
        while (i < input.length && hexVal(input[i]!) >= 0) {
          code = code * 16 + hexVal(input[i]!)!;
          i++;
        }
      } else {
        while (i < input.length && decVal(input[i]!) >= 0) {
          code = code * 10 + decVal(input[i]!)!;
          i++;
        }
      }
      if (i > digitStart) {
        if (input[i] === ';') i++;
        const decoded = decodeNumeric(code);
        this.emitRef(decoded, inAttribute);
        this.pos = i;
        return;
      }
    } else {
      const full = longestPrefix(NAMED_ENTITY_KEYS, input, start);
      if (full !== null) {
        this.emitRef(NAMED_ENTITIES[full]!, inAttribute);
        this.pos = start + full.length;
        return;
      }
      const legacy = longestPrefix(LEGACY_ENTITY_KEYS, input, start);
      if (legacy !== null) {
        const next = input[start + legacy.length];
        if (inAttribute) {
          // §13.2.5.72: legacy match in an attribute followed by '=' fails.
          if (next !== '=') {
            this.emitRef(LEGACY_ENTITIES[legacy]!, inAttribute);
            this.pos = start + legacy.length;
            return;
          }
        } else if (next === undefined || !isAsciiAlphanumeric(next)) {
          this.emitRef(LEGACY_ENTITIES[legacy]!, inAttribute);
          this.pos = start + legacy.length;
          return;
        }
      }
    }

    // No match: literal '&', continue at next character.
    this.emitRef('&', inAttribute);
    this.pos = start + 1;
  }

  private emitRef(text: string, inAttribute: boolean): void {
    if (inAttribute) {
      this.attrValue += text;
    } else {
      this.emitChar(text);
    }
  }

  // ------------------------------------------------------------- helpers

  private textLikeTagName(c: string, base: S): void {
    if ((WS.has(c) || c === '/' || c === '>') && this.matchesLast()) {
      if (WS.has(c)) { this.state = S.BeforeAttr; this.pos++; return; }
      if (c === '/') { this.state = S.SelfClosingStart; this.pos++; return; }
      this.tagName = this.tmpTag; // emitTag reads tagName
      this.emitTag();
      this.pos++;
      return;
    }
    this.tmpTag += c;
    this.pos++;
    void base;
  }

  private matchesLast(): boolean {
    const last = this.host.getLastStartTag();
    return last !== null && this.tmpTag === last;
  }

  private finishAttr(): void {
    if (this.attrName === '') return;
    const name = this.attrName;
    if (!this.attrs.some((a) => a.name === name)) {
      this.attrs.push({ name, value: this.attrValue, prefix: attrPrefix(name) });
    }
    this.attrName = '';
    this.attrValue = '';
  }

  private emitTag(): void {
    const token: Token = this.isEndTag
      ? { kind: 'endTag', tag: this.tagName, selfClosing: this.selfClosing }
      : { kind: 'startTag', tag: this.tagName, attrs: this.attrs, selfClosing: this.selfClosing };
    this.tagName = '';
    this.attrs = [];
    this.selfClosing = false;
    this.state = S.Data;
    this.host.onToken(token);
  }

  private emitComment(): void {
    this.host.onToken({ kind: 'comment', data: this.comment });
    this.comment = '';
    this.state = S.Data;
  }

  private emitChar(data: string): void {
    if (data !== '') this.host.onToken({ kind: 'character', data });
  }

  /** Tree builder calls this after inserting a raw-text start tag. */
  setContentModel(model: ContentModel): void {
    switch (model) {
      case 'rcdata': this.state = S.Rcdata; break;
      case 'rawtext': this.state = S.Rawtext; break;
      case 'script': this.state = S.ScriptData; break;
      case 'plaintext': this.state = S.Plaintext; break;
      default: this.state = S.Data;
    }
  }
}

function isAsciiAlpha(c: string): boolean {
  const code = c.charCodeAt(0);
  return (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
}
function isAsciiAlphanumeric(c: string): boolean {
  const code = c.charCodeAt(0);
  return (
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    (code >= 0x30 && code <= 0x39)
  );
}
function decVal(c: string): number {
  const code = c.charCodeAt(0);
  return code >= 0x30 && code <= 0x39 ? code - 0x30 : -1;
}
function hexVal(c: string): number {
  const code = c.charCodeAt(0);
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}
function startsWithCI(input: string, pos: number, literal: string): boolean {
  if (pos + literal.length > input.length) return false;
  for (let i = 0; i < literal.length; i++) {
    if (input[pos + i]!.toLowerCase() !== literal[i]!.toLowerCase()) return false;
  }
  return true;
}
function attrPrefix(name: string): string | null {
  const colon = name.indexOf(':');
  return colon > 0 ? name.slice(0, colon) : null;
}
