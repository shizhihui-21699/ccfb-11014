/**
 * Browser-facing re-exports. The core library is DOM-free TypeScript, so the
 * demo imports the same pipeline the server uses, plus a copy of the test
 * oracle's execution-primitive detector for the live safety indicator.
 */

import { purifyDetailed as corePurifyDetailed } from '../src/index.ts';

export const purifyDetailed = corePurifyDetailed;

const URL_ATTRS = new Set([
  'href', 'src', 'action', 'cite', 'poster', 'background', 'longdesc',
  'xlink:href', 'xml:base', 'usemap', 'data', 'formaction', 'srcset', 'imagesrcset',
]);

interface ParsedAttr {
  name: string;
  value: string;
}

const isSpace = (ch: string | undefined): boolean =>
  ch === ' ' || ch === '\t' || ch === '\n' || ch === '\f' || ch === '\r';

function parseAttrs(tagInner: string): ParsedAttr[] {
  const attrs: ParsedAttr[] = [];
  const n = tagInner.length;
  let i = 0;
  while (i < n && !isSpace(tagInner[i])) i++;
  while (i < n) {
    while (i < n && isSpace(tagInner[i])) i++;
    if (i >= n) break;
    const nameStart = i;
    while (i < n && !isSpace(tagInner[i]) && tagInner[i] !== '=' && tagInner[i] !== '/') i++;
    const name = tagInner.slice(nameStart, i);
    let value = '';
    while (i < n && isSpace(tagInner[i])) i++;
    if (tagInner[i] === '=') {
      i++;
      while (i < n && isSpace(tagInner[i])) i++;
      const q = tagInner[i];
      if (q === '"' || q === "'") {
        i++;
        const v0 = i;
        while (i < n && tagInner[i] !== q) i++;
        value = tagInner.slice(v0, i);
        if (i < n) i++;
      } else {
        const v0 = i;
        while (i < n && !isSpace(tagInner[i])) i++;
        value = tagInner.slice(v0, i);
      }
    } else if (tagInner[i] === '/') {
      i++;
    }
    if (name) attrs.push({ name: name.toLowerCase(), value });
  }
  return attrs;
}

export function findExecutionPrimitivesShim(html: string): string[] {
  const findings: string[] = [];
  const lower = html.toLowerCase();
  if (/<\s*(script|iframe|object|embed|applet|frame|frameset)\b/.test(lower)) {
    findings.push('存在可执行元素');
  }
  const tags = html.match(/<[^>]*>/g) ?? [];
  for (const tag of tags) {
    if (!/^<\/?[a-zA-Z]/.test(tag)) continue;
    const attrs = parseAttrs(tag.slice(1, -1).replace(/\/$/, ''));
    for (const a of attrs) {
      if (a.name.startsWith('on') && a.name.length > 2) findings.push(`事件属性 ${a.name}`);
      if (URL_ATTRS.has(a.name) && /(?:javascript|vbscript|livescript)\s*:/i.test(a.value)) {
        findings.push(`${a.name} 含脚本协议`);
      }
      if (a.name === 'style' && /expression\s*\(|behavior\s*:|-moz-binding\s*:/i.test(a.value)) {
        findings.push('style 含危险 CSS');
      }
    }
  }
  if (/<\s*(set|animate)\b[^>]*attributename\s*=\s*["']?\s*on/i.test(lower)) {
    findings.push('SVG 动画注入事件属性');
  }
  return findings;
}
