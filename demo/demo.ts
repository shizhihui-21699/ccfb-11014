/**
 * Browser demo: paste untrusted HTML, see the sanitized output and a
 * side-by-side structural diff. Bundled to a single IIFE by esbuild so the
 * page works from a plain file:// URL with no server.
 */

import { purifyDetailed, findExecutionPrimitivesShim } from './demo-shim.ts';

const $ = (id: string): HTMLElement => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
};

const input = $('input') as HTMLTextAreaElement;
const output = $('output') as HTMLTextAreaElement;
const findingsEl = $('findings');
const statsEl = $('stats');
const treeEl = $('tree');

const EXAMPLE = [
  '<p>这是一条<b>正常</b>评论，含 <a href="https://example.com">安全链接</a>。</p>',
  '<img src=x onerror="alert(1)">',
  '<svg><script>alert(2)</script><circle cx="1"/></svg>',
  '<a href="  javascript:alert(3)">恶意链接</a>',
  '<div style="width: expression(alert(4))">x</div>',
].join('\n');

function renderTree(node: unknown, depth = 0): string {
  const n = node as { type?: string; tag?: string; namespace?: string; attrs?: { name: string; value: string }[]; children?: unknown[]; data?: string };
  const pad = '  '.repeat(depth);
  if (n.type === 'text') return `${pad}#text ${JSON.stringify(n.data)}\n`;
  const ns = n.namespace?.includes('svg') ? 'svg' : n.namespace?.includes('MathML') ? 'math' : 'html';
  const attrs = (n.attrs ?? []).map((a) => ` ${a.name}="${a.value}"`).join('');
  let s = `${pad}<${n.tag} [${ns}]${attrs}>\n`;
  for (const c of n.children ?? []) s += renderTree(c, depth + 1);
  return s;
}

function run(): void {
  const raw = input.value;
  const t0 = performance.now();
  const { html, tree } = purifyDetailed(raw);
  const ms = performance.now() - t0;

  output.value = html;
  const findings = findExecutionPrimitivesShim(html);
  findingsEl.textContent = findings.length
    ? '⚠️ 检出残留危险特征（不应发生）：' + findings.join('；')
    : '✅ 输出未发现可执行特征';
  findingsEl.className = findings.length ? 'badge bad' : 'badge good';
  statsEl.textContent =
    `输入 ${raw.length} 字符 → 输出 ${html.length} 字符 · 耗时 ${ms.toFixed(2)} ms · 幂等: ${html === purifyDetailed(html).html ? '是' : '否'}`;
  treeEl.textContent = renderTree(tree);
}

function wire(): void {
  input.value = EXAMPLE;
  $('run').addEventListener('click', run);
  $('copy').addEventListener('click', async () => {
    await navigator.clipboard.writeText(output.value);
  });
  $('load-attack').addEventListener('click', () => {
    input.value = [
      '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
      '<!--><img src=x onerror=alert(2)>',
      '<svg><animate attributeName="onload" values="alert(3)">',
      '<a href="&#x2000;javascript:alert(4)">x</a>',
    ].join('\n');
    run();
  });
  run();
}

wire();
