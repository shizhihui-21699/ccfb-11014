/**
 * Throughput benchmark: 10,000 realistic comment fragments through the full
 * purify() pipeline (parse -> sanitize -> serialize). Run: npm run bench
 */

import { purify } from '../src/index.ts';

const COMMENT_TEMPLATES = [
  '<p>普通文本评论，带一点 <strong>加粗</strong> 和 <em>斜体</em>。</p>',
  '<p>链接：<a href="https://example.com/a/b?x=1" rel="nofollow">点我</a></p>',
  '<ul><li>列表项一</li><li>列表项二</li><li>列表项三</li></ul>',
  '<blockquote>引用一段文字<cite>—— 出处</cite></blockquote>',
  '<img src="/uploads/avatar/42.png" alt="头像" width="48" height="48">',
  '<p>混合 <code>inline code</code> 与 <a href="/p/123#frag">锚点</a> 的评论。</p>',
  '<table><thead><tr><th>列A</th><th>列B</th></tr></thead><tbody><tr><td>1</td><td>2</td></tr></tbody></table>',
  // Attack-laden comments that must still be processed at full speed.
  '<img src=x onerror=alert(1)><script>alert(2)</script><p>正文</p>',
  '<svg onload=alert(3)><circle cx="1"/></svg><a href="javascript:alert(4)">x</a>',
  '<div style="width: expression(alert(5)); color: red">样式</div>',
];

const N = 10_000;

function buildCorpus(): string[] {
  const corpus: string[] = new Array(N);
  for (let i = 0; i < N; i++) {
    corpus[i] = COMMENT_TEMPLATES[i % COMMENT_TEMPLATES.length]!;
  }
  return corpus;
}

function main(): void {
  const corpus = buildCorpus();

  // Warm up so JIT/ICs settle before measurement.
  for (let i = 0; i < 500; i++) purify(corpus[i]!);
  if (global.gc) global.gc();

  const start = performance.now();
  let sink = 0;
  for (let i = 0; i < N; i++) {
    const out = purify(corpus[i]!);
    sink += out.length;
  }
  const elapsedMs = performance.now() - start;

  const perCommentUs = (elapsedMs * 1000) / N;
  const perSecond = N / (elapsedMs / 1000);

  console.log('--- HTML purifier throughput ---');
  console.log(`comments processed : ${N.toLocaleString()}`);
  console.log(`total time         : ${elapsedMs.toFixed(1)} ms`);
  console.log(`per comment        : ${perCommentUs.toFixed(1)} µs`);
  console.log(`throughput         : ${Math.round(perSecond).toLocaleString()} comments/sec`);
  console.log(`target (10k/1s)    : ${perSecond >= N ? 'MET ✓' : 'MISSED ✗'}`);
  console.log(`(sink ${sink} keeps the optimizer honest)`);

  // Idempotence spot-check under timing pressure.
  const sample = purify(corpus[7]!);
  if (purify(sample) !== sample) throw new Error('idempotence regression in bench corpus');
}

main();
