# html-purifier-ts

一个**零运行时依赖**、按 WHATWG HTML 标准实现的 TypeScript HTML 净化器。不是基于正则的黑名单过滤，而是自带完整的 **tokenizer → 树构造 → 白名单过滤 → 安全序列化** 管线，从根上消除解析/序列化不一致导致的 mXSS。

## 为什么不用正则 / 直接调浏览器 DOM

正则方案无法理解 HTML 语法，`<<script>`、命名空间切换、实体编码、foster parenting 等都会绕过；而直接用浏览器 `innerHTML` 解析再清洗，则把「解析器如何理解输入」和「清洗后如何重新序列化」耦合在同一个有历史 mXSS 漏洞的 DOM 实现上。

本库自己实现标准解析，**净化结果再解析、再序列化是一个不动点（幂等）**，这是对抗 mXSS 的核心性质，并有测试强制保证。

## 架构

```
字符串
  │  src/tokenizer.ts    WHATWG §13.25 词法状态机
  │    · 完整字符引用（2125 命名 + 数字，win-1252 映射，legacy 边界）
  │    · RCDATA/RAWTEXT/script 转义状态、CDATA、bogus comment
  │    · 自闭合、重复属性、null→U+FFFD
  ▼
Token 流
  │  src/tree-builder.ts WHATWG §13.2.6 树构造
  │    · 开放元素栈 / 插入模式 / 活动格式化元素（adoption agency）
  │    · foster parenting、表格隐式闭合
  │    · SVG / MathML 命名空间切换、集成点、标签/属性名调整表
  ▼
DOM 树（带命名空间与 parent 指针）
  │  src/sanitizer.ts   白名单过滤（迭代遍历，防深嵌套爆栈）
  │    · 标签/属性按命名空间分别白名单，on* 事件属性全拦
  │    · URL 属性走 src/url.ts，style 走 src/css.ts
  ▼
安全 DOM
  │  src/serializer.ts  mXSS 安全序列化（迭代）
  │    · 文本/属性强制转义、属性永远双引号、控制字符数字引用
  │    · 命名空间决定标签大小写与自闭合
  ▼
净化后的 HTML 字符串
```

## 安全设计要点

- **命名空间正确**：`<svg>` / `<math>` 内外的同名标签按标准分到不同命名空间；HTML 集成点（`foreignObject`、`annotation-xml` 等）和 breakout 规则齐全，杜绝借命名空间混淆的 mXSS。
- **URL 协议校验**（`src/url.ts`）：剥离 C0 控制符与**全部 Unicode 空白**（含 `U+2000..U+200D`、`U+3000`、`U+FEFF` 等），反斜杠归一化，再按 RFC 风格提取 scheme；`javascript:`/`vbscript:` 等拒绝，`data:` 限制 MIME 且**明确排除可执行脚本的 `image/svg+xml` 与 `text/html`**；`srcset` 逐候选校验。
- **CSS 净化**（`src/css.ts`）：声明级解析，解码 CSS 转义后再检测，拦截 `expression()`、`url(javascript:)`、`behavior`、`-moz-binding`、`@import`，输出规范化且幂等。
- **SVG 动画注入**：`<set>/<animate attributeName="onload|href|...">` 这类通过动画给事件属性/URL 属性赋值的手法被拦截。
- **序列化收敛**：`>` 始终转义、控制字符输出为数字引用、绝不输出注释/DOCTYPE/处理指令，使 `purify(purify(x)) === purify(x)`。
- **深嵌套鲁棒**：净化与序列化均为显式栈迭代实现，2 万层嵌套不爆栈。

## 使用

```ts
import { purify, purifyDetailed, createSanitizer } from './src/index.ts';

purify('<img src=x onerror=alert(1)>');
// => '<img src="x">'

purify('<a href="javascript:alert(1)">x</a>');
// => '<a>x</a>'

// 需要拿到净化后的树时
const { html, tree } = purifyDetailed('<svg onload=alert(1)><circle/></svg>');

// 自定义策略
const sanitize = createSanitizer({
  policy: myPolicy,       // 标签/属性白名单
  urlPolicy: myUrlPolicy, // 允许的 scheme / data MIME
  cssPolicy: myCssPolicy,
});
```

白名单在 `src/policy.ts`，默认覆盖评论场景常用的 HTML、SVG 绘图元素与 MathML，按命名空间分三张表，可整体替换。

## 命令

```bash
npm install
npm run gen:entities   # 从 WHATWG entities.json 生成 src/entities.ts，并抽取测试向量
npm run typecheck      # tsc 严格模式（含 demo 的 DOM 类型检查）
npm test               # node:test，48 个测试文件全量
npm run bench          # 一万条评论吞吐基准
npm run build          # 输出 dist/（JS + .d.ts）与浏览器 bundle
npm run demo           # 重新打包对照页
```

## 测试与回归向量

- `test/tokenizer.test.ts`：词法、实体、raw text、script 转义、CDATA、null 处理。
- `test/url-css.test.ts`：协议混淆、Unicode 空白、data MIME、CSS 危险写法。
- `test/vectors.test.ts`：**223 条 DOMPurify 官方 fixture 向量 + 60 条手工高危向量**，每条都断言
  1. 输出无任何可执行特征（`test/oracle.ts` 结构化检测，不会把转义文本误判为属性）；
  2. 幂等（重解析重序列化不变）。
- `test/robustness.test.ts`：深嵌套、畸形输入、控制字符、命名空间往返。

向量来源文件存放在 `data/`（WHATWG entities、DOMPurify fixtures），由 `scripts/` 转成测试可用的 JSON。

## 性能

Mac (Apple Silicon) 上 `npm run bench`，一万条含攻击样本的真实评论：

```
throughput : ~330,000 comments/sec   （每条约 3 µs）
目标 10,000 条/秒：达成
```

## 对照页

`demo/index.html` 是纯静态页面（`npm run demo` 打包后可直接 `file://` 打开）：左侧粘贴不可信 HTML，右侧看净化结果、真实渲染效果与带命名空间标注的树结构，并实时显示可执行特征检测、耗时与幂等性。所有计算在浏览器本地完成。

## 范围与取舍

- 定位为**片段净化器**（评论正文），不处理完整文档的 `<head>`、安全策略响应头、CSP 等——纵深防御仍建议配合 CSP。
- 表格、adoption agency 等覆盖标准主路径；极端病态嵌套在保证安全与幂等的前提下做了保守收敛（不丢文本、不产生可执行结构），不追求与浏览器逐字节相同的 DOM。
- 净化保证的是「输出不可执行且幂等」，而非保留所有原始标签；不在白名单的元素默认解包（保留内容），`script/style/iframe` 等危险元素整棵子树删除。
