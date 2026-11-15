/**
 * Default allow-list policy. Organized by namespace because SVG and MathML
 * have separate vocabularies and separate danger surfaces.
 *
 * The defaults track the well-audited DOMPurify/bleach allow lists: ordinary
 * comment-formatting HTML, inline images/links, tables, the common SVG
 * drawing primitives (no <script>, no event handlers anywhere), and
 * presentational MathML.
 */

export interface SanitizePolicy {
  /** Allowed HTML element local names. */
  allowedTags: ReadonlySet<string>;
  allowedSvgTags: ReadonlySet<string>;
  allowedMathTags: ReadonlySet<string>;

  /**
   * Allowed attribute local names. Namespaced names appear with their prefix
   * (e.g. `xlink:href`). `data-*` is handled by a separate switch.
   */
  allowedAttrs: ReadonlySet<string>;
  allowedSvgAttrs: ReadonlySet<string>;
  allowedMathAttrs: ReadonlySet<string>;

  /** Attributes whose value must pass URL scheme validation. */
  urlAttrs: ReadonlySet<string>;
  /** Attributes parsed as srcset candidate lists. */
  srcsetAttrs: ReadonlySet<string>;

  allowDataAttrs: boolean;
  /** Keep aria-* / role attributes. */
  allowAria: boolean;
  /** Keep class (safe, but some sites prefer to scope it). */
  allowClass: boolean;

  /**
   * Tags whose *entire subtree* is removed (rather than unwrapped). Scripts,
   * stylesheets and frames must never leak even as text.
   */
  dropContentTags: ReadonlySet<string>;
}

const HTML_TAGS = [
  'a', 'abbr', 'address', 'article', 'aside', 'b', 'bdi', 'bdo', 'blockquote',
  'br', 'caption', 'cite', 'code', 'col', 'colgroup', 'data', 'dd', 'del',
  'details', 'dfn', 'div', 'dl', 'dt', 'em', 'figcaption', 'figure', 'footer',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'i', 'img',
  'ins', 'kbd', 'li', 'main', 'mark', 'nav', 'ol', 'p', 'picture', 'pre',
  'q', 'rp', 'rt', 'ruby', 's', 'samp', 'section', 'small', 'source', 'span',
  'strong', 'sub', 'summary', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
  'thead', 'time', 'tr', 'u', 'ul', 'var', 'wbr',
];

const SVG_TAGS = [
  'svg', 'a', 'altGlyph', 'altGlyphDef', 'altGlyphItem', 'animate',
  'animateColor', 'animateMotion', 'animateTransform', 'circle',
  'clipPath', 'defs', 'desc', 'ellipse', 'feBlend', 'feColorMatrix',
  'feComponentTransfer', 'feComposite', 'feConvolveMatrix',
  'feDiffuseLighting', 'feDisplacementMap', 'feDistantLight', 'feFlood',
  'feFuncA', 'feFuncB', 'feFuncG', 'feFuncR', 'feGaussianBlur', 'feImage',
  'feMerge', 'feMergeNode', 'feMorphology', 'feOffset', 'fePointLight',
  'feSpecularLighting', 'feSpotLight', 'feTile', 'feTurbulence', 'filter',
  'font', 'g', 'glyph', 'glyphRef', 'gradient', 'image', 'line',
  'linearGradient', 'marker', 'mask', 'metadata', 'mpath', 'path',
  'pattern', 'polygon', 'polyline', 'radialGradient', 'rect', 'stop',
  'switch', 'symbol', 'text', 'textPath', 'title', 'tref', 'tspan', 'use',
  'view',
];

const MATH_TAGS = [
  'math', 'maction', 'annotation', 'annotation-xml', 'menclose', 'merror',
  'mfenced', 'mfrac', 'mi', 'mmultiscripts', 'mn', 'mo', 'mover', 'mpadded',
  'mphantom', 'mprescripts', 'mroot', 'mrow', 'ms', 'mscarries', 'mscarry',
  'msgroup', 'msline', 'mspace', 'msqrt', 'msrow', 'mstack', 'mstyle',
  'msub', 'msubsup', 'msup', 'mtable', 'mtd', 'mtext', 'mtr', 'munder',
  'munderover', 'semantics',
];

const HTML_ATTRS = [
  'abbr', 'accept', 'accept-charset', 'action', 'align', 'alt', 'as',
  'autocomplete', 'axis', 'background', 'bgcolor', 'border', 'cellpadding',
  'cellspacing', 'char', 'charoff', 'charset', 'checked', 'cite', 'clear',
  'color', 'cols', 'colspan', 'compact', 'coords', 'datetime', 'declare',
  'dir', 'disabled', 'download', 'enctype', 'face', 'for', 'frame',
  'frameborder', 'headers', 'height', 'href', 'hreflang', 'hspace', 'id',
  'ismap', 'itemid', 'itemprop', 'itemref', 'itemscope', 'itemtype',
  'label', 'lang', 'language', 'longdesc', 'media', 'method', 'multiple',
  'name', 'nohref', 'noshade', 'nowrap', 'open', 'placeholder', 'poster',
  'preload', 'rel', 'rev', 'role', 'rows', 'rowspan', 'rules', 'scope',
  'selected', 'shape', 'size', 'sizes', 'span', 'src', 'srcset', 'start',
  'summary', 'target', 'title', 'type', 'usemap', 'valign', 'value',
  'vspace', 'width', 'xmlns',
];

const SVG_ATTRS = [
  'accent-height', 'accumulate', 'additive', 'alignment-baseline',
  'amplitude', 'arabic-form', 'ascent', 'attributeName', 'attributeType',
  'azimuth', 'baseFrequency', 'baseline-shift', 'baseProfile', 'begin',
  'bias', 'by', 'calcMode', 'cap-height', 'class', 'clip', 'clipPathUnits',
  'clip-path', 'clip-rule', 'color', 'color-interpolation',
  'color-interpolation-filters', 'color-profile', 'color-rendering',
  'contentScriptType', 'contentStyleType', 'crossorigin', 'cursor', 'cx',
  'cy', 'd', 'decelerate', 'descent', 'diffuseConstant', 'direction',
  'display', 'divisor', 'dominant-baseline', 'dur', 'dx', 'dy',
  'edgeMode', 'elevation', 'end', 'exponent', 'externalResourcesRequired',
  'fill', 'fill-opacity', 'fill-rule', 'filter', 'filterRes',
  'filterUnits', 'flood-color', 'flood-opacity', 'focusable',
  'font-family', 'font-size', 'font-size-adjust', 'font-stretch',
  'font-style', 'font-variant', 'font-weight', 'format', 'from', 'fx', 'fy',
  'g1', 'g2', 'glyph-name', 'glyph-orientation-horizontal',
  'glyph-orientation-vertical', 'glyphRef', 'gradientTransform',
  'gradientUnits', 'hanging', 'height', 'href', 'horiz-adv-x', 'horiz-origin-x',
  'id', 'ideographic', 'image-rendering', 'in', 'in2', 'intercept',
  'k', 'k1', 'k2', 'k3', 'k4', 'kernelMatrix', 'kernelUnitLength',
  'kerning', 'keyPoints', 'keySplines', 'keyTimes', 'lang', 'lengthAdjust',
  'letter-spacing', 'lighting-color', 'limitingConeAngle', 'local',
  'marker-end', 'marker-mid', 'marker-start', 'markerHeight', 'markerUnits',
  'markerWidth', 'mask', 'maskContentUnits', 'maskUnits', 'mathematical',
  'max', 'media', 'method', 'min', 'mode', 'name', 'numOctaves', 'offset',
  'opacity', 'operator', 'order', 'orient', 'orientation', 'origin',
  'overflow', 'overline-position', 'overline-thickness', 'paint-order',
  'panose-1', 'path', 'pathLength', 'patternContentUnits',
  'patternTransform', 'patternUnits', 'pointer-events', 'points', 'pointsAtX',
  'pointsAtY', 'pointsAtZ', 'preserveAlpha', 'preserveAspectRatio',
  'primitiveUnits', 'r', 'radius', 'refX', 'refY', 'rendering-intent',
  'repeatCount', 'repeatDur', 'requiredExtensions', 'requiredFeatures',
  'restart', 'result', 'role', 'rotate', 'rx', 'ry', 'scale', 'seed',
  'shape-rendering', 'slope', 'spacing', 'specularConstant',
  'specularExponent', 'speed', 'spreadMethod', 'startOffset', 'stdDeviation',
  'stemh', 'stemv', 'stitchTiles', 'stop-color', 'stop-opacity',
  'strikethrough-position', 'strikethrough-thickness', 'string', 'stroke',
  'stroke-dasharray', 'stroke-dashoffset', 'stroke-linecap',
  'stroke-linejoin', 'stroke-miterlimit', 'stroke-opacity', 'stroke-width',
  'surfaceScale', 'systemLanguage', 'tableValues', 'target', 'targetX',
  'targetY', 'text-anchor', 'text-decoration', 'text-rendering',
  'textLength', 'title', 'to', 'transform', 'type', 'u1', 'u2',
  'underline-position', 'underline-thickness', 'unicode', 'unicode-bidi',
  'unicode-range', 'units-per-em', 'values', 'version', 'vert-adv-y',
  'vert-origin-x', 'vert-origin-y', 'viewBox', 'viewTarget', 'visibility',
  'width', 'widths', 'word-spacing', 'writing-mode', 'x', 'x-height',
  'x1', 'x2', 'xChannelSelector', 'xlink:actuate', 'xlink:arcrole',
  'xlink:href', 'xlink:role', 'xlink:show', 'xlink:title', 'xlink:type',
  'xml:base', 'xml:lang', 'xml:space', 'y', 'y1', 'y2', 'yChannelSelector',
  'z', 'zoomAndPan',
];

const MATH_ATTRS = [
  'accent', 'accentunder', 'align', 'bevelled', 'class', 'close',
  'columnalign', 'columnlines', 'columnspan', 'denomalign', 'depth', 'dir',
  'display', 'displaystyle', 'encoding', 'fence', 'frame', 'height',
  'href', 'id', 'largeop', 'length', 'linethickness', 'lspace', 'lquote',
  'mathbackground', 'mathcolor', 'mathsize', 'mathvariant', 'maxsize',
  'minsize', 'movablelimits', 'notation', 'numalign', 'open', 'rowalign',
  'rowlines', 'rowspacing', 'rowspan', 'rspace', 'rquote', 'scriptlevel',
  'scriptminsize', 'scriptsizemultiplier', 'selection', 'separator',
  'separators', 'stretchy', 'subscriptshift', 'supscriptshift',
  'symmetric', 'voffset', 'width', 'xlink:href', 'xmlns:xlink',
];

export const DEFAULT_POLICY: SanitizePolicy = {
  allowedTags: new Set(HTML_TAGS),
  allowedSvgTags: new Set(SVG_TAGS),
  allowedMathTags: new Set(MATH_TAGS),
  allowedAttrs: new Set(HTML_ATTRS),
  allowedSvgAttrs: new Set(SVG_ATTRS),
  allowedMathAttrs: new Set(MATH_ATTRS),
  urlAttrs: new Set([
    'href', 'src', 'action', 'cite', 'poster', 'background', 'longdesc',
    'xlink:href', 'xml:base', 'usemap', 'data',
  ]),
  srcsetAttrs: new Set(['srcset', 'imagesrcset']),
  allowDataAttrs: true,
  allowAria: true,
  allowClass: true,
  // Everything here is also absent from the tag allow lists; this set drives
  // subtree removal for the raw-text dangerous elements the parser still
  // builds nodes for.
  dropContentTags: new Set([
    'script', 'style', 'iframe', 'object', 'embed', 'applet', 'noembed',
    'noframes', 'noscript', 'template', 'frame', 'frameset', 'title',
    'textarea', 'xmp', 'plaintext',
  ]),
};
