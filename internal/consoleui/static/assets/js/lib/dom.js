// Safe DOM construction. This is the only way the console builds markup:
// every dynamic value becomes a Text node or a validated attribute, never
// parsed HTML. Evidence from the API is attacker-controlled; nothing here
// turns it into markup, a URL, a class name or an event handler.

const SVG_NS = 'http://www.w3.org/2000/svg';

// Attributes the console may set. Anything else throws, which makes a
// mistake loud in development instead of silently widening the surface.
const ALLOWED_ATTRS = new Set([
  'id', 'class', 'role', 'type', 'name', 'value', 'title', 'placeholder',
  'for', 'href', 'tabindex', 'lang', 'dir', 'autocomplete', 'spellcheck',
  'maxlength', 'minlength', 'min', 'max', 'step', 'rows', 'cols', 'colspan',
  'scope', 'datetime', 'disabled', 'checked', 'selected', 'readonly',
  'required', 'hidden', 'open', 'multiple', 'inputmode', 'enterkeyhint',
  'method', 'novalidate', 'aria-hidden',
  // SVG geometry and presentation attributes used by the charts.
  'viewBox', 'width', 'height', 'x', 'y', 'x1', 'x2', 'y1', 'y2', 'rx', 'ry',
  'cx', 'cy', 'r', 'd', 'points', 'transform', 'text-anchor',
  'dominant-baseline', 'preserveAspectRatio', 'focusable', 'xmlns',
]);

const ALLOWED_PROPS = new Set(['value', 'checked', 'selected', 'disabled', 'indeterminate']);

const ATTR_NAME =/^(aria|data)-[a-z][a-z0-9-]*$/;
const CLASS_TOKEN = /^[A-Za-z][A-Za-z0-9_-]*$/;
// In-app routes only: "#/" followed by URL-safe characters. Dynamic route
// segments are percent-encoded by the route module before they get here.
const HASH_HREF = /^#\/[A-Za-z0-9\-._~%/?=&+]*$/;

// The fixed set of external links the console may render (project docs).
const EXTERNAL_HREFS = new Set([
  'https://github.com/metaforismo/AegisMesh',
  'https://github.com/metaforismo/AegisMesh/blob/master/docs/cli.md',
  'https://github.com/metaforismo/AegisMesh/blob/master/docs/architecture/console-api.md',
]);

export class UnsafeAttributeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UnsafeAttributeError';
  }
}

export function isSafeHref(value) {
  return typeof value === 'string' && (HASH_HREF.test(value) || EXTERNAL_HREFS.has(value));
}

export function isClassToken(value) {
  return typeof value === 'string' && CLASS_TOKEN.test(value);
}

function classValue(value) {
  const tokens = (Array.isArray(value) ? value : String(value).split(/\s+/)).filter(Boolean);
  for (const token of tokens) {
    if (!isClassToken(token)) throw new UnsafeAttributeError(`unsafe class token: ${JSON.stringify(token)}`);
  }
  return tokens.join(' ');
}

function setAttr(el, name, value) {
  if (value === false || value === null || value === undefined) return;
  if (!ALLOWED_ATTRS.has(name) && !ATTR_NAME.test(name)) {
    throw new UnsafeAttributeError(`attribute not allowed: ${name}`);
  }
  if (name === 'href' && !isSafeHref(value)) {
    throw new UnsafeAttributeError('href rejected: only in-app #/ routes and allowlisted project links');
  }
  if (name === 'class') value = classValue(value);
  el.setAttribute(name, value === true ? '' : String(value));
}

function append(doc, parent, child) {
  if (child === null || child === undefined || child === false || child === true) return;
  if (Array.isArray(child)) {
    for (const c of child) append(doc, parent, c);
    return;
  }
  if (typeof child === 'object' && typeof child.nodeType === 'number') {
    parent.appendChild(child);
    return;
  }
  parent.appendChild(doc.createTextNode(String(child)));
}

function build(doc, el, props, children) {
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (key === 'on') {
        for (const [type, handler] of Object.entries(value)) el.addEventListener(type, handler);
      } else if (key === 'ref') {
        value(el);
      } else if (key === 'text') {
        el.textContent = value === null || value === undefined ? '' : String(value);
      } else if (key === 'prop') {
        // A closed set of form-state properties; never a markup sink.
        for (const [p, v] of Object.entries(value)) {
          if (!ALLOWED_PROPS.has(p)) throw new UnsafeAttributeError(`property not allowed: ${p}`);
          el[p] = v;
        }
      } else {
        setAttr(el, key, value);
      }
    }
  }
  append(doc, el, children);
  return el;
}

// createDom binds the helpers to a document so tests can supply a fake one.
export function createDom(doc) {
  const h = (tag, props, ...children) => build(doc, doc.createElement(tag), props, children);
  const svg = (tag, props, ...children) => build(doc, doc.createElementNS(SVG_NS, tag), props, children);
  const text = (value) => doc.createTextNode(value === null || value === undefined ? '' : String(value));
  const frag = (...children) => {
    const f = doc.createDocumentFragment();
    append(doc, f, children);
    return f;
  };
  return { h, svg, text, frag };
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

// Replace a node's children. Same child rules as h(): null/false are
// skipped, arrays flatten, strings become Text nodes. (Native append() would
// render a null as the text "null".)
export function mount(node, ...children) {
  clear(node);
  append(node.ownerDocument, node, children);
  return node;
}

let bound = null;
function dom() {
  if (!bound) bound = createDom(globalThis.document);
  return bound;
}

export const h = (...args) => dom().h(...args);
export const svg = (...args) => dom().svg(...args);
export const text = (...args) => dom().text(...args);
export const frag = (...args) => dom().frag(...args);
