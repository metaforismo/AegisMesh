// A deliberately small DOM stand-in: enough for dom.js and component
// builders, with no HTML parser at all (so tests cannot pass by parsing).
class Node {
  constructor(doc) { this.ownerDocument = doc; this.childNodes = []; this.parentNode = null; }
  appendChild(c) {
    if (c.nodeType === 11) { for (const k of [...c.childNodes]) this.appendChild(k); c.childNodes = []; return c; }
    if (c.parentNode) c.parentNode.removeChild(c);
    c.parentNode = this; this.childNodes.push(c); return c;
  }
  removeChild(c) { this.childNodes = this.childNodes.filter((x) => x !== c); c.parentNode = null; return c; }
  get firstChild() { return this.childNodes[0] ?? null; }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) { this.childNodes = []; if (v !== '') this.appendChild(this.ownerDocument.createTextNode(v)); }
}
class Text extends Node { constructor(doc, v) { super(doc); this.nodeType = 3; this.data = v; } get textContent() { return this.data; } }
class Fragment extends Node { constructor(doc) { super(doc); this.nodeType = 11; } }
class Element extends Node {
  constructor(doc, tag, ns) { super(doc); this.nodeType = 1; this.tagName = tag; this.namespaceURI = ns; this.attributes = new Map(); this.listeners = {}; }
  setAttribute(k, v) { this.attributes.set(k, String(v)); }
  getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
  addEventListener(t, fn) { (this.listeners[t] ||= []).push(fn); }
  dispatch(t, ev = {}) { for (const fn of this.listeners[t] || []) fn(ev); }
  set innerHTML(_v) { throw new Error('innerHTML is forbidden'); }
  querySelectorAll(pred) { const out = []; const walk = (n) => { for (const c of n.childNodes) { if (c.nodeType === 1) { if (pred(c)) out.push(c); walk(c); } } }; walk(this); return out; }
}
export function createFakeDocument() {
  const doc = {
    createElement: (t) => new Element(doc, t, 'html'),
    createElementNS: (ns, t) => new Element(doc, t, ns),
    createTextNode: (v) => new Text(doc, v),
    createDocumentFragment: () => new Fragment(doc),
  };
  return doc;
}
