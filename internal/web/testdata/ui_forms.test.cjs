// Dependency-free behavioural tests for the form helpers in ui.js: the multi-value field
// (ui.MultiSelect), the info tooltip (ui.Tip) and the live field check (data-msg).
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

// A tiny DOM: enough elements, events and selectors for the code paths under test.
class Node {
  constructor(tag, doc) {
    this.tagName = tag.toUpperCase(); this.doc = doc; this.children = []; this.parentNode = null;
    this.attrs = {}; this.listeners = {}; this.style = {}; this.value = ''; this.hidden = false; this.textContent = '';
    this.required = false; this.disabled = false; this.className = '';
  }
  get firstChild() { return this.children[0] || null; }
  get id() { return this.attrs.id || ''; }
  set id(v) { this.attrs.id = v; }
  get form() { let n = this.parentNode; while (n && n.tagName !== 'FORM') n = n.parentNode; return n; }
  get isConnected() { let n = this; while (n.parentNode) n = n.parentNode; return n === this.doc.root; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.className = String(v); }
  getAttribute(k) { return k === 'class' ? (this.className || null) : (Object.hasOwn(this.attrs, k) ? this.attrs[k] : null); }
  hasAttribute(k) { return Object.hasOwn(this.attrs, k); }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c, ref) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; const i = this.children.indexOf(ref); this.children.splice(i < 0 ? this.children.length : i, 0, c); return c; }
  insertAdjacentElement(_, c) { const p = this.parentNode; const i = p.children.indexOf(this); c.parentNode = p; p.children.splice(i + 1, 0, c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); c.parentNode = null; return c; }
  addEventListener(n, f) { (this.listeners[n] ||= []).push(f); }
  dispatchEvent(e) { e.target = e.target || this; (this.listeners[e.type] || []).forEach(f => f(e)); bubble(this.parentNode, e); return true; }
  focus() { this.doc.activeElement = this; }
  matches(sel) { return sel.split(',').some(s => matchOne(this, s.trim())); }
  closest(sel) { let n = this; while (n && n.matches) { if (n.matches(sel)) return n; n = n.parentNode; } return null; }
  contains(n) { while (n) { if (n === this) return true; n = n.parentNode; } return false; }
  all() { const out = []; const walk = n => n.children.forEach(c => { out.push(c); walk(c); }); walk(this); return out; }
  querySelectorAll(sel) { return this.all().filter(n => n.matches(sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  checkValidity() {
    if (this.customError) return false;
    if (this.required && this.value === '') return false;
    const p = this.getAttribute('pattern');
    return !(p && this.value !== '' && !new RegExp('^(?:' + p + ')$').test(this.value));
  }
  setCustomValidity(m) { this.customError = m; }
  getBoundingClientRect() { return { left: 100, right: 122, top: 10, bottom: 32 }; }
}
function matchOne(n, s) {
  if (s.startsWith('[')) { const m = s.match(/^\[([\w-]+)(?:="([^"]*)")?\]$/); return m && n.hasAttribute(m[1]) && (m[2] === undefined || n.getAttribute(m[1]) === m[2]); }
  if (s.startsWith('.')) return (' ' + n.className + ' ').includes(' ' + s.slice(1) + ' ');
  return n.tagName === s.toUpperCase();
}
function bubble(n, e) { while (n) { (n.listeners[e.type] || []).forEach(f => f(e)); n = n.parentNode; } }
function makeDoc() {
  const doc = { listeners: {}, readyState: 'complete', activeElement: null };
  doc.root = new Node('html', doc);
  doc.documentElement = doc.root; doc.root.dataset = {}; doc.root.classList = { add() {}, toggle() {}, contains: () => false };
  doc.body = doc.root.appendChild(new Node('body', doc)); doc.head = doc.root.appendChild(new Node('head', doc));
  doc.createElement = t => new Node(t, doc);
  doc.createTextNode = t => { const n = new Node('#text', doc); n.textContent = t; return n; };
  doc.addEventListener = (n, f) => { (doc.listeners[n] ||= []).push(f); };
  doc.querySelector = s => doc.root.querySelector(s); doc.querySelectorAll = s => doc.root.querySelectorAll(s);
  doc.getElementById = id => doc.root.all().find(n => n.id === id) || null;
  doc.fire = (type, target, extra = {}) => { const e = { type, target, preventDefault() { this.prevented = true; }, ...extra }; (doc.listeners[type] || []).forEach(f => f(e)); return e; };
  return doc;
}
function load(doc) {
  const context = { document: doc, Element: Node, HTMLElement: Node, HTMLDialogElement: class extends Node {}, navigator: {}, Event: class { constructor(t) { this.type = t; } },
    localStorage: { getItem: () => null }, Intl, setTimeout: () => 0, requestAnimationFrame: f => f(), innerWidth: 1200, innerHeight: 800,
    matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} };
  context.window = context;
  vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), context);
}
// Element events reach the document-level listeners too (delegation).
function fire(doc, el, type, extra = {}) {
  const e = { type, target: el, preventDefault() { this.prevented = true; }, ...extra };
  el.dispatchEvent(e); (doc.listeners[type] || []).forEach(f => f(e)); return e;
}

// ---- ui.MultiSelect ----
{
  const doc = makeDoc();
  const form = doc.body.appendChild(new Node('form', doc));
  const label = form.appendChild(new Node('label', doc)); label.setAttribute('for', 'roles');
  const box = form.appendChild(new Node('div', doc)); box.setAttribute('data-multi', '');
  const ta = box.appendChild(new Node('textarea', doc));
  ta.id = 'roles'; ta.setAttribute('name', 'roles'); ta.value = 'devops\nyazilim'; ta.required = true;
  ta.setAttribute('data-multi-sep', '\n'); ta.setAttribute('data-multi-list', 'roles-opts'); ta.setAttribute('aria-describedby', 'roles-help');
  load(doc);
  const wrap = box.querySelector('.multi-box');
  assert.ok(wrap, 'chips box is built');
  const input = wrap.querySelector('input');
  assert.equal(ta.hidden, true, 'the plain field is hidden, not removed');
  assert.equal(input.id, 'roles', 'the visible label now names the typing input');
  assert.equal(ta.id, 'roles-value');
  assert.equal(input.getAttribute('list'), 'roles-opts', 'known values are suggested');
  assert.equal(input.getAttribute('aria-describedby'), 'roles-help', 'help stays attached');
  assert.deepEqual(wrap.querySelectorAll('.chip').map(c => c.firstChild.textContent), ['devops', 'yazilim']);
  input.value = 'tag:web:80,443';
  assert.equal(fire(doc, input, 'keydown', { key: 'Enter' }).prevented, true, 'Enter adds instead of submitting');
  assert.equal(ta.value, 'devops\nyazilim\ntag:web:80,443', 'a line value keeps its commas');
  input.value = 'devops'; fire(doc, input, 'change');
  assert.equal(ta.value.split('\n').length, 3, 'duplicates are not added');
  wrap.querySelectorAll('.chip-x')[0].listeners.click[0]();
  assert.equal(ta.value, 'yazilim\ntag:web:80,443', 'removing a chip updates the field');
  input.value = ''; fire(doc, input, 'keydown', { key: 'Backspace' });
  assert.equal(ta.value, 'yazilim', 'Backspace on empty input removes the last value');
  input.value = 'muhasebe'; form.dispatchEvent({ type: 'submit' });
  assert.equal(ta.value, 'yazilim\nmuhasebe', 'typed text is sent on submit');
  assert.equal(ta.required, false, 'the hidden field never blocks submission');
  wrap.querySelectorAll('.chip-x').forEach(() => wrap.querySelectorAll('.chip-x')[0].listeners.click[0]());
  assert.equal(input.required, true, 'an empty required field is required on the typing input');
}
{
  // A comma list (owners, namespaces) posts with its separator.
  const doc = makeDoc();
  const box = doc.body.appendChild(new Node('div', doc)); box.setAttribute('data-multi', '');
  const inp = box.appendChild(new Node('input', doc)); inp.id = 'owners'; inp.value = 'group:devops, carol@';
  inp.setAttribute('data-multi-sep', ', ');
  load(doc);
  const typing = box.querySelector('.multi-box').querySelector('input');
  typing.value = 'bob@'; fire(doc, typing, 'keydown', { key: ',' });
  assert.equal(inp.value, 'group:devops, carol@, bob@');
  assert.equal(typing.hasAttribute('list'), false, 'no options means no suggestion list');
}

// ---- ui.Tip ----
{
  const doc = makeDoc();
  const tip = doc.body.appendChild(new Node('span', doc)); tip.setAttribute('data-tip', '');
  const btn = tip.appendChild(new Node('button', doc)); btn.className = 'tip-btn';
  const body = tip.appendChild(new Node('span', doc)); body.className = 'tip-body';
  load(doc);
  doc.fire('focusin', btn);
  assert.equal(body.style.position, 'fixed', 'the tooltip is placed in the viewport');
  assert.equal(body.style.top, '38px');
  doc.fire('keydown', btn, { key: 'Escape' });
  assert.equal(tip.hasAttribute('data-tip-hidden'), true, 'Escape hides the tooltip');
  doc.fire('mouseover', btn);
  assert.equal(tip.hasAttribute('data-tip-hidden'), false, 'it comes back on the next hover');
}

// ---- live field check ----
{
  const doc = makeDoc();
  const field = doc.body.appendChild(new Node('div', doc));
  const el = field.appendChild(new Node('input', doc));
  el.id = 'endpoint'; el.setAttribute('pattern', 'https://\\S+'); el.setAttribute('data-msg', 'https:// ile başlayan bir adres girin.');
  const ta = field.appendChild(new Node('textarea', doc));
  ta.id = 'internal'; ta.setAttribute('data-line-pattern', '\\S+\\s+\\d{1,5}(\\s+\\S+)?'); ta.setAttribute('data-msg', 'IP port [entrypoint]');
  load(doc);
  el.value = 'http://x'; doc.fire('focusout', el);
  assert.equal(el.getAttribute('aria-invalid'), 'true');
  const err = doc.getElementById('endpoint-err');
  assert.equal(err.textContent, 'https:// ile başlayan bir adres girin.');
  assert.match(el.getAttribute('aria-describedby'), /endpoint-err/, 'the message describes the field');
  el.value = 'https://10.0.0.1:6443'; doc.fire('input', el);
  assert.equal(el.hasAttribute('aria-invalid'), false); assert.equal(err.textContent, '', 'fixing it clears the message');
  ta.value = '10.0.0.1 443\n10.0.0.2'; doc.fire('input', ta);
  assert.equal(ta.customError, '2. satır: IP port [entrypoint]', 'a bad line blocks the submit with its line number');
  ta.value = '10.0.0.1 443\n10.0.0.2 8443 web'; doc.fire('input', ta);
  assert.equal(ta.customError, '');
}
console.log('ui forms ok');
