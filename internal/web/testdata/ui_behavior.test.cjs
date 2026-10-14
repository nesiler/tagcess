// Dependency-free behavioural tests for the delegated interface script.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
class Element {
 constructor(kind, parent) { this.kind = kind; this.parent = parent; this.attrs = {}; this.style = {}; this.dataset = {}; this.nodes = {}; this.children = []; this.inert = false; this.textContent = ''; this.isConnected = true; if (parent) parent.children.push(this); this.classList = { toggle: (k, on) => { this.attrs[k] = !!on; }, add: k => { this.attrs[k] = true; }, contains: k => !!this.attrs[k] }; }
 setAttribute(k,v) { this.attrs[k] = v; } getAttribute(k) { return Object.hasOwn(this.attrs,k) ? this.attrs[k] : null; } hasAttribute(k) { return Object.hasOwn(this.attrs,k); } removeAttribute(k) { delete this.attrs[k]; }
 matches(s) { return this.kind === s; } closest(s) { return this.matches(s) ? this : this.parent?.closest(s) || null; }
 contains(el) { return this === el || this.children.some(n => n.contains(el)); }
 querySelector(s) { return this.nodes[s] || null; } querySelectorAll(s) { return this.nodes[s] || []; }
 focus() { doc.activeElement = this; }
 getBoundingClientRect() { return this.rect || {left: 270, right: 300, top: 150, bottom: 180, width: 30, height: 30}; }
 showPopover() { this.shown = true; } hidePopover() { this.shown = false; }
}
let doc;
function setup(clipboard) {
 const events = {}, windowEvents = {};
 const root = new Element('root'), shell = new Element('.shell'), main = new Element('.main', shell), sidebar = new Element('.sidebar', shell), btn = new Element('[data-nav-toggle]', main);
 const first = new Element('a', sidebar), last = new Element('a', sidebar);
 sidebar.nodes['a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])'] = [first,last];
 sidebar.nodes['a'] = first;
 const menu = new Element('details.menu', main), summary = new Element('summary', menu), list = new Element('.menu-list', menu), item = new Element('a', list);
 menu.nodes['summary'] = summary; menu.nodes['.menu-list'] = list; list.nodes['a, button:not([disabled])'] = item;
 list.rect = {left: 0,right: 220,top:0,bottom:120,width:220,height:120};
 const copy = new Element('[data-copy]', main), label = new Element('[data-copy-label]',copy), status = new Element('[data-copy-status]', main); label.textContent = 'Kopyala'; copy.attrs['data-copy'] = 'sample'; copy.nodes['[data-copy-label]'] = label; copy.closest = s => s === '[data-copy]' ? copy : s === '.secret' ? main : null; main.nodes['[data-copy-status]'] = status;
 doc = {documentElement:root, body:new Element('body'), activeElement:btn, readyState:'loading', head:new Element('head'), addEventListener:(n,f)=>{ (events[n] ||= []).push(f); }, querySelector:s=>({'.shell':shell,'[data-nav-toggle]':btn,'#sidebar':sidebar,'#sidebar a':first,'.main':main,'.shell.nav-open':shell.attrs['nav-open'] ? shell : null})[s] || null, querySelectorAll:s=>s === 'details.menu' ? [menu] : s === 'details.menu[open]' ? (menu.hasAttribute('open') ? [menu] : []) : [], getElementById:()=>null};
 const media = {matches:true, addEventListener:(n,f)=>{media.change=f;}};
 const context = {document:doc, Element, HTMLElement:Element, HTMLDialogElement:class extends Element{}, navigator:{clipboard}, localStorage:{getItem:()=>null}, Intl, setTimeout:()=>0, clearTimeout:()=>{}, requestAnimationFrame:f=>f(), cancelAnimationFrame:()=>{}, matchMedia:()=>media, innerWidth:320,innerHeight:240, addEventListener:(n,f)=>{ (windowEvents[n] ||= []).push(f); }};
 context.window = context;
 vm.runInNewContext(fs.readFileSync(process.argv[2],'utf8'),context);
 const dispatch = (name,target, extra={})=>{ const e={target,preventDefault(){this.prevented=true;},...extra}; (events[name]||[]).forEach(f=>f(e)); return e; };
 dispatch('DOMContentLoaded',doc);
 return {root,shell,main,sidebar,btn,first,last,menu,summary,list,item,copy,label,status,media,dispatch,windowEvents};
}
(async()=>{
 let x=setup();
 x.dispatch('click',x.btn);
 assert.equal(x.main.inert,true,'drawer background must be inert');
 assert.equal(doc.activeElement,x.first,'opening drawer focuses its first link');
 assert.equal(x.root.classList.contains('nav-locked'),true,'drawer locks page scrolling');
 x.last.focus(); const tab=x.dispatch('keydown',x.last,{key:'Tab'});
 assert.equal(tab.prevented,true); assert.equal(doc.activeElement,x.first,'Tab wraps within drawer');
 x.dispatch('keydown',x.first,{key:'Escape'});
 assert.equal(x.main.inert,false); assert.equal(doc.activeElement,x.btn,'closing drawer restores trigger focus');
 x.dispatch('click',x.btn); x.media.matches=false; x.media.change();
 assert.equal(x.main.inert,false,'desktop resize resets drawer state'); assert.equal(x.root.classList.contains('nav-locked'),false);
 x=setup(); x.dispatch('click',x.summary);
 assert.equal(x.list.shown,true,'menu opens in native top layer');
 assert.equal(x.summary.getAttribute('aria-expanded'),'true');
 assert.ok(parseFloat(x.list.style.left)>=8,'menu clamps left boundary');
 assert.ok(parseFloat(x.list.style.top)+120<=232,'menu clamps lower boundary');
 x.dispatch('keydown',x.item,{key:'Escape'});
 assert.equal(x.list.shown,false); assert.equal(doc.activeElement,x.summary);
 x.dispatch('click',x.summary); x.dispatch('click',x.main); assert.equal(x.list.shown,false,'outside click closes top-layer menu');
 x=setup({writeText:()=>Promise.reject(new Error('denied'))}); x.dispatch('click',x.copy); await new Promise(setImmediate);
 assert.match(x.status.textContent,/Kopyalanamadı/,'clipboard rejection is visible'); assert.equal(x.copy.hasAttribute('disabled'),false,'copy may be retried');
 x=setup(); x.dispatch('click',x.copy); await new Promise(setImmediate); assert.match(x.status.textContent,/Kopyalanamadı/,'clipboard absence is visible');
 x=setup({writeText:()=>Promise.resolve()}); x.dispatch('click',x.copy); await new Promise(setImmediate); assert.match(x.status.textContent,/Kopyalandı/,'copy success is announced');
 x=setup();
 function tableBox() {
  const box = new Element('[data-table]'), table = new Element('table',box), scroll = new Element('.tscroll',box), input = new Element('[data-table-search]',box), tools = new Element('tools');
  table.setAttribute('aria-label','Devices'); table.setAttribute('data-enhanced',''); table.tBodies=[{rows:[]}]; table.tHead={rows:[{cells:[]}]};
  box.nodes['table']=table; box.nodes['.tscroll']=scroll; box.nodes['[data-table-search]']=input; box.nodes['[data-table-tools]']=tools;
  input.value=''; input.setSelectionRange=(start,end)=>{input.selectionStart=start;input.selectionEnd=end;};
  return {box,table,scroll,input};
 }
 const before=tableBox(); before.input.value='server'; before.input.selectionStart=2; before.input.selectionEnd=4; before.scroll.scrollLeft=178; before.input.focus();
 x.dispatch('htmx:beforeSwap',before.box,{detail:{target:before.box}});
 before.box.isConnected=false; before.input.isConnected=false; doc.activeElement=doc.body;
 const after=tableBox(); after.box.nodes['table[data-sortable]']=[after.table];
 x.dispatch('htmx:afterSwap',after.box,{detail:{target:before.box}});
 assert.equal(after.input.value,'server','outerHTML refresh restores search query'); assert.equal(after.scroll.scrollLeft,178,'outerHTML refresh restores horizontal scroll');
 assert.equal(doc.activeElement,after.input,'outerHTML refresh restores search focus'); assert.equal(after.input.selectionStart,2); assert.equal(after.input.selectionEnd,4);

 // Existing row links regain focus; deleted rows must not focus a different item.
 for (const survives of [true,false]) {
  const oldBox=tableBox(), oldLink=new Element('a[href]',oldBox.box); oldLink.setAttribute('href','/devices/7'); oldLink.focus();
  x.dispatch('htmx:beforeSwap',oldBox.box,{detail:{target:oldBox.box}});oldLink.isConnected=false;doc.activeElement=doc.body;
  const fresh=tableBox(), freshLink=new Element('a[href]',fresh.box);freshLink.setAttribute('href','/devices/7');
  fresh.box.nodes['a[href]']=survives ? [freshLink] : [];
  x.dispatch('htmx:afterSwap',fresh.box,{detail:{target:oldBox.box}});
  assert.equal(doc.activeElement,survives ? freshLink : doc.body,'row focus follows only a surviving link');
 }
 console.log('UI behaviour passed: drawer focus/reset, top-layer menus, clipboard feedback');
})().catch(e=>{console.error(e);process.exitCode=1;});
