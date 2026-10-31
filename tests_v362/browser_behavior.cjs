'use strict';
/*
 * Zero-dependency, behavior-level regression runner for the REAL dashboard
 * JavaScript (extracted from ui/dashboard.html). Never touches any file on C:.
 */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const page = fs.readFileSync(path.join(__dirname, '..', 'ui', 'dashboard.html'), 'utf8');
const scriptMatch = page.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, 'dashboard must contain an inline script');
const script = scriptMatch[1];

class MockElement {
  constructor(id, document) {
    this.id = id;
    this.document = document;
    this.textContent = '';
    this.value = '';
    this.innerHTML = '';
    this.className = '';
    this.children = [];
    this.listeners = new Map();
    this.attributes = {};
    this.dataset = {};
    this.style = {};
    this.checked = false;
    this.disabled = false;
    this.open = false;
    this.isConnected = true;
    this.classes = new Set();
    this.classList = {
      add: x => this.classes.add(x),
      remove: x => this.classes.delete(x),
      contains: x => this.classes.has(x),
      toggle: (x, force) => {
        const enabled = force === undefined ? !this.classes.has(x) : !!force;
        if (enabled) this.classes.add(x); else this.classes.delete(x);
        return enabled;
      }
    };
  }
  setAttribute(n, v) { this.attributes[n] = String(v); }
  removeAttribute(n) { delete this.attributes[n]; }
  addEventListener(type, callback) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(callback);
  }
  emit(type, extra={}) {
    const event = {type, target:this, preventDefault(){this.defaultPrevented=true;}, ...extra};
    for (const callback of this.listeners.get(type) || []) callback(event);
    return event;
  }
  click() { this.emit('click'); }
  focus() { this.document.activeElement = this; }
  showModal() { if (this.open) throw Error('Dialog already open'); this.open = true; }
  close() { if (this.open) { this.open = false; this.emit('close'); } }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  appendChild(child) { this.children.push(child); return child; }
  querySelector(selector) {
    if (selector === '.quicknav-item') return this.children.find(x => x.className === 'quicknav-item') || null;
    return null;
  }
  querySelectorAll() { return []; }
  scrollIntoView() {}
  matches() { return false; }
  closest() { return null; }
}

function harness() {
  const elements = new Map(), requests = [], alerts = [], prompts = [];
  let route = async () => { throw Error('synthetic state fetch unavailable'); };
  const document = {
    body: {dataset:{view:'cache',density:'comfortable'}},
    activeElement:null,
    listeners:new Map(),
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, new MockElement(id, document));
      return elements.get(id);
    },
    createElement(tag) { return new MockElement(tag, document); },
    querySelectorAll() { return []; },
    addEventListener(type, callback) {
      if (!this.listeners.has(type)) this.listeners.set(type, []);
      this.listeners.get(type).push(callback);
    },
    emit(type, extra={}) {
      const evt = {type, key:'', ctrlKey:false, altKey:false, metaKey:false,
        target:document.getElementById('btn-quicknav'),
        preventDefault(){this.defaultPrevented=true;}, ...extra};
      for (const cb of this.listeners.get(type) || []) cb(evt);
      return evt;
    }
  };
  const context = vm.createContext({
    document,
    location:{search:'?t=synthetic',href:''},
    window:{scrollTo(){},open(){}},
    URLSearchParams,
    fetch(url, options) {
      requests.push({url:String(url), options:options || {}});
      return Promise.resolve().then(() => route(String(url), options || {}));
    },
    setInterval(){return 1;},
    alert(s){alerts.push(String(s));},
    prompt(s){prompts.push(String(s));return 'DELETE';},
    confirm(){throw Error('Unexpected confirmation from mock');}
  });
  vm.runInContext(script, context, {filename:'ui/dashboard.html',timeout:2000});
  const get = id => document.getElementById(id);
  const run = expr => vm.runInContext(expr, context, {timeout:2000});
  const okResponse = obj => ({ok:true,status:200,json:async()=>({ok:true,...obj})});
  return {context, document, get, run, requests, alerts, prompts, okResponse,
    setRoute(fn){route=fn;},
    postCalls:()=>requests.filter(x=>x.options.method==='POST'),
    flush:()=>new Promise(resolve=>setImmediate(resolve))
  };
}

const fixture = {
  busy:false,
  items:[
    {id:'green',name:'Demo Green',allowed:true,risk:'green',size:1024,count:1,priority:'P1',path:'C:\\Fake\\safe',note:'',state:''},
    {id:'amber',name:'Demo Amber',allowed:true,risk:'amber',size:2048,count:2,priority:'P2',path:'C:\\Fake\\review',note:'',state:''},
    {id:'protected',name:'Demo Protected',allowed:false,risk:'red',size:4096,count:1,priority:'P4',path:'C:\\Fake\\protected',note:'',state:''}
  ]
};
function seed(h, chosen=['green']) {
  h.context.fixture = fixture;
  h.context.seedIds = chosen;
  h.run("latest=fixture;connectionHealth='online';selected.clear();for(const id of seedIds)selected.add(id);updateSelection()");
}
function preview(ticket='p-test',expires=100) {
  return {preview:{ticket,categories:[{name:'Cache',path:'C:\\Fake\\safe',risk:'green',files:1,bytes:1024}],
    total_files:1,total_bytes:1024,expires_in_seconds:expires,warning:'Synthetic test'}};
}
function pageResult(expires=90) {
  return {page:{offset:0,total:1,next_offset:null,expires_in_seconds:expires,
    files:[{number:1,category:'Cache',path:'C:\\Fake\\safe\\file.tmp',bytes:1024,modified:'2026-01-01'}]}};
}
async function runTest(title, fn) {
  try { await fn(); console.log('PASS', title); }
  catch (error) { console.error('FAIL', title, error.stack || error); process.exitCode=1; }
}

(async () => {
  await runTest('quick navigation changes pages but never performs a POST', async()=>{
    const h=harness();await h.flush();
    const opener=h.get('btn-quicknav');opener.focus();
    const evt=h.document.emit('keydown',{key:'k',ctrlKey:true,target:opener});
    assert.equal(evt.defaultPrevented,true);
    assert.equal(h.get('quicknav-dialog').open,true);
    assert.equal(h.get('quicknav-list').children.length,7);
    h.get('quicknav-input').value='查重';
    h.get('quicknav-input').emit('input');
    assert.equal(h.get('quicknav-list').children.length,1);
    h.get('quicknav-list').querySelector('.quicknav-item').click();
    assert.equal(h.get('quicknav-dialog').open,false);
    assert.equal(h.document.activeElement,opener);
    assert.equal(h.run('view'),'inspect');
    assert.equal(h.postCalls().length,0);
    h.get('clean-preview-dialog').showModal();
    h.run('openQuickNav()');
    assert.equal(h.get('quicknav-dialog').open,false);
  });

  await runTest('green/amber selection counts exclude protected items and clear is non-destructive',async()=>{
    const h=harness();await h.flush();seed(h,['green','amber','protected']);
    assert.match(h.get('selection-review').textContent,/绿色 1 \/ 黄色 1/);
    assert.match(h.get('selection-review').textContent,/3\.00 KiB/);
    assert.equal(h.get('selection-review-strip').classList.contains('contains-amber'),true);
    assert.equal(h.get('btn-clean').disabled,false);
    h.get('clear-selection').click();
    assert.equal(h.run('selected.size'),0);
    assert.equal(h.get('btn-clean').disabled,true);
    assert.equal(h.postCalls().length,0);
  });

  await runTest('rapid repeated preview requests are serialized, stale selections revoke ticket',async()=>{
    const h=harness();await h.flush();seed(h);
    let release;
    h.setRoute((url)=>{
      if(url==='/api/preview-clean')return new Promise(resolve=>{release=resolve});
      if(url==='/api/cancel-preview')return h.okResponse({});
      throw Error('Unexpected URL '+url);
    });
    const first=h.run('cleanSelected()'),second=h.run('cleanSelected()');
    await h.flush();
    assert.equal(h.postCalls().filter(x=>x.url==='/api/preview-clean').length,1);
    h.run("selected.delete('green');markSelectionChanged();updateSelection()");
    release(h.okResponse(preview()));
    await Promise.all([first,second]);
    assert.equal(h.get('clean-preview-dialog').open,false);
    assert.equal(h.postCalls().filter(x=>x.url==='/api/cancel-preview').length,1);
    assert.equal(h.postCalls().filter(x=>x.url==='/api/clean').length,0);
  });

  await runTest('expired preview page never enables DELETE',async()=>{
    const h=harness();await h.flush();seed(h);
    h.setRoute(url=>{
      if(url==='/api/preview-clean')return h.okResponse(preview());
      if(url==='/api/preview-files')return h.okResponse(pageResult(0));
      if(url==='/api/cancel-preview')return h.okResponse({});
      throw Error('Unexpected URL '+url);
    });
    await h.run('cleanSelected()');
    assert.equal(h.get('clean-preview-dialog').open,true);
    assert.equal(h.get('preview-approve').disabled,true);
    assert.equal(h.run('previewPageValidated'),false);
    await h.run('approvePreview()');
    assert.equal(h.prompts.length,0);
    assert.equal(h.postCalls().filter(x=>x.url==='/api/clean').length,0);
    h.run('closePreview()');
  });

  await runTest('connection loss during preview loading permanently blocks that preview',async()=>{
    const h=harness();await h.flush();seed(h);
    let releasePage;
    h.setRoute(url=>{
      if(url==='/api/preview-clean')return h.okResponse(preview());
      if(url==='/api/preview-files')return new Promise(resolve=>{releasePage=resolve});
      if(url==='/api/cancel-preview')return h.okResponse({});
      throw Error('Unexpected URL '+url);
    });
    const opening=h.run('cleanSelected()');
    for(let i=0;i<8&&!releasePage;i++)await h.flush();
    assert.equal(typeof releasePage,'function');
    h.run("connectionHealth='offline';updateConnectionStatus()");
    releasePage(h.okResponse(pageResult(90)));
    await opening;
    assert.equal(h.get('preview-approve').disabled,true);
    assert.equal(h.run('previewPageValidated'),false);
    h.run("connectionHealth='online';updateConnectionStatus()");
    await h.run('approvePreview()');
    assert.equal(h.postCalls().filter(x=>x.url==='/api/clean').length,0);
    h.run('closePreview()');
  });

  await runTest('unknown result after POST /api/clean is reported as uncertain, never as not executed',async()=>{
    const h=harness();await h.flush();seed(h);
    h.setRoute(url=>{
      if(url==='/api/preview-clean')return h.okResponse(preview());
      if(url==='/api/preview-files')return h.okResponse(pageResult());
      if(url==='/api/clean')return Promise.reject(Error('simulated lost response'));
      throw Error('Unexpected URL '+url);
    });
    await h.run('cleanSelected()');
    assert.equal(h.get('preview-approve').disabled,false);
    await h.run('approvePreview()');
    assert.equal(h.postCalls().filter(x=>x.url==='/api/clean').length,1);
    assert.equal(h.get('clean-preview-dialog').open,false);
    assert.equal(h.run('selected.size'),0);
    assert.equal(h.get('preview-approve').disabled,true);
    assert.ok(h.alerts.some(s=>s.includes('执行结果未能确认')));
    assert.ok(!h.alerts.some(s=>s.includes('未执行清理')));
  });

  await runTest('double DELETE confirmation sends only one server request',async()=>{
    const h=harness();await h.flush();seed(h);
    let complete;
    h.setRoute(url=>{
      if(url==='/api/preview-clean')return h.okResponse(preview());
      if(url==='/api/preview-files')return h.okResponse(pageResult());
      if(url==='/api/clean')return new Promise(resolve=>{complete=resolve});
      throw Error('Unexpected URL '+url);
    });
    await h.run('cleanSelected()');
    const first=h.run('approvePreview()'),second=h.run('approvePreview()');
    await h.flush();
    assert.equal(h.postCalls().filter(x=>x.url==='/api/clean').length,1);
    assert.equal(h.get('clean-preview-dialog').open,true);
    assert.equal(h.run('cleanSubmitInFlight'),true);
    complete(h.okResponse({}));
    await Promise.all([first,second]);
    assert.equal(h.get('clean-preview-dialog').open,false);
    assert.equal(h.run('cleanSubmitInFlight'),false);
    assert.equal(h.postCalls().filter(x=>x.url==='/api/clean').length,1);
  });

  if(process.exitCode)process.exit(process.exitCode);
})().catch(error=>{console.error(error);process.exitCode=1;});
