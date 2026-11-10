'use strict';
/* Exercise the shipped dashboard with synthetic local API responses only. */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(path.join(__dirname, '..', 'ui', 'dashboard.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

class Element {
  constructor(id, document) {
    Object.assign(this, {id, document, textContent:'', innerHTML:'', value:'', disabled:false,
      checked:false, open:false, dataset:{}, style:{}, attributes:{}, listeners:new Map(),
      children:[], classes:new Set(), isConnected:true});
    this.classList={add:x=>this.classes.add(x),remove:x=>this.classes.delete(x),contains:x=>this.classes.has(x),
      toggle:(x,force)=>{const on=force===undefined?!this.classes.has(x):!!force;on?this.classes.add(x):this.classes.delete(x);return on;}};
  }
  setAttribute(k,v){this.attributes[k]=String(v);}
  removeAttribute(k){delete this.attributes[k];}
  addEventListener(k,fn){if(!this.listeners.has(k))this.listeners.set(k,[]);this.listeners.get(k).push(fn);}
  emit(k,extra={}){const event={type:k,target:this,preventDefault(){},...extra};for(const fn of this.listeners.get(k)||[])fn(event);return event;}
  showModal(){if(this.open)throw Error('dialog already open');this.open=true;}
  close(){if(this.open){this.open=false;this.emit('close');}}
  focus(){this.document.activeElement=this;}
  replaceChildren(...xs){this.children=xs;}
  append(...xs){this.children.push(...xs);}
  appendChild(x){this.children.push(x);return x;}
  querySelector(){return null;}
  querySelectorAll(){return [];}
  closest(){return null;}
  scrollIntoView(){}
}
function harness(){
  const elements=new Map(),requests=[],alerts=[];
  let route=async()=>{throw Error('No synthetic response registered');};
  const document={body:{dataset:{view:'cache'}},activeElement:null,listeners:new Map(),
    getElementById(id){if(!elements.has(id))elements.set(id,new Element(id,document));return elements.get(id);},
    createElement(tag){return new Element(tag,document);},querySelectorAll(){return [];},
    addEventListener(k,fn){if(!this.listeners.has(k))this.listeners.set(k,[]);this.listeners.get(k).push(fn);}};
  const get=id=>document.getElementById(id);
  get('unity-preserve-offline').checked=true;get('filter-cache').value='all';
  const context=vm.createContext({document,URLSearchParams,location:{search:'?t=synthetic'},
    window:{scrollTo(){},open(){}},setInterval(){},alert:x=>alerts.push(String(x)),
    prompt(){throw Error('No DELETE prompt expected');},confirm(){throw Error('No confirm expected');},
    fetch(url,options={}){requests.push({url:String(url),options});return Promise.resolve().then(()=>route(String(url),options));}});
  vm.runInContext(script,context,{filename:'ui/dashboard.html',timeout:2000});
  return {context,get,requests,alerts,document,run:expression=>vm.runInContext(expression,context,{timeout:2000}),
    setRoute:fn=>{route=fn;},ok:obj=>({ok:true,status:200,json:async()=>({ok:true,...obj})}),
    posts:()=>requests.filter(x=>x.options.method==='POST'),flush:()=>new Promise(resolve=>setImmediate(resolve))};
}
const GIB=1024**3;
function row(id,group,extra={}){return {id,group,name:id,path:'C:\\Synthetic\\'+id,size:GIB,count:1,complete:true,
  risk:'amber',priority:'P2',allowed:true,age_days:0,note:'synthetic cache',reason:'Rebuild required',state:'完成',...extra};}
const fixture={busy:false,preserve_offline:true,disk:{total:200*GIB,free:20*GIB,used:180*GIB},
  items:[row('upm','unity-upm',{allowed:false,state:'离线保护'}),row('gi','unity-gi'),
    row('logs','unity-logs',{risk:'green',age_days:14}),row('regular','user-temp',{risk:'green'}),
    row('locked','unity-logs',{allowed:false,state:'程序仍运行'}),row('partial','unity-gi',{allowed:false,complete:false})],
  unity:{complete:false,items:[
    {id:'readonly',name:'Asset Store <img src=x onerror=alert(1)>',path:'C:\\Synthetic\\<script>evil</script>',drive:'C:',bytes:8*GIB,count:5,complete:true,exists:true,action:'只读',source:'已知路径',reason:'保留资源'},
    {id:'d-cache',name:'自定义缓存',path:'D:\\Synthetic\\cache',drive:'D:',bytes:30*GIB,count:9,complete:true,exists:true,action:'仅诊断',source:'环境变量',reason:'其他盘缓存'},
    {id:'unread',name:'不可读取',path:'D:\\Synthetic\\blocked',drive:'D:',bytes:0,count:0,complete:false,exists:true,errors:1,state:'未完整'}],
    totals_by_drive:{'C:':{bytes:8*GIB,count:5,complete:true},'D:':{bytes:30*GIB,count:9,complete:false}},
    settings:[{name:'UPM_CACHE_ROOT',value:'D:\\Synthetic\\<img>',source:'环境变量',valid:true,note:'只读识别'}],
    guidance:[{title:'示例建议',text:'<img src=x>',steps:['<b>保留离线包</b>']}]}};
function seed(h,ids=[]){h.context.testFixture=JSON.parse(JSON.stringify(fixture));h.context.testIds=ids;
  h.run("latest=testFixture;connectionHealth='online';selected=new Set(testIds);unityPolicyDirty=false;renderUnity()");}
function change(h,id,checked){const input=new Element('input',h.document);input.dataset.unityCheck=id;input.checked=checked;
 input.closest=selector=>selector==='input[data-unity-check]'?input:null;
 h.get('unity-cache-cards').emit('change',{target:input});return input;}
async function test(title,fn){try{await fn();console.log('PASS',title);}catch(e){console.error('FAIL',title,e.stack);process.exitCode=1;}}

(async()=>{
 await test('Unity navigation is discoverable and performs no scan or deletion',async()=>{
   const h=harness();await h.flush();seed(h);
   h.run("switchPage('unity')");
   assert.equal(h.run('view'),'unity');assert.equal(h.get('nav-unity').attributes['aria-current'],'page');
   assert.equal(h.get('detail-panel').classList.contains('hide'),true);
   assert.match(h.get('main-title').textContent,/Unity/);assert.equal(h.posts().length,0);
   assert.match(html,/id="unity-preserve-offline" checked/);
 });
 await test('initial empty report is shown as not yet scanned, without invented capacity',async()=>{
   const h=harness();await h.flush();seed(h);
   h.run("latest.items=[];latest.unity={items:[],state:'未扫描',complete:false,preserve_offline:true};renderUnity()");
   assert.equal(h.get('unity-cleanable').textContent,'—');
   assert.equal(h.get('unity-policy').textContent,'待扫描');
   assert.match(h.get('unity-status').textContent,/尚未执行/);
 });
 await test('refresh reflects the server offline policy instead of the HTML default',async()=>{
   const h=harness();await h.flush();seed(h);
   h.run("latest.preserve_offline=false;latest.items.find(x=>x.id==='upm').allowed=true;renderUnity()");
   assert.equal(h.get('unity-preserve-offline').checked,false);
   assert.equal(h.get('unity-policy').textContent,'已解除');
   assert.match(h.get('unity-offline-note').textContent,/保护已取消/);
   change(h,'upm',true);assert.equal(h.run("selected.has('upm')"),true);
 });
 await test('a state refresh cannot overwrite an unsent offline-policy edit',async()=>{
   const h=harness();await h.flush();seed(h);
   let release;h.setRoute(()=>new Promise(resolve=>{release=resolve;}));
   const pending=h.run('poll()');await h.flush();
   h.get('unity-preserve-offline').checked=false;h.get('unity-preserve-offline').emit('change');
   release(h.ok(JSON.parse(JSON.stringify(fixture))));await pending;
   assert.equal(h.get('unity-preserve-offline').checked,false);
   assert.equal(h.run('unityPolicyDirty'),true);
   assert.equal(h.get('btn-unity-preview').disabled,true);
 });
 await test('polls from before a submitted scan cannot replace its pending policy',async()=>{
   const h=harness();await h.flush();seed(h);
   h.run('latest.preserve_offline=false;renderUnity()');
   let release;h.setRoute((url)=>url.startsWith('/api/state')?new Promise(resolve=>{release=resolve;}):h.ok({}));
   const stale=h.run('poll()');await h.flush();
   h.get('unity-preserve-offline').checked=true;h.get('unity-preserve-offline').emit('change');
   await h.run("startScan('unity')");
   const oldState=JSON.parse(JSON.stringify(fixture));oldState.preserve_offline=false;
   release(h.ok(oldState));await stale;
   assert.equal(h.get('unity-preserve-offline').checked,true);
   assert.equal(h.run('unityPendingPolicy'),true);
   assert.equal(h.get('btn-unity-preview').disabled,true);
   h.setRoute(()=>h.ok(JSON.parse(JSON.stringify(fixture))));await h.run('poll()');
   assert.equal(h.get('unity-preserve-offline').checked,true);
   assert.equal(h.run('unityPendingPolicy'),null);
   assert.equal(h.get('unity-policy').textContent,'已开启');
 });
 await test('Unity scan sends the offline policy and never sends a cleanup request',async()=>{
   const h=harness();await h.flush();seed(h,['regular','gi']);h.setRoute(()=>h.ok({}));
   await h.run("startScan('unity')");
   assert.deepEqual(JSON.parse(h.posts()[0].options.body),{mode:'unity',preserve_offline:true});
   assert.equal(h.run('selected.size'),0);
   h.get('unity-preserve-offline').checked=false;
   await h.run("startScan('unity')");
   assert.deepEqual(JSON.parse(h.posts()[1].options.body),{mode:'unity',preserve_offline:false});
   assert.equal(h.posts().filter(x=>x.url==='/api/clean').length,0);
 });
 await test('only server-authorized Unity candidates can be selected',async()=>{
   const h=harness();await h.flush();seed(h);
   for(const id of ['readonly','upm','locked','partial','regular','unknown']){
     const input=change(h,id,true);assert.equal(input.checked,false);assert.equal(h.run('selected.size'),0);
   }
   change(h,'gi',true);assert.equal(h.run("selected.has('gi')"),true);
   assert.equal(h.get('btn-unity-preview').disabled,false);
   h.run("connectionHealth='offline';updateConnectionStatus()");
   assert.equal(h.get('btn-unity-preview').disabled,true);change(h,'logs',true);
   assert.equal(h.run("selected.has('logs')"),false);
 });
 await test('offline policy change revokes previews and remains locked through stale server data',async()=>{
   const h=harness();await h.flush();seed(h,['gi']);h.setRoute(()=>h.ok({}));
   h.run("pendingPreview={ticket:'old',ids:['gi']};E('clean-preview-dialog').showModal()");
   h.get('unity-preserve-offline').checked=false;h.get('unity-preserve-offline').emit('change');
   await h.flush();assert.equal(h.run('pendingPreview'),null);assert.equal(h.get('clean-preview-dialog').open,false);
   assert.equal(h.posts().some(x=>x.url==='/api/cancel-preview'),true);
   h.run('latest=testFixture;renderUnity()');change(h,'gi',true);
   assert.equal(h.run('selected.size'),0);assert.equal(h.get('btn-unity-preview').disabled,true);
   assert.match(h.get('unity-status').textContent,/重新扫描/);
   assert.equal(h.posts().some(x=>x.url==='/api/clean'),false);
 });
 await test('Unity-specific preview excludes other selected caches and never auto-confirms DELETE',async()=>{
   const h=harness();await h.flush();seed(h,['regular','gi','readonly']);
   h.setRoute((url)=>{
     if(url==='/api/preview-clean')return h.ok({preview:{ticket:'unity-preview',categories:[{name:'GI',risk:'amber',path:'C:\\Synthetic\\gi',files:1,bytes:GIB}],total_files:1,total_bytes:GIB,expires_in_seconds:120,warning:'Rebuild'}});
     if(url==='/api/preview-files')return h.ok({page:{files:[{number:1,category:'GI',path:'C:\\Synthetic\\gi\\cache.bin',bytes:GIB,modified:'2026-01-01'}],offset:0,total:1,next_offset:null,expires_in_seconds:100}});
     throw Error('Unexpected '+url);
   });
   await h.run("cleanSelected('unity')");
   assert.deepEqual(JSON.parse(h.posts()[0].options.body),{ids:['gi']});
   assert.equal(h.get('clean-preview-dialog').open,true);assert.equal(h.get('preview-approve').disabled,false);
   assert.equal(h.posts().some(x=>x.url==='/api/clean'),false);
 });
 await test('green batch selection omits Unity even when old logs are green',async()=>{
   const h=harness();await h.flush();seed(h);
   h.get('check-all-green').checked=true;h.get('check-all-green').emit('change');
   assert.equal(h.run("selected.has('regular')"),true);assert.equal(h.run("selected.has('logs')"),false);
 });
 await test('other-drive diagnostic sizes are not counted as C-drive cleanup',async()=>{
   const h=harness();await h.flush();seed(h);
   assert.equal(h.get('unity-cleanable').textContent,'2.00 GiB');
   assert.match(h.get('unity-audit-volumes').innerHTML,/30\.0 GiB/);
   assert.match(h.get('unity-audit-volumes').innerHTML,/D: 其他位置/);
   assert.match(h.get('unity-audit-volumes').innerHTML,/未完整/);
   assert.equal(h.run('unityLogicalSize(0,false,true)'),'未完整');
   assert.equal(h.run('unityLogicalSize(0,false,null)'),'未完整');
   assert.equal(h.run('unityLogicalSize(0,true,false)'),'未找到');
 });
 await test('filenames, settings and guidance are escaped without active markup',async()=>{
   const h=harness();await h.flush();seed(h);
   for(const id of ['unity-audit-volumes','unity-settings-content','unity-extra-guidance']){
     assert.doesNotMatch(h.get(id).innerHTML,/<img|<script>/i);
     assert.match(h.get(id).innerHTML,/&lt;/);
   }
 });
 await test('clearing Unity selection preserves unrelated choices and is non-destructive',async()=>{
   const h=harness();await h.flush();seed(h,['regular','gi','logs']);
   h.run('clearUnitySelection()');assert.equal(h.run('selected.size'),1);
   assert.equal(h.run("selected.has('regular')"),true);assert.equal(h.posts().length,0);
 });
})();
