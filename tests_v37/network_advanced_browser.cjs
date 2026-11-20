'use strict';
/* Coractive-inspired local indexed browser is GET-only, paged and escaped. */
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync(path.join(__dirname,'..','ui','dashboard.html'),'utf8');
assert.equal(html.split('<script>').length,2);
const script=html.slice(html.indexOf('<script>')+8,html.indexOf('</script>'));
class Element {
 constructor(id){this.id=id;this._html='';this.value='';this.options=[];this.hidden=false;
  this.checked=true;this.disabled=false;this.textContent='';this.style={};this.dataset={};this.classes=new Set();this.listeners=new Map();this.attributes={};
  this.classList={add:v=>this.classes.add(v),remove:v=>this.classes.delete(v),contains:v=>this.classes.has(v),toggle:()=>false};}
 get innerHTML(){return this._html;}
 set innerHTML(s){this._html=String(s);if(this.id==='large-drive')this.options=[...this._html.matchAll(/<option value="([^"]+)"/g)].map(x=>({value:x[1]}));}
 addEventListener(name,fn){this.listeners.set(name,fn);}
 setAttribute(name,value){this.attributes[name]=value;}removeAttribute(name){delete this.attributes[name];}
 replaceChildren(){}append(){}appendChild(){}querySelectorAll(){return [];}querySelector(){return null;}closest(){return null;}
 scrollIntoView(){}focus(){}showModal(){}close(){}
}
const map=new Map(),requests=[];let holdSearch=false,releaseSearch=null;
const indexRequests=()=>requests.filter(r=>r.url.startsWith('/api/network-index/'));
const document={body:{dataset:{view:'cache'}},activeElement:null,
 getElementById(id){if(!map.has(id))map.set(id,new Element(id));return map.get(id);},
 querySelectorAll(){return []},addEventListener(){},createElement(n){return new Element(n)}};
const E=id=>document.getElementById(id);
const response=page=>({ok:true,status:200,json:async()=>({ok:true,page})});
const mockFiles=[{name:'<img onerror=alert(1)>Fab.pdf',path:'O:\\docs\\<img onerror=alert(1)>Fab.pdf',size:5,mtime:0}];
const sandbox={document,location:{search:'?t=secret'},URLSearchParams,
 window:{scrollTo(){},open(){}},setInterval(){},alert(message){throw Error('unexpected alert: '+message)},prompt(){throw Error('prompt')},confirm(){return false},
 fetch(url,options={}){requests.push({url,options});if(options.method)throw Error('browser must not post '+url);
  const route=url.split('?')[0];
  if(route==='/api/network-index/search' && holdSearch){holdSearch=false;return new Promise(resolve=>{releaseSearch=()=>resolve(response({rows:mockFiles,total:211,offset:0,limit:100,has_more:true,state:'complete',updated:'old',partial:false}))})}
  if(route==='/api/network-index/search')return Promise.resolve(response({rows:mockFiles,total:211,offset:Number(new URL('http://localhost'+url).searchParams.get('offset')),limit:100,has_more:true,state:'complete',updated:'2026-11-20',partial:false}));
  if(route==='/api/network-index/folders')return Promise.resolve(response({rows:[{rel:'docs',name:'docs',direct_files:2,indexed_files:30,nested_files:28}],total:1,offset:0,limit:100,has_more:false,state:'complete',folder:'',partial:false}));
  if(route==='/api/network-index/folder-files')return Promise.resolve(response({rows:mockFiles,total:1,offset:0,limit:100,has_more:false,state:'complete',updated:'2026-11-20',partial:false}));
  return new Promise(()=>{});
 }};
const ctx=vm.createContext(sandbox);vm.runInContext(script,ctx,{filename:'dashboard.html',timeout:3000});
(async()=>{
 for(const id of ['network-browser-tools','index-advanced-query','index-search-rows','index-folder-rows','index-folder-files','index-folder-recursive'])assert.match(html,new RegExp('id="'+id+'"'));
 ctx.fixture={network_drives:[{id:'O:',type:'映射网络盘'}],index_storage_drives:['D:'],large_files:[],large_info:{},busy:false};
 vm.runInContext('latest=fixture;renderLarge()',ctx);
 E('large-drive').value='O:';vm.runInContext('renderLarge()',ctx);
 assert.equal(E('network-browser-tools').hidden,false);
 assert.equal(E('index-storage-drive').value,'D:');
 E('index-advanced-query').value='Fab ext:pdf -audit';
 await vm.runInContext('indexSearchPage(0)',ctx);
 assert.equal(indexRequests().length,1);
 const search=new URL('http://localhost'+indexRequests()[0].url).searchParams;
 assert.equal(search.get('drive'),'O:');assert.equal(search.get('storage'),'D:');
 assert.equal(search.get('q'),'Fab ext:pdf -audit');assert.equal(search.get('t'),'secret');
 assert.ok(E('index-search-rows').innerHTML.includes('&lt;img onerror=alert(1)&gt;'));
 assert.ok(!E('index-search-rows').innerHTML.includes('<img'));
 assert.equal(E('index-search-next').disabled,false);
 await vm.runInContext('indexSearchPage(100)',ctx);
 assert.equal(new URL('http://localhost'+indexRequests()[1].url).searchParams.get('offset'),'100');
 await vm.runInContext('indexShowRoot()',ctx);
 assert.equal(indexRequests().length,4);
 assert.equal(indexRequests()[2].url.split('?')[0],'/api/network-index/folders');
 assert.equal(indexRequests()[3].url.split('?')[0],'/api/network-index/folder-files');
 await vm.runInContext("indexOpenFolder('docs')",ctx);
 assert.equal(new URL('http://localhost'+indexRequests()[4].url).searchParams.get('folder'),'docs');
 assert.equal(new URL('http://localhost'+indexRequests()[5].url).searchParams.get('folder'),'docs');
 assert.ok(!requests.some(x=>x.url.includes('/api/clean')||x.options.method==='POST'));
 // Out-of-order old response must not overwrite a newer request.
 holdSearch=true;
 const stale=vm.runInContext('indexSearchPage(0)',ctx);
 assert.ok(releaseSearch,'first query is held');
 await vm.runInContext('indexSearchPage(100)',ctx);
 const before=E('index-search-summary').textContent;
 releaseSearch();await stale;
 assert.equal(E('index-search-summary').textContent,before,'stale response did not repaint current page');
 // A drive switch must clear sensitive filenames from the previously selected share.
 ctx.fixture.network_drives=[{id:'O:'},{id:'P:'}];
 vm.runInContext('latest=fixture;renderLarge()',ctx);
 E('large-drive').value='P:';vm.runInContext('renderLarge()',ctx);
 assert.equal(E('index-search-rows').innerHTML,'');
 assert.match(E('index-search-summary').textContent,/盘符或索引存储位置已变化/);
 E('large-drive').value='C:';vm.runInContext('renderLarge()',ctx);
 assert.equal(E('network-browser-tools').hidden,true);
 console.log('PASS index search literal query, 100-row paging, safe HTML, mapped drive/storage and GET-only folder navigation');
})().catch(err=>{console.error(err.stack);process.exitCode=1});
