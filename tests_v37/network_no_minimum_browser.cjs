'use strict';
/* Dashboard contract: network mapping never inherits the C: minimum size. */
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync(path.join(__dirname,'..','ui','dashboard.html'),'utf8');
assert.equal(html.split('<script>').length,2);
const script=html.slice(html.indexOf('<script>')+8,html.indexOf('</script>'));
class Element {
 constructor(id,doc){this.id=id;this.doc=doc;this._html='';this.value='';this.options=[];
  this.hidden=false;this.checked=false;this.disabled=false;this.textContent='';this.style={};
  this.dataset={};this.classes=new Set();this.listeners=new Map();this.attributes={};
  this.classList={add:v=>this.classes.add(v),remove:v=>this.classes.delete(v),contains:v=>this.classes.has(v),toggle:()=>false};}
 get innerHTML(){return this._html;}
 set innerHTML(text){this._html=String(text);if(this.id==='large-drive'){
   this.options=[...this._html.matchAll(/<option value="([^"]+)"/g)].map(match=>({value:match[1]}));}}
 setAttribute(k,v){this.attributes[k]=v;}
 removeAttribute(k){delete this.attributes[k];}
 addEventListener(k,v){if(!this.listeners.has(k))this.listeners.set(k,[]);this.listeners.get(k).push(v);}
 replaceChildren(){}append(){}appendChild(){}querySelectorAll(){return [];}querySelector(){return null;}closest(){return null;}
 scrollIntoView(){}focus(){}showModal(){}close(){}
}
function harness(){const map=new Map(),requests=[],confirms=[];let approval=false;
 const document={body:{dataset:{view:'cache'}},activeElement:null,listeners:new Map(),
   getElementById(id){if(!map.has(id))map.set(id,new Element(id,document));return map.get(id);},
   createElement(name){return new Element(name,document)},querySelectorAll(){return []},addEventListener(){} };
 const get=id=>document.getElementById(id);
 const sandbox={document,location:{search:'?t=synthetic'},URLSearchParams,window:{scrollTo(){},open(){}},
   setInterval(){},alert(msg){throw Error('unexpected alert: '+msg)},prompt(){throw Error('delete prompt is forbidden')},
   confirm(msg){confirms.push(msg);return approval},
   fetch(url,options={}){requests.push({url,options});if(options.method!=='POST')return new Promise(()=>{});return Promise.resolve({ok:true,status:200,json:async()=>({ok:true})})}};
 const context=vm.createContext(sandbox);
 vm.runInContext(script,context,{filename:'dashboard.html',timeout:2000});
 return {get,requests,confirms,context,run:x=>vm.runInContext(x,context,{timeout:2000}),approval:x=>approval=x,
 posts:()=>requests.filter(r=>r.options.method==='POST')};}
(async()=>{
 assert.match(html,/id="large-minimum-filter"/);
 assert.match(html,/id="network-file-keyword"/);
 const h=harness();
 h.context.fixture={network_drives:[{id:'O:',type:'映射网络盘'}],index_storage_drives:['D:'],large_files:[],large_info:{},busy:false};
 h.run('latest=fixture;renderLarge()');
 h.get('large-drive').value='O:';
 h.run('renderLarge()');
 assert.equal(h.get('large-minimum-filter').hidden,true);
 assert.equal(h.get('large-minimum-filter').style.display,'none');
 assert.equal(h.get('network-keyword-control').hidden,false);
 assert.match(h.get('network-drive-help').textContent,/不限文件大小/);
 assert.equal(h.get('index-storage-drive').value,'D:');
 assert.equal(h.get('local-index-tools').hidden,false);
 h.get('min-mb').value='4096';
 h.get('network-file-keyword').value='工程 报告.pdf';
 await h.run('startLarge()');
 assert.equal(h.posts().length,1);
 assert.deepEqual(JSON.parse(h.posts()[0].options.body),{
   min_mb:0,drive:'O:',network_walk:false,filename:'工程 报告.pdf',storage_drive:'D:'});
 assert.ok(!h.posts().some(r=>r.url.includes('/api/clean')));
 console.log('PASS network size minimum hidden; request uses no minimum with filename');
 h.get('large-network-walk').checked=true;
 await h.run('startLarge()');
 assert.equal(h.posts().length,1,'no auto network walk without confirmation');
 assert.match(h.confirms[0],/只读/);
 h.approval(true);await h.run('startLarge()');
 assert.equal(h.posts().length,2);
 assert.equal(JSON.parse(h.posts()[1].options.body).network_walk,true);
 console.log('PASS network directory walk remains explicit opt-in');
 h.get('large-drive').value='C:';h.run('renderLarge()');
 assert.equal(h.get('large-minimum-filter').hidden,false);
 assert.equal(h.get('large-minimum-filter').style.display,'flex');
 assert.equal(h.get('network-keyword-control').hidden,true);
 h.get('min-mb').value='512';
 await h.run('startLarge()');
 assert.equal(h.posts().length,3);
 assert.deepEqual(JSON.parse(h.posts()[2].options.body),{
   min_mb:512,drive:'C:',network_walk:false,filename:'',storage_drive:''});
 console.log('PASS C: large-file size minimum remains unchanged');
 h.get('large-drive').value='O:';h.run('renderLarge()');
 assert.equal(h.get('index-storage-drive').value,'D:');
 h.approval(false);await h.run('startNetworkIndex()');
 assert.equal(h.posts().length,3,'no implicit local network indexing');
 h.approval(true);await h.run('startNetworkIndex()');
 assert.equal(h.posts().length,4,'index request requires confirmation');
 assert.ok(h.posts()[3].url.includes('/api/network-index/start'));
 assert.deepEqual(JSON.parse(h.posts()[3].options.body),{
  drive:'O:',storage:'D:',confirm:'INDEX_METADATA_READ_ONLY'});
 assert.ok(!h.posts().some(r=>r.url.includes('/api/clean')));
 console.log('PASS explicit network-index consent, local fixed drive and no cleanup');
})().catch(e=>{console.error(e.stack);process.exitCode=1});
