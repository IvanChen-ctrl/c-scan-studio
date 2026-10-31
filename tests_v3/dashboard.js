'use strict';
const session = new URLSearchParams(location.search).get('t') || '';
const sections=['cache','large','advice','tools','security','logs'];
let view='cache', latest=null, selected=new Set(), selectedRow=null, selectedKind=null;
let pendingPreview=null, sortBy='priority', sortDir=1, pollRunning=false;
const E=id=>document.getElementById(id);
const fmt=n=>{n=Number(n)||0;if(n<1024)return Math.round(n)+' B';const U=['KiB','MiB','GiB','TiB'];let i=-1;do{n/=1024;i++}while(n>=1024&&i<U.length-1);return n.toFixed(n>=100?0:n>=10?1:2)+' '+U[i]};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const riskName={green:'绿色 · 低',amber:'黄色 · 中',orange:'橙色 · 高',red:'红色 · 极高',gray:'灰色 · 保护'};
const sortRank={green:0,amber:1,orange:2,red:3,gray:4};
const riskTag=r=>`<span class="risk ${esc(r)}">${esc(riskName[r]||r)}</span>`;
const prioTag=p=>`<span class="priority ${esc((p||'').toLowerCase())}">${esc(p)}</span>`;
const QS=(path)=>`${path}${path.includes('?')?'&':'?'}t=${encodeURIComponent(session)}`;
async function getState(){const res=await fetch(QS('/api/state'),{cache:'no-store'});if(!res.ok)throw Error('无法获取状态 '+res.status);return await res.json()}
async function post(path,body={}){const res=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSCAN-Token':session},body:JSON.stringify(body)});const obj=await res.json();if(!res.ok||!obj.ok)throw Error(obj.message||obj.error||'操作失败');return obj}
function notify(s){E('task-msg').textContent=s}
function switchPage(s){view=s;E('workspace').classList.toggle('security-layout',s==='security'||s==='tools');for(const name of sections){E('page-'+name).classList.toggle('hide',name!==s);E('nav-'+name).classList.toggle('active',name===s)}selectedRow=null;selectedKind=null;showDetail()}
async function startScan(mode){if(latest?.busy)return;selected.clear();pendingPreview=null;if(latest)latest.items=[];renderCache();try{notify('正在启动扫描...');await post('/api/scan',{mode})}catch(e){alert(e.message)}}
async function setupEverything(){
 if(latest?.busy)return;
 if(!confirm('将从 voidtools 官方网站下载固定版本 Everything 与 ES CLI，并校验 SHA-256 后解压到本工具目录。\n\nEverything 启动后可能提示设置索引服务或管理员权限。\n\n不会自动安装服务、改注册表或修改系统 PATH。是否继续？'))return;
 try{notify('正在准备 Everything 官方文件...');await post('/api/everything',{confirm:'INSTALL_OFFICIAL'})}
 catch(e){alert(e.message)}
}
async function startLarge(){if(latest?.busy)return;try{notify('正在查询大文件...');await post('/api/large',{min_mb:Number(E('min-mb').value)})}catch(e){alert(e.message)}}
async function stopTask(){try{await post('/api/stop')}catch(e){alert(e.message)}}
function downloadReport(type){location.href=QS('/api/export?type='+encodeURIComponent(type))}
async function runIntegrityCheck(){const status=E('security-status'),detail=E('security-detail');status.textContent='正在读取包内清单...';status.className='security-status';detail.classList.add('hide');try{const r=await fetch(QS('/api/security'),{cache:'no-store'});if(!r.ok)throw Error('无法请求本地核验 '+r.status);const v=await r.json();const okay=v.status==='matched';status.className='security-status '+(okay?'matched':'mismatch');status.textContent=okay?'与包内清单一致（非杀毒结果）':'发现文件变化或校验错误';detail.textContent='已比对：'+v.checked+' 个文件；匹配：'+v.matching+'；变更：'+v.changed.length+'；缺失：'+v.missing.length+'；异常：'+(v.unsafe_paths.length+v.errors.length)+'。\n包内清单 SHA-256：'+(v.manifest_sha256||'无')+'\n'+v.disclaimer+(okay?'':'\n异常列表：'+[...v.changed,...v.missing,...v.unsafe_paths,...v.errors].slice(0,20).join('；'));detail.classList.remove('hide')}catch(e){status.className='security-status mismatch';status.textContent='本地核验失败';detail.textContent=e.message;detail.classList.remove('hide')}}
function downloadSecurityReport(){location.href=QS('/api/security/export')}
function openVirusHash(){const value=E('hash-lookup').value.trim();if(!/^[a-fA-F0-9]{64}$/.test(value)){alert('请输入完整的 64 位十六进制 SHA-256。');return;}window.open('https://www.virustotal.com/gui/file/'+value.toLowerCase()+'/detection','_blank','noopener,noreferrer')}


const toolConfirm={
 defender_scan:{text:'将请求 Windows Microsoft Defender 对本工具文件夹执行自定义扫描。Defender 可能按电脑的安全策略隔离文件；真实结果需在 Windows 安全中心查看。是否继续？',code:'DEFENDER_SCAN'},
 signature_check:{text:'只读取工具目录内最多 25 个 EXE 的 Windows 数字签名；不会运行这些 EXE。是否继续？',code:'CHECK_SIGNATURES'},
 share_offline:{text:'只打包文件清单中的源码及经 SHA-256 校验的 Everything/ES 官方 ZIP。若未准备官方 ZIP 将拒绝创建。是否生成？',code:'MAKE_SHARE_PACKAGE'},
 python_installer:{text:'将打开一个新的 Windows 命令窗口，供你选择下载/安装完整版 Python；随后还需输入 INSTALL。此操作与当前清理功能无关，可能更改系统 Python。是否打开？',code:'OPEN_PYTHON_INSTALLER'},
 everything_launch:{text:'只启动已经核验 SHA-256 的 Everything 原版便携程序。它可能提示索引或服务设置。是否继续？',code:'LAUNCH_VERIFIED_EVERYTHING'},
 windows_storage:{text:'只打开 Windows 官方存储设置，不自动执行系统清理。是否继续？',code:'OPEN_WINDOWS_STORAGE'}
};
async function runTool(action){const x=toolConfirm[action];if(!x)return;if(latest?.busy||latest?.toolbox?.busy){alert('另一个任务正在运行，请先结束。');return}if(!confirm(x.text))return;try{const r=await post('/api/tool-action',{action,confirm:x.code});notify(r.message);E('tool-result').textContent='已请求执行：'+r.message+'\n结果会显示在这里。'}catch(e){alert(e.message)}}
function downloadToolboxReport(){location.href=QS('/api/toolbox/export')}
function renderToolbox(){const t=latest?.toolbox||{},py=t.python||{},every=latest?.everything||{};
 E('python-state').textContent=py.version?('已使用：'+py.source+'\n版本：'+py.version+'\n路径：'+py.executable+'\n系统 PATH：没有被本工具自动修改'):'正在读取环境信息';
 E('everything-state').textContent=every.ready?'官方 Everything 已通过本地验证。可启动或查询索引。':('当前状态：'+(latest?.es_status||'未准备')+'\n首次准备需要联网和用户确认。');
 const last=t.last||{}, el=E('tool-result');
 if(last.action){el.textContent=(t.busy?'执行中':'最近操作')+' · '+(toolConfirm[last.action]?.code||last.action)+'\n'+(last.message||'')+'\n'+(last.at||'');el.classList.toggle('failure',last.status==='error');el.classList.toggle('success',last.status==='completed')}
 for(const name of ['btn-setup-everything','btn-launch-everything']) E(name).disabled=!!latest?.busy||!!t.busy;
}

function allSelected(){const byid=new Map(latest?.items?.map(x=>[x.id,x])||[]);return [...selected].map(id=>byid.get(id)).filter(x=>x&&x.allowed)}
function selectedSize(){return allSelected().reduce((n,x)=>n+x.size,0)}
function updateSelection(){const list=allSelected(),total=selectedSize();E('selected-size').textContent=fmt(total)+' / '+list.length+' 项';E('btn-clean').disabled=!list.length||latest?.busy;const green=(latest?.items||[]).filter(x=>x.allowed&&x.risk==='green');E('check-all-green').checked=green.length>0&&green.every(x=>selected.has(x.id));E('check-all-green').disabled=!green.length||latest?.busy}
async function cleanSelected(){
 const rows=allSelected();if(!rows.length)return;
 if(latest?.busy){notify('请在任务结束后重新预览。');return}
 const ids=rows.map(x=>x.id);
 try{
  const response=await post('/api/preview-clean',{ids});
  const p=response.preview;if(!p?.ticket)throw Error('服务器未提供有效预览凭证');
  pendingPreview={ticket:p.ticket,ids};
  const amber=p.categories.some(x=>x.risk==='amber');
  E('preview-metrics').textContent=`${p.categories.length} 类 · ${p.total_files.toLocaleString('zh-CN')} 个候选文件 · 预计最多 ${fmt(p.total_bytes)} · 预览凭证 ${p.expires_in_seconds} 秒内有效`;
  E('preview-rows').innerHTML=p.categories.map(x=>`<tr><td><strong>${esc(x.name)}</strong><div class="mono">${esc(x.path)}</div></td><td>${riskTag(x.risk)}</td><td class="tabular">${Number(x.files).toLocaleString()}</td><td class="tabular">${fmt(x.bytes)}</td></tr>`).join('');
  E('preview-samples').textContent=(p.sample_paths||[]).join('\n')||'没有文件路径样本';
  E('preview-warning').textContent=p.warning+(amber?' 包含黄色项目：缓存可能需要重新下载或重建。':'')+' 仅显示部分文件路径样本，所有候选仍以服务器完整扫描快照为准。';
  E('clean-preview-dialog').showModal();
 }catch(e){pendingPreview=null;alert('不能生成删除预览：'+e.message)}
}
function closePreview(){const active=!!pendingPreview;pendingPreview=null;E('clean-preview-dialog').close();if(active)post('/api/cancel-preview').catch(e=>notify('预览已关闭，但凭证撤销失败：'+e.message))}
async function approvePreview(){
 const p=pendingPreview;if(!p)return;
 const typed=prompt('最后确认：删除已预览的缓存文件不经过回收站。请输入大写 DELETE：','');
 if(typed!=='DELETE'){notify('已取消：未输入 DELETE，文件没有删除。');return}
 E('preview-approve').disabled=true;
 try{await post('/api/clean',{ids:p.ids,confirm:'DELETE',ticket:p.ticket});pendingPreview=null;E('clean-preview-dialog').close();selected.clear();notify('已开始清理已预览的项目；文件将逐个复核。')}
 catch(e){pendingPreview=null;E('clean-preview-dialog').close();alert('未执行清理：'+e.message)}
 finally{E('preview-approve').disabled=false}
}
E('clean-preview-dialog').addEventListener('close',()=>{if(pendingPreview){pendingPreview=null;post('/api/cancel-preview').catch(()=>notify('预览关闭；授权将在 120 秒内自动过期'))}});

async function reveal(){if(!selectedRow||!selectedKind)return;try{await post('/api/reveal',{id:selectedRow,type:selectedKind})}catch(e){alert(e.message)}}
function showDetail(){let item;if(selectedKind==='cache')item=(latest?.items||[]).find(x=>x.id===selectedRow);if(selectedKind==='large')item=(latest?.large_files||[]).find(x=>x.id===selectedRow);if(!item){E('detail-content').innerHTML='<div class="detail-title">请选择一个项目</div><p class="soft">点击列表项目后，可以看到它的具体路径、优先级和风险说明。</p>';return}const isCache=selectedKind==='cache';E('detail-content').innerHTML=`<div class="detail-title">${esc(isCache?item.name:(item.path.split(/[\\/]/).pop()))}</div><div class="detail-tags">${prioTag(item.priority)} ${riskTag(item.risk)}</div><div class="detail-row"><div class="key">完整位置</div><div class="val mono">${esc(item.path)}</div></div><div class="detail-row"><div class="key">${isCache?'符合清理条件的文件':'文件大小'}</div><div class="val">${fmt(item.size)} ${isCache?'· '+item.count+' 个文件':''}</div></div><div class="detail-row"><div class="key">推荐理由</div><div class="val">${esc(item.reason)}</div></div>${isCache?`<div class="detail-row"><div class="key">扫描与安全限制</div><div class="val">${esc(item.note)}<br>保留最近 ${item.age_days} 天。<br>状态：${esc(item.state)}<br>${item.allowed?'允许勾选。': '禁止在此界面清理。'} </div></div>`:`<div class="detail-row"><div class="key">处理原则</div><div class="val">${esc(item.action)}<br>修改日期：${esc(item.mtime)}</div></div>`}<button class="button wide" id="btn-reveal" style="margin-top:14px" onclick="reveal()">在文件资源管理器中打开</button>`;
}
function sortedCache(){const query=E('search-cache').value.trim().toLowerCase(),filter=E('filter-cache').value;const list=(latest?.items||[]).filter(x=>(filter==='all'||x.risk===filter)&&(!query||(x.name+' '+x.path+' '+x.note+' '+x.state).toLowerCase().includes(query)));list.sort((a,b)=>{let cmp=0;if(sortBy==='risk')cmp=(sortRank[a.risk]||0)-(sortRank[b.risk]||0);else if(sortBy==='priority')cmp=Number((a.priority||'P4').substring(1))-Number((b.priority||'P4').substring(1));else if(sortBy==='size'||sortBy==='count')cmp=(a[sortBy]||0)-(b[sortBy]||0);else cmp=String(a[sortBy]||'').localeCompare(String(b[sortBy]||''),'zh-CN');if(cmp===0)cmp=b.size-a.size;return cmp*sortDir});return list}
function renderCache(){const list=sortedCache(),el=E('cache-rows');if(!list.length){el.innerHTML=`<tr><td class="empty" colspan="7">${latest?.busy?'正在扫描，请查看上方进度...':'没有符合条件的清理项目；尝试清除筛选或重新扫描。'}</td></tr>`;updateSelection();return}const largest=Math.max(...list.map(x=>x.size),1);el.innerHTML=list.map(x=>`<tr data-kind="cache" data-id="${esc(x.id)}" class="${selectedRow===x.id&&selectedKind==='cache'?'selected ':''}${!x.allowed?'dim':''}"><td><input type="checkbox" class="checkbox" data-check="${esc(x.id)}" ${selected.has(x.id)?'checked':''} ${!x.allowed?'disabled':''}></td><td>${prioTag(x.priority)}</td><td>${riskTag(x.risk)}</td><td><div class="cell-name" title="${esc(x.name)}">${esc(x.name)}</div><div class="cell-path" title="${esc(x.path)}">${esc(x.path)}</div></td><td class="tabular"><strong>${fmt(x.size)}</strong><div class="sizebar"><span style="width:${Math.max(0,x.size/largest*100).toFixed(2)}%"></span></div></td><td class="tabular">${x.count.toLocaleString()}</td><td><div class="hint">${esc(x.note)}</div><div class="hint muted">${esc(x.state)}</div></td></tr>`).join('');E('cache-summary').textContent=`显示 ${list.length} 项 / 共 ${(latest?.items||[]).length} 项 · ${latest?.scan_complete?'扫描完整':'未完全扫描 / 尚未开始'}`;updateSelection()}
function renderLarge(){const query=E('search-large').value.trim().toLowerCase();const list=(latest?.large_files||[]).filter(x=>!query||(x.path+' '+x.reason).toLowerCase().includes(query));E('large-rows').innerHTML=list.length?list.map(x=>`<tr data-kind="large" data-id="${esc(x.id)}" class="${selectedRow===x.id&&selectedKind==='large'?'selected':''}"><td>${prioTag(x.priority)}</td><td>${riskTag(x.risk)}</td><td class="tabular">${fmt(x.size)}</td><td class="tabular">${esc(x.mtime)}</td><td><div class="cell-name" title="${esc(x.path)}">${esc(x.path.split(/[\\/]/).pop())}</div><div class="cell-path" title="${esc(x.path)}">${esc(x.path)}</div></td></tr>`).join(''):'<tr><td colspan="5" class="empty">暂无大文件结果。点击“开始查找”或调整筛选。</td></tr>';const info=latest?.large_info||{}, warning=info.warning||'';E('large-source').textContent=`数据来源：${info.source||'未扫描'} ${info.scanned_entries?'· 记录/检查 '+Number(info.scanned_entries).toLocaleString()+' 条':''} ${info.complete?'· 已完成':'· 可能不完整'}。${warning}`;E('large-summary').textContent=`显示 ${list.length} 项 / ${(latest?.large_files||[]).length} 项；此表只读，不允许删除。`}
function renderAdvice(){E('advice-list').innerHTML=(latest?.advisories||[]).map(x=>`<div class="note-row">${riskTag(x.risk)}<div style="min-width:0"><div class="note-title">${esc(x.name)} &nbsp; ${prioTag(x.priority)}</div><div class="note-body">${esc(x.reason)}</div></div></div>`).join('')}
function renderLogs(){E('log-box').textContent=(latest?.logs||[]).map(x=>`[${x.time}] ${x.message}`).join('\n')||'暂无日志'}
function draw(){if(!latest)return;const d=latest.disk||{},rows=latest.items||[],g=rows.filter(x=>x.allowed&&x.risk==='green'),a=rows.filter(x=>x.allowed&&x.risk==='amber');E('m-free').textContent=d.total?fmt(d.free):'不可用';E('m-percent').textContent=d.total?`总容量 ${fmt(d.total)} · 已使用 ${Math.round(d.used/d.total*100)}%`:'无法取得 C 盘用量';E('m-green').textContent=fmt(g.reduce((v,x)=>v+x.size,0));E('m-green-foot').textContent=`${g.length} 项 · 默认推荐`;E('m-amber').textContent=fmt(a.reduce((v,x)=>v+x.size,0));E('m-amber-foot').textContent=`${a.length} 项 · 主动选择`;E('m-count').textContent=rows.reduce((n,x)=>n+x.count,0).toLocaleString();E('m-count-foot').textContent=`${rows.length} 个已识别目录目标`;const percent=d.total?Math.round(d.used/d.total*100):0;E('disk-usage-bar').style.width=percent+'%';E('disk-usage-track').setAttribute('aria-valuenow',String(percent));E('disk-usage-note').textContent=d.total?('已使用 '+percent+'%'):'待检测';
 const busy=latest.busy;E('task-dot').classList.toggle('busy',busy);E('task-msg').textContent=latest.message||'';const pct=Math.max(0,Math.min(100,Math.round((latest.progress||0)/Math.max(1,latest.progress_max||1)*100)));E('progressbar').style.width=pct+'%';E('progressnum').textContent=pct+'%';for(const b of ['btn-fast','btn-full','btn-large','btn-everything','btn-hero-fast'])E(b).disabled=busy;E('btn-stop').disabled=!busy;E('esSide').textContent='索引：'+(latest.es_status||'检测中'); if(latest.everything?.ready)E('btn-everything').textContent='重新启动/校验 Everything';
const ids=new Set(rows.map(x=>x.id));for(const k of [...selected])if(!ids.has(k)||!rows.find(x=>x.id===k&&x.allowed))selected.delete(k);
 renderCache();renderLarge();renderAdvice();renderLogs();renderToolbox();if(selectedRow)showDetail();updateSelection()}
async function poll(){if(pollRunning)return;pollRunning=true;try{latest=await getState();draw()}catch(e){notify('本地连接暂时失败：'+e.message)}finally{pollRunning=false}}
E('cache-rows').addEventListener('click',e=>{const row=e.target.closest('tr[data-id]');if(!row)return;const id=row.dataset.id;if(e.target.matches('input[data-check]')){if(e.target.checked)selected.add(id);else selected.delete(id);pendingPreview=null;updateSelection();return}selectedRow=id;selectedKind='cache';renderCache();showDetail()});
E('large-rows').addEventListener('click',e=>{const row=e.target.closest('tr[data-id]');if(!row)return;selectedRow=row.dataset.id;selectedKind='large';renderLarge();showDetail()});
E('check-all-green').addEventListener('change',e=>{for(const x of (latest?.items||[]).filter(x=>x.allowed&&x.risk==='green'))e.target.checked?selected.add(x.id):selected.delete(x.id);pendingPreview=null;renderCache()});
E('search-cache').addEventListener('input',renderCache);E('filter-cache').addEventListener('change',renderCache);E('search-large').addEventListener('input',renderLarge);
document.querySelectorAll('th[data-sort]').forEach(el=>el.addEventListener('click',()=>{const field=el.dataset.sort;if(field===sortBy)sortDir=-sortDir;else{sortBy=field;sortDir=field==='size'||field==='count'?-1:1}renderCache()}));
setInterval(poll,1100);poll();setTimeout(async()=>{try{await post('/api/scan',{mode:'fast'})}catch(e){notify('请手动点击快速扫描：'+e.message)}},550);
