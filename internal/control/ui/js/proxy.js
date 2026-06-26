import { $, $$, esc, escAttr, state, toast, api, methodColor, statusColor, statusText, mimeLabel, fmtSize, fmtBytes, fmtTime, fmtDur, FLAG_WS, FLAG_AI, FLAG_DISCOVERY, RENDER_CAP, highlightHTTP, prettify, copyText, uiPrompt, uiConfirm, closeModals, isBinaryMime, bodyMime, headerBlockText } from './core.js';
import { sendToRepeater, sendToIntruder } from './tools.js';
import { retentionStats, loadRetention } from './settings.js';
import { openAi } from './ai.js';
import { openAuthz } from './authz.js';
import { openDecoder } from './scanner.js';
import { prefillDiscovery } from './discovery.js';

const FLOW_LIMIT=500;
const EXCLUDE_NORM=64|128|512; // repeater, intruder, active scan

function flowExcluded(f){return (f.flags&EXCLUDE_NORM)!==0&&(f.flags&FLAG_AI)===0;}
function canIncremental(){
  if(state.inScopeOnly||state.discoveryOnly)return false;
  if(state.filters.search)return false;
  if(state.filters.exclude&&state.filters.exclude.length)return false;
  return true;
}
function flowMatchesFilters(f){
  const fl=state.filters;
  if(flowExcluded(f))return false;
  if(state.discoveryOnly&&(f.flags&FLAG_DISCOVERY)===0)return false;
  if(!state.showAI&&(f.flags&FLAG_AI))return false;
  if(fl.scheme&&f.scheme!==fl.scheme)return false;
  if(fl.method&&f.method!==fl.method)return false;
  if(fl.host&&!f.host.toLowerCase().includes(fl.host.toLowerCase()))return false;
  if(fl.status&&Math.floor((f.status||0)/100)!==Number(fl.status))return false;
  for(const e of fl.exclude||[]){
    const v=String(e.value);
    if(e.field==='method'&&f.method===v)return false;
    if(e.field==='host'&&f.host.toLowerCase().includes(v.toLowerCase()))return false;
    if(e.field==='path'&&f.path.toLowerCase().includes(v.toLowerCase()))return false;
    if(e.field==='status'&&String(f.status)===v)return false;
  }
  return true;
}
function flowRowHTML(f){
  const intercepted=(f.flags&1)!==0;
  const pending=!f.status&&!f.error;
  const stHTML=f.status?String(f.status):(f.error?'ERR':'<span class="blink" style="color:var(--fg3)" title="waiting for response">•••</span>');
  return `<div class="trow ${f.id===state.selId?'sel':''}${state.selected.has(f.id)?' msel':''}${pending?' pending':''}" data-id="${f.id}" title="Click inspect · Shift+click range · Ctrl+Shift+click toggle">
      <div class="tr-id" data-field="id">${f.id}</div>
      <div class="tr-m" data-field="method" style="color:${methodColor(f.method)}">${esc(f.method)}</div>
      <div class="tr-host" data-field="host">${esc(f.scheme==='https'?'🔒 ':'')}${esc(f.host)}</div>
      <div class="tr-path" data-field="path">${esc(f.path)}${intercepted?' <span style="color:var(--accent)" title="intercepted">●</span>':''}${(f.flags&FLAG_AI)?'<span class="ai-tag" title="sent by the AI assistant">AI</span>':''}${(f.flags&FLAG_DISCOVERY)?'<span class="ai-tag" style="background:var(--violetDim);color:var(--violet)" title="found by content discovery">DSC</span>':''}${f.note?' <span title="has a note" style="cursor:help">📝</span>':''}</div>
      <div class="tr-st" data-field="status" style="color:${statusColor(f.status)}">${stHTML}</div>
      <div class="tr-mime" data-field="mime">${esc(mimeLabel(f.mime))}</div>
      <div class="tr-len" data-field="size">${f.status?fmtSize(f.resLen):''}</div>
      <div class="tr-t" data-field="time">${fmtTime(f.ts)}</div>
    </div>`;
}
function wireFlowRow(r){
  const id=Number(r.dataset.id);
  r.onclick=e=>flowRowClick(id,e);
  r.oncontextmenu=e=>{
    e.preventDefault();
    const f=state.flows.find(x=>x.id===id);
    const cell=e.target.closest('[data-field]');
    showCtx(e.clientX,e.clientY,f,cell?cell.dataset.field:'');
  };
}
function updateTruncBanner(){
  const b=$('#flowCapBanner');
  if(!b)return;
  b.style.display=state.flowTruncated?'block':'none';
}
function removeFlowRow(id){
  const row=document.querySelector('#rows .trow[data-id="'+id+'"]');
  if(row)row.remove();
}
export function patchFlowRow(f){
  const row=document.querySelector('#rows .trow[data-id="'+f.id+'"]');
  if(row){
    const tmp=document.createElement('div');
    tmp.innerHTML=flowRowHTML(f);
    const nr=tmp.firstElementChild;
    wireFlowRow(nr);
    row.replaceWith(nr);
    return;
  }
  if(!flowMatchesFilters(f))return;
  const box=$('#rows');
  if(!box||box.querySelector('.empty')||box.querySelector('#gsMcp')){renderRows();return;}
  const tmp=document.createElement('div');
  tmp.innerHTML=flowRowHTML(f);
  const nr=tmp.firstElementChild;
  wireFlowRow(nr);
  const sorted=applySort(state.flows);
  const idx=sorted.findIndex(x=>x.id===f.id);
  const next=sorted[idx+1];
  if(next){
    const anchor=document.querySelector('#rows .trow[data-id="'+next.id+'"]');
    if(anchor)anchor.before(nr);else box.prepend(nr);
  }else box.prepend(nr);
}
export function upsertFlow(f){
  const i=state.flows.findIndex(x=>x.id===f.id);
  if(i>=0)state.flows[i]=f;
  else{
    state.flows.unshift(f);
    if(state.flows.length>FLOW_LIMIT){
      const dropped=state.flows.pop();
      if(dropped)removeFlowRow(dropped.id);
      state.flowTruncated=true;
    }
  }
  $('#rowCount').textContent=state.flows.length;
  updateTruncBanner();
}
export function handleFlowNew(f){
  if(!f)return;
  const proxy=document.querySelector('.panel[data-panel="proxy"]');
  if(!proxy||!proxy.classList.contains('active')||!canIncremental()||!flowMatchesFilters(f)){scheduleReload();return;}
  upsertFlow(f);
  patchFlowRow(f);
  refreshMethodFilter();
}
export function handleFlowUpdate(f){
  if(!f)return;
  const i=state.flows.findIndex(x=>x.id===f.id);
  if(i<0){
    if(canIncremental()&&flowMatchesFilters(f)){upsertFlow(f);patchFlowRow(f);refreshMethodFilter();}
    else scheduleReload();
    return;
  }
  state.flows[i]=f;
  patchFlowRow(f);
}

export function applySort(flows){
  const k=state.sort.key,dir=state.sort.dir;
  const val=f=>k==='size'?(f.resLen||0):k==='time'?f.ts:k==='status'?(f.status||0):k==='method'?f.method:k==='host'?f.host:k==='path'?f.path:k==='mime'?mimeLabel(f.mime):f.id;
  return flows.slice().sort((a,b)=>{const x=val(a),y=val(b);return (x>y?1:x<y?-1:0)*dir;});
}
export function getStartedCard(){
  return `<div style="max-width:640px;margin:26px auto;padding:0 16px">
    <div style="font-size:14px;font-weight:700;color:var(--fg);margin-bottom:4px">No traffic yet — let's capture some</div>
    <div class="hint" style="margin-bottom:14px">Interceptor sits between your client and the internet; point traffic at it and it shows up here live.</div>
    <ol style="color:var(--fg2);line-height:2;font-size:12.5px;padding-left:20px;margin:0">
      <li>Point your browser/client at the proxy <b style="color:var(--accent);font-family:var(--mono)">${esc(state.proxyAddr)}</b></li>
      <li>To intercept <b>HTTPS</b>, <a href="/api/ca.crt" download style="color:var(--accent)">download the CA</a> and trust it (details in Settings)</li>
      <li>Browse — flows stream in here. <b style="color:var(--fg)">Right-click</b> a row to filter, copy as cURL, send to Repeater/Intruder, or ✨ ask AI</li>
      <li>Using an AI assistant? <button id="gsMcp" class="btn accent" style="padding:2px 9px;vertical-align:middle">Connect it via MCP</button></li>
    </ol>
    <div class="hint" style="margin-top:14px">Tip: press <b style="color:var(--fg)">Ctrl/⌘ K</b> for the command palette — jump to any tab, search flows, or run an action.</div></div>`;
}
export function renderRows(){
  const box=$('#rows');
  const flows=applySort(state.flows);
  $('#rowCount').textContent=state.flows.length;
  if(!flows.length){
    if(anyFilter()||state.inScopeOnly){
      // Traffic exists but nothing matches the active filters — don't show the
      // "no traffic yet" onboarding (it reads as if capture is broken).
      box.innerHTML='<div class="empty">No flows match the current filters.<br><button class="btn" id="emptyClear" style="margin-top:12px">Clear filters</button></div>';
      const c=document.getElementById('emptyClear');if(c)c.onclick=()=>{
        if(state.inScopeOnly){state.inScopeOnly=false;const st=$('#scopeToggle');if(st){st.classList.remove('accent');st.textContent='◎ in scope';}}
        clearAllFilters();
      };
    }else{
      box.innerHTML=getStartedCard();
      const b=document.getElementById('gsMcp');if(b)b.onclick=()=>{document.querySelector('.tab[data-tab="api"]').click();document.querySelector('#apiSub button[data-s="mcp"]').click();};
    }
    return;}
  box.innerHTML=flows.map(f=>flowRowHTML(f)).join('');
  $$('#rows .trow').forEach(wireFlowRow);
}
export function flowRowClick(id,e){
  const list=applySort(state.flows),idx=list.findIndex(f=>f.id===id);
  if(idx<0)return;
  const mod=e.ctrlKey||e.metaKey;
  if(e.shiftKey&&mod){
    state.selected.has(id)?state.selected.delete(id):state.selected.add(id);
    state.lastSelIdx=idx;selectFlow(id);updateSelBar();return;
  }
  if(e.shiftKey){
    const anchor=state.lastSelIdx>=0?state.lastSelIdx:idx;
    const a=Math.min(anchor,idx),b=Math.max(anchor,idx);
    state.selected.clear();
    for(let i=a;i<=b;i++)state.selected.add(list[i].id);
    state.lastSelIdx=idx;selectFlow(id);updateSelBar();return;
  }
  state.selected.clear();state.lastSelIdx=idx;selectFlow(id);updateSelBar();
}
export function walkFlowNav(down,e){
  const list=applySort(state.flows);
  if(!list.length)return null;
  const i=list.findIndex(f=>f.id===state.selId);
  const ni=i<0?0:(down?Math.min(i+1,list.length-1):Math.max(i-1,0));
  if(ni===i)return null;
  const id=list[ni].id,mod=e.ctrlKey||e.metaKey;
  if(e.shiftKey&&mod){
    state.selected.has(id)?state.selected.delete(id):state.selected.add(id);
    state.lastSelIdx=ni;selectFlow(id);updateSelBar();return id;
  }
  if(e.shiftKey){
    const anchor=state.lastSelIdx>=0?state.lastSelIdx:(i>=0?i:ni);
    const a=Math.min(anchor,ni),b=Math.max(anchor,ni);
    state.selected.clear();
    for(let j=a;j<=b;j++)state.selected.add(list[j].id);
    state.lastSelIdx=ni;selectFlow(id);updateSelBar();return id;
  }
  state.selected.clear();state.lastSelIdx=ni;selectFlow(id);updateSelBar();return id;
}
export function toggleSelectAllShown(){
  const list=applySort(state.flows);
  const all=list.length>0&&list.every(f=>state.selected.has(f.id));
  if(all)state.selected.clear();else list.forEach(f=>state.selected.add(f.id));
  updateSelBar();renderRows();
}
export async function loadFlows(){
  const q=new URLSearchParams();
  const f=state.filters;
  if(f.scheme)q.set('scheme',f.scheme);
  if(f.search)q.set('search',f.search);
  if(f.method)q.set('method',f.method);
  if(f.status)q.set('status',f.status);
  if(f.host)q.set('host',f.host);
  (f.exclude||[]).forEach(e=>{const k={method:'notMethod',host:'notHost',path:'notPath',status:'notStatus'}[e.field];if(k)q.append(k,e.value);});
  if(state.inScopeOnly)q.set('inScope','1');
  if(state.discoveryOnly)q.set('discovery','1');
  if(!state.showAI)q.set('ai','0');
  q.set('limit',String(FLOW_LIMIT));
  try{
    const d=await api('/api/flows?'+q.toString());
    state.flows=d.flows||[];
    state.flowTruncated=!!d.truncated;
    renderRows();
    updateTruncBanner();
    refreshMethodFilter();
  }catch(e){toast('flows: '+e.message);}
}
function refreshMethodFilter(){
  if(state.filters.method)return; // don't shrink the list while filtering by method
  const order=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','CONNECT','TRACE'];
  const present=[...new Set(state.flows.map(f=>f.method).filter(Boolean))]
    .sort((a,b)=>{const ia=order.indexOf(a),ib=order.indexOf(b);return (ia<0?99:ia)-(ib<0?99:ib)||a.localeCompare(b);});
  const sel=$('#fMethod');if(!sel)return;const cur=sel.value;
  sel.innerHTML='<option value="">method</option>'+present.map(m=>`<option ${m===cur?'selected':''}>${esc(m)}</option>`).join('');
}
let reloadTimer=null;
export function scheduleReload(){clearTimeout(reloadTimer);reloadTimer=setTimeout(loadFlows,150);}
export async function selectFlow(id){
  state.selId=id;renderRows();
  try{
    state.detail=await api('/api/flows/'+id);
    const d=state.detail;
    $('#noteInput').value=d.note||'';$('#noteBar').style.display='flex';
    await renderSide('req');
    if(d.flags&FLAG_WS){
      $('#resStatus').textContent='WebSocket frames';$('#resStatus').style.color='var(--accent)';
      await renderWSFrames(id);
    }else if(!d.status&&!d.error){
      // In-flight request: response not back yet. The flow.update handler
      // re-selects this flow once it lands, filling the pane in automatically.
      $('#resView').innerHTML='<span class="blink" style="color:var(--fg3)">waiting for response…</span>';
      $('#resStatus').textContent='pending';$('#resStatus').style.color='var(--fg3)';
    }else{
      await renderSide('res');
      $('#resStatus').textContent=(d.status?`${d.status} ${statusText(d.status)}`:(d.error||''))+(d.durationMs?` · ${fmtDur(d.durationMs)}`:'');
      $('#resStatus').style.color=statusColor(d.status);
    }
  }catch(e){toast('flow: '+e.message);}
}
function wsOpcode(o){return {0:'cont',1:'text',2:'bin',8:'close',9:'ping',10:'pong'}[o]||('0x'+o.toString(16));}
function wsFrameRow(dir,opcode,length,text){
  const arrow=dir==='send'?'<span style="color:var(--blue)">▲ send</span>':'<span style="color:var(--accent)">▼ recv</span>';
  return `<div style="display:flex;gap:10px;padding:3px 0;border-bottom:1px solid var(--line)">
    <span style="width:60px;flex:none">${arrow}</span>
    <span style="width:46px;flex:none;color:var(--fg3)">${wsOpcode(opcode)}</span>
    <span style="width:58px;flex:none;color:var(--fg2);text-align:right">${length} B</span>
    <span style="color:var(--fg);overflow-wrap:anywhere">${esc(text)}</span></div>`;
}
function flowWsURL(d){const s=d.scheme==='https'?'wss':'ws';const def=(d.scheme==='https'&&d.port===443)||(d.scheme==='http'&&d.port===80);return `${s}://${d.host}${def?'':':'+d.port}${d.path||'/'}`;}
export async function renderWSFrames(id){
  try{
    const d=await api('/api/flows/'+id+'/ws');const frames=d.frames||[];
    const url=flowWsURL(state.detail||{});
    const box=`<div style="display:flex;gap:6px;margin-bottom:10px">
        <input id="wsMsg" placeholder="Replay a frame to ${escAttr(url)}" style="flex:1;font-family:var(--mono)">
        <button class="btn accent" id="wsSendBtn">▲ Send</button></div>
      <div id="wsReplayOut" style="margin-bottom:10px"></div>`;
    const list=frames.length?frames.map(f=>wsFrameRow(f.dir,f.opcode,f.length,f.preview)).join('')
      :'<span style="color:var(--fg3)">No frames captured yet — frames stream in live as the socket exchanges messages.</span>';
    $('#resView').innerHTML=box+list;
    const sb=document.getElementById('wsSendBtn');if(sb)sb.onclick=()=>wsReplay(url);
    const inp=document.getElementById('wsMsg');if(inp)inp.onkeydown=e=>{if(e.key==='Enter')wsReplay(url);};
  }catch(e){$('#resView').textContent='(error: '+e.message+')';}
}
async function wsReplay(url){
  const msg=($('#wsMsg')||{}).value||'';
  const out=$('#wsReplayOut');if(out)out.innerHTML='<span style="color:var(--fg3)">opening socket…</span>';
  try{
    const r=await api('/api/ws/send',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url,message:msg})});
    const head=`<div style="font-size:9px;font-weight:700;letter-spacing:.6px;color:var(--fg3);margin:4px 0 4px">REPLAY · HTTP ${r.status} · ${(r.frames||[]).length} frame(s)</div>`;
    if(out)out.innerHTML=head+(r.frames||[]).map(f=>wsFrameRow(f.dir,f.opcode,f.len,f.text)).join('');
  }catch(e){if(out)out.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';}
}
export async function renderSide(side){
  const el=side==='req'?$('#reqView'):$('#resView');
  if(!state.selId){return;}
  const draw=async()=>{
    try{const raw=await api('/api/flows/'+state.selId+'/raw?side='+side);
      el.innerHTML=highlightHTTP(state.view[side]==='pretty'?prettify(raw):raw,state.view[side]==='pretty');
    }catch(e){el.textContent='(error: '+e.message+')';}
  };
  const len=state.detail?(side==='req'?state.detail.reqLen:state.detail.resLen):0;
  // Binary body (image/font/media/archive/…): show only the headers — the bytes
  // aren't readable as text. Built from the detail DTO, so the body isn't fetched.
  const mime=bodyMime(state.detail,side);
  if(isBinaryMime(mime)){
    el.innerHTML=highlightHTTP(headerBlockText(state.detail,side))+
      `<div class="hint" style="padding:14px 0 0;line-height:1.7">Body is <b>${esc(mime)}</b>${len?' · '+fmtSize(len):''} — binary, not rendered.<br>
        <a class="btn" style="margin-top:8px;display:inline-block" href="/api/flows/${state.selId}/raw?side=${side}" download="flow-${state.selId}-${side}">⤓ Download body</a>
        <button class="btn" data-bin="1" style="margin-top:8px;margin-left:6px">Show raw anyway</button></div>`;
    const b=el.querySelector('[data-bin]');
    if(b)b.onclick=()=>{el.innerHTML='<span class="hint" style="padding:16px">rendering…</span>';setTimeout(draw,10);};
    return;
  }
  if(len>RENDER_CAP){
    el.innerHTML=`<div class="hint" style="padding:18px;line-height:1.8">${side==='req'?'Request':'Response'} body is <b>${fmtSize(len)}</b> — not shown, to keep the browser responsive.<br>
      <a class="btn" style="margin-top:8px;display:inline-block" href="/api/flows/${state.selId}/raw?side=${side}" download="flow-${state.selId}-${side}.txt">⤓ Download raw</a>
      <button class="btn" data-bigshow="1" style="margin-top:8px">Show anyway</button></div>`;
    const b=el.querySelector('[data-bigshow]');
    if(b)b.onclick=()=>{el.innerHTML='<span class="hint" style="padding:16px">rendering…</span>';setTimeout(draw,10);};
    return;
  }
  await draw();
}
// Only the inspector's request/response view segs (data-side) — NOT every .seg on the
// page. Other tabs (Intruder, Repeater, AI, Map) own their own seg handlers; a bare
// $$('.seg') here would clobber them since this module loads after them.
$$('.seg[data-side]').forEach(seg=>{const side=seg.dataset.side;seg.querySelectorAll('button').forEach(b=>b.onclick=()=>{
  state.view[side]=b.dataset.view;seg.querySelectorAll('button').forEach(x=>{x.classList.toggle('on',x===b);x.setAttribute('aria-pressed',x===b?'true':'false');});renderSide(side);});});

$$('.thead [data-sort]').forEach(h=>h.onclick=()=>{
  const k=h.dataset.sort;if(state.sort.key===k)state.sort.dir*=-1;else{state.sort.key=k;state.sort.dir=k==='id'||k==='time'?-1:1;}renderRows();});

$('#fScheme').onchange=e=>setFilter('scheme',e.target.value);
$('#fMethod').onchange=e=>setFilter('method',e.target.value);
$('#fStatus').onchange=e=>setFilter('status',e.target.value);
$('#fSearch').oninput=e=>{state.filters.search=e.target.value;renderChips();scheduleReload();};
$('#refreshBtn').onclick=loadFlows;
// Inspector header actions — operate on the currently-selected flow.
function inspectorFlow(){return state.detail||state.flows.find(x=>x.id===state.selId)||null;}
{const b=$('#insRepeater');if(b)b.onclick=()=>{const f=inspectorFlow();if(f)sendToRepeater(f);else toast('select a flow first');};}
{const b=$('#insIntruder');if(b)b.onclick=()=>{const f=inspectorFlow();if(f)sendToIntruder(f);else toast('select a flow first');};}
{const b=$('#insCurl');if(b)b.onclick=()=>{const f=inspectorFlow();if(f)copyCurl(f);else toast('select a flow first');};}
$('#exportHar').onclick=()=>{$('#exportHar').href='/api/export/har'+(state.inScopeOnly?'?inScope=1':'');toast('History exported — .har downloaded');};
$('#importHarBtn').onclick=()=>$('#importHarFile').click();
$('#importHarFile').onchange=async e=>{
  const f=e.target.files[0];if(!f)return;
  try{const text=await f.text();const r=await api('/api/import/har',{method:'POST',headers:{'content-type':'application/json'},body:text});
    toast('imported '+r.imported+' flows');loadFlows();}catch(err){toast('import: '+err.message);}
  e.target.value='';
};
$('#scopeToggle').onclick=()=>{state.inScopeOnly=!state.inScopeOnly;$('#scopeToggle').classList.toggle('accent',state.inScopeOnly);$('#scopeToggle').textContent=(state.inScopeOnly?'◉':'◎')+' in scope';loadFlows();};
$('#discFilter').onclick=()=>{state.discoveryOnly=!state.discoveryOnly;$('#discFilter').classList.toggle('accent',state.discoveryOnly);loadFlows();};
$('#aiToggle').onclick=()=>{state.showAI=!state.showAI;$('#aiToggle').classList.toggle('accent',state.showAI);loadFlows();};
export async function saveNote(){
  if(!state.selId)return;
  const note=$('#noteInput').value;
  if(state.detail&&note===(state.detail.note||''))return; // unchanged — skip redundant PUT
  try{
    await api('/api/flows/'+state.selId+'/note',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({note})});
    if(state.detail)state.detail.note=note;
    const s=$('#noteSaved');s.style.opacity='1';setTimeout(()=>{s.style.opacity='0';},1200);
  }catch(e){toast('note: '+e.message);}
}
$('#noteInput').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();$('#noteInput').blur();}});
$('#noteInput').addEventListener('blur',saveNote);
/* ---- saved views ---- */
export async function loadViews(){try{const d=await api('/api/views');state.views=d.views||[];renderViews();}catch(e){}}
export function renderViews(){
  const sel=$('#viewsSelect'),cur=sel.value;
  sel.innerHTML='<option value="">views…</option>'+state.views.map(v=>`<option value="${v.id}">${esc(v.name)}</option>`).join('');
  if(state.views.find(v=>String(v.id)===cur))sel.value=cur;
  $('#delViewBtn').style.display=(state.views.length&&sel.value)?'inline-block':'none';
}
$('#viewsSelect').onchange=()=>{
  const id=$('#viewsSelect').value;$('#delViewBtn').style.display=id?'inline-block':'none';
  if(!id)return;const v=state.views.find(x=>String(x.id)===id);if(!v)return;
  let f={};try{f=JSON.parse(v.data||'{}');}catch(e){}
  state.filters={scheme:f.scheme||'',method:f.method||'',status:f.status||'',search:f.search||'',host:f.host||'',exclude:Array.isArray(f.exclude)?f.exclude:[]};
  state.inScopeOnly=!!f.inScope;
  syncControls();$('#scopeToggle').classList.toggle('accent',state.inScopeOnly);$('#scopeToggle').textContent=(state.inScopeOnly?'◉':'◎')+' in scope';
  renderChips();loadFlows();
};
$('#saveViewBtn').onclick=async()=>{
  const name=await uiPrompt({title:'Save current filters as a view',placeholder:'view name'});if(!name)return;
  const data={...state.filters,inScope:state.inScopeOnly};
  try{await api('/api/views',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name,data})});toast('view saved');loadViews();}catch(e){toast(e.message);}
};
$('#delViewBtn').onclick=async()=>{const id=$('#viewsSelect').value;if(!id)return;
  try{await api('/api/views/'+id,{method:'DELETE'});$('#viewsSelect').value='';$('#delViewBtn').style.display='none';loadViews();toast('view deleted');}catch(e){toast(e.message);}};
/* ---- target scope ---- */
export async function loadScope(){try{const d=await api('/api/scope');state.scope=d.rules||[];renderScope();}catch(e){}}
export async function addHostToScope(host){
  try{await api('/api/scope',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'include',host:host,enabled:true})});
    toast('added '+host+' to scope — toggle ◎ in scope to focus');loadScope();}
  catch(e){toast(e.message);}
}
export function renderScope(){
  const body=$('#scopeBody');if(!body)return;
  if(!state.scope.length){body.innerHTML='<tr><td colspan="6" class="hint" style="padding:10px 8px">No scope rules — everything is in scope.</td></tr>';return;}
  body.innerHTML=state.scope.map(r=>`<tr data-id="${r.id}">
    <td><input type="checkbox" ${r.enabled?'checked':''} data-k="enabled"></td>
    <td><select data-k="action"><option value="include" ${r.action==='include'?'selected':''}>include</option><option value="exclude" ${r.action==='exclude'?'selected':''}>exclude</option></select></td>
    <td><input type="text" data-k="host" value="${escAttr(r.host)}" placeholder="*.acme.com"></td>
    <td><input type="text" data-k="path" value="${escAttr(r.path)}" placeholder="/"></td>
    <td><input type="text" data-k="scheme" value="${escAttr(r.scheme)}" placeholder="any"></td>
    <td><button class="btn danger" data-del="${r.id}">Delete</button></td></tr>`).join('');
  body.querySelectorAll('tr').forEach(tr=>{const id=Number(tr.dataset.id);
    tr.querySelectorAll('[data-k]').forEach(inp=>inp.addEventListener('change',()=>updateScope(id,tr)));});
  body.querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>deleteScope(Number(b.dataset.del)));
}
async function updateScope(id,tr){
  const get=k=>tr.querySelector(`[data-k="${k}"]`);
  const upd={id,action:get('action').value,host:get('host').value.trim(),path:get('path').value.trim(),scheme:get('scheme').value.trim(),enabled:get('enabled').checked,port:0};
  try{await api('/api/scope/'+id,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(upd)});toast('scope saved');}catch(e){toast(e.message);loadScope();}
}
async function deleteScope(id){try{await api('/api/scope/'+id,{method:'DELETE'});loadScope();}catch(e){toast(e.message);}}
$('#addScopeBtn').onclick=async()=>{
  const rule={action:$('#newScopeAction').value,host:$('#newScopeHost').value.trim(),path:$('#newScopePath').value.trim(),scheme:'',enabled:true,port:0};
  if(!rule.host&&!rule.path){toast('host or path required');return;}
  try{await api('/api/scope',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(rule)});
    $('#newScopeHost').value='';$('#newScopePath').value='';loadScope();toast('scope rule added');}catch(e){toast(e.message);}
};
/* ---- filters: chips + apply/clear, kept in sync with the toolbar controls ---- */
export function syncControls(){
  $('#fScheme').value=state.filters.scheme;
  $('#fMethod').value=state.filters.method;
  $('#fStatus').value=state.filters.status;
  $('#fSearch').value=state.filters.search;
}
export function setFilter(key,val){state.filters[key]=val;syncControls();renderChips();loadFlows();}
export function clearFilter(key){setFilter(key,'');}
export function clearAllFilters(){state.filters={scheme:'',search:'',method:'',status:'',host:'',exclude:[]};syncControls();renderChips();loadFlows();}
export function anyFilter(){const f=state.filters;return !!(f.scheme||f.method||f.status||f.host||f.search||(f.exclude&&f.exclude.length));}
// Negative filters: exclude rows matching {field,value}. Toggles off if already present.
export function addExclude(field,value){
  if(value==null||value==='')return;
  const ex=state.filters.exclude||(state.filters.exclude=[]);
  const i=ex.findIndex(e=>e.field===field&&String(e.value)===String(value));
  if(i>=0)ex.splice(i,1); else ex.push({field,value:String(value)});
  renderChips();loadFlows();
}
export function removeExclude(i){state.filters.exclude.splice(i,1);renderChips();loadFlows();}
export function renderChips(){
  const f=state.filters,box=$('#chips'),items=[];
  const add=(k,label,val)=>{if(val)items.push(`<span class="chip"><span>${label} <b>${esc(val)}</b></span><span class="x" data-clear="${k}" title="remove">✕</span></span>`);};
  add('scheme','scheme',f.scheme);
  add('method','method',f.method);
  add('status','status',f.status?f.status+'xx':'');
  add('host','host',f.host);
  add('search','path',f.search);
  (f.exclude||[]).forEach((e,i)=>{items.push(`<span class="chip not"><span>${esc(e.field)} ≠ <b>${esc(e.value)}</b></span><span class="x" data-ex="${i}" title="remove">✕</span></span>`);});
  const hasFilters=items.length>0;
  if(hasFilters)items.push(`<button class="chip-clear" id="chipsClear" title="Remove all filters">Clear all ✕</button>`);
  box.innerHTML=items.join('');
  box.classList.toggle('has',hasFilters);
  box.querySelectorAll('[data-clear]').forEach(x=>x.onclick=()=>clearFilter(x.dataset.clear));
  box.querySelectorAll('[data-ex]').forEach(x=>x.onclick=()=>removeExclude(Number(x.dataset.ex)));
  const cc=$('#chipsClear');if(cc)cc.onclick=clearAllFilters;
  // The "save current filters as a view" (＋) only makes sense when something is filtered.
  const sv=$('#saveViewBtn');if(sv)sv.style.display=hasFilters?'':'none';
}
/* ---- right-click context menu ---- */
export const ctx=$('#ctxmenu');
function hideCtx(){
  if(ctx._keyHandler){document.removeEventListener('keydown',ctx._keyHandler);ctx._keyHandler=null;}
  ctx.classList.remove('show');ctx._acts=null;
}
// openMenu renders a sectioned context menu. Each section is {head?, items:[…]};
// each item is {label, val?, act, on?, danger?} or {sep:true}. It positions the
// menu and flips it on-screen if it would overflow the viewport.
function openMenu(x,y,sections){
  const acts=[];let html='';
  sections.forEach(sec=>{
    const items=(sec.items||[]).filter(Boolean);
    if(!items.length)return;
    if(sec.head)html+=`<div class="ctx-head">${esc(sec.head)}</div>`;
    items.forEach(it=>{
      if(it.sep){html+='<div class="ctx-sep"></div>';return;}
      const dStyle=it.danger?' style="color:var(--red)"':'';
      const right=it.val!=null?`<span class="mono"${dStyle}>${esc(it.val)}</span>`:'';
      html+=`<div class="ctx-item${it.on?' on':''}" data-i="${acts.length}"${it.danger&&it.val==null?dStyle:''}><span class="lbl"${dStyle}>${esc(it.label)}</span>${right}</div>`;
      acts.push(it.act);
    });
  });
  ctx.innerHTML=html;ctx._acts=acts;ctx._sel=0;
  const items=ctx.querySelectorAll('.ctx-item');
  items.forEach((el,i)=>el.classList.toggle('on',i===0));
  ctx.querySelectorAll('[data-i]').forEach(el=>el.onclick=()=>{const fn=ctx._acts[Number(el.dataset.i)];hideCtx();if(fn)fn();});
  ctx.style.left=x+'px';ctx.style.top=y+'px';ctx.classList.add('show');
  const r=ctx.getBoundingClientRect();
  if(r.right>innerWidth)ctx.style.left=Math.max(4,x-r.width)+'px';
  if(r.bottom>innerHeight)ctx.style.top=Math.max(4,y-r.height)+'px';
  const paintSel=()=>{items.forEach((el,i)=>el.classList.toggle('on',i===ctx._sel));const cur=items[ctx._sel];if(cur)cur.scrollIntoView({block:'nearest'});};
  ctx._keyHandler=e=>{
    if(!ctx.classList.contains('show'))return;
    if(e.key==='ArrowDown'){e.preventDefault();ctx._sel=Math.min(items.length-1,ctx._sel+1);paintSel();}
    else if(e.key==='ArrowUp'){e.preventDefault();ctx._sel=Math.max(0,ctx._sel-1);paintSel();}
    else if(e.key==='Enter'){e.preventDefault();const fn=ctx._acts[ctx._sel];hideCtx();if(fn)fn();}
    else if(e.key==='Escape'){e.preventDefault();hideCtx();}
  };
  document.addEventListener('keydown',ctx._keyHandler);
}

// isIPHost reports whether h is an IP literal / localhost (so "domain" actions,
// which only make sense for DNS names, are suppressed).
function isIPHost(h){return !h||/^\d{1,3}(\.\d{1,3}){3}$/.test(h)||h.includes(':')||h==='localhost';}
// Second-level public suffixes so "domain" picks app.acme.co.uk → *.acme.co.uk,
// not the useless *.co.uk. Heuristic, not a full PSL — good enough for filtering.
const TWO_LEVEL_TLD=new Set(['co','com','org','net','gov','edu','ac','mil','or','ne','go']);
function registrableDomain(host){
  if(isIPHost(host))return '';
  const p=host.split('.').filter(Boolean);
  if(p.length<=2)return host;
  if(p.length>=3&&TWO_LEVEL_TLD.has(p[p.length-2])&&p[p.length-1].length<=3)return p.slice(-3).join('.');
  return p.slice(-2).join('.');
}
function looksLikeHost(s){return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)&&!s.includes(' ');}
function deleteHost(f){
  return async()=>{
    const hstats=retentionStats&&retentionStats.hosts&&retentionStats.hosts.find(x=>x.host===f.host);
    const flowCount=hstats?hstats.flows:'all';
    const confirmed=await uiConfirm('Delete flows from '+esc(f.host),
      'Permanently delete '+flowCount+' flow'+(flowCount===1?'':'s')+' from <b style="color:var(--accent)">'+esc(f.host)+'</b>?<br>This cannot be undone.',
      'Delete','btn danger','var(--red)');
    if(!confirmed)return;
    try{
      const r=await api('/api/flows/purge',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({hosts:[f.host],mode:'delete'})});
      toast('deleted '+r.deleted+' flow'+(r.deleted===1?'':'s')+' · freed '+fmtBytes(r.freedBytes));
      loadRetention();loadFlows();
    }catch(e){toast('purge: '+e.message);}
  };
}

// flowGlobalSection — the flow-wide actions present in every history/inspector
// menu regardless of which column was clicked (send, copy, AI, authz).
function flowGlobalSection(f,head){
  return {head:head||'REQUEST', items:[
    {label:'Send to Repeater',act:()=>sendToRepeater(f)},
    {label:'Send to Intruder',act:()=>sendToIntruder(f)},
    {label:'Copy URL',act:()=>copyURL(f)},
    {label:'Copy as cURL',act:()=>copyCurl(f)},
    {sep:true},
    {label:'✨ Ask AI',val:'explain',act:()=>openAi('explain',[f.id])},
    {label:'✨ Ask AI',val:'payloads',act:()=>openAi('suggest',[f.id])},
    {label:'🔓 Authz test',val:'roles',act:()=>openAuthz(f.id)},
    {label:'🔑 Use as login macro',act:()=>saveLoginMacroFromFlow(f.id)},
  ]};
}

async function saveLoginMacroFromFlow(id){
  try{
    await api('/api/session/login/from-flow/'+id,{method:'POST'});
    toast('login macro saved — Settings → Session');
    document.querySelector('.tab[data-tab="settings"]').click();
    const b=document.querySelector('#setNav button[data-sec="session"]');if(b)b.click();
  }catch(e){toast(e.message);}
}

// showCtx builds the history-row menu: a contextual top section keyed to the
// clicked column (host / status / method / path) + the always-present global
// flow actions. Right-clicking a host shows host/domain/scope/discover actions;
// right-clicking a status shows status filters — not the other way around.
export function showCtx(x,y,f,field){
  if(!f)return;
  const cls=f.status?Math.floor(f.status/100):0;
  const dom=registrableDomain(f.host);
  const def=(f.scheme==='https'&&f.port===443)||(f.scheme==='http'&&f.port===80);
  const baseURL=`${f.scheme}://${f.host}${def?'':':'+f.port}/`;
  const sections=[];

  if(field==='host'||field==='scheme'||field==='id'){
    const items=[
      {label:'Filter this host',val:f.host,on:field==='host',act:()=>setFilter('host',f.host)},
      {label:'Exclude this host',val:f.host,danger:true,act:()=>addExclude('host',f.host)},
    ];
    if(dom&&dom!==f.host){
      items.push({label:'Filter domain',val:dom+' (+subs)',act:()=>setFilter('host',dom)});
      items.push({label:'Add domain to scope',val:'*.'+dom,act:()=>addHostToScope('*.'+dom)});
    }
    items.push({label:'Add host to scope',val:f.host,act:()=>addHostToScope(f.host)});
    items.push({label:'🔎 Discover content',val:f.host,act:()=>prefillDiscovery(baseURL)});
    items.push({sep:true});
    items.push({label:'🗑 Delete all from host',val:f.host,danger:true,act:deleteHost(f)});
    sections.push({head:'HOST · '+f.host, items});
  }else if(field==='status'){
    const items=[];
    if(cls){
      items.push({label:'Filter status',val:cls+'xx',on:true,act:()=>setFilter('status',String(cls))});
      items.push({label:'Exclude this status',val:String(f.status),danger:true,act:()=>addExclude('status',String(f.status))});
    }else items.push({label:'No response yet',val:'pending'});
    sections.push({head:'STATUS'+(f.status?' · '+f.status:''), items});
  }else if(field==='method'){
    sections.push({head:'METHOD · '+f.method, items:[
      {label:'Filter method',val:f.method,on:true,act:()=>setFilter('method',f.method)},
      {label:'Exclude method',val:f.method,danger:true,act:()=>addExclude('method',f.method)},
    ]});
  }else if(field==='path'){
    sections.push({head:'PATH', items:[
      {label:'Filter path',val:f.path,on:true,act:()=>setFilter('search',f.path)},
      {label:'Exclude path',val:f.path,danger:true,act:()=>addExclude('path',f.path)},
      {label:'Copy path',act:()=>copyText(f.path,'path copied')},
    ]});
  }
  // mime/size/time columns have no column-specific filter — they fall through to
  // the global section below.

  sections.push(flowGlobalSection(f,'REQUEST'));
  if(anyFilter())sections.push({items:[{label:'Clear all filters',act:clearAllFilters}]});
  openMenu(x,y,sections);
}

// showInspectorCtx builds the request/response pane menu: a SELECTION section
// (only when text is highlighted) for copy/decode/search/scope, plus the global
// flow actions.
// selectionWithin returns the trimmed selected text if the selection lies inside
// el. It falls back to the range's text because Selection.toString() returns ""
// when the document isn't focused (e.g. automation) even though a range exists.
function selectionWithin(el){
  const s=window.getSelection&&window.getSelection();
  if(!s||!s.rangeCount)return '';
  if(el&&s.anchorNode&&!el.contains(s.anchorNode))return '';
  let t=String(s);
  if(!t)t=s.getRangeAt(0).toString();
  return t.trim();
}
export function showInspectorCtx(x,y,side){
  const f=state.flows.find(z=>z.id===state.selId)||state.detail;
  if(!f)return;
  const sel=selectionWithin($(side==='req'?'#reqView':'#resView'));
  const sections=[];
  if(sel){
    const short=sel.length>40?sel.slice(0,40)+'…':sel;
    const items=[
      {label:'Copy',act:()=>copyText(sel,'copied')},
      {label:'Decode / encode',val:short,act:()=>openDecoder(sel)},
      {label:'Search in history',val:short,act:()=>setFilter('search',sel)},
    ];
    if(looksLikeHost(sel))items.push({label:'Add to scope',val:sel,act:()=>addHostToScope(sel)});
    sections.push({head:'SELECTION', items});
  }
  sections.push(flowGlobalSection(f, side==='req'?'REQUEST':'RESPONSE'));
  if(!sel)sections.push({items:[{label:'Open Decoder',act:()=>openDecoder('')}]});
  openMenu(x,y,sections);
}
document.addEventListener('click',e=>{if(!ctx.contains(e.target))hideCtx();});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){if(typeof closeModals==='function'&&closeModals())return;hideCtx();}});
// Suppress the browser's native context menu app-wide, but keep it where it's
// genuinely useful: editable fields (paste/cut) and over a live text selection (copy).
document.addEventListener('contextmenu',e=>{
  const t=e.target,tag=(t.tagName||'').toLowerCase();
  if(tag==='input'||tag==='textarea'||t.isContentEditable)return;
  const sel=window.getSelection&&window.getSelection();
  if(sel&&String(sel).length&&!sel.isCollapsed)return;
  e.preventDefault();
});
$('#rows').addEventListener('scroll',hideCtx,{passive:true});
window.addEventListener('blur',hideCtx);
// Request/response inspector panes get their own context menu (selection-aware).
// stopPropagation keeps the app-wide handler from also firing, so the native
// menu never double-shows over a selection.
['reqView','resView'].forEach(id=>{
  const el=$('#'+id);
  if(el)el.addEventListener('contextmenu',e=>{e.preventDefault();e.stopPropagation();showInspectorCtx(e.clientX,e.clientY,id==='reqView'?'req':'resp');});
});
export function flowURL(f){const def=(f.scheme==='https'&&f.port===443)||(f.scheme==='http'&&f.port===80);return `${f.scheme}://${f.host}${def?'':':'+f.port}${f.path}`;}
export function copyURL(f){copyText(flowURL(f),'URL copied');}
function shq(s){return "'"+String(s).replace(/'/g,"'\\''")+"'";}
export async function copyCurl(f){
  try{
    const d=await api('/api/flows/'+f.id);
    const parts=[`curl -x http://${state.proxyAddr}`];
    if(f.scheme==='https')parts.push('--cacert interceptor-ca.crt');
    parts.push('-X '+f.method);
    const headers=d.reqHeaders||{};
    Object.keys(headers).sort().forEach(k=>{if(k.toLowerCase()==='host')return;(headers[k]||[]).forEach(v=>parts.push('-H '+shq(k+': '+v)));});
    if(f.reqLen>0){const raw=await api('/api/flows/'+f.id+'/raw?side=req');const i=raw.indexOf('\r\n\r\n');const body=i>=0?raw.slice(i+4):'';if(body)parts.push('--data-raw '+shq(body));}
    parts.push(shq(flowURL(f)));
    copyText(parts.join(' \\\n  '),'cURL copied');
  }catch(e){toast('cURL: '+e.message);}
}
// ---- History multi-select actions ----
export function updateSelBar(){const n=state.selected.size;$('#selBar').style.display=n?'flex':'none';$('#selCount').textContent=n+' selected';}
$('#selClear').onclick=()=>{state.selected.clear();state.lastSelIdx=-1;renderRows();updateSelBar();};
$('#selAsk').onclick=()=>{const ids=[...state.selected];if(ids.length)openAi('summarize',ids);};
$('#selScope').onclick=async()=>{
  const hosts=[...new Set([...state.selected].map(id=>{const f=state.flows.find(x=>x.id===id);return f&&f.host;}).filter(Boolean))];
  if(!hosts.length)return;
  let added=0;
  for(const host of hosts){try{await api('/api/scope',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'include',host,enabled:true})});added++;}catch(e){}}
  toast('added '+added+' host'+(added===1?'':'s')+' to scope');loadScope();
};
export let _delArm=false,_delTimer;
$('#selDelete').onclick=async()=>{
  const ids=[...state.selected];if(!ids.length)return;
  if(!_delArm){_delArm=true;$('#selDelete').textContent='🗑 Confirm? ('+ids.length+')';clearTimeout(_delTimer);_delTimer=setTimeout(()=>{_delArm=false;$('#selDelete').textContent='🗑 Delete';},2500);return;}
  clearTimeout(_delTimer);_delArm=false;$('#selDelete').textContent='🗑 Delete';
  try{
    const r=await api('/api/flows/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ids})});
    if(state.selected.has(state.selId))state.selId=null;
    state.selected.clear();state.lastSelIdx=-1;updateSelBar();loadFlows();
    toast('deleted '+(r.deleted!=null?r.deleted:ids.length)+' flow'+((r.deleted!=null?r.deleted:ids.length)===1?'':'s'));
  }catch(e){toast('delete: '+e.message);}
};
/* ---- inspector splitter ---- */
(function(){
  const SPLITTER_KEY='inspect.height';
  const MIN_H=120, MAX_PCT=0.80;
  const splitter=document.getElementById('inspectSplitter');
  const inspect=document.getElementById('inspect');
  if(!splitter||!inspect)return;

  function clamp(h){
    const proxyPanel=inspect.closest('.panel');
    const maxH=proxyPanel?(proxyPanel.clientHeight*MAX_PCT):600;
    return Math.max(MIN_H,Math.min(maxH,h));
  }
  function applyHeight(h){
    h=clamp(h);
    inspect.style.height=h+'px';
    inspect.style.flex='none';
    try{localStorage.setItem(SPLITTER_KEY,String(h));}catch(e){}
  }

  // Restore persisted height on load.
  try{const saved=localStorage.getItem(SPLITTER_KEY);if(saved){const h=parseInt(saved,10);if(h>=MIN_H)applyHeight(h);}}catch(e){}

  // Pointer drag.
  let dragY=null,dragH=null;
  splitter.addEventListener('pointerdown',e=>{
    e.preventDefault();
    dragY=e.clientY;
    dragH=inspect.offsetHeight;
    splitter.setPointerCapture(e.pointerId);
  });
  splitter.addEventListener('pointermove',e=>{
    if(dragY===null)return;
    // Dragging up (negative delta) increases inspector height.
    applyHeight(dragH-(e.clientY-dragY));
  });
  splitter.addEventListener('pointerup',()=>{dragY=null;dragH=null;});
  splitter.addEventListener('pointercancel',()=>{dragY=null;dragH=null;});

  // Keyboard: Up/Down arrows nudge by 20px.
  splitter.addEventListener('keydown',e=>{
    if(e.key!=='ArrowUp'&&e.key!=='ArrowDown')return;
    e.preventDefault();
    const delta=e.key==='ArrowUp'?20:-20;
    applyHeight(inspect.offsetHeight+delta);
  });
})();
