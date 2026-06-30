import { $, esc, escAttr, state, toast, api, openModal, closeModal, copyText, fmtTime, renderMD, pickTextFile, normalizeListText, DEC_OPS, wireRowKey, saveFile, uiConfirm, methodColor, statusColor } from './core.js';
import { flowPopup } from './flowmodal.js';
import { openFinding } from './findings.js';

/* ---- out-of-band (OOB) interaction catcher ---- */
export async function loadOob(){
  try{const d=await api('/api/oob/state');
    if(document.activeElement!==$('#oobBase'))$('#oobBase').value=d.baseUrl||'';
    renderOobList(d.interactions||[]);
  }catch(e){}
}
function renderOobList(list){
  const c=$('#oobCount');if(c)c.textContent=list.length?list.length+' interaction'+(list.length===1?'':'s'):'';
  const box=$('#oobList');if(!box)return;
  if(!list.length){box.innerHTML='<div class="hint">No interactions yet — callbacks to a generated URL appear here live.</div>';return;}
  box.innerHTML=list.map(it=>`<div class="oob-row">
    <span class="oob-m">${esc(it.method)}</span>
    <span class="oob-p" title="${escAttr(it.path+(it.query?'?'+it.query:''))}">${esc(it.path)}${it.query?'<span style="color:var(--fg3)">?'+esc(it.query)+'</span>':''}</span>
    <span class="oob-src" title="source · ${escAttr(it.userAgent||'')}">${esc(it.remoteAddr||'')}</span>
    <span class="oob-t">${fmtTime(it.ts)}</span></div>`).join('');
}
$('#oobBtn')&&($('#oobBtn').onclick=()=>{
  if(!state.oobEnabled){toast('OOB is disabled — enable in Settings → Scanner');return;}
  openModal($('#oobModal'));loadOob();
});
$('#oobClose')&&($('#oobClose').onclick=()=>closeModal($('#oobModal')));
$('#oobGen')&&($('#oobGen').onclick=async()=>{try{const r=await api('/api/oob/new',{method:'POST'});$('#oobUrl').value=r.url||'';copyText(r.url||'','OOB URL generated & copied');}catch(e){toast(e.message);}});
$('#oobCopy')&&($('#oobCopy').onclick=()=>{const u=$('#oobUrl').value;if(u)copyText(u,'OOB URL copied');else toast('generate a URL first');});
$('#oobSaveBase')&&($('#oobSaveBase').onclick=async()=>{try{await api('/api/oob/base',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({baseUrl:$('#oobBase').value.trim()})});toast('OOB base saved');loadOob();}catch(e){toast(e.message);}});
$('#oobClear')&&($('#oobClear').onclick=async()=>{try{await api('/api/oob/interactions',{method:'DELETE'});loadOob();toast('OOB interactions cleared');}catch(e){toast(e.message);}});

const OOB_TUNNEL_CMD='cloudflared tunnel --url http://127.0.0.1:9966';
$('#oobModalTunnelCopy')&&($('#oobModalTunnelCopy').onclick=()=>copyText(OOB_TUNNEL_CMD,'Tunnel command copied'));

/* ---- custom checks editor ---- */
let checkMode='code',checkDocsLoaded=false;
// checkKind tracks which kind of check the editor is editing: 'passive' (inspects
// a captured flow) or 'active' (sends probes via /api/active-checks). Drives the
// Save/Test/Delete endpoint and the New template.
let checkKind='passive';
const checkEndpoint=()=>checkKind==='active'?'/api/active-checks':'/api/checks';
function checkSetMode(mode){
  checkMode=mode;
  const seg=$('#checkModeSeg');
  if(seg)seg.querySelectorAll('[data-mode]').forEach(b=>{
    const on=b.dataset.mode===mode;
    b.classList.toggle('on',on);
    b.setAttribute('aria-selected',on?'true':'false');
  });
  const panes={code:'#checkPaneCode',describe:'#checkPaneDescribe',docs:'#checkPaneDocs'};
  Object.entries(panes).forEach(([m,sel])=>{const el=$(sel);if(el)el.style.display=m===mode?'':'none';});
  if(mode==='docs')loadCheckDocs();
  if(mode==='describe')setTimeout(()=>$('#checkDescribe')?.focus(),0);
}
async function loadCheckDocs(){
  if(checkDocsLoaded)return;
  const box=$('#checkDocs');if(!box)return;
  try{
    const d=await api('/api/checks/reference');
    box.innerHTML=renderMD(d.markdown||'');
    checkDocsLoaded=true;
  }catch(e){box.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';}
}
function updateCheckFlowHint(){
  const el=$('#checkFlowHint');if(!el)return;
  el.textContent=state.selId!=null?('Test flow: #'+state.selId+' (selected)'):'Test uses latest captured flow';
}
export async function loadChecksList(){
  try{
    const d=await api('/api/checks');const box=$('#checksList');if(!box)return;
    const cs=d.checks||[];const dis=new Set(d.disabled||[]);
    const builtin=d.builtin||[];const active=d.active||[];
    const sevBadge=s=>`<span class="sev ${escAttr(s)}" style="font-size:9px">${esc(s)}</span>`;
    const catBadge=c=>c?`<span style="font-size:9px;color:var(--fg3);border:1px solid var(--line);border-radius:4px;padding:0 4px">${esc(c)}</span>`:'';
    // Built-in passive checks: toggleable, not deletable/editable. Grouped by category.
    let html='';
    if(builtin.length){
      html+=`<div class="checks-sec">BUILT-IN · PASSIVE <span class="hint" style="font-weight:400;text-transform:none;letter-spacing:0">— toggle on/off; bundled with the app</span></div>`;
      html+=builtin.map(b=>`<div class="checks-row checks-builtin" title="${escAttr(b.description||'')}" aria-label="built-in check ${escAttr(b.title)}">
        <input type="checkbox" class="check-en" data-id="${escAttr(b.id)}" ${dis.has(b.id)?'':'checked'} aria-label="enable ${escAttr(b.title)}">
        <span class="checks-title">${esc(b.title)}</span>${sevBadge(b.severity)}${catBadge(b.category)}</div>`).join('');
    }
    // Custom Starlark checks: full CRUD. Click a row to edit.
    html+=`<div class="checks-sec">CUSTOM · STARLARK <span class="hint" style="font-weight:400;text-transform:none;letter-spacing:0">— yours; click to edit</span></div>`;
    if(!cs.length){
      html+='<div class="hint" style="padding:6px 10px">No custom checks yet — click <b>+ New check</b>. Built-in checks run out of the box.</div>';
    }else{
      html+=cs.map(c=>`<div class="checks-row checks-custom" data-id="${escAttr(c.id)}" aria-label="custom check ${escAttr(c.id)}${c.error?' (error)':''}" title="click to edit">
        <input type="checkbox" class="check-en" data-id="${escAttr(c.id)}" ${dis.has(c.id)?'':'checked'} aria-label="enable check ${escAttr(c.id)}">
        <span class="checks-title" style="color:${c.error?'var(--red)':'var(--fg)'}">${esc(c.id)}${c.error?' ⚠':''}</span>${catBadge('custom')}</div>`).join('');
    }
    // Active probes: toggleable like passive, but tagged — they send real traffic
    // when you arm & run an active scan.
    if(active.length){
      html+=`<div class="checks-sec">ACTIVE · PROBES <span class="hint" style="font-weight:400;text-transform:none;letter-spacing:0">— toggle on/off; fire only when you arm &amp; run an active scan (sends traffic)</span></div>`;
      html+=active.map(a=>`<div class="checks-row checks-active" title="${escAttr(a.fix||'')}" aria-label="active probe ${escAttr(a.title)}">
        <input type="checkbox" class="check-en" data-id="${escAttr(a.id)}" ${dis.has(a.id)?'':'checked'} aria-label="enable ${escAttr(a.title)}">
        <span style="width:14px;flex:none;color:var(--amber)" title="sends traffic">⚡</span>
        <span class="checks-title">${esc(a.title)}</span>${sevBadge(a.severity)}${catBadge(a.class)}</div>`).join('');
    }
    // User-authored active checks (Starlark, sends traffic) — full CRUD like passive.
    let csA=[];
    try{csA=(await api('/api/active-checks')).checks||[];}catch(e){}
    html+=`<div class="checks-sec">CUSTOM · ACTIVE <span class="hint" style="font-weight:400;text-transform:none;letter-spacing:0">— yours; author probes (⚡ sends traffic); click to edit</span></div>`;
    if(!csA.length){
      html+='<div class="hint" style="padding:6px 10px">No custom active checks — click <b>+ New active</b> to author one.</div>';
    }else{
      html+=csA.map(c=>`<div class="checks-row checks-custom checks-custom-active" data-id="${escAttr(c.id)}" data-active="1" aria-label="custom active check ${escAttr(c.id)}${c.error?' (error)':''}" title="click to edit">
        <input type="checkbox" class="check-en" data-id="custom-active:${escAttr(c.id)}" ${dis.has('custom-active:'+c.id)?'':'checked'} aria-label="enable active check ${escAttr(c.id)}">
        <span style="width:14px;flex:none;color:var(--amber)">⚡</span>
        <span class="checks-title" style="color:${c.error?'var(--red)':'var(--fg)'}">${esc(c.id)}${c.error?' ⚠':''}</span>${catBadge('active')}</div>`).join('');
    }
    box.innerHTML=html;
    // Custom rows open the editor (passive + active).
    box.querySelectorAll('.checks-custom[data-id]').forEach(el=>{
      const id=el.dataset.id, kind=el.dataset.active==='1'?'active':'passive';
      el.onclick=e=>{if(e.target.classList.contains('check-en'))return;loadCheck(id,kind);};
      wireRowKey(el,()=>loadCheck(id,kind));
    });
    // Any checkbox change (built-in or custom) recomputes the disabled set.
    box.querySelectorAll('.check-en').forEach(cb=>cb.onchange=async()=>{
      const disabled=[...box.querySelectorAll('.check-en')].filter(x=>!x.checked).map(x=>x.dataset.id);
      try{await api('/api/checks/disabled',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({disabled})});
        toast('check '+(cb.checked?'enabled':'disabled'));}catch(e){toast(e.message);}
    });
  }catch(e){const box=$('#checksList');if(box)box.innerHTML=`<div class="hint" style="padding:10px;color:var(--red)">Couldn't load checks: ${esc(e.message)}</div>`;}
}
const ACTIVE_CHECK_TEMPLATE=`# Active check: send probes at an injection point, confirm a vuln.
# ⚡ probe(payload) sends a real request — it counts against the run's budget.
def check(point, baseline, probe):
    r = probe("'")
    if re_search("(?i)SQL syntax", r.body):
        return [finding("High", "SQL injection (custom)", evidence=r.body[:80], fix="parameterize queries")]
    return []
`;
function refreshCheckEditorMode(){
  // The AI "Describe" tab is passive-only; hide it for active checks.
  const describe=$('#checkModeSeg button[data-mode="describe"]');
  if(describe) describe.style.display = checkKind==='active'?'none':'';
  if(checkKind==='active' && checkMode==='describe') checkSetMode('code');
}
export async function loadCheck(id, kind='passive'){
  checkKind=kind; refreshCheckEditorMode();
  try{const d=await api(checkEndpoint()+'/'+encodeURIComponent(id));$('#checkId').value=id;$('#checkSrc').value=d.source||'';
    $('#checkOut').innerHTML='<span class="hint">Loaded <b>'+esc(id)+'</b> ('+(kind==='active'?'active · sends traffic':'passive')+').</span>';}catch(e){toast(e.message);}
}
export function checkNew(kind='passive'){
  checkKind=kind; refreshCheckEditorMode();
  $('#checkId').value='';
  $('#checkSrc').value = kind==='active' ? ACTIVE_CHECK_TEMPLATE : "def check(flow):\n    # inspect flow, return a list of finding(...)\n    return []\n";
  $('#checkOut').innerHTML='<span class="hint">New '+(kind==='active'?'active':'passive')+' check — give it an id and Save.</span>';$('#checkId').focus();
}
export async function checkTest(){
  const out=$('#checkOut');out.innerHTML='<span class="hint">running…</span>';
  try{const r=await api(checkEndpoint()+'/test',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({source:$('#checkSrc').value,flowId:state.selId||0})});
    if(r.error){out.innerHTML='<span style="color:var(--red);white-space:pre-wrap">'+esc(r.error)+'</span>';return;}
    const f=r.finding;
    const note=r.note||(f?('finding on flow #'+(f.flowId||'?')):'no finding');
    out.innerHTML='<div class="hint" style="margin-bottom:6px">'+esc(note)+(checkKind==='active'?' · ⚡ sent real probes':'')+'</div>'+
      (f?`<div style="padding:3px 0"><span class="sev ${escAttr(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)}${f.evidence?' <span class="hint">— '+esc(f.evidence)+'</span>':''}</div>`:'<span class="hint">No finding (check compiles &amp; runs).</span>');
  }catch(e){out.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';}
}
export async function checkSave(){
  const id=$('#checkId').value.trim();if(!id){toast('set a check id first');return;}
  try{await api(checkEndpoint()+'/'+encodeURIComponent(id),{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({source:$('#checkSrc').value})});
    $('#checkOut').innerHTML='<span style="color:var(--accent)">Saved ✓ — '+(checkKind==='active'?'runs on the next active scan':'runs on the next scan')+'.</span>';loadChecksList();}
  catch(e){$('#checkOut').innerHTML='<span style="color:var(--red);white-space:pre-wrap">'+esc(e.message)+'</span>';}
}
export async function checkDelete(){
  const id=$('#checkId').value.trim();if(!id)return;
  if(!await uiConfirm('Delete check',`Delete ${checkKind} check <b>${esc(id)}</b>? Its Starlark source will be removed and won't run on future scans.`,'Delete','btn danger','var(--red)'))return;
  try{await api(checkEndpoint()+'/'+encodeURIComponent(id),{method:'DELETE'});checkNew();loadChecksList();toast('deleted '+id);}catch(e){toast(e.message);}
}
async function checkAiGenerate(){
  if(state.aiDisabled){toast('AI features are disabled — enable in Settings → AI assist');return;}
  const desc=($('#checkDescribe')||{}).value?.trim();
  if(!desc){toast('describe what the check should detect');$('#checkDescribe')?.focus();return;}
  const status=$('#checkAiStatus'),btn=$('#checkAiGen');
  if(status)status.textContent='generating…';
  if(btn)btn.disabled=true;
  try{
    const r=await api('/api/ai/checks/generate',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({description:desc,source:$('#checkSrc').value||'',flowId:state.selId||0})});
    if(r.error&&!r.source){
      if(status)status.innerHTML='<span style="color:var(--red)">'+esc(r.error)+'</span>';
      return;
    }
    if(r.source)$('#checkSrc').value=r.source;
    if(r.suggestedId&&!$('#checkId').value.trim())$('#checkId').value=r.suggestedId;
    checkSetMode('code');
    if(status)status.textContent='generated — running test…';
    await checkTest();
    if(status){
      if(r.error)status.innerHTML='<span style="color:var(--amber)">compiled after retry; review output</span>';
      else status.textContent='done — review code, set id, Save';
    }
  }catch(e){
    if(status)status.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';
  }finally{if(btn)btn.disabled=false;}
}
export function openChecks(){openModal($('#checksModal'));loadChecksList();updateCheckFlowHint();if(!$('#checkSrc').value)checkNew();checkSetMode('code');}
if($('#checksBtn'))$('#checksBtn').onclick=openChecks;
if($('#checksClose'))$('#checksClose').onclick=()=>closeModal($('#checksModal'));
if($('#checkNew'))$('#checkNew').onclick=()=>checkNew('passive');
if($('#checkNewActive'))$('#checkNewActive').onclick=()=>checkNew('active');
if($('#checkTest'))$('#checkTest').onclick=checkTest;
if($('#checkSave'))$('#checkSave').onclick=checkSave;
if($('#checkDelete'))$('#checkDelete').onclick=checkDelete;
if($('#checkModeSeg'))$('#checkModeSeg').querySelectorAll('[data-mode]').forEach(b=>b.onclick=()=>checkSetMode(b.dataset.mode));
if($('#checkAiGen'))$('#checkAiGen').onclick=checkAiGenerate;

/* ---- decoder ---- */
export { DEC_OPS };
export function decBuildOps(){const box=$('#decOps');if(!box||box._built)return;box._built=1;
  box.innerHTML=DEC_OPS.map(([op,label])=>`<button class="btn" data-op="${op}">${esc(label)}</button>`).join('');
  box.querySelectorAll('[data-op]').forEach(b=>b.onclick=()=>decApply(b.dataset.op));}
export async function decApply(op){
  const err=$('#decErr');err.textContent='';
  try{const r=await api('/api/decode',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({op,input:$('#decIn').value})});
    if(r.error){err.style.color='var(--red)';err.textContent=r.error;return;}
    $('#decOut').value=r.output;}
  catch(e){err.style.color='var(--red)';err.textContent=e.message;}
}
export function openDecoder(seed){decBuildOps();openModal($('#decModal'));if(seed)$('#decIn').value=seed;$('#decOut').value='';$('#decErr').textContent='';setTimeout(()=>$('#decIn').focus(),0);}
async function decLoadFile(){
  try{
    const got=await pickTextFile();
    if(!got) return;
    $('#decIn').value=normalizeListText(got.text);
    $('#decOut').value='';$('#decErr').textContent='';
    toast('loaded from '+got.name);
  }catch(e){toast(e.message);}
}
if($('#decLoad'))$('#decLoad').onclick=decLoadFile;
if($('#decClose'))$('#decClose').onclick=()=>closeModal($('#decModal'));
if($('#decUp'))$('#decUp').onclick=()=>{$('#decIn').value=$('#decOut').value;$('#decOut').value='';$('#decIn').focus();};
if($('#decCopy'))$('#decCopy').onclick=()=>copyText($('#decOut').value,'output copied');

/* ---- active scan ---- */
function openSettingsScope(){
  closeModal($('#activeModal'));
  document.querySelector('.tab[data-tab="settings"]')?.click();
  document.querySelector('#setNav button[data-sec="scope"]')?.click();
}
function asScopeRuleLine(r){
  const tag=r.action==='exclude'?'exclude':'include';
  const color=tag==='exclude'?'var(--red)':'var(--accent)';
  const host=r.host||'(any host)';
  const extra=[r.path?'path:'+r.path:'',r.scheme?r.scheme:''].filter(Boolean).join(' · ');
  return `<div style="font-family:var(--mono);font-size:11.5px;padding:3px 0"><span style="font-weight:700;color:${color}">${tag}</span> <span style="color:var(--fg)">${esc(host)}</span>${extra?` <span class="hint">${esc(extra)}</span>`:''}</div>`;
}
export async function renderAsScopePanel(){
  const panel=$('#asScopePanel');if(!panel)return;
  const scopeMode=$('#asTargetScope')?.checked;
  panel.style.display=scopeMode?'':'none';
  if(!scopeMode)return;
  try{const d=await api('/api/scope');state.scope=d.rules||[];}catch(e){}
  const enabled=(state.scope||[]).filter(r=>r.enabled);
  const includes=enabled.filter(r=>r.action==='include');
  const excludes=enabled.filter(r=>r.action==='exclude');
  let html='';
  if(!state.scope.length){
    html=`<p class="hint" style="color:var(--amber);margin:0;line-height:1.55"><b>No scope rules.</b> Bulk active scan requires at least one <b>include</b> rule — without it, every captured host would be attacked. Define targets under <b>Settings → Target scope</b>.</p>`;
  }else if(!includes.length){
    html=`<p class="hint" style="color:var(--amber);margin:0 0 8px;line-height:1.55"><b>No include rules.</b> Add at least one enabled <b>include</b> rule before running bulk active scan.</p>`;
    if(excludes.length)html+=`<div style="font-size:9px;font-weight:700;letter-spacing:.6px;color:var(--fg3);margin:8px 0 4px">EXCLUDE RULES</div>`+excludes.map(asScopeRuleLine).join('');
  }else{
    html=`<div style="font-size:9px;font-weight:700;letter-spacing:.6px;color:var(--fg3);margin:0 0 6px">IN-SCOPE (from Settings → Target scope)</div>`;
    html+=includes.map(asScopeRuleLine).join('');
    if(excludes.length)html+=`<div style="font-size:9px;font-weight:700;letter-spacing:.6px;color:var(--fg3);margin:10px 0 4px">EXCLUDE (always wins)</div>`+excludes.map(asScopeRuleLine).join('');
  }
  html+=`<div class="row" style="gap:8px;margin-top:10px;flex-wrap:wrap;align-items:center"><button class="btn" type="button" id="asScopeEdit">Settings → Target scope</button><span class="hint" id="asScopeHosts">checking captured traffic…</span></div>`;
  panel.innerHTML=html;
  $('#asScopeEdit')?.addEventListener('click',openSettingsScope);
  try{
    const d=await api('/api/flows?limit=500&inScope=1');
    const hosts=[...new Set((d.flows||[]).map(f=>f.host).filter(Boolean))].sort();
    const el=$('#asScopeHosts');
    if(!el)return;
    if(!hosts.length)el.textContent='No in-scope traffic in history yet — browse the target through the proxy first.';
    else el.textContent=`${hosts.length} host${hosts.length===1?'':'s'} in history: ${hosts.slice(0,10).join(', ')}${hosts.length>10?'…':''} (only endpoints with query/body params are scanned)`;
  }catch(e){const el=$('#asScopeHosts');if(el)el.textContent='';}
}
export async function loadActive(){
  try{const d=await api('/api/activescan');renderActive(d);}catch(e){}
}
let asHistoryFlows=[];
async function loadAsHistory(){
  try{
    const d=await api('/api/activescan/history?limit=200');
    asHistoryFlows=d.flows||[];
    const st=await api('/api/activescan').catch(()=>null);
    if(st)renderAsLogs(st);
  }catch(e){}
}
function renderAsLogs(d){
  const box=$('#asLogs'),cnt=$('#asLogCount');
  if(!box)return;
  const runLogs=(d&&d.logs)||[];
  const items=runLogs.length?runLogs:asHistoryFlows.map(f=>({flowId:f.id,method:f.method,host:f.host,path:f.path,status:f.status,error:f.error||''}));
  if(cnt)cnt.textContent=items.length?'('+items.length+')':'';
  if(!items.length){box.innerHTML='<div class="hint">No probes yet — start a scan to record attack requests here.</div>';return;}
  box.innerHTML=items.map(p=>{
    const st=p.status||0;
    const err=p.error?` <span style="color:var(--red)">${esc(p.error)}</span>`:'';
    const flow=p.flowId?` <span style="color:var(--blue)">#${p.flowId}</span>`:'';
    return `<div class="as-log-row${p.flowId?'':' muted'}"${p.flowId?` data-flow="${p.flowId}"`:''} style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--line);cursor:${p.flowId?'pointer':'default'};font-size:11.5px;font-family:var(--mono)">
      <span style="width:44px;flex:none;color:${methodColor(p.method)}">${esc(p.method||'—')}</span>
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--fg2)">${esc(p.host||'')}${esc(p.path||'')}</span>
      <span style="width:36px;flex:none;text-align:right;color:${statusColor(st)}">${st||'—'}</span>${flow}${err}</div>`;
  }).join('');
  box.querySelectorAll('[data-flow]').forEach(el=>{el.onclick=()=>flowPopup(Number(el.dataset.flow));wireRowKey(el,()=>flowPopup(Number(el.dataset.flow)));});
}
export function renderActive(d){
  if($('#asArm'))$('#asArm').checked=!!d.armed;
  const fs=d.findings||[];
  if($('#asStart'))$('#asStart').disabled=d.running||!d.armed;
  if($('#asStop'))$('#asStop').disabled=!d.running;
  const prog=$('#asProgress');
  if(prog){
    if(d.running)prog.innerHTML='<span style="color:var(--accent)">⟳ running…</span> '+d.scanned+'/'+d.targets+' targets · '+d.requests+' requests';
    else if(d.scanned)prog.textContent='done · '+d.scanned+' targets · '+d.requests+' requests · '+fs.length+' findings';
    else prog.textContent='';
  }
  renderAsLogs(d);
  const box=$('#asFindings');if(!box)return;
  box.innerHTML=fs.length?fs.map(f=>`<div data-flow="${f.flowId}" style="padding:7px 0;border-bottom:1px solid var(--line);cursor:pointer">
    <span class="sev ${escAttr(f.severity)}">${esc(f.severity)}</span> <b>${esc(f.title)}</b>
    <div class="hint" style="margin-top:2px">${esc(f.class)}${f.point?` · ${esc(f.point.kind)}:${esc(f.point.name)}`:''} — ${esc(f.evidence)}${f.flowId?` <span style="color:var(--blue)">· flow #${f.flowId}</span>`:''}</div></div>`).join('')
    :'<div class="hint">No active findings yet.</div>';
  box.querySelectorAll('[data-flow]').forEach(el=>{el.onclick=()=>flowPopup(Number(el.dataset.flow));wireRowKey(el,()=>flowPopup(Number(el.dataset.flow)));});
}
export async function asArmToggle(){
  try{await api('/api/activescan/arm',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({armed:$('#asArm').checked})});loadActive();}
  catch(e){toast(e.message);}
}
export async function asStartScan(){
  const body={arm:$('#asArm').checked,maxRequests:parseInt($('#asMax').value,10)||0};
  if($('#asTargetFlow').checked){
    if(state.selId==null){toast('select a flow first, or choose "all in-scope"');return;}
    body.flowId=state.selId;
  }else body.inScope=true;
  try{await api('/api/activescan/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});loadActive();}
  catch(e){toast(e.message);}
}
export async function asStopScan(){try{await api('/api/activescan/stop',{method:'POST'});loadActive();toast('active scan stopped');}catch(e){toast(e.message);}}
export function openActive(){
  openModal($('#activeModal'));
  $('#asFlowLabel').textContent=state.selId!=null?('#'+state.selId):'(none selected)';
  loadActive();
  loadAsHistory();
  renderAsScopePanel();
}
if($('#activeBtn'))$('#activeBtn').onclick=openActive;
if($('#asClose'))$('#asClose').onclick=()=>closeModal($('#activeModal'));
if($('#asArm'))$('#asArm').onchange=asArmToggle;
if($('#asStart'))$('#asStart').onclick=asStartScan;
if($('#asStop'))$('#asStop').onclick=asStopScan;
if($('#asTargetFlow'))$('#asTargetFlow').onchange=renderAsScopePanel;
if($('#asTargetScope'))$('#asTargetScope').onchange=renderAsScopePanel;

/* ---- scanner ---- */
export const scanState={sel:null,issues:[]};
export async function loadIssues(){try{const d=await api('/api/scanner/issues');scanState.issues=d.issues||[];renderScan();}catch(e){}}
export async function runScan(){
  $('#scanRun').textContent='Scanning…';$('#scanRun').disabled=true;
  const host=($('#scanTarget')||{}).value||'',search=(($('#scanFilter')||{}).value||'').trim();
  const q=new URLSearchParams();if(host)q.set('host',host);if(search)q.set('search',search);
  try{const d=await api('/api/scanner/run'+(q.toString()?'?'+q:''),{method:'POST'});scanState.issues=d.issues||[];renderScan();
    toast(scanState.issues.length+' issue'+(scanState.issues.length===1?'':'s')+(host?' · '+host:'')+(search?' · "'+search+'"':''));}
  catch(e){toast(e.message);}
  $('#scanRun').textContent='Run scan ▸';$('#scanRun').disabled=false;
}
// Populate the scanner's target dropdown from the hosts seen in history.
export async function loadScanTargets(){
  const sel=$('#scanTarget');if(!sel)return;
  try{const d=await api('/api/flows?limit=2000');
    const hosts=[...new Set((d.flows||[]).map(f=>f.host).filter(Boolean))].sort();
    const cur=sel.value;
    sel.innerHTML='<option value="">All in-scope hosts</option>'+hosts.map(h=>`<option value="${escAttr(h)}">${esc(h)}</option>`).join('');
    if(hosts.includes(cur))sel.value=cur;
  }catch(e){}
}
export function prefillScanner(host, pathSearch){
  document.querySelector('.tab[data-tab="scanner"]')?.click();
  loadScanTargets().then(()=>{
    const sel=$('#scanTarget');
    if(sel&&host) sel.value=host;
    const f=$('#scanFilter');
    if(f&&pathSearch) f.value=pathSearch;
  });
  toast('Scanner ready'+(host?' · '+host:''));
}
// Group findings by title: one list row per finding type, the affected targets
// nested in its detail — instead of a separate row per (finding × target).
export const SEV_ORDER=['High','Medium','Low','Info'];
export const sevRank=s=>{const i=SEV_ORDER.indexOf(s);return i<0?SEV_ORDER.length:i;};
export function scanGroups(){
  const map=new Map();
  scanState.issues.forEach(i=>{
    let g=map.get(i.title);
    if(!g){g={title:i.title,severity:i.severity,items:[]};map.set(i.title,g);}
    g.items.push(i);
    if(sevRank(i.severity)<sevRank(g.severity))g.severity=i.severity; // keep the most severe
  });
  return [...map.values()].sort((a,b)=>sevRank(a.severity)-sevRank(b.severity)||a.title.localeCompare(b.title));
}
export function renderScan(){
  const list=$('#scanList');
  if(!scanState.issues.length){$('#scanCount').textContent='';list.innerHTML='<div class="hint" style="padding:12px">No issues found. Capture some traffic, then Run scan.</div>';$('#scanDetail').innerHTML='<div class="hint" style="padding:16px">Select a finding.</div>';return;}
  const groups=scanState.groups=scanGroups();
  const c={};scanState.issues.forEach(i=>c[i.severity]=(c[i.severity]||0)+1);
  $('#scanCount').textContent=`${groups.length} finding${groups.length===1?'':'s'} · ${scanState.issues.length} target${scanState.issues.length===1?'':'s'} · ${c.High||0}H ${c.Medium||0}M ${c.Low||0}L`;
  if(scanState.sel==null||scanState.sel>=groups.length)scanState.sel=0;
  list.innerHTML=groups.map((g,idx)=>`<div class="scan-item ${idx===scanState.sel?'sel':''}" data-i="${idx}">
    <span class="sev ${escAttr(g.severity)}">${esc(g.severity)}</span>
    <div class="t">${esc(g.title)}</div><div class="tg">${g.items.length} target${g.items.length===1?'':'s'}</div></div>`).join('');
  list.querySelectorAll('.scan-item').forEach(el=>{el.onclick=()=>{scanState.sel=Number(el.dataset.i);renderScan();};wireRowKey(el);});
  renderScanDetail();
}
export function renderScanDetail(){
  const g=(scanState.groups||[])[scanState.sel];if(!g)return;
  const first=g.items[0];
  const shared=g.items.every(i=>i.detail===first.detail); // show a common description once
  const tgts=g.items.map(i=>`<div class="scan-tgt"${i.flowId?` data-flow="${i.flowId}"`:''} style="${i.flowId?'cursor:pointer;':''}padding:7px 9px;border:1px solid var(--line);border-radius:6px;margin-bottom:6px">
    <div style="font-family:var(--mono);font-size:12px;color:var(--accent);word-break:break-all">${esc(i.target||'(no target)')}${i.flowId?` <span style="color:var(--fg3)">· flow #${i.flowId}</span>`:''}</div>
    ${(!shared&&i.detail)?`<div style="font-size:12px;color:var(--fg2);margin-top:5px;line-height:1.5">${esc(i.detail)}</div>`:''}
    ${i.evidence?`<div class="evidence" style="margin-top:6px">${esc(i.evidence)}</div>`:''}</div>`).join('');
  $('#scanDetail').innerHTML=`<div class="scan-wrap">
    <span class="sev ${escAttr(g.severity)}">${esc(g.severity)}</span>
    <div class="row" style="align-items:center;gap:10px;margin:12px 0 6px;flex-wrap:wrap">
      <h1 style="font-size:17px;font-weight:700;line-height:1.3;flex:1;margin:0;min-width:0">${esc(g.title)}</h1>
      <button class="btn accent" id="scanPromote" title="Create a curated finding from this issue — title, detail, fix, and every PoC flow attached">➕ Promote to Finding</button>
    </div>
    ${(shared&&first.detail)?`<p style="font-size:13px;color:var(--fg2);line-height:1.6">${esc(first.detail)}</p>`:''}
    <div style="font-size:9px;font-weight:700;letter-spacing:.6px;color:var(--fg3);margin:14px 0 6px">AFFECTED TARGETS (${g.items.length})</div>
    ${tgts}
    ${first.fix?`<div style="font-size:9px;font-weight:700;letter-spacing:.6px;color:var(--fg3);margin:14px 0 6px">REMEDIATION</div><div class="fixbox">${esc(first.fix)}</div>`:''}</div>`;
  $('#scanDetail').querySelectorAll('.scan-tgt[data-flow]').forEach(el=>{el.onclick=()=>flowPopup(Number(el.dataset.flow));wireRowKey(el,()=>flowPopup(Number(el.dataset.flow)));});
  const pm=$('#scanPromote'); if(pm) pm.onclick=()=>promoteFinding(g);
}
// promoteFinding turns a passive-scan issue group into a curated Finding (with all
// its PoC flows attached), then opens it — bridging the two views of "vulns" that
// were previously disconnected silos.
async function promoteFinding(g){
  const first=g.items[0]||{};
  const flowIds=g.items.map(i=>i.flowId).filter(Boolean);
  try{
    const f=await api('/api/findings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
      title:g.title,severity:g.severity,source:'scanner',
      detail:first.detail||'',evidence:first.evidence||'',fix:first.fix||'',
      flowIds,
    })});
    toast('Promoted to Finding #'+f.id+(flowIds.length?' · '+flowIds.length+' PoC flow'+(flowIds.length===1?'':'s'):''));
    openFinding(f.id);
  }catch(e){toast(e.message);}
}
$('#scanRun').onclick=runScan;
