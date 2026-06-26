// discovery.js — Content discovery (forced-browse) tab. Brute-forces paths from
// a wordlist against a base URL via /api/discovery/*, streaming results over the
// SSE 'discovery.update' event. Found endpoints are (optionally) recorded as
// flows server-side, so they also show up in History and the Map.
import { $, esc, escAttr, api, toast, statusColor, fmtSize, copyText } from './core.js';

let wordlistLoaded = false;

// loadDiscovery runs when the tab is first opened: prime the wordlist textarea
// (once) from the built-in list, then render whatever run state exists.
export async function loadDiscovery(){
  if(!wordlistLoaded){
    wordlistLoaded = true;
    const ta = $('#dscWords');
    if(ta && !ta.value.trim()){
      try{ ta.value = await (await fetch('/api/discovery/wordlist')).text(); }catch(e){}
    }
    updateWordCount();
  }
  refreshDiscovery();
}

// refreshDiscovery re-fetches and renders the current/last run.
export async function refreshDiscovery(){
  try{ render(await api('/api/discovery/state')); }catch(e){}
}

// prefillDiscovery opens the Discover tab with the base URL filled in — used by
// the history right-click "Discover content on this host" action.
export function prefillDiscovery(baseUrl){
  const b = $('#dscBase');
  if(b) b.value = baseUrl;
  const tab = document.querySelector('.tab[data-tab="discover"]');
  if(tab) tab.click();
  loadDiscovery();
  if(b){ b.focus(); }
  toast('Discover ready for '+baseUrl+' — press Start');
}

function updateWordCount(){
  const ta = $('#dscWords'), out = $('#dscWordCount');
  if(!ta || !out) return;
  const n = ta.value.split('\n').filter(l=>{const t=l.trim();return t && !t.startsWith('#');}).length;
  out.textContent = n ? n+' words' : '';
}

function render(st){
  const running = !!(st && st.running);
  const start = $('#dscStart'), stop = $('#dscStop'), count = $('#dscCount');
  if(start) start.disabled = running;
  if(stop) stop.disabled = !running;
  if(count){
    const found = (st && st.found) || 0, tried = (st && st.tried) || 0;
    count.textContent = running ? `scanning… ${found} found / ${tried} tried`
      : tried ? `${found} found / ${tried} tried` : '';
  }
  const box = $('#dscResults');
  if(!box) return;
  const results = (st && st.results) || [];
  if(!results.length){
    if(running){ box.innerHTML = '<div class="hint" style="padding:16px">Calibrating &amp; probing…</div>'; return; }
    if(st && st.tried){ box.innerHTML = '<div class="empty" style="padding:24px">No paths found.<br>Try a bigger wordlist, add extensions, or check the base URL is reachable.</div>'; return; }
    return; // keep the initial hint
  }
  const rows = results.map(r=>{
    const c = statusColor(r.status);
    const dir = r.dir ? '<span title="directory" style="color:var(--fg3)"> /</span>' : '';
    const redir = r.redirect ? `<span class="hint" style="margin-left:8px">→ ${esc(r.redirect)}</span>` : '';
    const depth = r.depth ? `<span class="hint" style="margin-left:6px">d${r.depth}</span>` : '';
    return `<div class="trow" data-url="${escAttr(r.url)}" title="${escAttr(r.url)} — click to copy" style="display:flex;align-items:center;gap:10px;padding:5px 12px;border-bottom:1px solid var(--line);cursor:pointer">
      <span style="font-weight:700;color:${c};min-width:34px">${r.status||'—'}</span>
      <span class="hint" style="min-width:74px;text-align:right">${fmtSize(r.length||0)}</span>
      <span style="flex:1;font-family:var(--mono);font-size:12px;color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.path)}${dir}${depth}${redir}</span>
      <span class="hint" style="min-width:90px">${esc((r.contentType||'').split(';')[0])}</span>
    </div>`;
  }).join('');
  const note = st && st.note ? `<div class="hint" style="padding:6px 12px;color:var(--amber)">${esc(st.note)}</div>` : '';
  box.innerHTML = `<div style="position:sticky;top:0;background:var(--bg2);border-bottom:1px solid var(--line2);padding:5px 12px;display:flex;gap:10px;font-size:9px;font-weight:700;letter-spacing:.5px;color:var(--fg3)"><span style="min-width:34px">CODE</span><span style="min-width:74px;text-align:right">SIZE</span><span style="flex:1">PATH</span><span style="min-width:90px">TYPE</span></div>${rows}${note}`;
  box.querySelectorAll('.trow').forEach(el=>el.onclick=()=>copyText(el.dataset.url,'URL copied'));
}

async function start(){
  const base = ($('#dscBase')||{}).value;
  if(!base || !base.trim()){ toast('enter a base URL'); $('#dscBase')&&$('#dscBase').focus(); return; }
  const body = {
    baseUrl: base.trim(),
    wordlist: ($('#dscWords')||{}).value || '',
    extensions: ($('#dscExt')||{}).value || '',
    threads: parseInt(($('#dscThreads')||{}).value,10) || 20,
    delayMs: parseInt(($('#dscDelay')||{}).value,10) || 0,
    recursive: !!($('#dscRec')||{}).checked,
    maxDepth: parseInt(($('#dscDepth')||{}).value,10) || 0,
    filterLen: parseInt(($('#dscFilterLen')||{}).value,10) || 0,
    record: !!($('#dscRecord')||{}).checked,
  };
  try{ await api('/api/discovery/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}); refreshDiscovery(); }
  catch(e){ toast(e.message||'could not start'); }
}

async function stop(){
  try{ await api('/api/discovery/stop',{method:'POST'}); }catch(e){}
}

{const b=$('#dscStart'); if(b) b.onclick=start;}
{const b=$('#dscStop'); if(b) b.onclick=stop;}
{const b=$('#dscBase'); if(b) b.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();start();}});}
{const b=$('#dscWordBtn'); if(b) b.onclick=()=>{const w=$('#dscWordWrap'); if(!w) return; const open=w.style.display==='none'; w.style.display=open?'block':'none'; b.setAttribute('aria-expanded',String(open));};}
{const t=$('#dscWords'); if(t) t.addEventListener('input',updateWordCount);}
