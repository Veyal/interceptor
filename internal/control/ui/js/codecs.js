import { $, api, toast, openModal, closeModal, esc, state } from './core.js';

const TEMPLATE = `meta = {
    "id": "aes-content-field",
    "title": "JSON content (prefix+AES-ECB)",
    "apply_on_send": False,
}

# Engagement secret from client JS — replace per target.
SECRET = "replace-me"

def _key(prefix):
    return hash("sha512", prefix + SECRET)[:32]

def match(flow, side):
    raw = flow.req_body if side == "req" else flow.res_body
    return '"content"' in raw

def decode(flow, side, raw):
    obj = json_decode(raw)
    blob = obj.get("content") or ""
    if len(blob) < 33:
        return {"plaintext": raw, "note": "no content field"}
    prefix = blob[:32]
    pt = aes_ecb_decrypt(_key(prefix), blob[32:])
    return {"plaintext": pt, "fields": {"content": pt}, "note": "prefix=" + prefix}

def encode(flow, side, plaintext):
    obj = json_decode(flow.req_body if side == "req" else flow.res_body)
    blob = obj.get("content") or ""
    prefix = blob[:32] if len(blob) >= 32 else "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    obj["content"] = prefix + aes_ecb_encrypt(_key(prefix), plaintext)
    return json_encode(obj)
`;

let codecSel = '';

export async function loadCodecsList() {
  const box = $('#codecsList');
  if (!box) return;
  try {
    const d = await api('/api/codecs');
    const list = d.codecs || [];
    const dir = d.dir || '';
    const hint = $('#codecsDirHint');
    if (hint) hint.textContent = dir ? 'Project: ' + dir : 'No project codecs dir';
    if (!list.length) {
      box.innerHTML = '<div class="hint" style="padding:12px">No codecs yet. New → save a Starlark codec under this project.</div>';
      return;
    }
    box.innerHTML = list.map(c => {
      const err = c.error ? ' <span style="color:var(--red)">✗</span>' : '';
      const on = c.meta && c.meta.applyOnSend ? ' <span class="hint">send</span>' : '';
      return `<div class="h${codecSel === c.id ? ' sel' : ''}" data-id="${esc(c.id)}" tabindex="0" role="button">
        <div><b>${esc(c.id)}</b>${err}${on}</div>
        <div class="u hint">${esc((c.meta && c.meta.title) || '')}</div></div>`;
    }).join('');
    box.querySelectorAll('.h').forEach(el => {
      el.onclick = () => openCodec(el.dataset.id);
    });
  } catch (e) {
    box.innerHTML = '<div class="hint" style="padding:12px;color:var(--red)">' + esc(e.message) + '</div>';
  }
}

async function openCodec(id) {
  codecSel = id;
  try {
    const d = await api('/api/codecs/' + encodeURIComponent(id));
    $('#codecId').value = d.id || id;
    $('#codecSrc').value = d.source || '';
    loadCodecsList();
  } catch (e) { toast(e.message); }
}

export function openCodecs() {
  openModal($('#codecsModal'));
  codecSel = '';
  $('#codecId').value = '';
  $('#codecSrc').value = TEMPLATE;
  loadCodecsList();
}

function codecNew() {
  codecSel = '';
  $('#codecId').value = 'aes-content-field';
  $('#codecSrc').value = TEMPLATE;
  loadCodecsList();
}

async function codecSave() {
  const id = ($('#codecId').value || '').trim();
  const source = $('#codecSrc').value || '';
  if (!id) { toast('enter a codec id'); return; }
  try {
    await api('/api/codecs/' + encodeURIComponent(id), {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ source }),
    });
    codecSel = id;
    toast('codec saved');
    loadCodecsList();
  } catch (e) { toast(e.message); }
}

async function codecDelete() {
  const id = ($('#codecId').value || codecSel || '').trim();
  if (!id) return;
  try {
    await api('/api/codecs/' + encodeURIComponent(id), { method: 'DELETE' });
    toast('deleted');
    codecNew();
    loadCodecsList();
  } catch (e) { toast(e.message); }
}

async function codecTest() {
  const source = $('#codecSrc').value || '';
  const flowId = state.selId || 0;
  try {
    const d = await api('/api/codecs/test', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ source, flowId, side: 'req' }),
    });
    const out = $('#codecTestOut');
    if (!out) return;
    if (d.error) { out.textContent = d.error; return; }
    if (d.note && !d.matched) { out.textContent = d.note; return; }
    if (!d.matched) { out.textContent = 'no match on flow #' + (d.flowId || flowId || '?'); return; }
    out.textContent = (d.title || d.codecId || '') + '\n\n' + (d.plaintext || '') +
      (d.note ? '\n\n(' + d.note + ')' : '');
  } catch (e) { toast(e.message); }
}

if ($('#codecsBtn')) $('#codecsBtn').onclick = openCodecs;
if ($('#codecsClose')) $('#codecsClose').onclick = () => closeModal($('#codecsModal'));
if ($('#codecNew')) $('#codecNew').onclick = codecNew;
if ($('#codecSave')) $('#codecSave').onclick = codecSave;
if ($('#codecDelete')) $('#codecDelete').onclick = codecDelete;
if ($('#codecTest')) $('#codecTest').onclick = codecTest;
