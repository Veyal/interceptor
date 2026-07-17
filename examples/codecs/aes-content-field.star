# Example message codec: JSON field `content` = 32-char prefix + Base64(AES-ECB).
# Key material: first 16 bytes of SHA512(prefix + SECRET), passed as 32 hex chars.
#
# Copy into <project>/codecs/ (or Scanner → Codecs → New) and set SECRET from the
# client JS for the engagement. Display-only by default; set apply_on_send True
# to re-encrypt Repeater edits on Send.

meta = {
    "id": "aes-content-field",
    "title": "JSON content (prefix+AES-ECB)",
    "apply_on_send": False,
}

SECRET = "replace-me"

def _key(prefix):
    return hash("sha512", prefix + SECRET)[:32]

def match(flow, side):
    raw = flow.req_body if side == "req" else flow.res_body
    return '"content"' in raw

def decode(flow, side, raw):
    obj = json_decode(raw)
    blob = obj["content"]
    prefix = blob[:32]
    pt = aes_ecb_decrypt(_key(prefix), blob[32:])
    return {"plaintext": pt, "fields": {"content": pt}, "note": "prefix=" + prefix}

def encode(flow, side, plaintext):
    obj = json_decode(flow.req_body if side == "req" else flow.res_body)
    blob = obj["content"]
    prefix = blob[:32]
    obj["content"] = prefix + aes_ecb_encrypt(_key(prefix), plaintext)
    return json_encode(obj)
