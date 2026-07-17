package starx

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"

	"go.starlark.net/starlark"
)

// AES-ECB helpers for message codecs. ECB is weak cryptographically but still
// common in client-side app crypto that operators need to unwrap during an
// engagement — expose it intentionally, sandboxed, with no other AES modes yet.

const aesMaxBytes = 1 << 20 // 1 MiB plaintext/ciphertext per call

func pkcs7Pad(b []byte, block int) []byte {
	n := block - (len(b) % block)
	if n == 0 {
		n = block
	}
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func pkcs7Unpad(b []byte, block int) ([]byte, error) {
	if len(b) == 0 || len(b)%block != 0 {
		return nil, fmt.Errorf("invalid padded length %d", len(b))
	}
	n := int(b[len(b)-1])
	if n == 0 || n > block || n > len(b) {
		return nil, fmt.Errorf("invalid PKCS7 padding")
	}
	for i := len(b) - n; i < len(b); i++ {
		if b[i] != byte(n) {
			return nil, fmt.Errorf("invalid PKCS7 padding")
		}
	}
	return b[:len(b)-n], nil
}

func aesKey(key []byte) ([]byte, error) {
	switch len(key) {
	case 16, 24, 32:
		return key, nil
	default:
		return nil, fmt.Errorf("AES key must be 16, 24, or 32 bytes (got %d)", len(key))
	}
}

// AESECBEncrypt pads with PKCS7 and encrypts with AES-ECB.
func AESECBEncrypt(key, plaintext []byte) ([]byte, error) {
	k, err := aesKey(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > aesMaxBytes {
		return nil, fmt.Errorf("plaintext too large (max %d bytes)", aesMaxBytes)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	in := pkcs7Pad(plaintext, block.BlockSize())
	out := make([]byte, len(in))
	bs := block.BlockSize()
	for i := 0; i < len(in); i += bs {
		block.Encrypt(out[i:i+bs], in[i:i+bs])
	}
	return out, nil
}

// AESECBDecrypt decrypts AES-ECB and strips PKCS7 padding.
func AESECBDecrypt(key, ciphertext []byte) ([]byte, error) {
	k, err := aesKey(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be a multiple of 16")
	}
	if len(ciphertext) > aesMaxBytes {
		return nil, fmt.Errorf("ciphertext too large (max %d bytes)", aesMaxBytes)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	bs := block.BlockSize()
	for i := 0; i < len(ciphertext); i += bs {
		block.Decrypt(out[i:i+bs], ciphertext[i:i+bs])
	}
	return pkcs7Unpad(out, bs)
}

func decodeKeyArg(s string) ([]byte, error) {
	// Prefer raw bytes; if it looks like hex of the right length, decode hex.
	if len(s) == 32 || len(s) == 48 || len(s) == 64 {
		if b, err := decodeHexLoose(s); err == nil {
			return b, nil
		}
	}
	return []byte(s), nil
}

func decodeHexLoose(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var v byte
		for _, c := range []byte{s[i*2], s[i*2+1]} {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v |= c - 'A' + 10
			default:
				return nil, fmt.Errorf("bad hex")
			}
		}
		out[i] = v
	}
	return out, nil
}

// AESECBEncryptBuiltin: aes_ecb_encrypt(key, plaintext) → base64 ciphertext.
// key may be raw string bytes (len 16/24/32) or hex of that length.
func AESECBEncryptBuiltin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, plaintext string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "plaintext", &plaintext); err != nil {
		return nil, err
	}
	kb, err := decodeKeyArg(key)
	if err != nil {
		return nil, fmt.Errorf("aes_ecb_encrypt: %w", err)
	}
	ct, err := AESECBEncrypt(kb, []byte(plaintext))
	if err != nil {
		return nil, fmt.Errorf("aes_ecb_encrypt: %w", err)
	}
	return starlark.String(base64.StdEncoding.EncodeToString(ct)), nil
}

// AESECBDecryptBuiltin: aes_ecb_decrypt(key, ciphertext) → plaintext string.
// ciphertext may be raw bytes (as Starlark string) or standard base64.
func AESECBDecryptBuiltin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, ciphertext string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "ciphertext", &ciphertext); err != nil {
		return nil, err
	}
	kb, err := decodeKeyArg(key)
	if err != nil {
		return nil, fmt.Errorf("aes_ecb_decrypt: %w", err)
	}
	raw := []byte(ciphertext)
	if dec, err := base64.StdEncoding.DecodeString(ciphertext); err == nil {
		raw = dec
	} else if dec, err := base64.RawStdEncoding.DecodeString(ciphertext); err == nil {
		raw = dec
	}
	pt, err := AESECBDecrypt(kb, raw)
	if err != nil {
		return nil, fmt.Errorf("aes_ecb_decrypt: %w", err)
	}
	return starlark.String(string(pt)), nil
}
