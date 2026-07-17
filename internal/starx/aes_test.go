package starx

import (
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"go.starlark.net/starlark"
)

func TestAESECBRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	copy(key, []byte("0123456789abcdef"))
	pt := []byte(`{"recNumb":"42"}`)
	ct, err := AESECBEncrypt(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AESECBDecrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pt) {
		t.Fatalf("got %q want %q", got, pt)
	}
}

func TestAESECBBuiltinPrefixStyle(t *testing.T) {
	// Engagement-shaped: SHA512(prefix+secret)[:16] as AES-ECB key.
	secret := "test-secret"
	prefix := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 chars
	sum := sha512.Sum512([]byte(prefix + secret))
	key := sum[:16]
	pt := `{"accountName":"alice"}`
	ct, err := AESECBEncrypt(key, []byte(pt))
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(ct)

	thread := &starlark.Thread{Name: "t"}
	dec, err := starlark.Call(thread, starlark.NewBuiltin("aes_ecb_decrypt", AESECBDecryptBuiltin),
		starlark.Tuple{starlark.String(string(key)), starlark.String(b64)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.(starlark.String)) != pt {
		t.Fatalf("builtin decrypt = %q", dec)
	}
}
