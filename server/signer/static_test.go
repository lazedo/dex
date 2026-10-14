package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func writeStaticKeys(t *testing.T, path, kid string, verification ...*jose.JSONWebKey) *jose.JSONWebKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv := &jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
	pub := priv.Public()
	keys := map[string]any{"signingKey": priv, "signingKeyPub": &pub}
	vks := make([]map[string]any, 0, len(verification))
	for _, v := range verification {
		vks = append(vks, map[string]any{"publicKey": v, "expiry": time.Now().Add(time.Hour)})
	}
	keys["verificationKeys"] = vks
	b, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return &pub
}

func TestStaticSigner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	writeStaticKeys(t, path, "one")
	s, err := (&StaticConfig{KeysFile: path}).Open(slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	jws, err := s.Sign(ctx, []byte(`{"sub":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := (&KeySet{Signer: s}).VerifySignature(ctx, jws)
	if err != nil || string(payload) != `{"sub":"x"}` {
		t.Fatalf("verify: %q %v", payload, err)
	}
	if alg, _ := s.Algorithm(ctx); alg != jose.RS256 {
		t.Errorf("algorithm %s", alg)
	}
}

func TestStaticSignerReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	old := writeStaticKeys(t, path, "old")
	s, err := (&StaticConfig{KeysFile: path}).Open(slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	oldToken, _ := s.Sign(ctx, []byte(`{}`))

	// the new file signs with a new key and keeps the old one for verification
	time.Sleep(10 * time.Millisecond)
	writeStaticKeys(t, path, "new", old)
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(path, future, future)
	s.(*staticSigner).reloadIfChanged()

	keys, _ := s.ValidationKeys(ctx)
	if len(keys) != 2 || keys[0].KeyID != "new" || keys[1].KeyID != "old" {
		t.Fatalf("validation keys after reload: %+v", keys)
	}
	if _, err := (&KeySet{Signer: s}).VerifySignature(ctx, oldToken); err != nil {
		t.Errorf("a token of the old key no longer verifies: %v", err)
	}
	newToken, _ := s.Sign(ctx, []byte(`{}`))
	parsed, err := jose.ParseSigned(newToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || parsed.Signatures[0].Header.KeyID != "new" {
		t.Errorf("new tokens are not signed with the new key: %v", err)
	}
}

func TestStaticSignerRefusesPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	pub := writeStaticKeys(t, path, "pub")
	b, _ := json.Marshal(map[string]any{"signingKey": pub})
	_ = os.WriteFile(path, b, 0o600)
	if _, err := (&StaticConfig{KeysFile: path}).Open(slog.Default()); err == nil {
		t.Fatal("a public signing key was accepted")
	}
}
