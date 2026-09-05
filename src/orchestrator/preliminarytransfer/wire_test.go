package preliminarytransfer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func wireSigner(t *testing.T) (*security.CommandSignatureSigner, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

type wireFixture struct {
	Name string `json:"name"`
}

func TestWireSignVerifyRefusals(t *testing.T) {
	signer, public := wireSigner(t)
	const domain = "TS-WIRE-TEST\x00"
	signed, err := signDocument(signer, domain, wireFixture{"valid"})
	if err != nil {
		t.Fatal(err)
	}
	var out wireFixture
	owner, err := verifyDocument(public, signed, domain, &out)
	wantOwner, _ := PublicKeyID(public)
	if err != nil || owner != wantOwner || out.Name != "valid" {
		t.Fatalf("round trip: %s %+v %v", owner, out, err)
	}
	_, other := wireSigner(t)
	for _, key := range [][]byte{other, append([]byte("\n"), public...), append(append([]byte(nil), public...), '\n'), append(append([]byte(nil), public...), public...)} {
		if _, err := verifyDocument(key, signed, domain, &out); err == nil {
			t.Fatal("incorrect or noncanonical key accepted")
		}
	}
	if _, err := verifyDocument(public, signed, "OTHER\x00", &out); err == nil {
		t.Fatal("wrong domain accepted")
	}
	for _, raw := range [][]byte{
		append(append([]byte(nil), signed...), '\n'),
		bytes.Replace(signed, []byte(`"signature":`), []byte(`"extra":0,"signature":`), 1),
		bytes.Replace(signed, []byte(`"valid"`), []byte(`"changed"`), 1),
		bytes.Repeat([]byte("x"), MaximumBytes+1),
	} {
		if _, err := verifyDocument(public, raw, domain, &out); err == nil {
			t.Fatal("malformed, modified or oversized wire accepted")
		}
	}
	// Even correctly signed ambiguous payloads must be rejected.
	for _, raw := range []string{`{"name":"valid","name":"valid"}`, `{"name":"valid","extra":0}`, `{"name": "valid"}`, `{"name":"valid"} {}`} {
		sig, err := signer.SignCanonicalMaterial(append([]byte(domain), []byte(raw)...))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(signedDocument{json.RawMessage(raw), sig.Bytes()})
		if err != nil { // Multiple JSON values cannot be marshaled into a RawMessage.
			var v wireFixture
			if canonicalDecode([]byte(raw), &v) == nil {
				t.Fatal("trailing JSON accepted")
			}
			continue
		}
		// json.Marshal compacts insignificant space, so preserve original payload spelling.
		wire = bytes.Replace(wire, []byte(`{"name":"valid"}`), []byte(raw), 1)
		if _, err := verifyDocument(public, wire, domain, &out); err == nil {
			t.Fatalf("ambiguous payload accepted: %s", raw)
		}
	}
	if _, err := signDocument(nil, domain, out); err == nil {
		t.Fatal("nil signer accepted")
	}
	// The payload fits alone, but signature and envelope push the wire over the cap.
	large := wireFixture{strings.Repeat("a", MaximumBytes-32)}
	payload, _ := json.Marshal(large)
	if len(payload) >= MaximumBytes {
		t.Fatal("bad bound fixture")
	}
	if _, err := signDocument(signer, domain, large); err == nil {
		t.Fatal("oversized signed envelope accepted")
	}
}

func TestWireValidators(t *testing.T) {
	if Digest(nil) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("digest mismatch")
	}
	if !validDigest(strings.Repeat("a", 64)) || validDigest(strings.Repeat("A", 64)) || validDigest(strings.Repeat("a", 63)) || !validSHA256("sha256:"+strings.Repeat("b", 64)) || validSHA256(strings.Repeat("b", 64)) {
		t.Fatal("digest validation")
	}
	if !validToken("gru-1") || validToken("GRU-1") || validToken("../a") {
		t.Fatal("token validation")
	}
	now := time.Now().UTC()
	if !finite(now, now.Add(24*time.Hour)) || finite(now, now) || finite(now, now.Add(24*time.Hour+time.Nanosecond)) || finite(time.Time{}, now) {
		t.Fatal("finite validation")
	}
	for _, key := range []string{"REGIONAL/EVENTS/epoch-1.snapshot", "one", "a_b/c.d"} {
		if !validObjectKey(key) {
			t.Fatalf("valid key rejected: %s", key)
		}
	}
	for _, key := range []string{"", "/a", "a/", "a//b", "a/./b", "a/../b", `a\b`, "a\nb", "a/%2e%2e/b", strings.Repeat("a", 1025)} {
		if validObjectKey(key) {
			t.Fatalf("unsafe key accepted: %q", key)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublicKeyID(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err == nil {
		t.Fatal("wrong curve accepted")
	}
}
