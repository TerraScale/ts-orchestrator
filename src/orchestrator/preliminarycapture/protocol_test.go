package preliminarycapture

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

func captureSigner(t *testing.T) (*security.CommandSignatureSigner, []byte) {
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
func captureRequest() Request {
	return Request{Version: 1, TransitionID: "transition-1", SourceNodeID: "gru-1", InitialGrantSHA256: strings.Repeat("a", 64), StoreScopeSHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64), Accounts: []AccountInventory{{Account: "REGIONAL", Streams: []string{"EVENTS", "KV_STATE"}}, {Account: "GLOBAL", Streams: []string{"SPEC"}}}, ControlEpoch: 1, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour)}
}
func verifiedRequest(t *testing.T) (VerifiedRequest, []byte) {
	t.Helper()
	signer, public := captureSigner(t)
	signed, err := SignRequest(signer, captureRequest())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRequest(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	return verified, signed
}
func TestRequestSignatureCanonicalScopeAndFiniteLifetime(t *testing.T) {
	signer, public := captureSigner(t)
	request := captureRequest()
	signed, err := SignRequest(signer, request)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRequest(public, signed)
	if err != nil || verified.Check(time.Now()) != nil {
		t.Fatalf("valid request: %+v %v", verified, err)
	}
	_, other := captureSigner(t)
	if _, err := VerifyRequest(other, signed); err == nil {
		t.Fatal("other owner accepted")
	}
	if verified.Check(request.IssuedAt.Add(-time.Nanosecond)) == nil || verified.Check(request.ExpiresAt) == nil {
		t.Fatal("request accepted outside finite lifetime")
	}
	changed := verified
	changed.Request.ControlEpoch++
	if changed.Check(time.Now()) == nil {
		t.Fatal("modified verification object accepted")
	}
	var doc signedDocument
	if json.Unmarshal(signed, &doc) != nil {
		t.Fatal("signed fixture")
	}
	mutations := [][]byte{append(append([]byte(nil), signed...), '\n'), bytes.Replace(signed, []byte(`"signature":`), []byte(`"unknown":0,"signature":`), 1), bytes.Replace(signed, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(signed, []byte(`"streams":[`), []byte(`"streams":[],"streams":[`), 1)}
	for _, raw := range mutations {
		if _, err := VerifyRequest(public, raw); err == nil {
			t.Fatalf("noncanonical request accepted: %s", raw)
		}
	}
	signature, err := signer.SignCanonicalMaterial(append([]byte(receiptDomain), doc.Payload...))
	if err != nil {
		t.Fatal(err)
	}
	doc.Signature = signature.Bytes()
	wrongDomain, _ := json.Marshal(doc)
	if _, err := VerifyRequest(public, wrongDomain); err == nil {
		t.Fatal("receipt-domain signature authorized request")
	}
	for _, change := range []func(*Request){func(r *Request) { r.ExpiresAt = r.IssuedAt.Add(24*time.Hour + time.Nanosecond) }, func(r *Request) { r.Accounts[0].Streams = []string{"Z", "A"} }, func(r *Request) { r.Accounts[1].Account = r.Accounts[0].Account }, func(r *Request) { r.ControlEpoch = 0 }, func(r *Request) { r.Accounts[0].Streams = []string{"../escape"} }} {
		r := captureRequest()
		change(&r)
		if _, err := SignRequest(signer, r); err == nil {
			t.Fatal("invalid request signed")
		}
	}
	large := captureRequest()
	for i := range large.Accounts {
		large.Accounts[i].Streams = nil
		for j := range 128 {
			large.Accounts[i].Streams = append(large.Accounts[i].Streams, strings.Repeat("A", 250)+string(rune('A'+j/26))+string(rune('A'+j%26)))
		}
	}
	if _, err := SignRequest(signer, large); err == nil {
		t.Fatal("oversize signed wire accepted")
	}
}
