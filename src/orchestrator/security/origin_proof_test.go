package security

import (
	"errors"
	"testing"
	"time"
)

func TestOriginProofInteropContract(t *testing.T) {
	now := time.Unix(2931234*600+1, 0)
	key := []byte("0123456789abcdef0123456789abcdef")
	got, err := MintOriginProofAt(key, "get", "/api/v1/reactive/views/v/log?offset=3", now)
	if err != nil {
		t.Fatal(err)
	}
	wantBody := "v1.GET./api/v1/reactive/views/v/log?offset=3.2931234"
	body, err := OriginProofBody("GET", "/api/v1/reactive/views/v/log?offset=3", 2931234)
	if err != nil || body != wantBody {
		t.Fatalf("body=%q err=%v, want %q", body, err, wantBody)
	}
	if err := VerifyOriginProof([][]byte{key}, got, "GET", "/api/v1/reactive/views/v/log?offset=3", now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyOriginProof([][]byte{key}, got, "POST", "/api/v1/reactive/views/v/log?offset=3", now); !errors.Is(err, ErrOriginProofMismatch) {
		t.Fatalf("method binding error=%v", err)
	}
}

func TestOriginProofAcceptsOnePreviousBucketOnly(t *testing.T) {
	now := time.Unix(2931234*600+1, 0)
	key := []byte("0123456789abcdef0123456789abcdef")
	previous, err := MintOriginProof(key, "GET", "/x", 2931233)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOriginProof([][]byte{key}, previous, "GET", "/x", now); err != nil {
		t.Fatalf("previous bucket should overlap: %v", err)
	}
	old, err := MintOriginProof(key, "GET", "/x", 2931232)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(VerifyOriginProof([][]byte{key}, old, "GET", "/x", now), ErrOriginProofExpired) {
		t.Fatal("proof older than one bucket was accepted")
	}
}

