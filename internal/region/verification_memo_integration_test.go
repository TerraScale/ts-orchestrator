package region

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestFoundationVerificationMemoNeverWidensTrust(t *testing.T) {
	f := newFoundationProvisionFixture(t)
	memo := newFoundationVerificationMemo()
	resolver, err := verifyRetainedFoundationWith(t.Context(), f.bundle, f.roots, memo)
	if err != nil {
		t.Fatal(err)
	}
	reader := resolver.Footprint.(*SignedFootprint)
	if reader.memo != memo {
		t.Fatal("resolved reader does not share the authority memo")
	}
	first, expires, err := reader.verifyOriginalDocument(f.bundle.GrantWire)
	if err != nil || len(memo.entries) != 1 {
		t.Fatal("verified grant was not remembered", err)
	}
	again, againExpires, err := reader.verifyOriginalDocument(f.bundle.GrantWire)
	if err != nil || !sameOriginalSourceValue(again, first) || !againExpires.Equal(expires) {
		t.Fatal("remembered grant differs from its full verification", err)
	}
	again.Regions[0].Plan["cell"] = "mutated"
	if third, _, err := reader.verifyOriginalDocument(f.bundle.GrantWire); err != nil || !sameOriginalSourceValue(third, first) {
		t.Fatal("caller mutation reached the remembered grant", err)
	}

	t.Run("changed byte", func(t *testing.T) {
		changed := bytes.Clone(f.bundle.GrantWire)
		changed[len(changed)/2] ^= 1
		if _, _, err := reader.verifyOriginalDocument(changed); err == nil {
			t.Fatal("changed grant bytes reused a remembered verification")
		}
		if len(memo.entries) != 1 {
			t.Fatal("refused grant was remembered")
		}
	})
	t.Run("revoked root", func(t *testing.T) {
		other, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		roots, err := trust.ParseKeyring(other)
		if err != nil {
			t.Fatal(err)
		}
		revoked := *reader
		revoked.roots = roots
		if _, _, err := revoked.verifyOriginalDocument(f.bundle.GrantWire); err == nil {
			t.Fatal("a different root set reused a remembered verification")
		}
		if len(memo.entries) != 1 {
			t.Fatal("refused root set was remembered")
		}
	})
	t.Run("expired entry", func(t *testing.T) {
		for key, entry := range memo.entries {
			entry.expiresAt = time.Now().Add(-time.Second)
			memo.entries[key] = entry
		}
		if _, _, err := reader.verifyOriginalDocument(f.bundle.GrantWire); !errors.Is(err, trust.ErrExpired) {
			t.Fatal("remembered verification outlived its signed validity", err)
		}
	})
}
