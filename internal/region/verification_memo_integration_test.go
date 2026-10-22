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
	if err := reader.validatePreparedOriginalDocument(f.bundle.GrantWire, first); err != nil || len(memo.entries) != 2 {
		t.Fatal("prepared grant check was not remembered", err)
	}
	if err := reader.validatePreparedOriginalDocument(f.bundle.GrantWire, first); err != nil || len(memo.entries) != 2 {
		t.Fatal("remembered prepared grant check changed", err)
	}

	t.Run("changed byte", func(t *testing.T) {
		changed := bytes.Clone(f.bundle.GrantWire)
		changed[len(changed)/2] ^= 1
		if _, _, err := reader.verifyOriginalDocument(changed); err == nil {
			t.Fatal("changed grant bytes reused a remembered verification")
		}
		if len(memo.entries) != 2 {
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
		if len(memo.entries) != 2 {
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

func TestOriginalRecordChecksRememberOnlyExactSuccesses(t *testing.T) {
	record := FoundationRecord{Cell: "GRU", Stage: "probe-" + time.Now().Format(time.RFC3339Nano)}
	calls := 0
	check := func(r FoundationRecord) error {
		calls++
		if r.Stage == "refused" {
			return ErrOriginalSourceProducerHold
		}
		return nil
	}
	if rememberOriginalRecordCheck("probe", record, check) != nil || rememberOriginalRecordCheck("probe", record, check) != nil || calls != 1 {
		t.Fatal("an identical successful record check was not remembered")
	}
	changed := record
	changed.Stage += "x"
	if rememberOriginalRecordCheck("probe", changed, check) != nil || calls != 2 {
		t.Fatal("a changed record reused a remembered check")
	}
	if rememberOriginalRecordCheck("other", record, check) != nil || calls != 3 {
		t.Fatal("a different check reused a remembered result")
	}
	refused := record
	refused.Stage = "refused"
	for range 2 {
		if rememberOriginalRecordCheck("probe", refused, check) == nil {
			t.Fatal("a refused record passed")
		}
	}
	if calls != 5 {
		t.Fatal("a refused record check was remembered")
	}
}
