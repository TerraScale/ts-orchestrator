package rootnetbird

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/nats-io/nkeys"
)

func TestManagerReadOpenRequiresOriginalDeliveryAndCurrentGuard(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only backend")
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	state := &managerReaderState{cell: "GRU", user: public, source: strings.Repeat("a", 64), deadline: deadline, guard: func(context.Context) error { return nil }}
	backend := &Backend{managerReader: state}
	proof := rootoci.NetBirdReadOpen{Schema: 1, Cell: state.cell, User: public, SourceSHA256: state.source, Nonce: entityid.Derive("netbird-read-test", "one"), ExpiresAt: deadline}
	proof.Signature, err = user.Sign(rootsecret.NetBirdReadOpenSigningBytes(proof))
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.checkManagerReadOpen(t.Context(), proof); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*rootoci.NetBirdReadOpen){
		"schema":    func(p *rootoci.NetBirdReadOpen) { p.Schema = 2 },
		"source":    func(p *rootoci.NetBirdReadOpen) { p.SourceSHA256 = strings.Repeat("b", 64) },
		"deadline":  func(p *rootoci.NetBirdReadOpen) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
		"nonce":     func(p *rootoci.NetBirdReadOpen) { p.Nonce = "" },
		"signature": func(p *rootoci.NetBirdReadOpen) { p.Signature = make([]byte, 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proof
			change(&changed)
			if backend.checkManagerReadOpen(t.Context(), changed) == nil {
				t.Fatal("accepted a changed original delivery")
			}
		})
	}
	state.guard = func(context.Context) error { return errors.New("original source lost") }
	if backend.checkManagerReadOpen(t.Context(), proof) == nil {
		t.Fatal("signature bypassed source loss")
	}
	backend.managerReader = nil
	if backend.checkManagerReadOpen(t.Context(), proof) == nil {
		t.Fatal("accepted a proof before genuine delivery")
	}
}
