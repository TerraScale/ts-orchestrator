package natscell

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// TestClaimsUpdateCannotBypassTheContractCheck: the NATS CLAIMS.UPDATE
// handler installs a claim without calling the resolver's Store. A system
// account user (or a routed peer broker) sending an operator-signed cell
// claim that widens the interregion contract must not change the account;
// only ApplyCellClaim, which validates first, may install a claim.
func TestClaimsUpdateCannotBypassTheContractCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	region := newTestRegion(t, filepath.Join(root, "gru"), "gru", HubAndSpoke("gru", []string{"sfo"}))
	region.cfg.Embedded.InterRegion.Listen = &LeafListen{Host: "127.0.0.1", Port: freeClientPort(t),
		TLS: testBridgeTLS(t, filepath.Join(root, "leaf-tls"))}
	runtime, err := Start(ctx, region.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	initial := runtime.InitialCellJWT()
	contract := InterRegionContract{Cell: "gru", Peers: []string{"sfo"}, GlobalHome: "gru"}
	cellJWT := func(mutate func(*jwt.AccountClaims)) string {
		t.Helper()
		_, cell, _ := region.claims(contract, 1)
		mutate(cell)
		raw, err := cell.Encode(region.operator)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// NATS uses second-resolution iat; replacements must be issued later.
	time.Sleep(1100 * time.Millisecond)
	widened := cellJWT(func(cell *jwt.AccountClaims) {
		cell.Exports.Add(&jwt.Export{Subject: jwt.Subject(protocol.PlacementApplySubject("gru")), Type: jwt.Service})
	})

	// The resolver refuses it on the validated path.
	if err := runtime.ApplyCellClaim(ctx, 1, widened); err == nil {
		t.Fatal("ApplyCellClaim installed a claim that widens the contract")
	}
	// The system account user pushes it straight at the server. Before the
	// fix the server installed it without any contract check.
	reply, err := runtime.systemConn.RequestWithContext(ctx, "$SYS.REQ.ACCOUNT."+region.cellID+".CLAIMS.UPDATE", []byte(widened))
	if err == nil {
		t.Logf("CLAIMS.UPDATE answered: %s", reply.Data)
	}
	time.Sleep(300 * time.Millisecond)
	current, err := runtime.server.Accountz(&server.AccountzOptions{Account: region.cellID})
	if err != nil || current.Account == nil {
		t.Fatalf("accountz = %+v, %v", current, err)
	}
	if current.Account.Jwt != initial {
		t.Fatal("a CLAIMS.UPDATE request replaced the cell claim without the contract check")
	}
	if fetched, _ := runtime.resolver.Fetch(region.cellID); fetched != initial {
		t.Fatal("the resolver adopted a refused claim")
	}

	// A claim not signed by the pinned operator is refused before Store.
	_, foreign, _ := region.claims(contract, 1)
	other := newTestRegionKeys(t)
	foreignRaw, err := foreign.Encode(other.operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.ApplyCellClaim(ctx, 1, foreignRaw); err == nil {
		t.Fatal("ApplyCellClaim installed a claim from a foreign operator")
	}

	// A contract-preserving replacement still installs, exactly and locally.
	tightened := cellJWT(func(cell *jwt.AccountClaims) { cell.Limits.JetStreamLimits.Streams = 19 })
	if err := runtime.ApplyCellClaim(ctx, 1, tightened); err != nil {
		t.Fatalf("contract-preserving replacement: %v", err)
	}
	current, err = runtime.server.Accountz(&server.AccountzOptions{Account: region.cellID})
	if err != nil || current.Account == nil || current.Account.Jwt != tightened {
		t.Fatalf("replacement readback = %+v, %v", current, err)
	}
	// And a pushed claim cannot roll it back either.
	reply, err = runtime.systemConn.RequestWithContext(ctx, "$SYS.REQ.ACCOUNT."+region.cellID+".CLAIMS.UPDATE", []byte(initial))
	if err == nil {
		t.Logf("CLAIMS.UPDATE answered: %s", reply.Data)
	}
	time.Sleep(300 * time.Millisecond)
	current, err = runtime.server.Accountz(&server.AccountzOptions{Account: region.cellID})
	if err != nil || current.Account == nil || current.Account.Jwt != tightened {
		t.Fatal("a CLAIMS.UPDATE request rolled the cell claim back")
	}
}
