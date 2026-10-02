package natscell

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
)

func TestInterRegionConfigFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	region := newTestRegion(t, root, "gru", HubAndSpoke("gru", []string{"sfo"}))
	leafTLS := testBridgeTLS(t, filepath.Join(root, "leaf"))
	region.cfg.Embedded.InterRegion.Listen = &LeafListen{Host: "127.0.0.1", Port: 7422, TLS: leafTLS}
	if err := region.cfg.validate(); err != nil {
		t.Fatalf("valid interregion config rejected: %v", err)
	}
	disabled := region.cfg
	embedded := *disabled.Embedded
	embedded.InterRegion = &InterRegion{Enabled: false}
	disabled.Embedded = &embedded
	if err := disabled.validate(); err != nil {
		t.Fatalf("disabled interregion block must be inert: %v", err)
	}
	remote := LeafRemote{Peer: "sfo", URLs: []string{"nats-leaf://10.0.0.1:7422"}, CredentialsFile: "x.creds",
		PeerAccount: region.interregionID, TLS: leafTLS}
	// gru is the global home in this fixture and the home never dials, so the
	// remote cases move the home to sfo to reach the remote checks themselves.
	withRemote := func(mutate func(*LeafRemote)) func(*InterRegion, *Config) {
		return func(ir *InterRegion, _ *Config) {
			bad := remote
			mutate(&bad)
			ir.Remotes = []LeafRemote{bad}
			ir.GlobalHome = "sfo"
		}
	}
	dialing := *region.cfg.Embedded.InterRegion
	dialing.Remotes, dialing.GlobalHome = []LeafRemote{remote}, "sfo"
	if err := dialing.validate(region.cfg); err != nil {
		t.Fatalf("valid remote of a non-home region rejected: %v", err)
	}
	cases := map[string]func(ir *InterRegion, cfg *Config){
		"lab":                     func(_ *InterRegion, cfg *Config) { cfg.Lab = true },
		"missing account":         func(ir *InterRegion, _ *Config) { ir.AccountJWTFile = "" },
		"no peers":                func(ir *InterRegion, _ *Config) { ir.Peers = nil },
		"self peer":               func(ir *InterRegion, _ *Config) { ir.Peers = []string{"gru"} },
		"global peer":             func(ir *InterRegion, _ *Config) { ir.Peers = []string{"global"} },
		"repeated peer":           func(ir *InterRegion, _ *Config) { ir.Peers = []string{"sfo", "sfo"} },
		"no links":                func(ir *InterRegion, _ *Config) { ir.Listen = nil },
		"listener sans mTLS":      func(ir *InterRegion, _ *Config) { ir.Listen.TLS = TLSFiles{} },
		"remote not a peer":       withRemote(func(r *LeafRemote) { r.Peer = "fra" }),
		"remote plain URL":        withRemote(func(r *LeafRemote) { r.URLs = []string{"nats://10.0.0.1:7422"} }),
		"remote URL userinfo":     withRemote(func(r *LeafRemote) { r.URLs = []string{"nats-leaf://u:p@10.0.0.1:7422"} }),
		"remote unpinned account": withRemote(func(r *LeafRemote) { r.PeerAccount = "" }),
		"remote without mTLS":     withRemote(func(r *LeafRemote) { r.TLS = TLSFiles{} }),
		"remote repeated": func(ir *InterRegion, _ *Config) {
			ir.Remotes, ir.GlobalHome = []LeafRemote{remote, remote}, "sfo"
		},
		"global home dials": func(ir *InterRegion, _ *Config) { ir.Remotes = []LeafRemote{remote} },
	}
	for name, mutate := range cases {
		cfg := region.cfg
		embedded := *cfg.Embedded
		ir := *embedded.InterRegion
		listen := *ir.Listen
		ir.Listen = &listen
		embedded.InterRegion = &ir
		cfg.Embedded = &embedded
		mutate(&ir, &cfg)
		if err := ir.validate(cfg); err == nil {
			t.Errorf("%s: invalid interregion config accepted", name)
		}
	}
}

func TestLeafCredentialsMustBeLeafOnlyPeerUsers(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	region := newTestRegion(t, root, "gru", HubAndSpoke("gru", []string{"sfo"}))
	leaf := region.leafCredentials(t, "leaf.creds")
	if err := validateLeafCredentials(leaf, region.interregionID); err != nil {
		t.Fatal(err)
	}
	if err := validateLeafCredentials(leaf, region.cellID); err == nil {
		t.Fatal("leaf credentials accepted for an unpinned account")
	}
	standard := testJWTUserCredentials(t, root, "standard.creds", region.interregion, region.interregionID, nil, nil)
	if err := validateLeafCredentials(standard, region.interregionID); err == nil {
		t.Fatal("non-leaf user accepted as leaf credentials")
	}
	// A leaf user with permissions of its own would override the peer
	// account's deny-by-default contract permissions.
	for name, mutate := range map[string]func(*jwt.UserClaims){
		"publish allow":   func(claim *jwt.UserClaims) { claim.Pub.Allow.Add(">") },
		"subscribe allow": func(claim *jwt.UserClaims) { claim.Sub.Allow.Add(">") },
		"publish deny":    func(claim *jwt.UserClaims) { claim.Pub.Deny.Add("x") },
		"responses":       func(claim *jwt.UserClaims) { claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1} },
	} {
		path := region.leafCredentialsWith(t, name+".creds", region.interregion, region.interregionID, mutate)
		if err := validateLeafCredentials(path, region.interregionID); err == nil {
			t.Errorf("%s: leaf credentials overriding the contract defaults accepted", name)
		}
	}
}

func TestResolverRefusesCellClaimThatWidensInterRegionContract(t *testing.T) {
	t.Parallel()

	keys := newTestRegionKeys(t)
	contract := InterRegionContract{Cell: "gru", Peers: []string{"sfo"}}
	system, cell, interregion := keys.claims(contract, 1)
	encode := func(claim *jwt.AccountClaims) string {
		t.Helper()
		raw, err := claim.Encode(keys.operator)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	resolver := newAccountResolver(keys.systemID, encode(system), keys.cellID, encode(cell))
	resolver.admitInterRegion(keys.interregionID, encode(interregion), contract, 1)
	// NATS issued-at has second resolution; a replacement must be later.
	time.Sleep(time.Until(time.Unix(cell.IssuedAt+1, 0)))
	widened := *cell
	widened.Limits.LeafNodeConn = -1
	if err := resolver.Store(keys.cellID, encode(&widened)); err == nil {
		t.Fatal("cell claim allowing leafnodes was stored")
	}
	if err := resolver.Store(keys.cellID, encode(cell)); err != nil {
		t.Fatalf("contract-preserving cell claim refused: %v", err)
	}
	if err := resolver.Store(keys.interregionID, encode(interregion)); err == nil {
		t.Fatal("interregion claim replaced through the cell update path")
	}
}
