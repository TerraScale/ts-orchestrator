package natscell

import (
	"path/filepath"
	"testing"
)

// TestInterRegionConfigMatchesItsTopology checks the runtime view of the
// whole leaf tree: with a topology configured, each region's peers,
// subtrees, remotes and global home must be exactly its view of that tree.
func TestInterRegionConfigMatchesItsTopology(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	tree := HubAndSpoke("gru", []string{"sfo", "fra"}).WithSpokeParent("fra", "sfo")
	region := newTestRegion(t, root, "gru", tree)
	leafTLS := testBridgeTLS(t, filepath.Join(root, "leaf"))
	region.cfg.Embedded.InterRegion.Listen = &LeafListen{Host: "0.0.0.0", Port: 7422, TLS: leafTLS}
	region.cfg.Embedded.InterRegion.Topology = &tree
	if err := region.cfg.validate(); err != nil {
		t.Fatalf("hub matching its topology rejected: %v", err)
	}
	remote := LeafRemote{Peer: "gru", URLs: []string{"nats-leaf://10.0.0.1:7422"}, CredentialsFile: "x.creds",
		PeerAccount: region.interregionID, TLS: leafTLS, ServerName: testLeafServerName}
	// sfo is a spoke with its own child fra: it dials gru and accepts fra.
	spoke := InterRegion{Enabled: true, Peers: []string{"gru", "fra"}, AccountJWTFile: "x.jwt", GlobalHome: "gru",
		Listen: &LeafListen{Host: "0.0.0.0", Port: 7422, TLS: leafTLS}, Subtrees: map[string][]string{"fra": {"fra"}},
		Remotes: []LeafRemote{remote}, Topology: &tree}
	spokeCfg := region.cfg
	spokeCfg.Cell = "sfo"
	if err := spoke.validate(spokeCfg); err != nil {
		t.Fatalf("spoke matching its topology rejected: %v", err)
	}
	cyclic := LeafTopology{Hub: "gru", Parents: map[string]string{"sfo": "fra", "fra": "sfo"}}
	cases := map[string]func(ir *InterRegion){
		"cyclic tree":          func(ir *InterRegion) { ir.Topology = &cyclic },
		"region not in tree":   func(ir *InterRegion) { other := HubAndSpoke("gru", []string{"fra"}); ir.Topology = &other },
		"home is not the hub":  func(ir *InterRegion) { ir.GlobalHome = "fra" },
		"extra roster peer":    func(ir *InterRegion) { ir.Peers = append(ir.Peers, "iad") },
		"missing roster peer":  func(ir *InterRegion) { ir.Peers = []string{"gru"} },
		"child not in tree":    func(ir *InterRegion) { ir.Subtrees = map[string][]string{"fra": {"fra"}, "gru": {"gru"}} },
		"subtree differs":      func(ir *InterRegion) { ir.Subtrees = map[string][]string{"fra": {}} },
		"dials the wrong peer": func(ir *InterRegion) { ir.Remotes = []LeafRemote{{Peer: "fra"}} },
		"dials no parent":      func(ir *InterRegion) { ir.Remotes = nil },
	}
	for name, mutate := range cases {
		candidate := spoke
		candidate.Peers = append([]string(nil), spoke.Peers...)
		mutate(&candidate)
		if err := candidate.matchTopology("sfo", *candidate.Topology); err == nil {
			t.Errorf("%s: config that differs from its topology accepted", name)
		}
	}
	// The hub never dials.
	hub := *region.cfg.Embedded.InterRegion
	hub.Remotes = []LeafRemote{remote}
	if err := hub.matchTopology("gru", tree); err == nil {
		t.Error("hub with a remote matched its topology")
	}
}
