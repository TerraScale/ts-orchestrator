package manager

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestM1BootstrapReconcilesPeerDNSWithoutReplacingConnectedIdentities(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	home := f.peer(ids.server1)
	home.Name, home.Hostname, home.ConnectionIP = "gru-1-ctl-1", "ts-gru-2", "163.176.124.12"
	home.DNSLabel = "gru-1-ctl-1.netbird.selfhosted"
	home.LoginExpirationEnabled, home.InactivityExpirationEnabled = true, true
	spokes := []string{
		f.addPeer("ts-sjc-1", "163.192.54.17", true, time.Now(), ids.servers),
		f.addPeer("ts-fra-1", "130.162.238.198", true, time.Now(), ids.servers),
	}
	// A server-looking operator name neither migrates nor gains admission.
	operator := f.addPeer("gru-1-ctl-8", "203.0.113.8", true, time.Now(), ids.operators)
	count := len(f.peers)
	vault := newMemVault()
	server := ServerVault{Target: serverTarget, Management: vault, Versions: vault, Bundles: vault}
	if err := PrepareServer(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapServer(t.Context(), server, f.server.URL); err != nil {
		t.Fatal(err)
	}
	if len(f.peers) != count || home.ID != ids.server1 || home.Name != "ts-gru-1" ||
		!cleanLabel(home.apiPeer, "ts-gru-1") || !home.Connected || !home.SSHEnabled ||
		!home.LoginExpirationEnabled || !home.InactivityExpirationEnabled {
		t.Fatal("bootstrap failed to preserve the connected controller's identity and settings")
	}
	if rawString(f.account, "dns_domain") != "nb.ts.internal" || len(f.dnsGroups) != 0 {
		t.Fatal("bootstrap did not converge the peer domain and DNS management")
	}
	for _, id := range spokes {
		if peer := f.peer(id); peer == nil || !peer.Connected || !hasGroup(f.peerView(peer).Groups, ids.servers) {
			t.Fatal("bootstrap replaced or changed the admission of a connected spoke")
		}
	}
	if f.peer(operator).Name != "gru-1-ctl-8" || len(f.peerView(f.peer(operator)).Groups) != 1 {
		t.Fatal("operator hostname acquired server identity or membership")
	}
	for _, zone := range f.zones {
		if slices.ContainsFunc(zone.records, func(r apiRecord) bool {
			return strings.Contains(r.Name, "ts-sjc-1") || strings.Contains(r.Name, "ts-fra-1")
		}) {
			t.Fatal("spoke was published in the GRU cell zone")
		}
	}
	f.mutations = nil
	if err := BootstrapServer(t.Context(), server, f.server.URL); err != nil || len(f.mutations) != 0 {
		t.Fatalf("bootstrap did not converge: mutations=%v error=%v", f.mutations, err)
	}
}

func TestNodeRenameRefusesNameOrDNSLabelCollisionBeforeMutation(t *testing.T) {
	for _, scenario := range []string{"name", "label", "two legacy peers"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFakeManager(t)
			ids := f.seedLegacy(t)
			home := f.peer(ids.server1)
			home.Name = "gru-1-ctl-1"
			home.DNSLabel = "gru-1-ctl-1.netbird.selfhosted"
			holder := f.addPeer("other", "203.0.113.8", false, time.Now(), ids.operators)
			switch scenario {
			case "name":
				f.peer(holder).Name = "ts-gru-1"
			case "label":
				f.peer(holder).DNSLabel = "ts-gru-1.netbird.selfhosted"
			case "two legacy peers":
				f.addPeer("gru-1-ctl-1", "203.0.113.9", true, time.Now(), ids.servers)
			}
			if _, err := Sync(t.Context(), f.api(t), GRU(), true); err == nil || len(f.mutations) != 0 || home.Name != "gru-1-ctl-1" {
				t.Fatalf("ambiguous identity reached mutations: %v %v", f.mutations, err)
			}
		})
	}
}
