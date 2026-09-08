package brokeradmission

import (
	"slices"
	"testing"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

func TestReaderGrantsRequireExactInventoryAndPreserveBaseline(t *testing.T) {
	public := func() string {
		pair, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		defer pair.Wipe()
		key, err := pair.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	first, second, existing := public(), public(), public()
	baseline := &server.Options{Accounts: []*server.Account{server.NewAccount("GLOBAL"), server.NewAccount("REGIONAL")}, Nkeys: []*server.NkeyUser{{Nkey: existing}}}
	policy := Policy{Regions: map[string]Accounts{"gru": {Global: "GLOBAL", Regional: "REGIONAL"}}}
	grants := []ReaderGrant{{BrokerID: "one", PublicNKey: first, Account: "GLOBAL"}, {BrokerID: "two", PublicNKey: second, Account: "GLOBAL"}}
	result, err := ApplyReaderGrants(baseline, grants, []string{"one", "two"}, policy)
	if err != nil || len(result.Nkeys) != 3 || len(baseline.Nkeys) != 1 || baseline.Nkeys[0].Nkey != existing {
		t.Fatalf("baseline altered or exact readers omitted: %v", err)
	}
	for name, edit := range map[string]func([]ReaderGrant){
		"foreign broker":   func(g []ReaderGrant) { g[0].BrokerID = "other" },
		"duplicate broker": func(g []ReaderGrant) { g[1].BrokerID = g[0].BrokerID },
		"duplicate key":    func(g []ReaderGrant) { g[1].PublicNKey = g[0].PublicNKey },
		"replace baseline": func(g []ReaderGrant) { g[0].PublicNKey = existing },
		"regional account": func(g []ReaderGrant) { g[0].Account = "REGIONAL" },
		"system account":   func(g []ReaderGrant) { g[0].Account = "$SYS" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := slices.Clone(grants)
			edit(bad)
			if _, err := ApplyReaderGrants(baseline, bad, []string{"one", "two"}, policy); err == nil {
				t.Fatal("reader inventory widened privileges")
			}
		})
	}
	if _, err := ApplyReaderGrants(baseline, grants[:1], []string{"one", "two"}, policy); err == nil {
		t.Fatal("incomplete reader inventory admitted")
	}
}
