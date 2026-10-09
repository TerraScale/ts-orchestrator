package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestTerraScaleSystemAdvertisesActualRaftIdentity(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()
	account, key := createAccount(s)
	s.setSystemAccount(account)
	client, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, key))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	message, err := client.Request("$SYS.REQ.SERVER.PING.STATSZ", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var stats ServerStatsMsg
	if err := json.Unmarshal(message.Data, &stats); err != nil {
		t.Fatal(err)
	}
	if stats.Server.RaftNodeID == "" || stats.Server.RaftNodeID != s.NodeName() || stats.Server.RaftNodeID != s.Node() {
		t.Fatalf("advertised identity differs from Raft: %+v", stats.Server)
	}
	if stats.Server.Name != opts.ServerName && opts.ServerName != "" {
		t.Fatalf("preparation changed the server name: %+v", stats.Server)
	}
}
