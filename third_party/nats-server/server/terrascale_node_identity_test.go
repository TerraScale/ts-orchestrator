package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// TerraScale keeps only this regression from the vendored test suite; the
// helpers below are minimal copies of the upstream test helpers it used.
var terraScaleOperatorSeed = []byte("SOAFYNORQLQFJYBYNUGC5D7SH2MXMUX5BFEWWGHN3EK4VGG5TPT5DZP7QU")

func TestTerraScaleSystemAdvertisesActualRaftIdentity(t *testing.T) {
	operator, _ := nkeys.FromSeed(terraScaleOperatorSeed)
	operatorKey, _ := operator.PublicKey()
	opts := &Options{Host: "127.0.0.1", Port: -1, HTTPPort: -1, Cluster: ClusterOpts{Port: -1, Name: "abc"},
		NoLog: true, NoSigs: true, TrustedKeys: []string{operatorKey}, AccountResolver: &MemAccResolver{}}
	s, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	defer s.Shutdown()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}

	accountKeys, _ := nkeys.CreateAccount()
	accountKey, _ := accountKeys.PublicKey()
	accountJWT, _ := jwt.NewAccountClaims(accountKey).Encode(operator)
	s.AccountResolver().Store(accountKey, accountJWT)
	account, err := s.LookupAccount(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	s.setSystemAccount(account)

	userKeys, _ := nkeys.CreateUser()
	user := jwt.NewUserClaims("test")
	user.Subject, _ = userKeys.PublicKey()
	userJWT, err := user.Encode(accountKeys)
	if err != nil {
		t.Fatal(err)
	}
	client, err := nats.Connect(s.ClientURL(), nats.UserJWT(
		func() (string, error) { return userJWT, nil },
		func(nonce []byte) ([]byte, error) { return userKeys.Sign(nonce) }))
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
