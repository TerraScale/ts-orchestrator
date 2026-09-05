package vmcontrolseed

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func membershipPublic(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
func TestGRUConfigurationParsesWithGuestBroker(t *testing.T) {
	guests := []Guest{{ID: "gru-member-2", Address: "10.77.0.11", MembershipPublicKey: membershipPublic(t)}, {ID: "gru-member-1", Address: "10.77.0.10", MembershipPublicKey: membershipPublic(t)}}
	materials, err := GenerateGRU("run1", guests)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range materials {
			m.Clear()
		}
	}()
	first, second := materials["gru-member-1"], materials["gru-member-2"]
	if !first.Selected || second.Selected || bytes.Equal(first.Files[NKeyPath], second.Files[NKeyPath]) || bytes.Equal(first.Files[PrivateKeyPath], second.Files[PrivateKeyPath]) {
		t.Fatal("controller ownership or identities not distinct")
	}
	for _, m := range materials {
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		config, err := initialgrant.ParseConfig([]byte(m.Settings))
		if err != nil {
			t.Fatal(err)
		}
		if config.Broker.Endpoint != "tls://10.77.0.10:4222" || config.SeedInstance != "gru-member-1" || len(config.Peers) != 2 || config.ProfileSHA256 == "" {
			t.Fatal("signed scope missing")
		}
		if strings.Contains(m.Settings, "TS_ORCH_") {
			t.Fatal("flat production configuration retained")
		}
		if !m.Selected {
			if config.Role != "participant" || config.Global != nil || config.Regional.Provisioner != nil || config.Broker.Configuration != "" || len(m.Files) != 8 {
				t.Fatal("participant received seed authority")
			}
			continue
		}
		size, err := m.DataDriveBytes()
		if err != nil || size <= config.Broker.StorageBudgetBytes || size < 1352<<20 {
			t.Fatal("disk cannot contain admitted topology")
		}
		root := t.TempDir()
		for path, data := range m.Files {
			target := filepath.Join(root, path)
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, data, 0400); err != nil {
				t.Fatal(err)
			}
		}
		broker := strings.ReplaceAll(config.Broker.Configuration, Directory, root+Directory)
		options := &natsserver.Options{}
		if err := options.ProcessConfigString(broker); err != nil {
			t.Fatal(err)
		}
		if options.Host != "10.77.0.10" || options.Port != 4222 || !options.JetStream || options.StoreDir != StorePath || options.MaxPayload != 4<<20 || options.TLSConfig.MinVersion != tls.VersionTLS13 || options.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || options.JetStreamMaxStore != config.Broker.StorageBudgetBytes {
			t.Fatal("broker production settings lost")
		}
		if len(options.Accounts) != 2 || len(options.Nkeys) != 9 {
			t.Fatal("account or candidate identity inventory differs")
		}
		counts := map[string]int{}
		for _, user := range options.Nkeys {
			counts[user.Account.Name]++
			if user.Permissions == nil || user.Permissions.Publish == nil || user.Permissions.Subscribe == nil {
				t.Fatal("broker user unrestricted")
			}
		}
		if counts[RegionalAccount] != 6 || counts[GlobalAccount] != 3 {
			t.Fatal("cross-account user assignment")
		}
	}
	for name, change := range map[string]func(*Material){"host": func(m *Material) { m.HostID = "gru-other" }, "broker": func(m *Material) { m.Settings = strings.ReplaceAll(m.Settings, "10.77.0.10", "10.77.0.1") }, "credential": func(m *Material) { m.Files[NKeyPath] = append([]byte(nil), second.Files[NKeyPath]...) }, "extra": func(m *Material) { m.Files["/tmp/secret"] = []byte("extra") }, "budget": func(m *Material) {
		var c initialgrant.Config
		json.Unmarshal([]byte(m.Settings), &c)
		c.Broker.StorageBudgetBytes = 64 << 20
		data, _ := json.Marshal(c)
		m.Settings = string(data)
	}} {
		t.Run(name, func(t *testing.T) {
			bad := first.Clone()
			defer bad.Clear()
			change(&bad)
			if bad.Validate() == nil {
				t.Fatal("changed material accepted")
			}
		})
	}
}
