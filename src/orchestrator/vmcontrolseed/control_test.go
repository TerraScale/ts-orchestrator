package vmcontrolseed

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
)

func commandKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
func TestGRUConfigurationParsesWithGuestBroker(t *testing.T) {
	guests := []Guest{{ID: "gru-member-2", Address: "10.77.0.11", CommandPrivateKey: commandKey(t)}, {ID: "gru-member-1", Address: "10.77.0.10", CommandPrivateKey: commandKey(t)}}
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
		membership := commandKey(t)
		_, public, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(membership)
		if err != nil {
			t.Fatal(err)
		}
		pins, _ := json.Marshal(map[string]string{m.HostID: public})
		for path, data := range map[string][]byte{Directory + "/identity.pem": membership, Directory + "/membership-pins.json": pins} {
			if err := os.WriteFile(filepath.Join(root, path), data, 0400); err != nil {
				t.Fatal(err)
			}
		}
		settings := map[string]string{}
		if err := json.Unmarshal([]byte(m.Settings), &settings); err != nil {
			t.Fatal(err)
		}
		if settings["TS_ORCH_NATS_URL"] != "tls://10.77.0.10:4222" || settings["TS_ORCH_PROVIDER"] != "oci" {
			t.Fatal("wrong authority endpoint or provider")
		}
		for key, value := range settings {
			if strings.Contains(key, "OCI") {
				t.Fatal("fabricated estate settings")
			}
			settings[key] = strings.ReplaceAll(value, Directory, root+Directory)
		}
		if _, err := control.ParseOrchestratorOptions([]string{"run"}, func(key string) (string, bool) { value, ok := settings[key]; return value, ok }); err != nil {
			t.Fatal(err)
		}
		if m.Selected {
			config := strings.ReplaceAll(string(m.Files[ServerConfigPath]), Directory, root+Directory)
			options := &natsserver.Options{}
			if err := options.ProcessConfigString(config); err != nil {
				t.Fatal(err)
			}
			if options.Host != "10.77.0.10" || options.Port != 4222 || !options.JetStream || options.StoreDir != StorePath || options.MaxPayload != 4<<20 || options.TLSConfig.MinVersion != tls.VersionTLS13 || options.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
				t.Fatal("broker production settings lost")
			}
			if len(options.Accounts) != 1 || options.Accounts[0].Name != "GRU_CONTROL" || len(options.Nkeys) != 2 {
				t.Fatal("broker users escaped GRU account")
			}
		}
	}
	bad := first.Clone()
	bad.HostID = "other"
	if bad.Validate() == nil {
		t.Fatal("foreign host accepted")
	}
	bad.Clear()
	bad = first.Clone()
	bad.Files[ServerConfigPath] = bytes.ReplaceAll(bad.Files[ServerConfigPath], []byte("10.77.0.10"), []byte("10.77.0.1"))
	if bad.Validate() == nil {
		t.Fatal("root fixture broker accepted")
	}
	bad.Clear()
}
