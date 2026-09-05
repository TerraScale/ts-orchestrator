package initialcontrol

import (
	"encoding/json"
	"testing"

	"github.com/nats-io/nats-server/v2/server"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func TestBrokerParserDoesNotReopenAdmittedTLSPaths(t *testing.T) {
	ref := initialgrant.TLSFiles{CertificateFile: "/missing/cert.pem", KeyFile: "/missing/key.pem", CAFile: "/missing/ca.pem"}
	tlsFields := map[string]any{"cert_file": ref.CertificateFile, "key_file": ref.KeyFile, "ca_file": ref.CAFile, "verify": true, "min_version": "1.3"}
	document := map[string]any{"port": -1, "tls": tlsFields, "accounts": map[string]any{"regional": map[string]any{}, "global": map[string]any{}}}
	config := func() initialgrant.Config {
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return initialgrant.Config{Broker: initialgrant.Broker{Configuration: string(raw), TLS: ref}}
	}
	raw, err := brokerConfigurationWithoutTLS(config())
	if err != nil {
		t.Fatal(err)
	}
	options := &server.Options{}
	if err := options.ProcessConfigString(string(raw)); err != nil {
		t.Fatalf("parser attempted to open missing credential paths: %v", err)
	}
	if options.TLSConfig != nil {
		t.Fatal("parser recreated TLS from paths")
	}
	for _, change := range []struct {
		key   string
		value any
	}{{"allow_non_tls", true}, {"verify", false}, {"min_version", "1.2"}, {"key_file", "/different/key.pem"}} {
		old, existed := tlsFields[change.key]
		tlsFields[change.key] = change.value
		if _, err := brokerConfigurationWithoutTLS(config()); err == nil {
			t.Fatalf("accepted changed TLS declaration %s", change.key)
		}
		if existed {
			tlsFields[change.key] = old
		} else {
			delete(tlsFields, change.key)
		}
	}
}
