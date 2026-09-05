package nodeauthority

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func TestReaderConfigExactJSON(t *testing.T) {
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	public, _ := pair.PublicKey()
	config := ReaderConfig{Endpoint: "tls://broker:4222", ServerName: "guest", Account: "GRU_REGIONAL", NKeySeedFile: "/etc/reader/seed", PublicNKey: public, CAFile: "/etc/reader/ca", CASHA256: strings.Repeat("a", 64), CertificateFile: "/etc/reader/cert", CertificateSHA256: strings.Repeat("b", 64), KeyFile: "/etc/reader/key"}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReaderConfig
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded != config {
		t.Fatalf("round trip: %v", err)
	}
	for name, wire := range map[string]string{
		"missing":   strings.Replace(string(raw), `"serverName":"guest",`, "", 1),
		"duplicate": strings.Replace(string(raw), `"serverName":"guest"`, `"serverName":"guest","serverName":"other"`, 1),
		"null":      strings.Replace(string(raw), `"serverName":"guest"`, `"serverName":null`, 1),
		"unknown":   strings.Replace(string(raw), `"serverName":"guest"`, `"serverName":"guest","extra":true`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var value ReaderConfig
			if err := json.Unmarshal([]byte(wire), &value); err == nil {
				t.Fatal("inexact identity accepted")
			}
		})
	}
}
