package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStorageTargetsIncludeEveryNetBirdHostAndIgnoreConnectionState(t *testing.T) {
	data := `{"fqdn":"ts-gru-1.nb.ts.internal","netbirdIp":"10.200.1.1/16","peers":{"details":[
  {"fqdn":"ts-fra-1.nb.ts.internal","netbirdIp":"10.200.1.2","status":"Disconnected"},
  {"fqdn":"ts-fra-2.nb.ts.internal","netbirdIp":"10.200.1.3"},
  {"fqdn":"delta.nb.ts.internal","netbirdIp":"10.200.1.4"}]}}`
	targets, err := storageTargets([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("lost own host, disconnected host or same-region worker: %v", targets)
	}
	body, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "delta") {
		t.Fatal(string(body))
	}
	if _, err := storageTargets([]byte(strings.ReplaceAll(data, "10.200.1.3", "8.8.8.8"))); err == nil {
		t.Fatal("public address accepted")
	}
	if _, err := storageTargets([]byte(`{}`)); err == nil {
		t.Fatal("missing identity accepted")
	}
}
