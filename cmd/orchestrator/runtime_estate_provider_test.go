package main

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func TestProductionEstateTokenRotationAndAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := productionEstateFile{Endpoint: "https://api.example.test", Database: "control", ProjectID: "project", TokenFile: path}
	client, closeClient, err := constructProductionEstateClient(config)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	if client == nil {
		t.Fatal("missing public client")
	}
	if err := os.WriteFile(path, []byte("second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	token, err := readProductionEstateToken(path)
	if err != nil || token != "second" {
		t.Fatalf("rotation = %q, %v", token, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readProductionEstateToken(path); err == nil {
		t.Fatal("accepted public token file")
	}
	config.Endpoint = "http://api.example.test"
	if err := config.validate(); err == nil {
		t.Fatal("accepted plaintext endpoint")
	}
}

func TestProductionEstateSnapshotPreservesMissingHostObservation(t *testing.T) {
	spec := estate.Spec{Regions: []estate.Region{{Code: "gru"}}}
	config := healthObservationConfig{Regions: []healthRegion{{Code: "gru", Latitude: new(0.0), Longitude: new(0.0), Members: []healthMember{{ID: "gru-one", Address: "10.0.0.1", Architecture: new(runtimeplan.HostArchitectureArm64)}, {ID: "gru-two", Address: "10.0.0.2", Architecture: new(runtimeplan.HostArchitectureArm64)}}}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "health.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	source := &productionEstateSource{health: &observedKVHealthSource{spec: spec, path: path, sample: func(context.Context, healthRegion) ([]hostagent.NodeStatusReport, error) {
		return []hostagent.NodeStatusReport{{NodeId: "gru-one", State: hostagent.NodeStateServing}}, nil
	}}}
	snapshot, err := source.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(snapshot.Hosts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"id":"gru-two","region":"gru","observed":false`) {
		t.Fatalf("missing host invented or lost: %s", body)
	}
	if len(snapshot.Documents()) != 6 {
		t.Fatal("incomplete projection")
	}
}

func TestProductionKVTransportFencesBeforeCredentialRead(t *testing.T) {
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, "https://api.cloudflare.com/client/v4/accounts/a", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &productionKVTransport{tokenFile: "/missing-credential"}
	if _, err := transport.RoundTrip(request); err == nil || !strings.Contains(err.Error(), "session is not active") {
		t.Fatalf("authority did not precede transport and credential access: %v", err)
	}
}
