package main

import (
	"encoding/json/v2"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
)

func TestPlacementHostConfigurationFailsClosed(t *testing.T) {
	options := &control.OrchestratorOptions{Cell: "gru", Instance: "member-a"}
	if _, err := startProductionPlacementHost(t.Context(), options, func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("missing placement control config accepted")
	}
	files := placementpublisher.TLSFiles{CertificateFile: "/etc/terrascale/cert", PrivateKeyFile: "/etc/terrascale/key", TrustBundleFile: "/etc/terrascale/ca"}
	valid := placementpublisher.HostFileConfig{Version: 1, Cell: "gru", Instance: "member-a", NATSURL: "tls://control.example:4222", NKeyFile: "/etc/terrascale/host.nkey", NATSIdentity: files, EngineTLS: files, EngineIdentity: "spiffe://terrascale.tech/production/member/a", EngineEndpoint: "127.0.0.1:8421"}
	data, _ := json.Marshal(valid)
	if _, err := placementpublisher.ParseHostFile(data, options.Cell, options.Instance); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte(`{"version":1,"cell":"gru","instance":"member-a","natsUrl":"nats://control:4222"}`),
		[]byte(`{"version":1,"cell":"gru","instance":"foreign","natsUrl":"tls://control:4222"}`),
		[]byte(`{"version":1,"cell":"gru","instance":"member-a","natsUrl":"tls://user:secret@control:4222"}`),
		[]byte(`{"version":1,"cell":"gru","instance":"member-a","natsUrl":"tls://control:4222","version":1}`),
		[]byte(`{"version":1,"cell":"gru","instance":"member-a","natsUrl":"tls://control:4222","ready":true}`),
	} {
		if _, err := placementpublisher.ParseHostFile(data, options.Cell, options.Instance); err == nil {
			t.Fatalf("invalid host configuration accepted: %s", data)
		}
	}
}
func TestProductionPlacementRequiresAdmittedPolicyAndTargets(t *testing.T) {
	if _, err := newProductionPlacement(productionPlacementConfig{}, globalWorkerSession{}); err == nil {
		t.Fatal("placement target and policy omission accepted")
	}
	runtime := new(productionRuntime)
	if err := runtime.AcceptPlacement(t.Context(), "host", "op", nil); err == nil {
		t.Fatal("placement accepted without active GRU session")
	}
}
