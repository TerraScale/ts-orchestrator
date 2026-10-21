package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestGlobalControlHomeComesFromTopology(t *testing.T) {
	t.Parallel()
	home := natscell.Config{Cell: "gru"}
	spoke := natscell.Config{Cell: "sjc", Embedded: &natscell.Embedded{
		InterRegion: &natscell.InterRegion{Peers: []string{"gru"}, GlobalHome: "gru"},
	}}
	linkedHome := natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{
		InterRegion: &natscell.InterRegion{Peers: []string{"fra", "sjc"}, GlobalHome: "gru"},
	}}
	if peers := globalMirrorPeers(linkedHome); len(peers) != 2 || peers[0] != "fra" || peers[1] != "sjc" {
		t.Fatalf("home mirror peers = %v", peers)
	}
	if peers := globalMirrorPeers(home); peers != nil {
		t.Fatalf("standalone home mirror peers = %v", peers)
	}
	for name, tc := range map[string]struct {
		global *GlobalControlConfig
		nats   natscell.Config
		want   string
	}{
		"absent block":    {nil, home, "gru"},
		"empty block":     {&GlobalControlConfig{}, home, "gru"},
		"explicit home":   {&GlobalControlConfig{Home: "gru"}, home, "gru"},
		"derived spoke":   {nil, spoke, "gru"},
		"explicit spoke":  {&GlobalControlConfig{Home: "gru"}, spoke, "gru"},
		"linked home":     {nil, linkedHome, "gru"},
		"uppercase home":  {&GlobalControlConfig{Home: "GRU"}, home, ""},
		"reserved home":   {&GlobalControlConfig{Home: "global"}, home, ""},
		"unlinked spoke":  {&GlobalControlConfig{Home: "gru"}, natscell.Config{Cell: "sjc"}, ""},
		"mismatched home": {&GlobalControlConfig{Home: "fra"}, spoke, ""},
		"missing topology home": {nil, natscell.Config{Cell: "sjc", Embedded: &natscell.Embedded{
			InterRegion: &natscell.InterRegion{Peers: []string{"gru"}},
		}}, ""},
	} {
		got, err := globalControlHome(tc.global, tc.nats)
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("%s: home = %q, %v; want %q", name, got, err, tc.want)
		}
	}
}

func TestGlobalAndInterRegionRejectRemovedEnabledFields(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		for _, block := range []string{
			`"controller":{"global":{"enabled":` + value + `}}`,
			`"nats":{"embedded":{"interregion":{"enabled":` + value + `}}}`,
		} {
			if _, err := decodeConfig([]byte(`{"version":2,` + block + `}`)); err == nil {
				t.Fatalf("removed field accepted: %s", block)
			}
		}
	}
}

func TestGlobalControlAlwaysStartsWithHomeDeployment(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	cfg := Config{Version: ConfigVersion, NATS: natscell.Config{Cell: "gru", Instance: "home", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(dir, "nats")}},
		Controller: ControllerConfig{SpecTrust: authorityTestSpecTrust(t, dir, "gru")}}
	auth := newAuthenticatedNATS(t, "gru")
	newAcceptedSpecTrust(t, &cfg)
	cfg.NATS = auth.config(t, cfg.NATS)
	services, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.start(t, ctx, cfg.NATS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	global, err := startGlobalControl(ctx, cfg, broker.JetStream(), services.identity.DeploymentID,
		"0000000000C66H81REBS854264", nil, func() bool { return broker.FullClusterReady(1) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(global.close)
	local := global.authority.Current()
	observed, err := authority.Observe(ctx, broker.JetStream(), protocol.GlobalScope)
	if err != nil || !local.CanMutate() || local.Scope != protocol.GlobalScope ||
		local.DeploymentID != services.identity.DeploymentID || observed.DeploymentID != local.DeploymentID {
		t.Fatalf("global authority lost the home deployment: local=%+v observed=%+v err=%v", local, observed, err)
	}
}
