package app

import (
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

func TestGlobalControlConfigDefaultsOffAndRequiresAMirrorLink(t *testing.T) {
	t.Parallel()

	home := natscell.Config{Cell: "gru"}
	spoke := natscell.Config{Cell: "sfo", Embedded: &natscell.Embedded{
		InterRegion: &natscell.InterRegion{Enabled: true, GlobalHome: "gru"},
	}}
	linkedHome := natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{
		InterRegion: &natscell.InterRegion{Enabled: true, Peers: []string{"fra", "sfo"}, GlobalHome: "gru"},
	}}
	if peers := globalMirrorPeers(linkedHome); len(peers) != 2 || peers[0] != "fra" || peers[1] != "sfo" {
		t.Fatalf("home mirror peers = %v", peers)
	}
	if peers := globalMirrorPeers(home); peers != nil {
		t.Fatalf("standalone home mirror peers = %v", peers)
	}
	global, err := startGlobalControl(t.Context(), Config{NATS: home}, nil, "a", nil, nil)
	if err != nil || global != nil {
		t.Fatalf("disabled global control started: %v, %v", global, err)
	}
	global.close()
	for name, tc := range map[string]struct {
		global *GlobalControlConfig
		nats   natscell.Config
		ok     bool
	}{
		"nil":             {nil, home, true},
		"disabled":        {&GlobalControlConfig{Home: "bad home"}, home, true},
		"home region":     {&GlobalControlConfig{Enabled: true, Home: "gru"}, home, true},
		"linked spoke":    {&GlobalControlConfig{Enabled: true, Home: "gru"}, spoke, true},
		"uppercase home":  {&GlobalControlConfig{Enabled: true, Home: "GRU"}, home, false},
		"global home":     {&GlobalControlConfig{Enabled: true, Home: "global"}, home, false},
		"unlinked spoke":  {&GlobalControlConfig{Enabled: true, Home: "gru"}, natscell.Config{Cell: "sfo"}, false},
		"mismatched home": {&GlobalControlConfig{Enabled: true, Home: "fra"}, spoke, false},
		"disabled link":   {&GlobalControlConfig{Enabled: true, Home: "gru"}, natscell.Config{Cell: "sfo", Embedded: &natscell.Embedded{InterRegion: &natscell.InterRegion{GlobalHome: "gru"}}}, false},
		"linked home":     {&GlobalControlConfig{Enabled: true, Home: "gru"}, linkedHome, true},
		"home link elsewhere": {&GlobalControlConfig{Enabled: true, Home: "gru"}, natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{
			InterRegion: &natscell.InterRegion{Enabled: true, Peers: []string{"sfo"}, GlobalHome: "sfo"},
		}}, false},
	} {
		err := validateGlobalControlConfig(tc.global, tc.nats)
		if (err == nil) != tc.ok {
			t.Errorf("%s: validate = %v, want ok=%v", name, err, tc.ok)
		}
	}
}
