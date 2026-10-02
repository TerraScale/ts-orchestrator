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
	} {
		err := validateGlobalControlConfig(tc.global, tc.nats)
		if (err == nil) != tc.ok {
			t.Errorf("%s: validate = %v, want ok=%v", name, err, tc.ok)
		}
	}
}
