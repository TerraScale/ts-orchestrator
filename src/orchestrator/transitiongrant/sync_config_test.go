package transitiongrant_test

import (
	"encoding/json"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func TestCandidateSyncConfigRequiresPinnedIsolatedBoundedInputs(t *testing.T) {
	_, public := owner(t)
	_, config := grantFixture()
	config.Sync = &transitiongrant.CandidateSyncConfig{AuthorityReaderSHA256: strings.Repeat("a", 64), RequestFile: "/etc/terrascale/candidate/sync.json", StagingDir: "/var/lib/terrascale/orchestrator/staging", ReceiptDir: "/var/lib/terrascale/orchestrator/receipts", ReceiptPrivateKeyFile: "/etc/terrascale/candidate/receipt.key", ReceiptPublicKeyPEM: string(public), MaxSnapshotBytes: 1 << 20, MaxTotalBytes: 4 << 20, MaxRestoreBytes: 8 << 20, Identity: ociinstance.Config{Region: "us-sanjose-1"}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := transitiongrant.ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Equal(parsed) || config.Sync == parsed.Sync {
		t.Fatal("independently decoded signed sync config differs")
	}
	component := hostmanifest.ComponentSpec{Name: "orchestrator", User: "terrascale-orchestrator", Arguments: transitiongrant.Arguments, Configuration: string(raw), DataVolume: "/var/lib/terrascale/orchestrator"}
	if _, ok, err := transitiongrant.ComponentConfig(component); err != nil || !ok {
		t.Fatal("valid candidate sync component rejected")
	}
	for name, mutate := range map[string]func(*transitiongrant.CandidateSyncConfig){
		"preparation grant collision": func(s *transitiongrant.CandidateSyncConfig) { s.RequestFile = config.GrantFile },
		"preparation owner collision": func(s *transitiongrant.CandidateSyncConfig) { s.ReceiptPrivateKeyFile = config.GrantPublicKeyFile },
		"reader pin":                  func(s *transitiongrant.CandidateSyncConfig) { s.AuthorityReaderSHA256 = "" },
		"reused ingress":              func(s *transitiongrant.CandidateSyncConfig) { s.RequestFile = s.ReceiptPrivateKeyFile },
		"staging final overlap":       func(s *transitiongrant.CandidateSyncConfig) { s.StagingDir = config.StoreDir + "/staging" },
		"receipt staging overlap":     func(s *transitiongrant.CandidateSyncConfig) { s.ReceiptDir = s.StagingDir },
		"receipt public":              func(s *transitiongrant.CandidateSyncConfig) { s.ReceiptPublicKeyPEM = "not a key" },
		"unbounded restore":           func(s *transitiongrant.CandidateSyncConfig) { s.MaxRestoreBytes = 1 << 40 },
		"small total":                 func(s *transitiongrant.CandidateSyncConfig) { s.MaxTotalBytes = 1 },
		"unknown OCI region":          func(s *transitiongrant.CandidateSyncConfig) { s.Identity.Region = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := config
			copy := *config.Sync
			changed.Sync = &copy
			mutate(changed.Sync)
			if err := changed.Validate(); err == nil {
				t.Fatal("invalid sync scope accepted")
			}
			if config.Equal(changed) {
				t.Fatal("changed sync config equals pinned original")
			}
		})
	}
	changed := config
	copy := *config.Sync
	changed.Sync = &copy
	changed.Sync.StagingDir = "/var/lib/other/staging"
	badRaw, _ := json.Marshal(changed)
	component.Configuration = string(badRaw)
	if _, _, err := transitiongrant.ComponentConfig(component); err == nil {
		t.Fatal("staging escaped component data volume")
	}
	changed.Sync.StagingDir = config.Sync.StagingDir
	changed.Sync.ReceiptPrivateKeyFile = component.DataVolume + "/receipt.key"
	badRaw, _ = json.Marshal(changed)
	component.Configuration = string(badRaw)
	if _, _, err := transitiongrant.ComponentConfig(component); err == nil {
		t.Fatal("private receipt key entered writable component data volume")
	}
	// A disabled existing declaration retains byte-identical canonical fields.
	config.Sync = nil
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"sync"`) {
		t.Fatal("disabled old config acquired sync fields")
	}
}
