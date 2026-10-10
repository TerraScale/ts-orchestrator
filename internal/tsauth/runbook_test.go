package tsauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTSAuthRunbookRequiresAutomaticDeliveryAndFailClosedStartup(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "ts-auth-deployment.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	for _, requirement := range []string{
		"OCI Vault must automatically create, deliver and configure",
		"Operators do not generate, upload or copy production keys.",
		"private NetBird admission, region discovery/inference and Vault creation/delivery",
		"loads it before the host service:",
		"rejected ruleset prevents host startup.",
		"every host start (including after reboot)",
		"Stopping the unit leaves the rule installed.",
		"Do not flush the global nftables ruleset.",
	} {
		if !strings.Contains(text, requirement) {
			t.Errorf("runbook missing requirement %q", requirement)
		}
	}
}
