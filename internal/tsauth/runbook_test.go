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
		"Only host root may access OCI instance metadata",
		"rejected ruleset prevent those startup paths.",
		"every dependent start reloads the rules.",
		"before APP migrates every legitimate",
		"a firewall does not revoke previously acquired credentials.",
		"Stopping the unit leaves the rule installed.",
		"Do not flush the global nftables ruleset.",
	} {
		if !strings.Contains(text, requirement) {
			t.Errorf("runbook missing requirement %q", requirement)
		}
	}
}
