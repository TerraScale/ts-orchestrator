package hostagent

import (
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
)

func testComponentSpec() hostmanifest.ComponentSpec {
	return hostmanifest.ComponentSpec{
		Name:           "terrabase",
		Version:        "1.2.3",
		ArtifactURL:    "https://releases.terrascale.tech/terrabase/1.2.3/terrabase",
		SignatureURL:   "https://releases.terrascale.tech/terrabase/1.2.3/terrabase.sig",
		Sha256:         strings.Repeat("0a", 32),
		User:           "terrascale-terrabase",
		DataVolume:     "/var/lib/terrascale/terrabase",
		CPUWeight:      200,
		MemoryMaxBytes: 8 << 30,
		IOWeight:       300,
	}
}

// TestRenderSystemdUnitIsPinnedToD69 asserts the exact directive list of
// decision D-69: every decided hardening directive is present, in the
// hardened shape, and nothing beyond the decided set plus the minimal unit
// scaffolding is rendered.
func TestRenderSystemdUnitIsPinnedToD69(t *testing.T) {
	rendered, err := RenderSystemdUnit("/opt/terrascale", testComponentSpec())
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	want := `[Unit]
Description=TerraScale terrabase 1.2.3
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=terrascale-terrabase
Group=terrascale-terrabase
ExecStart=/opt/terrascale/terrabase/current/terrabase
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/terrascale/terrabase
CapabilityBoundingSet=
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CPUWeight=200
MemoryMax=8589934592
IOWeight=300

[Install]
WantedBy=multi-user.target
`
	if rendered != want {
		t.Fatalf("unit drifted from the D-69 pin:\n%s", rendered)
	}
}

// TestRenderSystemdUnitNetlinkSwitch asserts AF_NETLINK appears only when a
// component declares it; no launch component does.
func TestRenderSystemdUnitNetlinkSwitch(t *testing.T) {
	spec := testComponentSpec()
	spec.NeedsNetlink = true
	rendered, err := RenderSystemdUnit("/opt/terrascale", spec)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if !strings.Contains(rendered, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n") {
		t.Fatalf("declared netlink missing: %s", rendered)
	}
}

// TestRenderSystemdUnitRejectsInvalidSpecs asserts the renderer revalidates
// its input at the trust boundary.
func TestRenderSystemdUnitRejectsInvalidSpecs(t *testing.T) {
	spec := testComponentSpec()
	spec.User = "root"
	if _, err := RenderSystemdUnit("/opt/terrascale", spec); err == nil {
		t.Fatal("root user accepted")
	}
	spec = testComponentSpec()
	spec.ArtifactURL = "http://insecure.example/terrabase"
	if _, err := RenderSystemdUnit("/opt/terrascale", spec); err == nil {
		t.Fatal("non-https artifact URL accepted")
	}
	spec = testComponentSpec()
	spec.CPUWeight = 0
	if _, err := RenderSystemdUnit("/opt/terrascale", spec); err == nil {
		t.Fatal("zero CPUWeight accepted")
	}
}
