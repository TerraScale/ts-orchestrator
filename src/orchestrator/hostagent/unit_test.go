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
// decision D-69 plus bounded locked memory and disabled core files.
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
SupplementaryGroups=terrascale-keylease
RuntimeDirectory=terrascale-database
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=no
ExecStartPre=/usr/bin/chgrp terrascale-keylease /run/terrascale-database
ExecStartPre=/usr/bin/chmod 0710 /run/terrascale-database
ExecStart=/opt/terrascale/terrabase/current/terrabase
Restart=on-failure
RestartSec=2s
LimitCORE=0
LimitMEMLOCK=268435456
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

func TestOrchestratorUnitPreparesOnlyDedicatedKeySocketDirectory(t *testing.T) {
	spec := testComponentSpec()
	spec.Name = "orchestrator"
	spec.User = "terrascale-orchestrator"
	spec.DataVolume = "/var/lib/terrascale/orchestrator"
	rendered, err := RenderSystemdUnit("/opt/terrascale", spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"User=terrascale-orchestrator\nGroup=terrascale-orchestrator\n", "SupplementaryGroups=terrascale-keylease\n", "RuntimeDirectoryMode=0700\n", "ExecStartPre=/usr/bin/chgrp terrascale-keylease /run/terrascale-keys\n", "ExecStartPre=/usr/bin/chmod 0710 /run/terrascale-keys\n"} {
		if !strings.Contains(rendered, required) {
			t.Fatalf("missing %q in unit %s", required, rendered)
		}
	}
	if strings.Contains(rendered, "Group=terrascale-terrabase") || strings.Contains(rendered, "DynamicUser=") {
		t.Fatal("service identity isolation lost")
	}
}
