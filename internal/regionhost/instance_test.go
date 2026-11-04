package regionhost

import (
	"encoding/base64"
	"strings"
	"testing"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
)

func TestUserDataInstallsEveryUnitAndVerifiesTheBinary(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	script, err := userData(m1.Files, "https://github.com/TerraScale/ts-orchestrator/releases/download/ci-x/terrascale-orchestrator-linux-arm64", sum)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#!/bin/bash\n", "echo '" + sum + "  '\"$tmp\" | sha256sum -c --quiet",
		"/etc/systemd/system/ts-orch.service", "systemctl enable ts-orch.service\n", "apt-get install -y -qq netbird"} {
		if !strings.Contains(script, want) {
			t.Errorf("user data lacks %q", want)
		}
	}
	if strings.Contains(script, "netbird-server") || strings.Count(script, "/etc/systemd/system/") != 2 {
		t.Error("cloud-init installs a unit besides ts-orch.service; gru runs the one NetBird server")
	}
	runtime, _ := m1.Files.ReadFile("host-runtime.sh")
	if !strings.Contains(script, base64.StdEncoding.EncodeToString(runtime)) {
		t.Error("user data does not run host-runtime.sh")
	}
	if _, err := userData(m1.Files, "https://example.com/x';reboot;'", sum); err == nil {
		t.Error("a URL with quotes was accepted")
	}
	if _, err := userData(m1.Files, "https://example.com/x", "nothex"); err == nil {
		t.Error("a bad sha256 was accepted")
	}
}
