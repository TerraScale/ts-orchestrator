package regionhost

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestUserDataInstallsEveryUnitAndVerifiesTheBinary(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	script, err := userData(m1.Files, "https://github.com/TerraScale/ts-orchestrator/releases/download/ci-x/terrascale-orchestrator-linux-arm64", sum)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#!/bin/bash\n", "echo '" + sum + "  '\"$tmp\" | sha256sum -c --quiet",
		"/etc/systemd/system/ts-orch.service", "/etc/systemd/system/netbird-server.service",
		"systemctl enable ts-orch.service netbird-server.service\n", "apt-get install -y -qq netbird"} {
		if !strings.Contains(script, want) {
			t.Errorf("user data lacks %q", want)
		}
	}
	if strings.Count(script, "/etc/systemd/system/") != 4 {
		t.Error("cloud-init installs units besides ts-orch.service and the NetBird companion")
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

// A region's second host goes to its first host's AD in another fault domain
// (PIVOT D16), and a region with every fault domain taken launches nothing.
func TestSpreadPicksAFreeFaultDomainBesideTheRegionHost(t *testing.T) {
	domains := func(string) ([]string, error) {
		return []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"}, nil
	}
	first := core.Instance{AvailabilityDomain: new("AD-1"), FaultDomain: new("FAULT-DOMAIN-1"), TimeCreated: &common.SDKTime{Time: time.Unix(1, 0)}}
	ad, free, err := spread([]core.Instance{first}, domains)
	if err != nil || ad != "AD-1" || !slices.Equal(free, []string{"FAULT-DOMAIN-2", "FAULT-DOMAIN-3"}) {
		t.Fatalf("spread = %q %v %v, want AD-1 [FAULT-DOMAIN-2 FAULT-DOMAIN-3]", ad, free, err)
	}
	// Picking a new host's name must leave the region's hosts intact for spread.
	hosts := []core.Instance{first}
	if found, err := pick(hosts, "ts-sjc-2"); found != nil || err != nil {
		t.Fatalf("pick = %v %v", found, err)
	}
	if ad, free, err := spread(live(hosts), domains); err != nil || ad != "AD-1" || len(free) != 2 {
		t.Fatalf("spread after pick = %q %v %v", ad, free, err)
	}
	var full []core.Instance
	for _, name := range []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"} {
		full = append(full, core.Instance{AvailabilityDomain: new("AD-1"), FaultDomain: new(name), TimeCreated: first.TimeCreated})
	}
	if _, _, err := spread(full, domains); err == nil {
		t.Fatal("a fourth host was placed with every fault domain taken")
	}
}
