package regionhost

import (
	"encoding/base64"
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

func TestSizedPicksTodayOrTheSmallestHost(t *testing.T) {
	for shape, want := range map[string]machine{
		"":                    {shape: defaultShape, ocpus: 2, gb: 12, arch: "arm64"},
		"VM.Standard.A1.Flex": {shape: "VM.Standard.A1.Flex", ocpus: 1, gb: 6, arch: "arm64"},
		"VM.Standard.E4.Flex": {shape: "VM.Standard.E4.Flex", ocpus: 1, gb: 8, arch: "amd64"},
		"VM.Standard3.Flex":   {shape: "VM.Standard3.Flex", ocpus: 1, gb: 8, arch: "amd64"},
		"VM.Standard.A2.Flex": {shape: "VM.Standard.A2.Flex", ocpus: 1, gb: 6, arch: "arm64"},
	} {
		if got := sized(shape); got != want {
			t.Errorf("sized(%q) = %+v, want %+v", shape, got, want)
		}
	}
}

func TestPickAdoptsTheOldestLiveInstanceAsRegionHost(t *testing.T) {
	at := func(h int) *common.SDKTime {
		return &common.SDKTime{Time: time.Date(2026, 10, 21, h, 0, 0, 0, time.UTC)}
	}
	vm := func(name string, h int, state core.InstanceLifecycleStateEnum) core.Instance {
		return core.Instance{DisplayName: new(name), Id: new("id-" + name), TimeCreated: at(h), LifecycleState: state}
	}
	items := func() []core.Instance {
		return []core.Instance{vm("old-dead", 1, core.InstanceLifecycleStateTerminated), vm("ts-gru-2", 14, core.InstanceLifecycleStateRunning),
			vm("gru-1-ctl-1", 12, core.InstanceLifecycleStateRunning), vm("going", 2, core.InstanceLifecycleStateTerminating)}
	}
	if got, _ := pick(items(), ""); deref(got.DisplayName) != "gru-1-ctl-1" {
		t.Fatalf("region host = %v, want gru-1-ctl-1", deref(got.DisplayName))
	}
	if got, _ := pick(items(), "ts-gru-2"); deref(got.DisplayName) != "ts-gru-2" {
		t.Fatalf("--host ts-gru-2 = %v", deref(got.DisplayName))
	}
	if got, _ := pick(items(), "old-dead"); got != nil {
		t.Fatal("a terminated instance was adopted")
	}
	if got, _ := pick(nil, ""); got != nil {
		t.Fatal("an empty compartment has a host")
	}
	if _, err := pick(append(items(), vm("ts-gru-2", 15, core.InstanceLifecycleStateRunning)), "ts-gru-2"); err == nil {
		t.Fatal("two live instances with one name were accepted")
	}
}
