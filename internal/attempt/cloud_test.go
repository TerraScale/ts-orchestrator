package attempt

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion"
)

// sampleLaunch has exactly the members `oci-region preview seed-launch`
// writes (internal/ociregion/seed.go seedLaunch).
const sampleLaunch = `{"availabilityDomain":"AD-1","faultDomain":"FAULT-DOMAIN-1","compartmentId":"ocid1.compartment.oc1..c","displayName":"gru-1-ctl-1","shape":"VM.Standard.A1.Flex","shapeConfig":{"ocpus":1,"memoryInGBs":6},"sourceDetails":{"sourceType":"image","imageId":"ocid1.image.fixture","bootVolumeSizeInGBs":50,"bootVolumeVpusPerGB":10},"subnetId":"ocid1.subnet.oc1..s","privateIp":"10.0.0.11","nsgIds":["ocid1.networksecuritygroup.oc1..n"],"assignPublicIp":false,"metadata":{"terrascale-bootstrap":"{\"schemaVersion\":1,\"slot\":\"controller-a\"}","user_data":"Y2xvdWQtaW5pdA=="},"freeformTags":{"BootstrapCreateKey":"seed-a"}}`

func TestLaunchDetailsCarriesTheSeedLaunchInputIntoTheVNIC(t *testing.T) {
	details, err := LaunchDetails([]byte(sampleLaunch))
	if err != nil {
		t.Fatal(err)
	}
	vnic := details.CreateVnicDetails
	if vnic == nil || *vnic.SubnetId != "ocid1.subnet.oc1..s" || *vnic.PrivateIp != "10.0.0.11" ||
		!slices.Equal(vnic.NsgIds, []string{"ocid1.networksecuritygroup.oc1..n"}) || vnic.AssignPublicIp == nil || *vnic.AssignPublicIp {
		t.Fatalf("vnic=%+v", vnic)
	}
	// The deprecated top-level subnet member stays unset: the VNIC carries it.
	if details.SubnetId != nil {
		t.Fatal("set the deprecated top-level subnet")
	}
	source, ok := details.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || *source.ImageId != "ocid1.image.fixture" || *source.BootVolumeSizeInGBs != 50 || *source.BootVolumeVpusPerGB != 10 {
		t.Fatalf("source=%+v", details.SourceDetails)
	}
	if *details.ShapeConfig.Ocpus != 1 || *details.ShapeConfig.MemoryInGBs != 6 || *details.DisplayName != "gru-1-ctl-1" ||
		*details.FaultDomain != "FAULT-DOMAIN-1" || details.Metadata["terrascale-bootstrap"] == "" || details.FreeformTags["BootstrapCreateKey"] != "seed-a" {
		t.Fatalf("details=%+v", details)
	}
}

func TestLaunchDetailsRefusesUnknownOrMissingMembers(t *testing.T) {
	var input map[string]any
	if err := json.Unmarshal([]byte(sampleLaunch), &input); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]any){
		"unknown":        func(m map[string]any) { m["hostnameLabel"] = "a" },
		"unknown-nested": func(m map[string]any) { m["sourceDetails"].(map[string]any)["kmsKeyId"] = "k" },
		"missing-ip":     func(m map[string]any) { delete(m, "privateIp") },
		"missing-public": func(m map[string]any) { delete(m, "assignPublicIp") },
		"volume-source":  func(m map[string]any) { m["sourceDetails"].(map[string]any)["sourceType"] = "bootVolume" },
	} {
		t.Run(name, func(t *testing.T) {
			copied := map[string]any{}
			b, _ := json.Marshal(input)
			if err := json.Unmarshal(b, &copied); err != nil {
				t.Fatal(err)
			}
			change(copied)
			b, _ = json.Marshal(copied)
			if _, err := LaunchDetails(b); err == nil {
				t.Fatal("accepted launch input")
			}
		})
	}
}

func TestLaunchRetryTokenBindsTheInputBytes(t *testing.T) {
	a, b := LaunchRetryToken([]byte(sampleLaunch)), LaunchRetryToken([]byte(sampleLaunch+" "))
	if a == b || a != LaunchRetryToken([]byte(sampleLaunch)) || len(a) > 64 {
		t.Fatal(a, b)
	}
}

type policyCloud struct {
	Cloud
	statements []string
	etag       string
	updated    [][]string
	matched    []string
	objects    map[string][]byte
	reads      int
}

func (p *policyCloud) PolicyStatements(context.Context, string) ([]string, string, error) {
	return p.statements, p.etag, nil
}
func (p *policyCloud) ReplacePolicyStatements(_ context.Context, _ string, etag string, statements []string) error {
	p.updated, p.matched = append(p.updated, statements), append(p.matched, etag)
	return nil
}
func (p *policyCloud) GetObject(_ context.Context, _, _, name string) ([]byte, bool, error) {
	p.reads++
	if p.reads == 1 {
		return nil, false, errors.New("transient read failure")
	}
	data, ok := p.objects[name]
	return data, ok, nil
}

func TestControllerObjectGrantsReplaceOnlyDifferingStatements(t *testing.T) {
	a := smallAttempt(t)
	a.Sleep = func(context.Context, time.Duration) error { return nil }
	plan := Object{"cell": "GRU", "region": "sa-saopaulo-1", "foundation_buckets": Object{"ledger": "ledger", "head": "head", "backup": "backup", "material": "material"}}
	ids := Object{"controller_policy": "ocid1.policy.oc1..p", "controller_dynamic_group": "ocid1.dynamicgroup.oc1..g",
		"control_compartment": "ocid1.compartment.oc1..c", "key": "ocid1.key.oc1.sa-saopaulo-1.k", "vault": "ocid1.vault.oc1.sa-saopaulo-1.v"}
	plan["resource_ids"] = ids
	cloud := &policyCloud{statements: []string{"stale"}, etag: "etag-1"}
	a.Cloud = cloud
	a.controllerObjectGrants(plan)
	want, err := ociregion.RequiredControllerStatements(plan, ids, a.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if a.Err() != nil || len(cloud.updated) != 1 || cloud.matched[0] != "etag-1" || !slices.Equal(cloud.updated[0], want) {
		t.Fatal(cloud.updated, cloud.matched)
	}
	cloud.statements = cloud.updated[0]
	a.controllerObjectGrants(plan)
	if a.Err() != nil || len(cloud.updated) != 1 {
		t.Fatal("rewrote matching statements", a.Err(), cloud.updated)
	}
}

func TestControllerObjectGrantsRefuseAnUnconditionalPolicyUpdate(t *testing.T) {
	a := smallAttempt(t)
	a.Sleep = func(context.Context, time.Duration) error { return nil }
	ids := Object{"controller_policy": "ocid1.policy.oc1..p", "controller_dynamic_group": "ocid1.dynamicgroup.oc1..g",
		"control_compartment": "ocid1.compartment.oc1..c", "key": "ocid1.key.oc1.sa-saopaulo-1.k", "vault": "ocid1.vault.oc1.sa-saopaulo-1.v"}
	plan := Object{"cell": "GRU", "region": "sa-saopaulo-1", "foundation_buckets": Object{"ledger": "ledger", "head": "head", "backup": "backup", "material": "material"}, "resource_ids": ids}
	cloud := &policyCloud{statements: []string{"stale"}}
	a.Cloud = cloud
	a.controllerObjectGrants(plan)
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "ETag") || len(cloud.updated) != 0 {
		t.Fatal("updated the policy without an ETag", a.Err(), cloud.updated)
	}
	if err := (&sdkCloud{}).ReplacePolicyStatements(t.Context(), "ocid1.policy.oc1..p", "", []string{"x"}); err == nil {
		t.Fatal("SDK cloud accepted an update without If-Match")
	}
}

func TestContinuityMarkerReadRetriesThenWritesExactBytes(t *testing.T) {
	a := smallAttempt(t)
	a.Out, a.ErrOut = io.Discard, io.Discard
	cloud := &policyCloud{objects: map[string][]byte{}}
	a.Cloud = cloud
	var slept int
	a.Sleep = func(context.Context, time.Duration) error {
		slept++
		// Publish every marker after the first failed read.
		for _, slot := range Slots {
			cloud.objects[a.markerObject(slot)] = []byte(`{"slot":"` + slot + `"}`)
		}
		return nil
	}
	a.writeJSON(a.Plan(), Object{"cell": "GRU", "foundation_buckets": Object{"head": "head"}})
	a.Runner = func(context.Context, Command) (string, error) { return "", errors.New("stop after markers") }
	a.PhaseContinuity()
	for _, slot := range Slots {
		b, err := os.ReadFile(a.Path("continuity", slot+".marker.json"))
		if err != nil || !strings.Contains(string(b), slot) {
			t.Fatal(slot, string(b), err)
		}
	}
	if slept != 1 {
		t.Fatal("slept", slept)
	}
}

func TestContinuityMarkerPollAnnouncesOncePerSlot(t *testing.T) {
	a := smallAttempt(t)
	var out strings.Builder
	a.Out, a.ErrOut = &out, io.Discard
	cloud := &policyCloud{objects: map[string][]byte{}}
	a.Cloud = cloud
	slept := 0
	a.Sleep = func(context.Context, time.Duration) error {
		// Publish every marker only after several empty polls.
		if slept++; slept == 3 {
			for _, slot := range Slots {
				cloud.objects[a.markerObject(slot)] = []byte(`{"slot":"` + slot + `"}`)
			}
		}
		return nil
	}
	a.writeJSON(a.Plan(), Object{"cell": "GRU", "foundation_buckets": Object{"head": "head"}})
	a.Runner = func(context.Context, Command) (string, error) { return "", errors.New("stop after markers") }
	a.PhaseContinuity()
	if cloud.reads < 3 {
		t.Fatalf("polled %d times, want several", cloud.reads)
	}
	if banners := strings.Count(out.String(), "accepted-install marker"); banners != len(Slots) {
		t.Fatalf("%d poll banners for %d slots:\n%s", banners, len(Slots), out.String())
	}
}

// The launch input writer and this strict reader live in different packages;
// a member added to or dropped from the writer must fail here, not at the
// next real launch.
func TestLaunchDetailsDecodesTheSeedLaunchWriterOutput(t *testing.T) {
	reviewed := ociregion.Object{"availability_domain": "AD-1", "fault_domain": "FAULT-DOMAIN-1",
		"compartment_id": "ocid1.compartment.oc1..c", "shape": "VM.Standard.A1.Flex", "ocpus": 1, "memory_gb": 6,
		"image_id": "ocid1.image.fixture", "boot_gb": 50, "boot_vpus_per_gb": 10, "subnet_id": "ocid1.subnet.oc1..s",
		"network_security_group_ids": []any{"ocid1.networksecuritygroup.oc1..n"}, "assign_public_ip": false,
		"create_identity": "seed-a"}
	host := ociregion.Object{"slot": "controller-a", "private_ip": "10.0.0.11"}
	metadata := ociregion.Object{"terrascale-bootstrap": `{"schemaVersion":1,"slot":"controller-a"}`, "user_data": "Y2xvdWQtaW5pdA=="}
	wire, err := json.Marshal(ociregion.SeedLaunchDocument(reviewed, host, "gru-1-ctl-1", metadata))
	if err != nil {
		t.Fatal(err)
	}
	details, err := LaunchDetails(wire)
	if err != nil {
		t.Fatalf("the seed-launch writer output does not decode: %v", err)
	}
	if *details.DisplayName != "gru-1-ctl-1" || *details.CreateVnicDetails.PrivateIp != "10.0.0.11" ||
		details.FreeformTags["BootstrapCreateKey"] != "seed-a" {
		t.Fatalf("details=%+v", details)
	}
}

// `oci-region preview member-launch` writes a C# database host launch input
// with the same strict shape; the static host tags must survive the decode.
func TestLaunchDetailsDecodesTheMemberLaunchWriterOutput(t *testing.T) {
	plan := ociregion.Object{"availability_domain": "AD-1", "volume_vpus_per_gb": 10, "orchestrator_owner": "ts-470-gru-rebuild-2",
		"resource_ids": ociregion.Object{"workload_compartment": "ocid1.compartment.oc1..w", "subnet": "ocid1.subnet.oc1..s",
			"workload_network_security_group": "ocid1.networksecuritygroup.oc1..w"}}
	host := ociregion.Object{"slot": "member-a", "fault_domain": "FAULT-DOMAIN-1", "private_ip": "10.251.0.21",
		"shape": "VM.Standard.A1.Flex", "ocpus": 1, "memory_gb": 6, "boot_gb": 50}
	metadata := ociregion.Object{"terrascale_hostboot_v1": `{"schema_version":2,"cell":"gru","region":"GRU","node":"gru-1-db-1"}`}
	wire, err := json.Marshal(ociregion.MemberLaunchDocument(plan, host, "gru-1-db-1", "ocid1.image.fixture", metadata))
	if err != nil {
		t.Fatal(err)
	}
	details, err := LaunchDetails(wire)
	if err != nil {
		t.Fatalf("the member-launch writer output does not decode: %v", err)
	}
	if *details.DisplayName != "gru-1-db-1" || *details.CreateVnicDetails.PrivateIp != "10.251.0.21" ||
		!slices.Equal(details.CreateVnicDetails.NsgIds, []string{"ocid1.networksecuritygroup.oc1..w"}) ||
		*details.CompartmentId != "ocid1.compartment.oc1..w" || *details.CreateVnicDetails.AssignPublicIp ||
		len(details.FreeformTags) != 3 || details.FreeformTags["terrascale-owner"] != "ts-470-gru-rebuild-2" ||
		details.FreeformTags["terrascale-resource"] != "terrabase-host" || details.FreeformTags["terrascale-host-node"] != "gru-1-db-1" {
		t.Fatalf("details=%+v", details)
	}
}

// A new deployment checks only its own ledger paths, so it can re-found a
// cell whose earlier deployment left records under the same prefix.
func TestSlotRecordPrefixesScopeToTheDeployment(t *testing.T) {
	prefixes := slotRecordPrefixes("gru-1", "ts-550-gru-refound-3")
	for name, want := range map[string]bool{
		"gru-1/bootstrap/v1/ts-550-gru-refound-3/abc/head.json":               true,
		"gru-1/bootstrap/v2/ts-550-gru-refound-3/abc/attempt-1/progress.json": true,
		"gru-1/bootstrap/v1/ts-470-gru-rebuild-2/abc/head.json":               false,
		"gru-1/bootstrap/v1/ts-550-gru-refound-30/abc/head.json":              false,
	} {
		matched := false
		for _, prefix := range prefixes {
			matched = matched || strings.HasPrefix(name, prefix)
		}
		if matched != want {
			t.Errorf("%s matched=%v, want %v", name, matched, want)
		}
	}
}

// An attempt whose installs adopted material generations renders their
// continuity from the chain it holds, not from its bootstrap material.
func TestContinuityRendersFromAdoptedGenerations(t *testing.T) {
	for _, adopted := range []bool{false, true} {
		a := smallAttempt(t)
		a.Out, a.ErrOut = io.Discard, io.Discard
		cloud := &policyCloud{objects: map[string][]byte{}}
		for _, slot := range Slots {
			cloud.objects[a.markerObject(slot)] = []byte(`{"slot":"` + slot + `"}`)
		}
		a.Cloud = cloud
		a.Sleep = func(context.Context, time.Duration) error { return nil }
		a.writeJSON(a.Plan(), Object{"cell": "GRU", "foundation_buckets": Object{"head": "head"}})
		chain := a.Path("material-generations.json")
		if adopted {
			a.WriteNew(chain, []byte("[]"))
		}
		var render []string
		a.Runner = func(_ context.Context, c Command) (string, error) {
			if render == nil {
				render = c.Args
			}
			return "", errors.New("stop after the first render")
		}
		a.PhaseContinuity()
		joined := strings.Join(render, " ")
		if !strings.Contains(joined, "render-founder-continuity") {
			t.Fatalf("first command = %q", joined)
		}
		if got := strings.Contains(joined, "--material-generations "+chain); got != adopted ||
			strings.Contains(joined, "--material-directory") == adopted {
			t.Fatalf("adopted=%v rendered with %q", adopted, joined)
		}
	}
}
