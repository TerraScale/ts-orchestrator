package terrabase

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDataVolumeDryRunSizesFromThePlan reads the reviewed gru-1 plan: without
// --apply the command only prints the volume each member gets.
func TestDataVolumeDryRunSizesFromThePlan(t *testing.T) {
	plan := filepath.Join("..", "..", "deploy", "oci-region", "plan.json")
	var output bytes.Buffer
	if err := Run(t.Context(), []string{"data-volume", "--plan", plan, "--member", "gru-1-db-2",
		"--instance", "ocid1.instance.oc1.sa-saopaulo-1.member", "--compartment", "ocid1.compartment.oc1..workload"}, &output); err != nil {
		t.Fatal(err)
	}
	var got dataVolumeRequest
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := dataVolumeRequest{Step: "attach", Member: "gru-1-db-2", Volume: "gru-1-db-2-data", SizeGB: 50,
		Instance: "ocid1.instance.oc1.sa-saopaulo-1.member", Device: "/dev/oracleoci/oraclevdb",
		Compartment: "ocid1.compartment.oc1..workload", AvailabilityDomain: "YDvv:SA-SAOPAULO-1-AD-1", VPUsPerGB: 10}
	if got != want {
		t.Fatalf("dry run = %+v, want %+v", got, want)
	}
}

func TestDataVolumeRejectsUnplannedMembersAndAmbiguousFlags(t *testing.T) {
	plan := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(plan, []byte(`{"cell":"GRU","availability_domain":"AD-1","volume_vpus_per_gb":10,
		"hosts":[{"slot":"controller-a","data_gb":0},{"slot":"member-a","data_gb":50},{"slot":"member-b","data_gb":80}],
		"resource_ids":{"workload_compartment":null,"data_volumes":{"member-a":"ocid1.volume.a","member-b":null}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(t.Context(), []string{"data-volume", "--plan", plan, "--member", "gru-1-db-2", "--grow-gb", "100",
		"--compartment", "c"}, &output); err != nil || !strings.Contains(output.String(), `"step":"grow","apply":false`) ||
		!strings.Contains(output.String(), `"size_gb":80,"grow_gb":100`) {
		t.Fatalf("grow dry run = %q, %v", output.String(), err)
	}
	output.Reset()
	if err := Run(t.Context(), []string{"data-volume", "--plan", plan, "--member", "gru-1-db-1", "--instance", "i",
		"--compartment", "c"}, &output); err != nil || !strings.Contains(output.String(), `"recorded_volume":"ocid1.volume.a"`) {
		t.Fatalf("a recorded volume is not passed on: %q, %v", output.String(), err)
	}
	for name, args := range map[string][]string{
		"unplanned member":      {"--member", "gru-1-db-3", "--instance", "i", "--compartment", "c"},
		"controller":            {"--member", "gru-1-ctl-1", "--instance", "i", "--compartment", "c"},
		"other cell":            {"--member", "scl-1-db-1", "--instance", "i", "--compartment", "c"},
		"no compartment":        {"--member", "gru-1-db-1", "--instance", "i"},
		"instance and grow":     {"--member", "gru-1-db-1", "--instance", "i", "--grow-gb", "100", "--compartment", "c"},
		"neither instance/grow": {"--member", "gru-1-db-1", "--compartment", "c"},
	} {
		if err := Run(t.Context(), append([]string{"data-volume", "--plan", plan}, args...), &output); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestRestoreVolumeDryRunMakesNoOCICall(t *testing.T) {
	plan := filepath.Join("..", "..", "deploy", "oci-region", "plan.json")
	var output bytes.Buffer
	if err := Run(t.Context(), []string{"restore-volume", "--plan", plan, "--member", "gru-1-db-1", "--scratch-instance", "ocid1.instance.scratch",
		"--backup", "ocid1.volumebackup.daily", "--compartment", "ocid1.compartment.oc1..workload"}, &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"step":"restore","apply":false`, `"volume":"restore-gru-1-db-1-data"`, `"device":"/dev/oracleoci/oraclevdz"`,
		`"instance":"ocid1.instance.scratch"`,
		`"backup":"ocid1.volumebackup.daily"`} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("dry run %q lacks %s", output.String(), want)
		}
	}
	for name, args := range map[string][]string{
		"no scratch instance": {"--plan", plan, "--member", "gru-1-db-1", "--compartment", "c"},
		"unplanned member":    {"--plan", plan, "--member", "gru-1-db-9", "--scratch-instance", "i", "--compartment", "c"},
		"extra argument":      {"--plan", plan, "--member", "gru-1-db-1", "--scratch-instance", "i", "--compartment", "c", "extra"},
	} {
		if err := Run(t.Context(), append([]string{"restore-volume"}, args...), &output); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
