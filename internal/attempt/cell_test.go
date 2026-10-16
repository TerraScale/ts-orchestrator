package attempt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport/imageimporttest"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// launchCloud records launches and reports every instance RUNNING after one
// pending read.
type launchCloud struct {
	Cloud
	launched []string // display names
	tokens   []string
	reads    map[string]int
	details  map[string]core.LaunchInstanceDetails // by instance ID
	unlisted bool                                  // ListInstances lags the launches
}

func (c *launchCloud) LaunchInstance(_ context.Context, details core.LaunchInstanceDetails, token string) (core.Instance, string, error) {
	c.launched, c.tokens = append(c.launched, *details.DisplayName), append(c.tokens, token)
	id := "ocid1.instance.oc1..i-" + *details.DisplayName
	if c.details == nil {
		c.details = map[string]core.LaunchInstanceDetails{}
	}
	c.details[id] = details
	return core.Instance{Id: &id, DisplayName: details.DisplayName}, "ocid1.workrequest.oc1..w", nil
}
func (c *launchCloud) ListInstances(context.Context, string) ([]Instance, error) {
	if c.unlisted {
		return nil, nil
	}
	var instances []Instance
	for _, name := range c.launched {
		instances = append(instances, Instance{ID: "ocid1.instance.oc1..i-" + name, DisplayName: name, LifecycleState: "RUNNING"})
	}
	return instances, nil
}

// GetInstance reports the instance as OCI would after the recorded launch.
func (c *launchCloud) GetInstance(_ context.Context, id string) (Instance, error) {
	if c.reads == nil {
		c.reads = map[string]int{}
	}
	d := c.details[id]
	launched := Instance{ID: id, LifecycleState: "RUNNING", DisplayName: deref(d.DisplayName), CompartmentID: deref(d.CompartmentId),
		AvailabilityDomain: deref(d.AvailabilityDomain), FaultDomain: deref(d.FaultDomain), Shape: deref(d.Shape),
		Metadata: d.Metadata, FreeformTags: d.FreeformTags}
	if d.ShapeConfig != nil {
		launched.OCPUs, launched.MemoryInGBs = *d.ShapeConfig.Ocpus, *d.ShapeConfig.MemoryInGBs
	}
	if source, ok := d.SourceDetails.(core.InstanceSourceViaImageDetails); ok {
		launched.ImageID = deref(source.ImageId)
	}
	if c.reads[id]++; c.reads[id] == 1 {
		launched.LifecycleState = "PROVISIONING"
	}
	return launched, nil
}

func flagValue(args []string, name string) string {
	if i := slices.Index(args, name); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

// cellAttempt is an attempt over the repository plan whose previews write
// their outputs; admissionLeft is the cost admission lifetime it reports.
func cellAttempt(t *testing.T, admissionLeft time.Duration, launch string) (*Attempt, *launchCloud, *[][]string) {
	t.Helper()
	a := smallAttempt(t)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return now }
	a.Sleep = func(context.Context, time.Duration) error { return nil }
	plan, err := os.ReadFile("../../deploy/oci-region/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.Plan(), plan, 0600); err != nil {
		t.Fatal(err)
	}
	a.writeJSON(a.Path("image", "import.json"), Object{"image_id": "ocid1.image.fixture"})
	cloud := &launchCloud{}
	a.Cloud = cloud
	var commands [][]string
	a.Runner = func(_ context.Context, c Command) (string, error) {
		commands = append(commands, c.Args)
		out := flagValue(c.Args, "--out")
		switch {
		case slices.Contains(c.Args, "inventory"):
			return "", os.WriteFile(out, []byte("{}"), 0600)
		case slices.Contains(c.Args, "admit"):
			return "", os.WriteFile(out, []byte(`{"expires_at":"`+now.Add(admissionLeft).Format(time.RFC3339Nano)+`"}`), 0600)
		case slices.Contains(c.Args, "member-launch"):
			name := map[string]string{"member-a": "gru-1-db-1", "member-b": "gru-1-db-2"}[flagValue(c.Args, "--slot")]
			return "", os.WriteFile(out, []byte(strings.Replace(launch, "gru-1-ctl-1", name, 1)), 0600)
		}
		return "", nil
	}
	if a.Err() != nil {
		t.Fatal(a.Err())
	}
	return a, cloud, &commands
}

func TestMembersLaunchEachDatabaseHostOnce(t *testing.T) {
	a, cloud, _ := cellAttempt(t, 10*time.Minute, sampleLaunch)
	a.PhaseMembers()
	if a.Err() != nil || !slices.Equal(cloud.launched, []string{"gru-1-db-1", "gru-1-db-2"}) {
		t.Fatal(a.Err(), cloud.launched)
	}
	for i, name := range cloud.launched {
		wire, err := os.ReadFile(a.Path("launch", name+"-launch.json"))
		if err != nil || cloud.tokens[i] != LaunchRetryToken(wire) {
			t.Fatal(name, "retry token does not bind the launch bytes", err)
		}
		id, err := os.ReadFile(a.Path("launch", name+".ocid"))
		if err != nil || string(id) != "ocid1.instance.oc1..i-"+name+"\n" || cloud.reads[strings.TrimSpace(string(id))] != 2 {
			t.Fatal(name, string(id), err, cloud.reads)
		}
		if !exists(a.Path("launch", name+"-launch-submit.json")) {
			t.Fatal(name, "submit record missing")
		}
	}
	a.PhaseMembers()
	if a.Err() != nil || len(cloud.launched) != 2 {
		t.Fatal("rerun launched again", a.Err(), cloud.launched)
	}
	// A run interrupted after the launch, before it wrote the OCID, adopts
	// the live host of that name when it is exactly this attempt's launch.
	if err := os.Remove(a.Path("launch", "gru-1-db-2.ocid")); err != nil {
		t.Fatal(err)
	}
	a.PhaseMembers()
	id, err := os.ReadFile(a.Path("launch", "gru-1-db-2.ocid"))
	if a.Err() != nil || len(cloud.launched) != 2 || err != nil || string(id) != "ocid1.instance.oc1..i-gru-1-db-2\n" {
		t.Fatal("interrupted launch was not adopted", a.Err(), cloud.launched, string(id), err)
	}
}

// A rerun whose instance list still lags an interrupted launch, while the
// inventory already holds the name, keeps the launch input that adoption
// needs; the next rerun adopts the instance.
func TestMembersKeepTheLaunchInputWhileTheLaunchIsUnresolved(t *testing.T) {
	a, cloud, _ := cellAttempt(t, 10*time.Minute, sampleLaunch)
	a.PhaseMembers()
	if a.Err() != nil {
		t.Fatal(a.Err())
	}
	input := a.Path("launch", "gru-1-db-2-launch.json")
	original, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(a.Path("launch", "gru-1-db-2.ocid")); err != nil {
		t.Fatal(err)
	}
	cloud.unlisted = true
	run := a.Runner
	a.Runner = func(ctx context.Context, c Command) (string, error) {
		if slices.Contains(c.Args, "member-launch") {
			return "", errors.New("gru-1-db-2 already exists in the inventory")
		}
		return run(ctx, c)
	}
	if a.PhaseMembers(); a.Err() == nil {
		t.Fatal("member-launch refusal was ignored")
	}
	if kept, err := os.ReadFile(input); err != nil || !bytes.Equal(kept, original) {
		t.Fatal("the unresolved launch input was replaced", err)
	}
	a.err, cloud.unlisted, a.Runner = nil, false, run
	launches := len(cloud.tokens)
	a.PhaseMembers()
	if id, err := os.ReadFile(a.Path("launch", "gru-1-db-2.ocid")); a.Err() != nil || err != nil ||
		string(id) != "ocid1.instance.oc1..i-gru-1-db-2\n" || len(cloud.tokens) != launches {
		t.Fatal("the interrupted launch was not adopted", a.Err(), err, cloud.tokens)
	}
}

// An instance of a host's name that this attempt cannot prove it launched
// (another deployment's host, or no retained launch input) is never adopted.
func TestMembersRefuseToAdoptAForeignInstanceOfTheName(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Attempt, *launchCloud)
	}{
		{"other metadata", func(_ *Attempt, cloud *launchCloud) {
			d := cloud.details["ocid1.instance.oc1..i-gru-1-db-2"]
			d.Metadata = map[string]string{"terrascale-host-enrollment-v1": "another deployment's bundle"}
			cloud.details["ocid1.instance.oc1..i-gru-1-db-2"] = d
		}},
		{"other owner tag", func(_ *Attempt, cloud *launchCloud) {
			d := cloud.details["ocid1.instance.oc1..i-gru-1-db-2"]
			d.FreeformTags = map[string]string{"terrascale-owner": "older-attempt"}
			cloud.details["ocid1.instance.oc1..i-gru-1-db-2"] = d
		}},
		{"no launch input", func(a *Attempt, _ *launchCloud) {
			if err := os.Remove(a.Path("launch", "gru-1-db-2-launch.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"resized after launch", func(_ *Attempt, cloud *launchCloud) {
			d := cloud.details["ocid1.instance.oc1..i-gru-1-db-2"]
			ocpus, memory := float32(4), float32(24)
			d.ShapeConfig = &core.LaunchInstanceShapeConfigDetails{Ocpus: &ocpus, MemoryInGBs: &memory}
			cloud.details["ocid1.instance.oc1..i-gru-1-db-2"] = d
		}},
		{"two live instances", func(_ *Attempt, cloud *launchCloud) { cloud.launched = append(cloud.launched, "gru-1-db-2") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, cloud, _ := cellAttempt(t, 10*time.Minute, sampleLaunch)
			a.PhaseMembers()
			if a.Err() != nil {
				t.Fatal(a.Err())
			}
			if err := os.Remove(a.Path("launch", "gru-1-db-2.ocid")); err != nil {
				t.Fatal(err)
			}
			test.change(a, cloud)
			launches := len(cloud.tokens)
			if a.PhaseMembers(); a.Err() == nil || !strings.Contains(a.Err().Error(), "reconcile") ||
				exists(a.Path("launch", "gru-1-db-2.ocid")) || len(cloud.tokens) != launches {
				t.Fatal("adopted or relaunched", a.Err(), cloud.tokens)
			}
		})
	}
}

func TestMembersLaunchNothingOnAShortAdmissionOrABadInput(t *testing.T) {
	a, cloud, _ := cellAttempt(t, 179*time.Second, sampleLaunch)
	a.PhaseMembers()
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "180 seconds") || len(cloud.launched) != 0 {
		t.Fatal(a.Err(), cloud.launched)
	}
	a, cloud, _ = cellAttempt(t, 10*time.Minute, strings.Replace(sampleLaunch, `"assignPublicIp":false,`, `"hostnameLabel":"x",`, 1))
	a.PhaseMembers()
	if a.Err() == nil || len(cloud.launched) != 0 || exists(a.Path("launch", "gru-1-db-1.ocid")) {
		t.Fatal(a.Err(), cloud.launched)
	}
}

func TestPlanPreviewsTheCellPlanWithoutLaunching(t *testing.T) {
	a, cloud, commands := cellAttempt(t, 10*time.Minute, sampleLaunch)
	a.Config["terrabase_profile"] = "/etc/terrabase/profile.json"
	if err := a.Phase("plan"); err != nil {
		t.Fatal(err)
	}
	if len(*commands) != 2 || !slices.Contains((*commands)[0], "inventory") || flagValue((*commands)[0], "--out") != a.Path("plan-inventory.json") {
		t.Fatal(*commands)
	}
	want := []string{a.Executable, "oci-region", "preview", "cell-plan", "--plan", a.Plan(), "--inventory", a.Path("plan-inventory.json"), "--profile", "/etc/terrabase/profile.json"}
	if !slices.Equal((*commands)[1], want) || len(cloud.launched) != 0 {
		t.Fatal((*commands)[1], cloud.launched)
	}
	if slices.Contains(Phases, "plan") {
		t.Fatal("plan is part of up")
	}
	// Before material writes the attempt plan, the dry run reads base_plan.
	a, _, commands = cellAttempt(t, 10*time.Minute, sampleLaunch)
	if err := os.Remove(a.Plan()); err != nil {
		t.Fatal(err)
	}
	a.Config["base_plan"] = "/reviewed/plan.json"
	if err := a.Phase("plan"); err != nil {
		t.Fatal(err)
	}
	if flagValue((*commands)[0], "--plan") != "/reviewed/plan.json" || flagValue((*commands)[1], "--plan") != "/reviewed/plan.json" {
		t.Fatal(*commands)
	}
}

const terrabaseCommit = "641274f7482bcf0ce2ae556af8be162d49e445be"

// taggedCommit is the commit `git rev-parse` resolves a version tag to.
var taggedCommit = terrabaseCommit

// terrabaseAttempt has the arm64 release fixture already downloaded.
func terrabaseAttempt(t *testing.T, commit string) (*Attempt, *[][]string) {
	t.Helper()
	a := smallAttempt(t)
	a.Config["terrabase"] = Object{"tag": "ci-" + terrabaseCommit + "-run-1", "commit": commit, "environment": "canary"}
	a.Config["terrabase_profile"] = "/etc/terrabase/profile.json"
	for _, asset := range []string{"terrabase-linux-arm64", "terrabase-linux-arm64.sha256"} {
		b, err := os.ReadFile(filepath.Join("..", "terrabase", "testdata", asset))
		if err == nil {
			err = a.WriteNew(a.Path("terrabase", "ci-"+terrabaseCommit+"-run-1", asset), b)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	var commands [][]string
	a.Runner = func(_ context.Context, c Command) (string, error) {
		commands = append(commands, c.Args)
		if slices.Contains(c.Args, "rev-parse") {
			return taggedCommit + "\n", nil
		}
		if c.Args[0] == "gh" {
			b, err := os.ReadFile(filepath.Join("..", "terrabase", "testdata", flagValue(c.Args, "--pattern")))
			if err != nil {
				return "", err
			}
			return "", os.WriteFile(flagValue(c.Args, "--output"), b, 0600)
		}
		return "", nil
	}
	return a, &commands
}

func TestTerraBaseRollsOutTheVerifiedRelease(t *testing.T) {
	a, commands := terrabaseAttempt(t, terrabaseCommit)
	a.PhaseTerraBase()
	binary, source := a.Path("terrabase", "ci-"+terrabaseCommit+"-run-1", "terrabase-linux-arm64"), a.Path("terrabase", "source")
	want := [][]string{
		{"git", "clone", "--quiet", "https://github.com/TerraScale/terrabase", source},
		{"git", "-C", source, "cat-file", "-e", terrabaseCommit + "^{commit}"},
		{"sudo", "--preserve-env=PATH,LIBGUESTFS_PATH", a.Path("release", OperatorCLI), "operator", "terrabase-release",
			"--config", "/var/lib/terrascale-operator/operator.json", "--binary", binary, "--sha256", binary + ".sha256",
			"--source-checkout", source, "--commit", terrabaseCommit, "--environment", "canary",
			"--profile", "/etc/terrabase/profile.json", "--wait", "10m"},
	}
	if a.Err() != nil || !slices.EqualFunc(*commands, want, slices.Equal) {
		t.Fatal(a.Err(), *commands)
	}
	// A later release fetches the existing clone and downloads its own
	// assets into its own tag directory.
	a.mkdir(source)
	a.Config["terrabase"] = Object{"tag": "v0.2.0", "commit": terrabaseCommit, "environment": "canary"}
	*commands = nil
	a.PhaseTerraBase()
	next := a.Path("terrabase", "v0.2.0", "terrabase-linux-arm64")
	if a.Err() != nil || len(*commands) != 6 ||
		!slices.Equal((*commands)[0], []string{"gh", "release", "download", "v0.2.0", "--repo", "TerraScale/terrabase", "--pattern", "terrabase-linux-arm64", "--output", next}) ||
		!slices.Equal((*commands)[2], []string{"git", "-C", source, "fetch", "--quiet", "--tags", "origin"}) ||
		!slices.Equal((*commands)[4], []string{"git", "-C", source, "rev-parse", "--verify", "--end-of-options", "v0.2.0^{commit}"}) ||
		flagValue((*commands)[5], "--binary") != next {
		t.Fatal(a.Err(), *commands)
	}
	for _, tag := range []string{"../v1", "v1/x", ".hidden"} {
		a, commands = terrabaseAttempt(t, terrabaseCommit)
		a.Config["terrabase"] = Object{"tag": tag, "commit": terrabaseCommit, "environment": "canary"}
		if a.PhaseTerraBase(); a.Err() == nil || len(*commands) != 0 {
			t.Fatal(tag, a.Err(), *commands)
		}
	}
}

// The rollout records the configured commit as the binary's source, so a
// release tag naming another commit stops before the operator command.
func TestTerraBaseRefusesACommitTheReleaseTagDoesNotName(t *testing.T) {
	other := strings.Repeat("a", 40)
	a, commands := terrabaseAttempt(t, other)
	if a.PhaseTerraBase(); a.Err() == nil || !strings.Contains(a.Err().Error(), "not the configured") || len(*commands) != 0 {
		t.Fatal("CI tag of another commit", a.Err(), *commands)
	}
	a, commands = terrabaseAttempt(t, terrabaseCommit)
	a.Config["terrabase"] = Object{"tag": "v0.2.0", "commit": terrabaseCommit, "environment": "canary"}
	taggedCommit = other
	t.Cleanup(func() { taggedCommit = terrabaseCommit })
	a.PhaseTerraBase()
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "not the configured") ||
		slices.ContainsFunc(*commands, func(args []string) bool { return slices.Contains(args, "terrabase-release") }) {
		t.Fatal("version tag of another commit", a.Err(), *commands)
	}
	for _, tag := range []string{"ci-" + terrabaseCommit + "-run-", "ci-" + terrabaseCommit[:39] + "-run-1", "ci-" + terrabaseCommit + "-run-1x"} {
		if _, ok := ciReleaseCommit(tag); ok {
			t.Fatal("parsed a malformed CI tag", tag)
		}
	}
}

func TestTerraBaseStopsOnATamperedChecksumOrABadCommit(t *testing.T) {
	a, commands := terrabaseAttempt(t, terrabaseCommit)
	if err := os.WriteFile(a.Path("terrabase", "ci-"+terrabaseCommit+"-run-1", "terrabase-linux-arm64.sha256"), []byte(strings.Repeat("0", 64)+"  terrabase-linux-arm64\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a.PhaseTerraBase()
	if a.Err() == nil || len(*commands) != 0 {
		t.Fatal(a.Err(), *commands)
	}
	for _, commit := range []string{"", strings.ToUpper(terrabaseCommit), terrabaseCommit[:39]} {
		a, commands = terrabaseAttempt(t, commit)
		a.PhaseTerraBase()
		if a.Err() == nil || !strings.Contains(a.Err().Error(), "commit") || len(*commands) != 0 {
			t.Fatal(commit, a.Err(), *commands)
		}
	}
}

// The image is imported into the plan's own region under its cell's static
// name, and every release record names that cell.
func TestImageImportsTheStaticCellImageName(t *testing.T) {
	for cell, want := range map[string][2]string{"GRU": {"gru-1-arm64", "sa-saopaulo-1"}, "SFO": {"sfo-1-arm64", "us-sanjose-1"}} {
		a := smallAttempt(t)
		a.Config["orchestrator"] = Object{"source_revision": terrabaseCommit}
		a.Config["namespace"] = "ns"
		a.Config["image"] = Object{"bucket": "images"}
		a.writeJSON(a.Plan(), Object{"cell": cell, "resource_ids": Object{"control_compartment": "ocid1.compartment.oc1..c"}})
		if err := a.WriteNew(a.Path("image", "terrascale-arm64.qcow2"), []byte("qcow2")); err != nil {
			t.Fatal(err)
		}
		server := imageimporttest.Start(t, "ocid1.image.fixture")
		var region string
		a.imageImporter = func(requested string) (imageimport.Importer, error) {
			region = requested
			return imageimporttest.Importer(server.URL)(requested)
		}
		var cells []string
		a.Runner = func(_ context.Context, c Command) (string, error) {
			for _, flag := range []string{"--image-cell", "--region"} {
				if value := flagValue(c.Args, flag); value != "" {
					cells = append(cells, value)
				}
			}
			return "", nil
		}
		a.PhaseImage()
		display := str(a.read(a.Path("image", "import.json")), "display_name")
		if a.Err() != nil || display != want[0] || region != want[1] || len(cells) != 3 || slices.ContainsFunc(cells, func(c string) bool { return c != cell }) {
			t.Fatal(cell, a.Err(), display, region, cells)
		}
	}
}

// Signed controller configs hold the cell's identity only: TerraBase's and
// ts-auth's profiles go to the services phase, never into the render. The
// KV snapshot location stays, since a rebuilt cell restores from it first.
func TestSignRendersIdentityOnlyConfigs(t *testing.T) {
	a := smallAttempt(t)
	profile := a.Path("terrabase-profile.json")
	for _, key := range []string{"region_intent", "placement_config", "managed_material_domain", "operator_grant"} {
		a.Config[key] = a.Path(key + ".json")
	}
	a.Config["terrabase_profile"] = profile
	for _, path := range []string{profile, a.Path("anchor.signed.json"), a.Path("controller-vault-references.json"), a.Path("peer-receipt-delegation.signed.json"),
		a.Path("controller-material.json"), a.ImageReceipt(), a.Path("region_intent.json"), a.Path("placement_config.json"), a.Path("managed_material_domain.json"), a.Path("operator_grant.json")} {
		a.writeJSON(path, Object{})
	}
	a.writeJSON(a.Path("image", "import.json"), Object{"image_id": "ocid1.image.fixture"})
	plan, err := os.ReadFile("../../deploy/oci-region/plan.json")
	if err == nil {
		err = os.WriteFile(a.Plan(), plan, 0600)
	}
	if err != nil {
		t.Fatal(err)
	}
	var render []string
	stop := errors.New("stop after render")
	a.Runner = func(_ context.Context, c Command) (string, error) {
		if slices.Contains(c.Args, "render-controller-config") {
			render = c.Args
		}
		return "", stop
	}
	snapshot := a.Path("kv-snapshot.json")
	a.writeJSON(snapshot, Object{"enabled": true})
	a.Config["kv_snapshot"] = snapshot
	digest := a.sha(snapshot)
	a.PhaseSign()
	if !errors.Is(a.Err(), stop) || slices.Contains(render, "--terrabase-profile") || render[len(render)-2] != "--out" ||
		flagValue(render, "--kv-snapshot") != snapshot || flagValue(render, "--kv-snapshot-sha256") != digest {
		t.Fatal(a.Err(), render)
	}

	// A cell that runs ts-auth renders no ts-auth either.
	a.err = nil
	authProfile, authService := a.Path("ts-auth-profile.json"), a.Path("ts-auth-service.json")
	a.writeJSON(authProfile, Object{"env": Object{}})
	a.writeJSON(authService, Object{"role": "ts-auth"})
	a.Config["ts_auth_profile"], a.Config["ts_auth_service"] = authProfile, authService
	render = nil
	a.PhaseSign()
	if !errors.Is(a.Err(), stop) || slices.Contains(render, "--ts-auth-profile") || slices.Contains(render, "--ts-auth-service") {
		t.Fatal(a.Err(), render)
	}
	// One without the other is refused before anything is rendered.
	delete(a.Config, "ts_auth_service")
	a.err, render = nil, nil
	a.PhaseSign()
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "ts_auth_profile and ts_auth_service together") || render != nil {
		t.Fatal(a.Err(), render)
	}
	// A resumed attempt keeps the configs an earlier attempt rendered with
	// the profiles and renders the rest identity only.
	a.Config["ts_auth_service"] = authService
	a.err, render = nil, nil
	resumed := a.Path("signed", "controller-a.config.json")
	a.writeJSON(resumed, Object{"controller": Object{"workloads": Object{"ts-auth": Object{}}}})
	var signed []string
	a.Runner = func(_ context.Context, c Command) (string, error) {
		signed = c.Args
		return "", stop
	}
	a.PhaseSign()
	if !errors.Is(a.Err(), stop) || !slices.Contains(signed, "sign-manifest") || flagValue(signed, "--controller-config") != resumed {
		t.Fatal(a.Err(), signed)
	}
	// It refuses to drop the role a retained config carries: that workload
	// stays generation 0 until a cell spec replaces it.
	delete(a.Config, "ts_auth_profile")
	delete(a.Config, "ts_auth_service")
	a.err, signed = nil, nil
	a.PhaseSign()
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "keep ts_auth_profile") || signed != nil {
		t.Fatal(a.Err(), signed)
	}
}

// The services phase applies TerraBase's profile first, then ts-auth, then
// the configured services; a role set both ways is refused.
func TestServicesPhaseAppliesTheCellsProfilesFirst(t *testing.T) {
	a := smallAttempt(t)
	a.Config["terrabase_profile"] = "/deploy/terrabase-profile.json"
	a.Config["ts_auth_profile"], a.Config["ts_auth_service"] = "/deploy/ts-auth-profile.json", "/deploy/ts-auth-service.json"
	a.Config["services"] = []any{Object{"role": "web", "profile": "/deploy/web-profile.json"}}
	want := []any{
		Object{"role": "terrabase", "profile": "/deploy/terrabase-profile.json"},
		Object{"role": "ts-auth", "profile": "/deploy/ts-auth-profile.json", "spec": "/deploy/ts-auth-service.json"},
		Object{"role": "web", "profile": "/deploy/web-profile.json"},
	}
	if got, err := a.cellServices(); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("services = %v, %v", got, err)
	}
	// A ts-auth entry without its service spec would otherwise replace the
	// pinned pair silently.
	a.Config["services"] = []any{Object{"role": "ts-auth", "profile": "/deploy/other-profile.json"}}
	if _, err := a.cellServices(); err == nil || !strings.Contains(err.Error(), "names ts-auth in services and in its own settings") {
		t.Fatalf("ts-auth set both ways: %v", err)
	}
	a.Config["services"] = []any{Object{"role": "terrabase", "profile": "/deploy/other-profile.json"}}
	if _, err := a.cellServices(); err == nil {
		t.Fatal("terrabase set both ways was accepted")
	}
	a.Config["services"] = nil
	delete(a.Config, "ts_auth_service")
	if _, err := a.cellServices(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Fatalf("ts-auth profile without its service: %v", err)
	}
}

// The services phase adds each configured service through a signed service
// set: plan, sign under the root's delegation to the leaf, apply. A service
// already in the set plans nothing, and a rerun reapplies the signed set.
func TestServicesPhaseAddsServicesThroughSignedSets(t *testing.T) {
	a := smallAttempt(t)
	a.Config["trust"] = Object{"root_public": "/keys/root.pub", "root_private": "/keys/root.key",
		"release_leaf_public": "/keys/leaf.pub", "release_leaf_private": "/keys/leaf.key"}
	// TerraBase, named last here, is already in the spec, and so are the
	// controllers' host grants.
	a.Config["services"] = []any{
		Object{"role": "ts-auth", "profile": "/deploy/ts-auth-profile.json", "spec": "/deploy/ts-auth-service.json"},
		Object{"role": "web", "profile": "/deploy/web-profile.json"},
		Object{"role": "terrabase", "profile": "../../deploy/oci-region/terrabase-gru-1-profile.json"},
	}
	plan, err := os.ReadFile("../../deploy/oci-region/plan.json")
	if err == nil {
		err = os.WriteFile(a.Plan(), plan, 0600)
	}
	if err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	a.Runner = func(_ context.Context, c Command) (string, error) {
		commands = append(commands, c.Args)
		write := slices.Contains(c.Args, "sign-spec-delegation") || slices.Contains(c.Args, "sign-spec") ||
			slices.Contains(c.Args, "add") && flagValue(c.Args, "--role") != "terrabase"
		if write {
			// ts-auth names Vault secrets, which only a root may add.
			plan := map[string]string{"ts-auth": `{"root_required":["service ts-auth Vault secrets"]}`, "web": `{"status":"planned"}`}[flagValue(c.Args, "--role")]
			return plan, os.WriteFile(flagValue(c.Args, "--out"), []byte("{}"), 0o600)
		}
		return "", nil
	}
	a.PhaseServices()
	cli, dir := a.Path("release", OperatorCLI), a.Path("services")
	sudo := []string{"sudo", "--preserve-env=PATH,LIBGUESTFS_PATH"}
	operator := []string{"--config", "/var/lib/terrascale-operator/operator.json"}
	candidate, signed := filepath.Join(dir, "ts-auth.candidate.json"), filepath.Join(dir, "ts-auth.signed.json")
	want := [][]string{
		nil, // the root's cell spec delegation, checked below
		append(sudo, "rm", "-f", "--", candidate, signed),
		join(sudo, []string{cli, "service", "add"}, operator, []string{"--role", "ts-auth", "--profile", "/deploy/ts-auth-profile.json",
			"--out", candidate, "--spec", "/deploy/ts-auth-service.json"}),
		nil, // the root signature, checked below
		join(sudo, []string{cli, "service", "apply"}, operator, []string{"--file", signed}),
		append(sudo, "rm", "-f", "--", filepath.Join(dir, "web.candidate.json"), filepath.Join(dir, "web.signed.json")),
		join(sudo, []string{cli, "service", "add"}, operator, []string{"--role", "web", "--profile", "/deploy/web-profile.json",
			"--out", filepath.Join(dir, "web.candidate.json")}),
		nil, // the leaf signature, checked below
		join(sudo, []string{cli, "service", "apply"}, operator, []string{"--file", filepath.Join(dir, "web.signed.json")}),
	}
	// Each planned and unchanged: TerraBase, then the three grants.
	if a.Err() != nil || len(commands) != len(want)+8 || flagValue(commands[len(want)+3], "--roles") != "ts-auth" {
		t.Fatal(a.Err(), commands)
	}
	for index, command := range want {
		if command != nil && !slices.Equal(commands[index], command) {
			t.Fatalf("command %d = %v, want %v", index, commands[index], command)
		}
	}
	delegation := commands[0]
	if !slices.Contains(delegation, "sign-spec-delegation") || flagValue(delegation, "--signing-key") != "/keys/root.key" ||
		flagValue(delegation, "--subject-public-key") != "/keys/leaf.pub" || flagValue(delegation, "--deployment-id") != "0000000000F9PR1WNVDTEXS31Z" ||
		flagValue(delegation, "--cell") != "gru" || flagValue(delegation, "--environment") != "canary" {
		t.Fatal(delegation)
	}
	sign := commands[3]
	if !slices.Contains(sign, "sign-spec") || !slices.Contains(sign, "--root") || flagValue(sign, "--candidate") != candidate ||
		flagValue(sign, "--signing-key") != "/keys/root.key" || flagValue(sign, "--out") != signed || slices.Contains(sign, "--delegation") {
		t.Fatal(sign)
	}
	sign = commands[7]
	if !slices.Contains(sign, "sign-spec") || slices.Contains(sign, "--root") || flagValue(sign, "--signing-key") != "/keys/leaf.key" ||
		flagValue(sign, "--delegation") != filepath.Join(dir, "spec-delegation.signed.json") {
		t.Fatal(sign)
	}
	// A rerun issues a fresh delegation and plans again from the cell's set.
	commands = nil
	a.PhaseServices()
	if a.Err() != nil || len(commands) != len(want)+8 || !slices.Contains(commands[0], "sign-spec-delegation") ||
		!slices.Equal(commands[4], want[4]) {
		t.Fatal(a.Err(), commands)
	}
	// A role names files the phase deletes as root, so it must be a role.
	a.Config["services"] = []any{Object{"role": "../../etc/x", "profile": "/deploy/web-profile.json"}}
	commands = nil
	if a.PhaseServices(); a.Err() == nil || len(commands) != 0 {
		t.Fatal(a.Err(), commands)
	}
}

// The bootstrap commands need a DEFAULT profile in the cell's region, so a
// second region's attempt names its own OCI config.
func TestAttemptOCIConfigDefaultsToTheOperatorsConfig(t *testing.T) {
	a := smallAttempt(t)
	home, _ := os.UserHomeDir()
	if got := a.ociConfig(); got != filepath.Join(home, ".oci", "config") {
		t.Fatal(got)
	}
	a.Config["oci_config"] = "/operator/oci-config-sfo"
	if got := a.ociConfig(); got != "/operator/oci-config-sfo" {
		t.Fatal(got)
	}
}
