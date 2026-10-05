package attempt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
		if c.Args[0] == "fj" {
			b, err := os.ReadFile(filepath.Join("..", "terrabase", "testdata", c.Args[len(c.Args)-3]))
			if err != nil {
				return "", err
			}
			return "", os.WriteFile(flagValue(c.Args, "-o"), b, 0600)
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
		{"git", "clone", "--quiet", "https://git.terrascale.tech/TerraScale/terrabase", source},
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
		!slices.Equal((*commands)[0], []string{"fj", "release", "asset", "download", "-r", "TerraScale/terrabase", "v0.2.0", "terrabase-linux-arm64", "-o", next}) ||
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

func TestImageImportsTheStaticCellImageName(t *testing.T) {
	a := smallAttempt(t)
	a.Config["orchestrator"] = Object{"source_revision": terrabaseCommit}
	a.writeJSON(a.Plan(), Object{"resource_ids": Object{"control_compartment": "ocid1.compartment.oc1..c"}})
	if err := a.WriteNew(a.Path("image", "terrascale-arm64.qcow2"), []byte("qcow2")); err != nil {
		t.Fatal(err)
	}
	var display string
	a.Runner = func(_ context.Context, c Command) (string, error) {
		if slices.Contains(c.Args, "import-image") {
			display = flagValue(c.Args, "--display-name")
			return "", os.WriteFile(flagValue(c.Args, "--out"), []byte(`{"image_id":"ocid1.image.fixture"}`), 0600)
		}
		return "", nil
	}
	a.PhaseImage()
	if a.Err() != nil || display != "gru-1-arm64" {
		t.Fatal(a.Err(), display)
	}
}

func TestSignRendersTheTerraBaseProfile(t *testing.T) {
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
	digest := a.sha(profile)
	a.PhaseSign()
	if !errors.Is(a.Err(), stop) || flagValue(render, "--terrabase-profile") != profile ||
		flagValue(render, "--terrabase-profile-sha256") != digest || render[len(render)-2] != "--out" ||
		slices.Contains(render, "--ts-auth-profile") {
		t.Fatal(a.Err(), render)
	}

	// A cell that runs ts-auth renders its pinned profile and service into
	// the controller config, which cannot gain them after it is signed.
	a.err = nil
	authProfile, authService := a.Path("ts-auth-profile.json"), a.Path("ts-auth-service.json")
	a.writeJSON(authProfile, Object{"env": Object{}})
	a.writeJSON(authService, Object{"role": "ts-auth"})
	a.Config["ts_auth_profile"], a.Config["ts_auth_service"] = authProfile, authService
	render = nil
	profileDigest, serviceDigest := a.sha(authProfile), a.sha(authService)
	a.PhaseSign()
	if !errors.Is(a.Err(), stop) || flagValue(render, "--ts-auth-profile") != authProfile ||
		flagValue(render, "--ts-auth-profile-sha256") != profileDigest || flagValue(render, "--ts-auth-service") != authService ||
		flagValue(render, "--ts-auth-service-sha256") != serviceDigest || render[len(render)-2] != "--out" {
		t.Fatal(a.Err(), render)
	}
	// One without the other is refused before anything is rendered.
	delete(a.Config, "ts_auth_service")
	a.err, render = nil, nil
	a.PhaseSign()
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "ts_auth_profile and ts_auth_service together") || render != nil {
		t.Fatal(a.Err(), render)
	}
	// A resumed attempt whose controller-a config was rendered without
	// ts-auth refuses to render the others with it.
	a.Config["ts_auth_service"] = authService
	a.err, render = nil, nil
	a.writeJSON(a.Path("signed", "controller-a.config.json"), Object{"controller": Object{"workloads": Object{"terrabase": Object{}}}})
	a.PhaseSign()
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "cannot gain or lose ts-auth") || render != nil {
		t.Fatal(a.Err(), render)
	}
}
