package region

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/foundation"
)

// Runner runs one ts-orch command, as root when sudo is set, and returns its
// stdout. Output also goes to the operator as it is produced.
type Runner func(ctx context.Context, sudo bool, args ...string) (string, error)

// Creation is one region create run. Every step it runs is idempotent
// itself, so the journal only saves time: a step that failed or was
// interrupted runs again from its start.
type Creation struct {
	Label, OCIRegion string
	// State is the region's working directory: its plans, attempt,
	// journal and signed amendments.
	State string
	// Template is a reviewed plan of another non-home region.
	Template string
	// AttemptBase is the operator's attempt settings that no region
	// changes: trust keys, tools, image and release inputs.
	AttemptBase string
	// HomeOperator is the global home's operator config; Atlas lives
	// in the home cell's spec.
	HomeOperator string
	// HomePlan is the global home's bound plan, the region's private peer.
	HomePlan   string
	Deployment string
	// Wait bounds the final verification while the cell starts serving.
	Wait time.Duration

	Run    Runner
	Lookup Lookup
	Verify func(ctx context.Context, bound string, wait time.Duration) error
	Now    func() time.Time
	Out    io.Writer
}

// Journal records every step run with its wall time.
type Journal struct {
	Cell  string  `json:"cell"`
	Steps []Entry `json:"steps"`
}

// Entry is one run of one step.
type Entry struct {
	Step     string    `json:"step"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
	Error    string    `json:"error,omitempty"`
}

// Steps is the order region create runs.
var Steps = []string{"plan", "foundation", "netbird", "ts-auth-secrets", "found", "edge-cert", "edge", "peer", "dns", "atlas", "verify"}

func (c *Creation) path(name string) string { return filepath.Join(c.State, name) }

// Create runs every step not yet done, in order, and prints the wall time
// of each.
func (c *Creation) Create(ctx context.Context) error {
	entry, ok := catalog.LookupName(c.Label)
	if !ok || entry.OCIRegion != c.OCIRegion || entry.Cell == catalog.Bootstrap {
		return fmt.Errorf("region %s in %s is not a non-home region of the catalog (internal/ociregion/catalog)", c.Label, c.OCIRegion)
	}
	cell, err := naming.RegionCell(entry.Cell).Name()
	if err != nil {
		return err
	}
	// Refuse before anything is spent: the edge and NetBird steps need them.
	if os.Getenv("CF_API_TOKEN") == "" || os.Getenv("NB_PAT") == "" {
		return errors.New("region create needs CF_API_TOKEN and NB_PAT (gru-1-cloudflare-dns-edit-token and gru-1-netbird-admin-pat, docs/secrets.md)")
	}
	if c.HomePlan == "" {
		return errors.New("region create needs --home-plan, the global home's bound plan, to peer the region with it")
	}
	if home, err := ociregion.LoadPlan(c.HomePlan); err != nil || home["cell"] != catalog.Bootstrap {
		return fmt.Errorf("--home-plan %s is not the global home's plan: %v", c.HomePlan, err)
	}
	if err := os.MkdirAll(c.State, 0o700); err != nil {
		return err
	}
	journal := Journal{Cell: cell}
	if data, err := os.ReadFile(c.path("journal.json")); err == nil {
		if err := json.Unmarshal(data, &journal); err != nil || journal.Cell != cell {
			return fmt.Errorf("%s is another region's journal", c.path("journal.json"))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	steps := map[string]func(context.Context, string) error{
		"plan": c.plan, "foundation": c.foundation, "peer": c.peer, "netbird": c.netbird, "ts-auth-secrets": c.secrets, "found": c.found,
		"edge-cert": c.edgeCert, "edge": c.edge, "dns": c.dns, "atlas": c.atlas,
		"verify": func(ctx context.Context, _ string) error { return c.Verify(ctx, c.path("bound-plan.json"), c.Wait) },
	}
	for _, name := range Steps {
		if done(journal, name) {
			fmt.Fprintf(c.Out, "== %s: done\n", name)
			continue
		}
		fmt.Fprintf(c.Out, "== %s\n", name)
		journal.Steps = append(journal.Steps, Entry{Step: name, Started: c.Now().UTC()})
		if err := c.save(journal); err != nil {
			return err
		}
		err := steps[name](ctx, cell)
		last := &journal.Steps[len(journal.Steps)-1]
		last.Finished = c.Now().UTC()
		if err != nil {
			last.Error = err.Error()
		}
		if saveErr := c.save(journal); err != nil || saveErr != nil {
			return errors.Join(err, saveErr)
		}
	}
	return c.report(journal)
}

func done(journal Journal, step string) bool {
	for _, e := range slices.Backward(journal.Steps) {
		if e.Step == step {
			return !e.Finished.IsZero() && e.Error == ""
		}
	}
	return false
}

func (c *Creation) save(journal Journal) error {
	return writeJSON(c.path("journal.json"), journal)
}

// report prints each step's last successful run and the whole run's wall
// time, resumes and failed tries included.
func (c *Creation) report(journal Journal) error {
	fmt.Fprintln(c.Out, "| Step | Wall time |\n| --- | --- |")
	for _, name := range Steps {
		for _, e := range slices.Backward(journal.Steps) {
			if e.Step == name && e.Error == "" {
				fmt.Fprintf(c.Out, "| %s | %s |\n", name, e.Finished.Sub(e.Started).Round(time.Second))
				break
			}
		}
	}
	total := journal.Steps[len(journal.Steps)-1].Finished.Sub(journal.Steps[0].Started)
	_, err := fmt.Fprintf(c.Out, "| total | %s |\n", total.Round(time.Second))
	return err
}

func (c *Creation) plan(ctx context.Context, _ string) error {
	if _, err := os.Stat(c.path("plan.json")); err == nil {
		return nil
	}
	return DerivePlan(ctx, c.Lookup, c.Template, c.Label, c.OCIRegion, c.path("plan.json"))
}

// DerivePlan writes label's plan, derived from template, to out.
func DerivePlan(ctx context.Context, lookup Lookup, template, label, ociRegion, out string) error {
	reviewed, err := ociregion.LoadPlan(template)
	if err != nil {
		return fmt.Errorf("template plan: %w", err)
	}
	delete(reviewed, "_source_path")
	live, err := lookup(ctx, fmt.Sprint(reviewed["tenancy_id"]), ociRegion)
	if err != nil {
		return err
	}
	plan, err := Derive(reviewed, label, ociRegion, live)
	if err != nil {
		return err
	}
	return writePlan(out, plan)
}

// writePlan writes a plan the regional tools accept, or nothing.
func writePlan(path string, plan map[string]any) error {
	temporary := path + ".new"
	if err := writeJSON(temporary, plan); err != nil {
		return err
	}
	if _, err := ociregion.LoadPlan(temporary); err != nil {
		return errors.Join(fmt.Errorf("derived plan: %w", err), os.Remove(temporary))
	}
	return os.Rename(temporary, path)
}

func (c *Creation) foundation(ctx context.Context, _ string) error {
	_, err := c.Run(ctx, false, "oci-region", "foundation", "--plan", c.path("plan.json"), "--out", c.path("bound-plan.json"), "--apply")
	return err
}

// peerPorts are the TCP ports the region and the global home open to each
// other's private subnet: NATS leafnodes between regions and TerraBase's
// peer port.
var peerPorts = []int{7422, 9443}

// peer connects the region (left) and the global home (right) over a private
// DRG and remote peering connection with `oci-region peer` (TS-668). The
// draft pair intent is written once and pins both plans; a plan changed
// since is refused, so the intent is reviewed before it is replaced.
func (c *Creation) peer(ctx context.Context, _ string) error {
	intent, bound := c.path("peer-intent.json"), c.path("bound-plan.json")
	draft, err := foundation.DraftPeerIntent(bound, c.HomePlan, peerPorts)
	if err != nil {
		return err
	}
	if data, err := os.ReadFile(intent); errors.Is(err, os.ErrNotExist) {
		if err := writeJSON(intent, draft); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if !samePlans(data, draft) {
		return fmt.Errorf("%s pins plans that changed since it was written; review the change, delete it and rerun", intent)
	}
	_, err = c.Run(ctx, false, "oci-region", "peer", "--pair-intent", intent, "--left-plan", bound, "--right-plan", c.HomePlan,
		"--out", c.path("peer-bound-intent.json"), "--apply")
	return err
}

// samePlans reports whether a written pair intent pins the plans of draft.
func samePlans(data []byte, draft map[string]any) bool {
	var pinned struct {
		Cells map[string]struct {
			PlanSHA256 string `json:"plan_sha256"`
		} `json:"cells"`
	}
	cells, _ := draft["cells"].(map[string]any)
	if json.Unmarshal(data, &pinned) != nil || len(pinned.Cells) != len(cells) {
		return false
	}
	for cell, row := range cells {
		if pinned.Cells[cell].PlanSHA256 != row.(map[string]any)["plan_sha256"] {
			return false
		}
	}
	return true
}

// netbird lets the region's nodes enroll in NetBird: its servers group and
// policies, a setup key in the region's Vault and the image's netbird.json.
func (c *Creation) netbird(ctx context.Context, cell string) error {
	input, record := c.path("netbird.json"), c.path("netbird-setup-key.json")
	if _, err := os.Stat(record); errors.Is(err, os.ErrNotExist) {
		bound, err := ociregion.LoadPlan(c.path("bound-plan.json"))
		if err != nil {
			return err
		}
		ids, _ := bound["resource_ids"].(map[string]any)
		if _, err := c.Run(ctx, false, "netbird", "sync", "--apply"); err != nil {
			return err
		}
		key := c.path("netbird-setup-key")
		if err := os.Remove(key); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		defer os.Remove(key)
		if _, err := c.Run(ctx, false, "netbird", "setup-key", "--servers-group", c.Label+"-servers", "--out", key, "--apply"); err != nil {
			return err
		}
		// ponytail: a crash between this put and the record below leaves a
		// stored key a rerun's new key cannot replace (put refuses); write
		// the record by hand from vault put's output then.
		stored, err := c.Run(ctx, false, "vault", "put", "--vault-id", fmt.Sprint(ids["vault"]), "--key-id", fmt.Sprint(ids["key"]),
			"--compartment-id", fmt.Sprint(ids["control_compartment"]), "--name", cell+"-netbird-setup-key", "--file", key)
		if err != nil {
			return err
		}
		if err := os.WriteFile(record, []byte(lastLine(stored)+"\n"), 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	var stored struct {
		ID string `json:"id"`
	}
	data, err := os.ReadFile(record)
	if err == nil {
		err = json.Unmarshal(data, &stored)
	}
	if err != nil || stored.ID == "" {
		return fmt.Errorf("%s names no setup key secret: %v", record, err)
	}
	if err := os.Remove(input); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, err = c.Run(ctx, false, "netbird", "image-input", "--plan", c.path("bound-plan.json"), "--setup-key-secret-id", stored.ID, "--out", input)
	return err
}

func (c *Creation) secrets(ctx context.Context, _ string) error {
	_, err := c.Run(ctx, false, "ts-auth", "secrets", "--plan", c.path("bound-plan.json"))
	return err
}

// found founds the cell with the attempt every region uses
// (internal/attempt), run with the region's own settings.
func (c *Creation) found(ctx context.Context, cell string) error {
	var config map[string]any
	data, err := os.ReadFile(c.AttemptBase)
	if err == nil {
		err = json.Unmarshal(data, &config)
	}
	if err != nil || config == nil {
		return fmt.Errorf("attempt base %s: %v", c.AttemptBase, err)
	}
	for _, key := range []string{"workdir", "deployment_id", "prefix", "base_plan", "oci_config"} {
		if _, ok := config[key]; ok {
			return fmt.Errorf("the attempt base sets %s; region create sets it per region", key)
		}
	}
	// The bootstrap commands need a DEFAULT profile in the cell's region
	// (PR #279); derive it from the operator's.
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	profile, err := regionProfile(filepath.Join(home, ".oci", "config"), c.OCIRegion)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.path("oci-config"), profile, 0o600); err != nil {
		return err
	}
	deployment := c.Deployment
	if deployment == "" {
		deployment = entityid.Derive("regional-deployment", cell)
	}
	config["workdir"], config["deployment_id"], config["prefix"] = c.path("attempt"), deployment, cell
	config["base_plan"], config["oci_config"] = c.path("bound-plan.json"), c.path("oci-config")
	image, _ := config["image"].(map[string]any)
	if image == nil {
		image = map[string]any{}
	}
	if _, ok := image["netbird_config"]; ok {
		return errors.New("the attempt base sets image.netbird_config; region create sets it per region")
	}
	image["netbird_config"], config["image"] = c.path("netbird.json"), image
	if err := writeJSON(c.path("attempt.json"), config); err != nil {
		return err
	}
	_, err = c.Run(ctx, false, "oci-region", "attempt", "--config", c.path("attempt.json"), "up")
	return err
}

// regionProfile is the DEFAULT profile of an OCI config file with its region
// set to region.
func regionProfile(path, region string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	in, set := false, false
	for line := range strings.Lines(string(data)) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			in = trimmed == "[DEFAULT]"
		} else if key, _, ok := strings.Cut(trimmed, "="); in && ok && strings.TrimSpace(key) == "region" {
			line, set = "region="+region+"\n", true
		}
		if in {
			lines = append(lines, strings.TrimRight(line, "\n")+"\n")
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("%s has no DEFAULT profile", path)
	}
	if !set {
		lines = append(lines, "region="+region+"\n")
	}
	return []byte(strings.Join(lines, "")), nil
}

func (c *Creation) edgeCert(ctx context.Context, _ string) error {
	_, err := c.Run(ctx, false, "oci-region", "public-api", "cert", "--plan", c.path("bound-plan.json"), "--apply")
	return err
}

// edge creates the load balancer and records the IDs it prints in the
// bound plan, which inspect-foundation and verify read.
func (c *Creation) edge(ctx context.Context, _ string) error {
	material := filepath.Join(c.path("attempt"), "material")
	bound, err := ociregion.LoadPlan(c.path("bound-plan.json"))
	if err != nil {
		return err
	}
	args := []string{"oci-region", "public-api", "apply", "--plan", c.path("bound-plan.json"),
		"--member-ca", filepath.Join(material, "terrabase-member-ca.pem")}
	if public, _ := bound["public_api"].(map[string]any); public["orch"] == true {
		args = append(args, "--cell-ca", filepath.Join(material, "ca.pem"))
	}
	printed, err := c.Run(ctx, false, args...)
	if err != nil {
		return err
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(lastLine(printed)), &created); err != nil {
		return fmt.Errorf("public-api apply printed no resource IDs: %w", err)
	}
	ids, _ := bound["resource_ids"].(map[string]any)
	for key, id := range created {
		if _, planned := ids[key]; !planned {
			continue
		}
		if ids[key] != nil && ids[key] != id {
			return fmt.Errorf("bound plan %s is %v, the load balancer's is %v", key, ids[key], id)
		}
		ids[key] = id
	}
	delete(bound, "_source_path")
	return writePlan(c.path("bound-plan.json"), bound)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func (c *Creation) dns(ctx context.Context, _ string) error {
	_, err := c.Run(ctx, false, "oci-region", "dns", "--plan", c.path("bound-plan.json"), "--apply")
	return err
}

// atlas lists the region in the global home's Atlas section: one
// root-signed amendment of the home cell's spec, planned by its leader.
func (c *Creation) atlas(ctx context.Context, cell string) error {
	var base struct {
		Trust struct {
			RootPublic  string `json:"root_public"`
			RootPrivate string `json:"root_private"`
		} `json:"trust"`
	}
	data, err := os.ReadFile(c.AttemptBase)
	if err == nil {
		err = json.Unmarshal(data, &base)
	}
	if err != nil || base.Trust.RootPublic == "" || base.Trust.RootPrivate == "" {
		return fmt.Errorf("attempt base %s names no root trust keys: %v", c.AttemptBase, err)
	}
	candidate, signed := c.path("atlas.candidate.json"), c.path("atlas.signed.json")
	// Every run plans from the home cell's current spec.
	for _, path := range []string{candidate, signed} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if _, err := c.Run(ctx, true, "atlas", "add-region", "--config", c.HomeOperator, "--cell", cell, "--out", candidate); err != nil {
		return err
	}
	if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
		return nil // already listed
	}
	if _, err := c.Run(ctx, false, "release", "sign-spec", "--candidate", candidate, "--root",
		"--root-key", base.Trust.RootPublic, "--signing-key", base.Trust.RootPrivate, "--out", signed); err != nil {
		return err
	}
	_, err = c.Run(ctx, true, "apply", "--config", c.HomeOperator, "-f", signed)
	return err
}

// Exec runs the ts-orch executable itself, as attempt does.
func Exec(out, errOut io.Writer) (Runner, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, sudo bool, args ...string) (string, error) {
		name := "ts-orch " + strings.Join(args[:min(2, len(args))], " ")
		args = append([]string{executable}, args...)
		if sudo {
			args = append([]string{"sudo", "--preserve-env=PATH"}, args...)
		}
		var captured bytes.Buffer
		command := exec.CommandContext(ctx, args[0], args[1:]...)
		command.Stdout, command.Stderr = io.MultiWriter(out, &captured), errOut
		if err := command.Run(); err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		return captured.String(), nil
	}, nil
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value, json.Deterministic(true), jsontext.Multiline(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
