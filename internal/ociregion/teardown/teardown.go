// Package teardown deletes exactly the OCI resources a reviewed cell
// teardown plan lists, in dependency order, and prints the diff first.
package teardown

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Kinds lists the supported resource kinds in deletion order. Compartments
// go last: OCI refuses to delete one that still holds a resource, including
// a vault or key waiting out its deletion window.
var Kinds = []string{"vault-secret", "kms-key", "kms-vault", "compartment"}

// NotFound is the State a provider reports for an OCI 404. OCI answers 404
// (NotAuthorizedOrNotFound) for a resource the caller may not read as well
// as for one that is gone, so it proves absence only inside a compartment
// that is itself DELETED.
const NotFound = "NOT_FOUND"

// Plan is a reviewed teardown input.
type Plan struct {
	Cell   string     `json:"cell"`
	Region string     `json:"region"`
	Delete []Resource `json:"delete"`
	// Keep records the shared resources reviewed as staying. It is printed,
	// never read from OCI, and may not overlap Delete.
	Keep []Resource `json:"keep"`
}

type Resource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
	// Compartment is the resource's compartment; a compartment's is its
	// parent. Every resource other than a compartment must live in a
	// compartment the plan also deletes.
	Compartment string `json:"compartment,omitempty"`
	// VaultID locates a kms-key's management endpoint.
	VaultID string `json:"vault_id,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Observed is a resource's current provider state.
type Observed struct {
	Name, Compartment, State string
	DeleteAt                 *time.Time
}

// Provider reads and deletes single resources. Delete of a vault, key or
// secret schedules its deletion at the earliest time OCI accepts.
type Provider interface {
	Get(context.Context, Resource) (Observed, error)
	Delete(context.Context, Resource) error
	// VaultContents lists live identities and ownership of every remaining
	// key and secret; deleting the vault deletes them too.
	VaultContents(context.Context, Resource) ([]Resource, error)
}

func Run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oci-region teardown", flag.ContinueOnError)
	fs.SetOutput(out)
	planPath := fs.String("plan", "", "reviewed teardown plan JSON")
	apply := fs.Bool("apply", false, "delete; without it only print the diff")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *planPath == "" {
		return errors.New("usage: ts-orch oci-region teardown --plan FILE [--apply]")
	}
	b, err := os.ReadFile(*planPath)
	if err != nil {
		return err
	}
	var plan Plan
	if err := json.Unmarshal(b, &plan, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("teardown plan: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	provider, err := NewSDKProvider(ctx, plan.Region)
	if err != nil {
		return err
	}
	return provider.teardown(ctx, plan, *apply, out)
}

func (p Plan) Validate() error {
	if p.Cell == "" || !catalog.IsOCIRegion(p.Region) {
		return fmt.Errorf("teardown plan needs a cell and a catalog OCI region, got %q/%q", p.Cell, p.Region)
	}
	deleted, owned := map[string]bool{}, map[string]bool{}
	for _, r := range p.Delete {
		if !slices.Contains(Kinds, r.Kind) || r.ID == "" || r.Name == "" || r.Compartment == "" ||
			(r.Kind == "kms-key") != (r.VaultID != "") {
			return fmt.Errorf("invalid teardown resource %+v", r)
		}
		if deleted[r.ID] {
			return fmt.Errorf("teardown plan lists %s twice", r.ID)
		}
		deleted[r.ID] = true
		if r.Kind == "compartment" {
			owned[r.ID] = true
		}
	}
	for _, r := range p.Delete {
		if r.Kind != "compartment" && !owned[r.Compartment] {
			return fmt.Errorf("%s %s lives in compartment %s, which the plan does not delete", r.Kind, r.ID, r.Compartment)
		}
	}
	for _, r := range p.Keep {
		if deleted[r.ID] || deleted[r.VaultID] || deleted[r.Compartment] {
			return fmt.Errorf("teardown plan deletes %s or the vault or compartment it needs, but keeps it", r.ID)
		}
	}
	return nil
}

type step struct {
	Resource
	observed       Observed
	action, detail string
}

// Teardown reads every planned resource and prints the whole diff, one
// action per resource in dependency order:
//
//	gone     absent already
//	absent   OCI answered 404 but its compartment still exists, so absence
//	         is unproven; OCI itself refuses to delete a non-empty compartment
//	pending  deletion accepted by OCI, waiting to finish
//	delete   live
//	held     a compartment that still holds a planned resource
//
// With apply it then deletes the resources marked delete. Rerunning is safe:
// gone, absent and pending resources are never touched again.
func Teardown(ctx context.Context, plan Plan, provider Provider, apply bool, out io.Writer) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	steps := make([]step, len(plan.Delete))
	verified := map[string]Resource{}
	for i, r := range plan.Delete {
		steps[i].Resource = r
	}
	slices.SortStableFunc(steps, func(a, b step) int {
		return slices.Index(Kinds, a.Kind) - slices.Index(Kinds, b.Kind)
	})
	deletedCompartments := map[string]bool{}
	for i := range steps {
		s := &steps[i]
		o, err := provider.Get(ctx, s.Resource)
		if err != nil {
			return fmt.Errorf("read %s %s: %w", s.Kind, s.ID, err)
		}
		if o.State != NotFound && o.State != "DELETED" && o.State != "TERMINATED" {
			if o.Name != s.Name || o.Compartment != s.Compartment {
				return fmt.Errorf("%s %s is %q in %s, the plan says %q in %s", s.Kind, s.ID, o.Name, o.Compartment, s.Name, s.Compartment)
			}
			verified[s.ID] = s.Resource
		}
		if s.Kind == "compartment" && o.State == "DELETED" {
			deletedCompartments[s.ID] = true
		}
		s.observed = o
	}
	for i := range steps {
		s := &steps[i]
		switch s.observed.State {
		case "DELETED", "TERMINATED":
			s.action = "gone"
		case NotFound:
			s.action = "absent"
			if deletedCompartments[s.Compartment] {
				s.action = "gone"
			}
		case "DELETING", "SCHEDULING_DELETION", "PENDING_DELETION", "TERMINATING":
			s.action = "pending"
			if s.observed.DeleteAt != nil {
				s.detail = "purge " + s.observed.DeleteAt.UTC().Format(time.RFC3339)
			}
		default:
			s.action = "delete"
		}
	}
	// Steps are final before any mutation: a compartment waits for every
	// planned resource inside it, child compartments included.
	for i := range steps {
		s := &steps[i]
		if s.Kind != "compartment" || s.action != "delete" {
			continue
		}
		inside := 0
		for _, c := range steps {
			if c.Compartment == s.ID && c.action != "gone" && c.action != "absent" {
				inside++
			}
		}
		if inside > 0 {
			s.action, s.detail = "held", fmt.Sprintf("waits for %d resources inside it to be gone", inside)
		}
	}
	var blocked []error
	for i := range steps {
		s := &steps[i]
		if s.Kind != "kms-vault" || s.action == "gone" || s.action == "absent" {
			continue
		}
		if err := verifyVaultContents(ctx, provider, s.Resource, verified); err != nil {
			s.action, s.detail = "blocked", err.Error()
			blocked = append(blocked, err)
		}
	}

	mode := "dry run"
	if apply {
		mode = "apply"
	}
	if _, err := fmt.Fprintf(out, "teardown %s %s (%s)\n", plan.Cell, plan.Region, mode); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, s := range steps {
		counts[s.action]++
		if _, err := fmt.Fprintf(out, "%-8s %-12s %s %s %s\n", s.action, s.Kind, s.Name, s.ID, s.detail); err != nil {
			return err
		}
	}
	for _, r := range plan.Keep {
		if _, err := fmt.Fprintf(out, "%-8s %-12s %s %s %s\n", "keep", r.Kind, r.Name, r.ID, r.Reason); err != nil {
			return err
		}
	}
	status := "incomplete"
	if counts["gone"] == len(steps) {
		status = "complete"
	}
	if _, err := fmt.Fprintf(out, "%s: gone %d, absent %d, pending %d, delete %d, held %d, keep %d\n", status,
		counts["gone"], counts["absent"], counts["pending"], counts["delete"], counts["held"], len(plan.Keep)); err != nil {
		return err
	}
	if len(blocked) > 0 {
		if _, err := fmt.Fprintf(out, "blocked: %d vaults; no mutations permitted\n", len(blocked)); err != nil {
			return errors.Join(err, errors.Join(blocked...))
		}
		return errors.Join(blocked...)
	}
	if !apply {
		return nil
	}
	deleted := 0
	for _, s := range steps {
		if s.action != "delete" {
			continue
		}
		if s.Kind == "kms-vault" {
			if err := verifyVaultContents(ctx, provider, s.Resource, verified); err != nil {
				if _, writeErr := fmt.Fprintf(out, "blocked  kms-vault    %s %s %s\n", s.Name, s.ID, err); writeErr != nil {
					return errors.Join(err, writeErr)
				}
				return fmt.Errorf("refuse vault deletion after %d deletions: %w", deleted, err)
			}
		}
		if err := provider.Delete(ctx, s.Resource); err != nil {
			return fmt.Errorf("delete %s %s after %d deletions: %w", s.Kind, s.ID, deleted, err)
		}
		deleted++
		if _, err := fmt.Fprintf(out, "deleted  %-12s %s %s\n", s.Kind, s.Name, s.ID); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(out, "applied: deleted %d; rerun to follow pending deletions\n", deleted)
	return err
}

func verifyVaultContents(ctx context.Context, provider Provider, vault Resource, verified map[string]Resource) error {
	contents, err := provider.VaultContents(ctx, vault)
	if err != nil {
		return fmt.Errorf("list vault %s: %w", vault.ID, err)
	}
	var unexpected []error
	for _, live := range contents {
		inventory, ok := verified[live.ID]
		if !ok || (live.Kind != "kms-key" && live.Kind != "vault-secret") || live.Kind != inventory.Kind ||
			live.Name != inventory.Name || live.Compartment != inventory.Compartment || live.VaultID != vault.ID ||
			(live.Kind == "kms-key" && inventory.VaultID != vault.ID) {
			unexpected = append(unexpected, fmt.Errorf("vault %s has unexpected %s %s %q in compartment %s (vault %s); not verified as cell-owned by the inventory",
				vault.ID, live.Kind, live.ID, live.Name, live.Compartment, live.VaultID))
		}
	}
	return errors.Join(unexpected...)
}
