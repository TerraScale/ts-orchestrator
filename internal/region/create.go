package region

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// ResolveRegion names a region by its cell token (fra), its OCI region (eu-frankfurt-1).
// The global home is refused: it is founded, never created.
func ResolveRegion(token string) (catalog.Entry, error) {
	entry, ok := catalog.LookupName(token)
	if !ok {
		entry, ok = catalog.CellForOCIRegion(token)
	}
	if !ok {
		return catalog.Entry{}, fmt.Errorf("region %s is not in the region catalog (internal/ociregion/catalog)", token)
	}
	if entry.Cell == catalog.Bootstrap {
		return catalog.Entry{}, fmt.Errorf("region %s is the global home; it is founded, not created", token)
	}
	return entry, nil
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

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value, json.Deterministic(true), jsontext.Multiline(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
